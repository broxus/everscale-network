use std::borrow::Cow;
use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};
use rand::Rng;
use smallvec::smallvec;
use tl_proto::{BoxedConstructor, BoxedWrapper, TlRead, TlWrite};

use crate::adnl_node::{AdnlNode, NewPeerContext};
use crate::overlay_node::MAX_OVERLAY_PEERS;
use crate::proto;
use crate::subscriber::*;
use crate::utils::*;

use self::buckets::*;
use self::peers_iter::*;
use self::storage::*;
pub use self::values_stream::DhtValuesStream;

mod buckets;
mod peers_iter;
mod storage;
mod values_stream;

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DhtNodeOptions {
    /// Default: 3600
    pub value_timeout_sec: u32,
    /// Default: 5
    pub query_value_batch_len: usize,
    /// Default: 5
    pub max_fail_count: usize,
    /// Default: 5
    pub max_peers_response_len: u32,
}

impl Default for DhtNodeOptions {
    fn default() -> Self {
        Self {
            value_timeout_sec: 3600,
            query_value_batch_len: 5,
            max_fail_count: 5,
            max_peers_response_len: 20,
        }
    }
}

/// Kademlia-like DHT node
pub struct DhtNode {
    /// Underlying ADNL node
    adnl: Arc<AdnlNode>,
    /// Local ADNL key
    node_key: Arc<StoredAdnlNodeKey>,
    /// Configuration
    options: DhtNodeOptions,

    /// Known DHT nodes
    known_peers: PeersCache,
    /// DHT nodes penalty scores table
    bad_peers: BadPeers,

    /// DHT nodes organized by buckets
    buckets: Buckets,
    /// Local DHT values storage
    storage: Storage,

    /// Serialized [`proto::rpc::DhtQuery`] with own DHT node info
    query_prefix: Vec<u8>,
}

impl DhtNode {
    /// Create new DHT node on top of ADNL node
    pub fn new(adnl: Arc<AdnlNode>, key_tag: usize, options: DhtNodeOptions) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?.clone();

        let buckets = Buckets::new(node_key.id());

        let mut dht_node = Self {
            adnl,
            node_key,
            options,
            known_peers: PeersCache::with_capacity(MAX_OVERLAY_PEERS),
            buckets,
            bad_peers: Default::default(),
            storage: Storage::default(),
            query_prefix: Vec::new(),
        };

        dht_node.query_prefix = tl_proto::serialize(proto::rpc::DhtQuery {
            node: dht_node.sign_local_node().as_equivalent_ref(),
        });

        Ok(Arc::new(dht_node))
    }

    /// Configuration
    #[inline(always)]
    pub fn options(&self) -> &DhtNodeOptions {
        &self.options
    }

    /// Instant metrics
    pub fn metrics(&self) -> DhtNodeMetrics {
        DhtNodeMetrics {
            peers_cache_len: self.known_peers.len(),
            bucket_peer_count: self.buckets.iter().map(|bucket| bucket.len()).sum(),
            storage_len: self.storage.len(),
            storage_total_size: self.storage.total_size(),
        }
    }

    /// Underlying ADNL node
    pub fn adnl(&self) -> &Arc<AdnlNode> {
        &self.adnl
    }

    /// Adds new peer to DHT or explicitly marks existing as good. Returns new peer short id
    pub fn add_dht_peer(&self, mut peer: proto::dht::NodeOwned) -> Result<Option<AdnlNodeIdShort>> {
        let peer_full_id = AdnlNodeIdFull::try_from(peer.id.as_equivalent_ref())?;

        // Verify signature
        let signature = std::mem::take(&mut peer.signature);
        if peer_full_id.verify(peer.as_boxed(), &signature).is_err() {
            tracing::warn!("Invalid DHT peer signature");
            return Ok(None);
        }
        peer.signature = signature;

        // Parse remaining peer data
        let peer_id = peer_full_id.compute_short_id();
        let peer_ip_address =
            parse_address_list(&peer.addr_list, self.adnl.options().clock_tolerance_sec)?;

        // Add new ADNL peer
        let is_new_peer = self.adnl.add_peer(
            NewPeerContext::Dht,
            self.node_key.id(),
            &peer_id,
            peer_ip_address,
            peer_full_id,
        )?;
        if !is_new_peer {
            return Ok(None);
        }

        // Add new peer to the bucket
        if self.known_peers.put(peer_id) {
            self.buckets.insert(&peer_id, peer);
        } else {
            self.set_good_peer(&peer_id);
        }

        Ok(Some(peer_id))
    }

    /// Queries given peer for at most `k` DHT nodes with
    /// the same affinity as `local_id <-> peer_id`
    pub async fn query_dht_nodes(
        &self,
        peer_id: &AdnlNodeIdShort,
        k: u32,
    ) -> Result<Vec<proto::dht::NodeOwned>> {
        let query = proto::rpc::DhtFindNode {
            key: self.node_key.id().as_slice(),
            k,
        };
        Ok(match self.query_with_prefix(peer_id, query).await? {
            Some(BoxedWrapper(proto::dht::NodesOwned { nodes })) => nodes,
            None => Vec::new(),
        })
    }

    /// Queries given peer for the value
    pub async fn query_value<T>(
        &self,
        peer_id: &AdnlNodeIdShort,
        key: proto::dht::Key<'_>,
    ) -> Result<Option<(proto::dht::KeyDescriptionOwned, T)>>
    where
        for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
    {
        let key_id = tl_proto::hash_as_boxed(key);

        let query = tl_proto::serialize(proto::rpc::DhtFindValue { key: &key_id, k: 6 }).into();

        let result = match self.query_raw(peer_id, query).await? {
            Some(answer) => answer,
            None => return Ok(None),
        };

        match tl_proto::deserialize::<proto::dht::ValueResult>(&result)? {
            proto::dht::ValueResult::ValueFound(BoxedWrapper(value)) => {
                let parsed = tl_proto::deserialize(value.value)?;
                Ok(Some((value.key.as_equivalent_owned(), parsed)))
            }
            proto::dht::ValueResult::ValueNotFound(proto::dht::NodesOwned { nodes }) => {
                for node in nodes {
                    if let Err(e) = self.add_dht_peer(node) {
                        tracing::warn!("Failed to add DHT peer: {e:?}");
                    }
                }
                Ok(None)
            }
        }
    }

    pub fn values<T>(self: &Arc<Self>, key: proto::dht::Key<'_>) -> DhtValuesStream<T>
    where
        for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
    {
        DhtValuesStream::new(self.clone(), key)
    }

    /// Returns values stream over all overlay nodes stored in DHT
    // pub fn overlay_nodes(
    //     self: &Arc<Self>,
    //     overlay_id: &OverlayIdShort,
    // ) -> impl Stream<Item = (PackedSocketAddr, proto::overlay::NodeOwned)> {
    //     //
    // }

    pub async fn find_overlay_nodes(
        self: &Arc<Self>,
        overlay_id: &OverlayIdShort,
        external_iter: &mut Option<PeersIter>,
    ) -> Result<Vec<(PackedSocketAddr, proto::overlay::NodeOwned)>> {
        let mut result = Vec::new();
        let mut nodes = Vec::new();

        let key = make_dht_key(overlay_id, DHT_KEY_NODES);

        loop {
            type Value = BoxedWrapper<proto::overlay::NodesOwned>;
            let mut nodes_lists = self.find_value::<Value>(key, true, external_iter).await?;
            if nodes_lists.is_empty() {
                break;
            }

            while let Some((_, BoxedWrapper(nodes_lists))) = nodes_lists.pop() {
                nodes.extend(nodes_lists.nodes);
            }

            let mut response_collector = ResponseCollector::new();

            let cache = PeersCache::with_capacity(MAX_OVERLAY_PEERS);
            while let Some(node) = nodes.pop() {
                let peer_full_id = AdnlNodeIdFull::try_from(node.id.as_equivalent_ref())?;
                let peer_id = peer_full_id.compute_short_id();
                if !cache.put(peer_id) {
                    continue;
                }

                let response_tx = response_collector.make_request();

                let dht = self.clone();
                tokio::spawn(async move {
                    match dht.find_address(&peer_id).await {
                        Ok((ip, _)) => {
                            tracing::debug!("---- Got overlay node {ip}");
                            response_tx.send(Some((Some(ip), node)));
                        }
                        Err(_) => {
                            tracing::debug!("---- Overlay node {peer_id} not found");
                            response_tx.send(Some((None, node)));
                        }
                    }
                });
            }

            loop {
                match response_collector.wait(false).await {
                    Some(Some((None, node))) => nodes.push(node),
                    Some(Some((Some(ip), node))) => result.push((ip, node)),
                    _ => break,
                }
            }

            if !result.is_empty() {
                break;
            }

            if external_iter.is_none() {
                break;
            }
        }

        Ok(result)
    }

    pub async fn store_overlay_node(
        self: &Arc<Self>,
        overlay_full_id: &OverlayIdFull,
        node: proto::overlay::Node<'_>,
    ) -> Result<bool> {
        let overlay_id = overlay_full_id.compute_short_id();
        verify_node(&overlay_id, &node)?;

        let value = tl_proto::serialize_as_boxed(proto::overlay::Nodes {
            nodes: smallvec![node],
        });

        let value = proto::dht::Value {
            key: proto::dht::KeyDescription {
                key: make_dht_key(&overlay_id, DHT_KEY_NODES),
                id: everscale_crypto::tl::PublicKey::Overlay {
                    name: overlay_full_id.as_slice(),
                },
                update_rule: proto::dht::UpdateRule::OverlayNodes,
                signature: Default::default(),
            },
            value: &value,
            ttl: now() + self.options.value_timeout_sec,
            signature: Default::default(),
        };

        self.storage.insert_overlay_nodes(value)?;

        type StoredValue = BoxedWrapper<proto::overlay::NodesOwned>;
        self.store_value::<StoredValue, _>(value, true, move |values| {
            for (_, value) in values.iter().rev() {
                for stored_node in &value.0.nodes {
                    if stored_node.as_equivalent_ref() == node {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
        .await
    }

    pub async fn find_address(
        self: &Arc<Self>,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<(PackedSocketAddr, AdnlNodeIdFull)> {
        type Value = BoxedWrapper<proto::adnl::AddressList>;
        let mut address_list = self
            .find_value::<Value>(make_dht_key(peer_id, DHT_KEY_ADDRESS), false, &mut None)
            .await?;

        match address_list.pop() {
            Some((key, BoxedWrapper(value))) => {
                let ip_address =
                    parse_address_list(&value, self.adnl.options().clock_tolerance_sec)?;
                let full_id = AdnlNodeIdFull::try_from(key.id.as_equivalent_ref())?;

                Ok((ip_address, full_id))
            }
            None => Err(DhtNodeError::NoAddressFound.into()),
        }
    }

    pub async fn store_ip_address(self: &Arc<Self>, key: &StoredAdnlNodeKey) -> Result<bool> {
        let value = tl_proto::serialize_as_boxed(self.adnl.build_address_list());

        let mut value = proto::dht::Value {
            key: proto::dht::KeyDescription {
                key: make_dht_key(key.id(), DHT_KEY_ADDRESS),
                id: key.full_id().as_tl(),
                update_rule: proto::dht::UpdateRule::Signature,
                signature: Default::default(),
            },
            value: &value,
            ttl: now() + self.options.value_timeout_sec,
            signature: Default::default(),
        };
        let key_signature = key.sign(value.key.as_boxed());
        value.signature = &key_signature;

        let value_signature = key.sign(value.as_boxed());
        value.signature = &value_signature;

        self.storage.insert_signed_value(value)?;

        type StoredValue = BoxedWrapper<proto::adnl::AddressList>;
        self.store_value::<StoredValue, _>(value, false, |mut values| {
            while let Some((_, value)) = values.pop() {
                let ip = parse_address_list(&value.0, self.adnl.options().clock_tolerance_sec)?;
                if ip == self.adnl.ip_address() {
                    return Ok(true);
                } else {
                    tracing::warn!(
                        "Found another stored address {ip}, expected {}",
                        self.adnl.ip_address()
                    );
                    continue;
                }
            }
            Ok(false)
        })
        .await
    }

    pub fn fetch_address_locally(
        &self,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<Option<(PackedSocketAddr, AdnlNodeIdFull)>> {
        let key = make_dht_key(peer_id, DHT_KEY_ADDRESS);
        Ok(match self.storage.get_ref(&tl_proto::hash_as_boxed(key)) {
            Some(stored) => Some(parse_dht_value_address(
                stored.key.as_equivalent_ref(),
                &stored.value,
                self.adnl.options().clock_tolerance_sec,
            )?),
            None => None,
        })
    }

    pub fn iter_known_peers(&self) -> impl Iterator<Item = &AdnlNodeIdShort> {
        self.known_peers.iter()
    }

    pub async fn ping(&self, peer_id: &AdnlNodeIdShort) -> Result<bool> {
        let random_id = rand::thread_rng().gen();
        match self
            .query(peer_id, proto::rpc::DhtPing { random_id })
            .await?
        {
            Some(proto::dht::Pong { random_id: answer }) => Ok(answer == random_id),
            None => Ok(false),
        }
    }

    fn process_find_node(&self, query: proto::rpc::DhtFindNode<'_>) -> proto::dht::NodesOwned {
        self.buckets.find(query.key, query.k)
    }

    fn process_find_value(
        &self,
        query: proto::rpc::DhtFindValue<'_>,
    ) -> Result<proto::dht::ValueResultOwned> {
        if query.k == 0 || query.k > self.options.max_peers_response_len {
            return Err(DhtNodeError::InvalidNodeCountLimit.into());
        }

        Ok(if let Some(value) = self.storage.get_ref(query.key) {
            proto::dht::ValueResultOwned::ValueFound(value.clone().into_boxed())
        } else {
            let mut nodes = Vec::with_capacity(query.k as usize);

            'outer: for bucket in &self.buckets {
                for peer in bucket {
                    nodes.push(peer.clone());

                    if nodes.len() >= query.k as usize {
                        break 'outer;
                    }
                }
            }

            proto::dht::ValueResultOwned::ValueNotFound(proto::dht::NodesOwned { nodes })
        })
    }

    fn process_get_signed_address_list(&self) -> proto::dht::NodeOwned {
        self.sign_local_node()
    }

    fn process_store(&self, query: proto::rpc::DhtStore<'_>) -> Result<proto::dht::Stored> {
        if query.value.ttl <= now() {
            return Err(DhtNodeError::InsertedValueExpired.into());
        }

        match query.value.key.update_rule {
            proto::dht::UpdateRule::Signature => {
                self.storage.insert_signed_value(query.value)?;
            }
            proto::dht::UpdateRule::OverlayNodes => {
                self.storage.insert_overlay_nodes(query.value)?;
            }
            _ => return Err(DhtNodeError::UnsupportedStoreQuery.into()),
        }

        Ok(proto::dht::Stored)
    }

    async fn query<Q, A>(&self, peer_id: &AdnlNodeIdShort, query: Q) -> Result<Option<A>>
    where
        Q: TlWrite,
        for<'a> A: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
    {
        let result = self
            .adnl
            .query(self.node_key.id(), peer_id, query, None)
            .await;
        self.update_peer_status(peer_id, result.is_ok());
        result
    }

    async fn query_raw(&self, peer_id: &AdnlNodeIdShort, query: Bytes) -> Result<Option<Vec<u8>>> {
        let result = self
            .adnl
            .query_raw(self.node_key.id(), peer_id, query, None)
            .await;
        self.update_peer_status(peer_id, result.is_ok());
        result
    }

    async fn query_with_prefix<Q, A>(
        &self,
        peer_id: &AdnlNodeIdShort,
        query: Q,
    ) -> Result<Option<A>>
    where
        Q: TlWrite,
        for<'a> A: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
    {
        let result = self
            .adnl
            .query_with_prefix::<Q, A>(self.node_key.id(), peer_id, &self.query_prefix, query, None)
            .await;
        self.update_peer_status(peer_id, result.is_ok());
        result
    }

    pub async fn find_value<T>(
        self: &Arc<Self>,
        key: proto::dht::Key<'_>,
        all: bool,
        external_iter: &mut Option<PeersIter>,
    ) -> Result<Vec<(proto::dht::KeyDescriptionOwned, T)>>
    where
        for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
    {
        let key_id = tl_proto::hash_as_boxed(key);
        let iter = external_iter.get_or_insert_with(|| PeersIter::with_key_id(key_id));
        if iter.key_id() != &key_id {
            return Err(DhtNodeError::KeyMismatch.into());
        }

        let max_tasks = self.options.query_value_batch_len;

        let mut result = Vec::new();
        let mut known_peers_version = self.known_peers.version();

        let mut futures = FuturesUnordered::new();
        'outer: loop {
            // Spawn at most `max_tasks` queries
            while let Some(peer_id) = iter.next() {
                let dht = self.clone();
                let key = key.as_equivalent_owned();

                futures.push(async move {
                    let key = key.as_equivalent_ref();
                    match dht.query_value::<T>(&peer_id, key).await {
                        Ok(value) => value,
                        Err(e) => {
                            tracing::warn!("Failed to query value: {e}");
                            None
                        }
                    }
                });

                if futures.len() > max_tasks {
                    break;
                }
            }

            loop {
                // Wait for the next response
                match futures.next().await {
                    Some(Some(response)) => result.push(response),
                    Some(None) => {}
                    None => break 'outer,
                }

                // If we should receive all values, or we haven't received any yet,
                // then we should check whether known peers were updated
                if all || result.is_empty() {
                    match self.known_peers.version() {
                        version if version != known_peers_version => {
                            iter.reset(self, Some(self.options.query_value_batch_len));
                            known_peers_version = version;
                        }
                        _ => {}
                    }
                }

                // Stop waiting for responses if we have any and we don't need the rest
                if !all && !result.is_empty() || all && result.len() >= max_tasks {
                    break 'outer;
                }

                // Try to refill futures queue
                if result.len() < max_tasks {
                    continue 'outer;
                }
            }
        }

        if iter.is_empty() {
            external_iter.take();
        }

        Ok(result)
    }

    pub async fn store_value<T, FV>(
        self: &Arc<Self>,
        value: proto::dht::Value<'_>,
        check_all: bool,
        check_values: FV,
    ) -> Result<bool>
    where
        FV: Fn(Vec<(proto::dht::KeyDescriptionOwned, T)>) -> Result<bool>,
        for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
    {
        let key = value.key.key;
        let query = Bytes::from(tl_proto::serialize(proto::rpc::DhtStore { value }));

        let mut response_collector = ResponseCollector::new();

        let mut index = 0;
        while index < self.known_peers.len() {
            while let Some(peer_id) = self.known_peers.get(index) {
                index += 1;

                let dht = self.clone();
                let query = query.clone();
                let response_tx = response_collector.make_request();
                tokio::spawn(async move {
                    let response = match dht.query_raw(&peer_id, query).await {
                        Ok(Some(answer)) => {
                            match tl_proto::deserialize::<proto::dht::Stored>(&answer) {
                                Ok(_) => Some(()),
                                Err(_) => None,
                            }
                        }
                        Ok(None) => None,
                        Err(_) => None,
                    };
                    response_tx.send(response);
                });
            }

            while response_collector.wait(false).await.is_some() {}

            let values = self.find_value(key, check_all, &mut None).await?;
            if check_values(values)? {
                return Ok(true);
            }

            index += 1;
        }

        Ok(false)
    }

    fn sign_local_node(&self) -> proto::dht::NodeOwned {
        let mut node = proto::dht::NodeOwned {
            id: self.node_key.full_id().as_tl().as_equivalent_owned(),
            addr_list: self.adnl.build_address_list(),
            version: now(),
            signature: Default::default(),
        };
        node.signature = self.node_key.sign(node.as_boxed()).to_vec().into();
        node
    }

    fn update_peer_status(&self, peer: &AdnlNodeIdShort, is_good: bool) {
        use dashmap::mapref::entry::Entry;

        if is_good {
            self.set_good_peer(peer);
        } else {
            match self.bad_peers.entry(*peer) {
                Entry::Occupied(mut entry) => {
                    *entry.get_mut() += 2;
                }
                Entry::Vacant(entry) => {
                    entry.insert(0);
                }
            }
        }
    }

    fn set_good_peer(&self, peer: &AdnlNodeIdShort) {
        if let Some(mut count) = self.bad_peers.get_mut(peer) {
            *count.value_mut() = count.saturating_sub(1);
        }
    }
}

#[async_trait::async_trait]
impl Subscriber for DhtNode {
    async fn try_consume_query<'a>(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        constructor: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        match constructor {
            proto::rpc::DhtPing::TL_ID => {
                let proto::rpc::DhtPing { random_id } = tl_proto::deserialize(&query)?;
                QueryConsumingResult::consume(proto::dht::Pong { random_id })
            }
            proto::rpc::DhtFindNode::TL_ID => {
                let query = tl_proto::deserialize(&query)?;
                QueryConsumingResult::consume(self.process_find_node(query).into_boxed())
            }
            proto::rpc::DhtFindValue::TL_ID => {
                let query = tl_proto::deserialize(&query)?;
                QueryConsumingResult::consume(self.process_find_value(query)?)
            }
            proto::rpc::DhtGetSignedAddressList::TL_ID => {
                QueryConsumingResult::consume(self.process_get_signed_address_list().into_boxed())
            }
            proto::rpc::DhtStore::TL_ID => {
                let query = tl_proto::deserialize(&query)?;
                QueryConsumingResult::consume(self.process_store(query)?)
            }
            proto::rpc::DhtQuery::TL_ID => {
                let mut offset = 0;
                let proto::rpc::DhtQuery { node } = <_>::read_from(&query, &mut offset)?;
                let constructor = u32::read_from(&query, &mut std::convert::identity(offset))?;

                if offset >= query.len() {
                    return Err(DhtNodeError::UnexpectedQuery.into());
                }

                self.add_dht_peer(node.as_equivalent_owned())?;

                match self
                    .try_consume_query(
                        local_id,
                        peer_id,
                        constructor,
                        Cow::Borrowed(&query[offset..]),
                    )
                    .await?
                {
                    QueryConsumingResult::Consumed(answer) => {
                        Ok(QueryConsumingResult::Consumed(answer))
                    }
                    QueryConsumingResult::Rejected(_) => Err(DhtNodeError::UnexpectedQuery.into()),
                }
            }
            _ => Ok(QueryConsumingResult::Rejected(query)),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct DhtNodeMetrics {
    pub peers_cache_len: usize,
    pub bucket_peer_count: usize,
    pub storage_len: usize,
    pub storage_total_size: usize,
}

const DHT_KEY_ADDRESS: &str = "address";
const DHT_KEY_NODES: &str = "nodes";

type BadPeers = FxDashMap<AdnlNodeIdShort, usize>;
pub type ReceivedValue<T> = (proto::dht::KeyDescriptionOwned, T);

#[derive(thiserror::Error, Debug)]
enum DhtNodeError {
    #[error("No address found")]
    NoAddressFound,
    #[error("Unexpected DHT query")]
    UnexpectedQuery,
    #[error("Inserted value is expired")]
    InsertedValueExpired,
    #[error("Unsupported store query")]
    UnsupportedStoreQuery,
    #[error("DHT key mismatch in value search")]
    KeyMismatch,
    #[error("Invalid node count limit")]
    InvalidNodeCountLimit,
}
