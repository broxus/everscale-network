use std::borrow::{Borrow, Cow};
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use rand::Rng;
use smallvec::smallvec;
use tl_proto::{BoxedConstructor, BoxedWrapper, TlRead, TlWrite};

use super::buckets::Buckets;
use super::futures::DhtStoreValue;
use super::storage::Storage;
use super::{DHT_KEY_ADDRESS, DHT_KEY_NODES};
use crate::adnl::{AdnlNode, NewPeerContext};
use crate::dht::entry::DhtEntry;
use crate::overlay::MAX_OVERLAY_PEERS;
use crate::proto;
use crate::subscriber::*;
use crate::utils::*;

/// DHT node configuration
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DhtNodeOptions {
    /// Default stored value timeout used for [`DhtNode::store_overlay_node`] and
    /// [`DhtNode::store_ip_address`]
    ///
    /// Default: `3600` seconds
    pub value_ttl_sec: u32,

    /// ADNL query timeout
    ///
    /// Default: `1000` ms
    pub query_timeout_ms: u64,

    /// Amount of DHT peers, used for values search
    ///
    /// Default: `5`
    pub default_value_batch_len: usize,

    /// Max peer penalty points. On each unsuccessful query every peer gains 2 points,
    /// and then they are reduced by one on each good action.
    ///
    /// Default: `5`
    pub bad_peer_threshold: usize,

    /// Max allowed `k` value for DHT `FindValue` query.
    ///
    /// Default: `5`
    pub max_allowed_k: u32,

    /// Storage GC interval. Will remove all outdated entries
    ///
    /// Default: `10000` ms
    pub storage_gc_interval_ms: u64,
}

impl Default for DhtNodeOptions {
    fn default() -> Self {
        Self {
            value_ttl_sec: 3600,
            query_timeout_ms: 1000,
            default_value_batch_len: 5,
            bad_peer_threshold: 5,
            max_allowed_k: 20,
            storage_gc_interval_ms: 10000,
        }
    }
}

/// Kademlia-like DHT node
pub struct DhtNode {
    /// Underlying ADNL node
    pub(super) adnl: Arc<AdnlNode>,
    /// Local ADNL key
    pub(super) node_key: Arc<StoredAdnlNodeKey>,
    /// Configuration
    pub(super) options: DhtNodeOptions,

    /// Known DHT nodes
    pub(super) known_peers: PeersCache,
    /// DHT nodes penalty scores table
    pub(super) penalties: Penalties,

    /// DHT nodes organized by buckets
    pub(super) buckets: Buckets,
    /// Local DHT values storage
    pub(super) storage: Storage,

    /// Serialized [`proto::rpc::DhtQuery`] with own DHT node info
    pub(super) query_prefix: Vec<u8>,
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
            penalties: Default::default(),
            storage: Storage::default(),
            query_prefix: Vec::new(),
        };

        dht_node.query_prefix = tl_proto::serialize(proto::rpc::DhtQuery {
            node: dht_node.sign_local_node().as_equivalent_ref(),
        });

        let dht_node = Arc::new(dht_node);

        let dht = Arc::downgrade(&dht_node);
        let interval = Duration::from_millis(dht_node.options.storage_gc_interval_ms);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Some(dht) = dht.upgrade() {
                    dht.storage.gc();
                }
            }
        });

        Ok(dht_node)
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
    #[inline(always)]
    pub fn adnl(&self) -> &Arc<AdnlNode> {
        &self.adnl
    }

    #[inline(always)]
    pub fn key(&self) -> &Arc<StoredAdnlNodeKey> {
        &self.node_key
    }

    pub fn iter_known_peers(&self) -> impl Iterator<Item = &AdnlNodeIdShort> {
        self.known_peers.iter()
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

    /// Sends ping query to the given peer
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

    /// Returns an entry interface for manipulating DHT values
    pub fn entry<'a, T>(self: &'a Arc<Self>, id: &'a T, name: &'a str) -> DhtEntry<'a>
    where
        T: Borrow<[u8; 32]>,
    {
        DhtEntry::new(self, id, name)
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

    /// Searches overlay nodes and their ip addresses.
    ///
    /// NOTE: For the sake of speed it uses only a subset of nodes, so
    /// results may vary between calls.
    pub async fn find_overlay_nodes(
        self: &Arc<Self>,
        overlay_id: &OverlayIdShort,
    ) -> Result<Vec<(PackedSocketAddr, proto::overlay::NodeOwned)>> {
        let mut result = Vec::new();
        let mut nodes = Vec::new();
        let mut cache = FxHashSet::default();
        loop {
            // Receive a several nodes records
            let received = self
                .entry(overlay_id, DHT_KEY_NODES)
                .values()
                .use_new_peers(true)
                .map(|(_, BoxedWrapper(proto::overlay::NodesOwned { nodes }))| nodes)
                .collect::<Vec<_>>()
                .await;
            if received.is_empty() {
                break;
            }

            let mut futures = FuturesUnordered::new();

            // Spawn IP resolution tasks.
            // It combines received nodes with nodes from the previous iteration
            for node in received
                .into_iter()
                .flatten()
                .chain(std::mem::take(&mut nodes).into_iter())
            {
                let peer_id = match AdnlNodeIdFull::try_from(node.id.as_equivalent_ref())
                    .map(|full_id| full_id.compute_short_id())
                {
                    // Only resolve address for new peers with valid id
                    Ok(peer_id) if cache.insert(peer_id) => peer_id,
                    _ => continue,
                };

                let dht = self.clone();
                futures.push(async move {
                    match dht.find_address(&peer_id).await {
                        Ok((ip, _)) => (Some(ip), node),
                        Err(_) => (None, node),
                    }
                });
            }

            // Wait all results
            while let Some((ip, node)) = futures.next().await {
                match ip {
                    // Add nodes with ips to result
                    Some(ip) => result.push((ip, node)),
                    // Prepare nodes for the next iteration in case we haven't found any yet
                    None if result.is_empty() => nodes.push(node),
                    _ => {}
                }
            }

            if !result.is_empty() {
                break;
            }
        }

        Ok(result)
    }

    /// Searches for the first stored IP address for the given peer id
    pub async fn find_address(
        self: &Arc<Self>,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<(PackedSocketAddr, AdnlNodeIdFull)> {
        let mut values = self.entry(peer_id, DHT_KEY_ADDRESS).values();
        while let Some((key, BoxedWrapper(value))) = values.next().await {
            match (
                parse_address_list(&value, self.adnl.options().clock_tolerance_sec),
                AdnlNodeIdFull::try_from(key.id.as_equivalent_ref()),
            ) {
                (Ok(ip_address), Ok(full_id)) => return Ok((ip_address, full_id)),
                _ => continue,
            }
        }

        Err(DhtNodeError::NoAddressFound.into())
    }

    /// Returns a future which stores value into multiple DHT nodes.
    ///
    /// See [`DhtNode::entry`] for more convenient API
    pub fn store_value(self: &Arc<Self>, value: proto::dht::Value<'_>) -> Result<DhtStoreValue> {
        DhtStoreValue::new(self.clone(), value)
    }

    /// Stores given overlay node into multiple DHT nodes
    ///
    /// Returns and error if stored value is incorrect
    pub async fn store_overlay_node(
        self: &Arc<Self>,
        overlay_full_id: &OverlayIdFull,
        node: proto::overlay::Node<'_>,
    ) -> Result<bool> {
        let overlay_id = overlay_full_id.compute_short_id();
        verify_overlay_node(&overlay_id, &node)?;

        let value = tl_proto::serialize_as_boxed(proto::overlay::Nodes {
            nodes: smallvec![node],
        });

        let value = proto::dht::Value {
            key: proto::dht::KeyDescription {
                key: proto::dht::Key {
                    id: overlay_id.as_slice(),
                    name: DHT_KEY_NODES.as_bytes(),
                    idx: 0,
                },
                id: everscale_crypto::tl::PublicKey::Overlay {
                    name: overlay_full_id.as_slice(),
                },
                update_rule: proto::dht::UpdateRule::OverlayNodes,
                signature: Default::default(),
            },
            value: &value,
            ttl: now() + self.options.value_ttl_sec,
            signature: Default::default(),
        };

        self.store_value(value)?
            .ensure_stored(
                move |_, BoxedWrapper(proto::overlay::NodesOwned { nodes })| {
                    for stored_node in &nodes {
                        if stored_node.as_equivalent_ref() == node {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                },
            )
            .check_all()
            .await
    }

    /// Stores given ip into multiple DHT nodes
    pub async fn store_ip_address(
        self: &Arc<Self>,
        key: &StoredAdnlNodeKey,
        ip: PackedSocketAddr,
    ) -> Result<bool> {
        let clock_tolerance_sec = self.adnl.options().clock_tolerance_sec;

        self.entry(key.id(), DHT_KEY_ADDRESS)
            .with_data(
                proto::adnl::AddressList {
                    address: Some(ip.as_tl()),
                    version: now(),
                    reinit_date: self.adnl.start_time(),
                    expire_at: 0,
                }
                .into_boxed(),
            )
            .sign_and_store(key)?
            .ensure_stored(move |_, BoxedWrapper(address_list)| {
                match parse_address_list(&address_list, clock_tolerance_sec)? {
                    stored_ip if stored_ip == ip => Ok(true),
                    stored_ip => {
                        tracing::warn!("Found another stored address {stored_ip}, expected {ip}");
                        Ok(false)
                    }
                }
            })
            .await
    }

    fn process_find_node(&self, query: proto::rpc::DhtFindNode<'_>) -> proto::dht::NodesOwned {
        self.buckets.find(query.key, query.k)
    }

    fn process_find_value(
        &self,
        query: proto::rpc::DhtFindValue<'_>,
    ) -> Result<proto::dht::ValueResultOwned> {
        if query.k == 0 || query.k > self.options.max_allowed_k {
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
        self.storage.insert(query.value)?;
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

    pub(super) async fn query_raw(
        &self,
        peer_id: &AdnlNodeIdShort,
        query: Bytes,
    ) -> Result<Option<Vec<u8>>> {
        let result = self
            .adnl
            .query_raw(
                self.node_key.id(),
                peer_id,
                query,
                Some(self.options.query_timeout_ms),
            )
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

    pub(super) fn parse_value_result<T>(
        &self,
        result: &[u8],
    ) -> Result<Option<(proto::dht::KeyDescriptionOwned, T)>>
    where
        for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
    {
        match tl_proto::deserialize::<proto::dht::ValueResult>(result)? {
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

    fn update_peer_status(&self, peer: &AdnlNodeIdShort, is_good: bool) {
        use dashmap::mapref::entry::Entry;

        if is_good {
            self.set_good_peer(peer);
        } else {
            match self.penalties.entry(*peer) {
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
        if let Some(mut count) = self.penalties.get_mut(peer) {
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

/// Instant DHT node metrics
#[derive(Debug, Copy, Clone)]
pub struct DhtNodeMetrics {
    pub peers_cache_len: usize,
    pub bucket_peer_count: usize,
    pub storage_len: usize,
    pub storage_total_size: usize,
}

type Penalties = FxDashMap<AdnlNodeIdShort, usize>;

#[derive(thiserror::Error, Debug)]
enum DhtNodeError {
    #[error("No address found")]
    NoAddressFound,
    #[error("Unexpected DHT query")]
    UnexpectedQuery,
    #[error("Invalid node count limit")]
    InvalidNodeCountLimit,
}
