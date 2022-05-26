use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use rand::Rng;
use ton_api::ton::{self, TLObject};
use ton_api::IntoBoxed;

use crate::adnl_node::{AdnlNode, PeerContext};
use crate::overlay_node::MAX_OVERLAY_PEERS;
use crate::subscriber::*;
use crate::utils::*;

use self::buckets::*;
use self::storage::*;

mod buckets;
mod storage;

pub struct DhtNode {
    adnl: Arc<AdnlNode>,
    node_key: Arc<StoredAdnlNodeKey>,
    options: DhtNodeOptions,
    known_peers: PeersCache,

    buckets: Buckets,
    bad_peers: FxDashMap<AdnlNodeIdShort, usize>,
    storage: Storage,

    query_prefix: Vec<u8>,
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DhtNodeOptions {
    /// Default: 3600
    pub value_timeout_sec: u32,
    /// Default: 5
    pub max_dht_tasks: usize,
    /// Default: 5
    pub max_fail_count: usize,
}

impl Default for DhtNodeOptions {
    fn default() -> Self {
        Self {
            value_timeout_sec: 3600,
            max_dht_tasks: 5,
            max_fail_count: 5,
        }
    }
}

impl DhtNode {
    pub fn new(adnl: Arc<AdnlNode>, key_tag: usize, options: DhtNodeOptions) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;

        let mut dht_node = Self {
            adnl,
            node_key,
            options,
            known_peers: PeersCache::with_capacity(MAX_OVERLAY_PEERS),
            buckets: Buckets::default(),
            bad_peers: Default::default(),
            storage: Storage::default(),
            query_prefix: Vec::new(),
        };

        let query = ton::rpc::dht::Query {
            node: dht_node.sign_local_node(),
        };
        serialize_inplace(&mut dht_node.query_prefix, &query);

        Ok(Arc::new(dht_node))
    }

    #[inline(always)]
    pub fn options(&self) -> &DhtNodeOptions {
        &self.options
    }

    pub fn metrics(&self) -> DhtNodeMetrics {
        DhtNodeMetrics {
            peers_cache_len: self.known_peers.len(),
            bucket_peer_count: self.buckets.iter().map(|bucket| bucket.len()).sum(),
            storage_len: self.storage.len(),
            storage_total_size: self.storage.total_size(),
        }
    }

    pub fn adnl(&self) -> &Arc<AdnlNode> {
        &self.adnl
    }

    pub fn add_peer(&self, peer: ton::dht::node::Node) -> Result<Option<AdnlNodeIdShort>> {
        let peer_full_id = AdnlNodeIdFull::try_from(&peer.id)?;

        if peer_full_id
            .verify_boxed(&peer, |p| &mut p.signature)
            .is_err()
        {
            tracing::warn!("Error when verifying DHT peer");
            return Ok(None);
        }

        let peer_id = peer_full_id.compute_short_id();
        let peer_ip_address =
            parse_address_list(&peer.addr_list, self.adnl.options().clock_tolerance_sec)?;

        let is_new_peer = self.adnl.add_peer(
            PeerContext::Dht,
            self.node_key.id(),
            &peer_id,
            peer_ip_address,
            peer_full_id,
        )?;
        if !is_new_peer {
            return Ok(None);
        }

        if self.known_peers.put(peer_id) {
            self.buckets.insert(self.node_key.id(), &peer_id, &peer);
        } else {
            self.set_good_peer(&peer_id);
        }

        Ok(Some(peer_id))
    }

    pub async fn find_dht_nodes(&self, peer_id: &AdnlNodeIdShort) -> Result<bool> {
        let query = TLObject::new(ton::rpc::dht::FindNode {
            key: ton::int256(*self.node_key.id().as_slice()),
            k: 10,
        });
        let answer: ton::dht::Nodes = match self.query_with_prefix(peer_id, &query).await? {
            Some(answer) => parse_answer(answer)?,
            None => return Ok(false),
        };
        let nodes = answer.only().nodes;
        for node in nodes.0.into_iter() {
            self.add_peer(node)?;
        }
        Ok(true)
    }

    pub async fn find_overlay_nodes(
        self: &Arc<Self>,
        overlay_id: &OverlayIdShort,
        external_iter: &mut Option<ExternalDhtIter>,
    ) -> Result<Vec<(AdnlAddressUdp, ton::overlay::node::Node)>> {
        let mut result = Vec::new();
        let mut nodes = Vec::new();

        let key = make_dht_key(overlay_id, DHT_KEY_NODES);

        loop {
            let mut nodes_lists = self
                .find_value(
                    key.clone(),
                    |value| value.is::<ton::overlay::Nodes>(),
                    true,
                    external_iter,
                )
                .await?;
            if nodes_lists.is_empty() {
                break;
            }

            while let Some((_, nodes_lists)) = nodes_lists.pop() {
                if let Ok(nodes_list) = nodes_lists.downcast::<ton::overlay::Nodes>() {
                    nodes.append(&mut nodes_list.only().nodes.0);
                } else {
                    continue;
                }
            }

            let mut response_collector = ResponseCollector::new();

            let cache = PeersCache::with_capacity(MAX_OVERLAY_PEERS);
            while let Some(node) = nodes.pop() {
                let peer_full_id = AdnlNodeIdFull::try_from(&node.id)?;
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
        node: &ton::overlay::node::Node,
    ) -> Result<bool> {
        let overlay_full_id = ton::pub_::publickey::Overlay {
            name: ton::bytes(overlay_full_id.as_slice().to_vec()),
        };
        let overlay_id = hash(overlay_full_id.clone()).into();

        verify_node(&overlay_id, node)?;

        let key = make_dht_key(&overlay_id, DHT_KEY_NODES);
        let value = ton::dht::value::Value {
            key: ton::dht::keydescription::KeyDescription {
                key: key.clone(),
                id: overlay_full_id.into_boxed(),
                update_rule: ton::dht::UpdateRule::Dht_UpdateRule_OverlayNodes,
                signature: Default::default(),
            },
            value: ton::bytes(serialize_boxed(ton::overlay::nodes::Nodes {
                nodes: vec![node.clone()].into(),
            })),
            ttl: now() as i32 + self.options.value_timeout_sec as i32,
            signature: Default::default(),
        };

        self.storage
            .insert_overlay_nodes(hash(key.clone()), value.clone())?;

        self.store_value(
            key,
            value,
            |value| value.is::<ton::overlay::Nodes>(),
            true,
            |mut values| {
                while let Some((_, value)) = values.pop() {
                    match value.downcast::<ton::overlay::Nodes>() {
                        Ok(value) => {
                            for stored_node in value.only().nodes.iter() {
                                if stored_node == node {
                                    return Ok(true);
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Ok(false)
            },
        )
        .await
    }

    pub async fn find_address(
        self: &Arc<Self>,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<(AdnlAddressUdp, AdnlNodeIdFull)> {
        let mut address_list = self
            .find_value(
                make_dht_key(peer_id, DHT_KEY_ADDRESS),
                |value| value.is::<ton::adnl::AddressList>(),
                false,
                &mut None,
            )
            .await?;

        match address_list.pop() {
            Some((key, value)) => {
                parse_dht_value_address(key, value, self.adnl.options().clock_tolerance_sec)
            }
            None => Err(DhtNodeError::NoAddressFound.into()),
        }
    }

    pub async fn store_ip_address(self: &Arc<Self>, key: &StoredAdnlNodeKey) -> Result<bool> {
        let value = serialize_boxed(self.adnl.build_address_list(None));
        let value = sign_dht_value(key, DHT_KEY_ADDRESS, &value, self.options.value_timeout_sec);
        let key = make_dht_key(key.id(), DHT_KEY_ADDRESS);

        self.storage
            .insert_signed_value(hash(key.clone()), value.clone())?;

        self.store_value(
            key,
            value,
            |value| value.is::<ton::adnl::AddressList>(),
            false,
            |mut values| {
                while let Some((_, value)) = values.pop() {
                    match value.downcast::<ton::adnl::AddressList>() {
                        Ok(address_list) => {
                            let ip = parse_address_list(
                                &address_list.only(),
                                self.adnl.options().clock_tolerance_sec,
                            )?;
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
                        Err(_) => continue,
                    }
                }
                Ok(false)
            },
        )
        .await
    }

    pub fn fetch_address_locally(
        &self,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<Option<(AdnlAddressUdp, AdnlNodeIdFull)>> {
        let key = make_dht_key(peer_id, DHT_KEY_ADDRESS);
        Ok(match self.storage.get(&hash(key)) {
            Some(stored) => {
                let value = deserialize(&stored.value)?;
                Some(parse_dht_value_address(
                    stored.key,
                    value,
                    self.adnl.options().clock_tolerance_sec,
                )?)
            }
            None => None,
        })
    }

    pub fn iter_known_peers(&self) -> impl Iterator<Item = &AdnlNodeIdShort> {
        self.known_peers.iter()
    }

    pub fn get_known_peer(
        &self,
        external_iter: &mut Option<ExternalPeersCacheIter>,
    ) -> Option<AdnlNodeIdShort> {
        loop {
            let peer = match external_iter {
                Some(iter) => {
                    iter.bump();
                    iter
                }
                None => external_iter.get_or_insert_with(Default::default),
            }
            .get(&self.known_peers);

            if let Some(peer) = &peer {
                if matches!(
                    self.bad_peers.get(peer),
                    Some(count) if *count > self.options.max_fail_count
                ) {
                    continue;
                }
            }

            break peer;
        }
    }

    pub fn get_known_peers(&self, limit: usize) -> Vec<ton::dht::node::Node> {
        let mut result = Vec::new();

        'outer: for bucket in &self.buckets {
            for peer in bucket {
                result.push(peer.value().clone());
                if result.len() == limit {
                    break 'outer;
                }
            }
        }

        result
    }

    pub async fn ping(&self, peer_id: &AdnlNodeIdShort) -> Result<bool> {
        let random_id = rand::thread_rng().gen();
        let query = TLObject::new(ton::rpc::dht::Ping { random_id });
        let answer = match self.query(peer_id, &query).await? {
            Some(answer) => parse_answer::<ton::dht::Pong>(answer)?,
            None => return Ok(false),
        };
        Ok(answer.random_id() == &random_id)
    }

    fn process_ping(&self, query: &ton::rpc::dht::Ping) -> ton::dht::pong::Pong {
        ton::dht::pong::Pong {
            random_id: query.random_id,
        }
    }

    fn process_find_node(&self, query: &ton::rpc::dht::FindNode) -> ton::dht::nodes::Nodes {
        self.buckets.find(self.node_key.id(), &query.key.0, query.k)
    }

    fn process_find_value(
        &self,
        query: &ton::rpc::dht::FindValue,
    ) -> Result<ton::dht::ValueResult> {
        let result = match self.storage.get(&query.key.0) {
            Some(value) => ton::dht::valueresult::ValueFound {
                value: value.into_boxed(),
            }
            .into_boxed(),
            None => ton::dht::valueresult::ValueNotFound {
                nodes: ton::dht::nodes::Nodes {
                    nodes: self.get_known_peers(query.k as usize).into(),
                },
            }
            .into_boxed(),
        };

        Ok(result)
    }

    fn process_get_signed_address_list(&self) -> ton::dht::node::Node {
        self.sign_local_node()
    }

    fn process_store(&self, query: ton::rpc::dht::Store) -> Result<ton::dht::Stored> {
        if query.value.ttl as u32 <= now() {
            return Err(DhtNodeError::InsertedValueExpired.into());
        }

        let key_id = hash(query.value.key.key.clone());

        match query.value.key.update_rule {
            ton::dht::UpdateRule::Dht_UpdateRule_Signature => {
                self.storage.insert_signed_value(key_id, query.value)?;
            }
            ton::dht::UpdateRule::Dht_UpdateRule_OverlayNodes => {
                self.storage.insert_overlay_nodes(key_id, query.value)?;
            }
            _ => return Err(DhtNodeError::UnsupportedStoreQuery.into()),
        }

        Ok(ton::dht::Stored::Dht_Stored)
    }

    async fn query(&self, peer_id: &AdnlNodeIdShort, query: &TLObject) -> Result<Option<TLObject>> {
        let result = self
            .adnl
            .query(self.node_key.id(), peer_id, query, None)
            .await;
        self.update_peer_status(peer_id, result.is_ok());
        result
    }

    async fn query_with_prefix(
        &self,
        peer_id: &AdnlNodeIdShort,
        query: &TLObject,
    ) -> Result<Option<TLObject>> {
        let result = self
            .adnl
            .query_with_prefix(
                self.node_key.id(),
                peer_id,
                Some(&self.query_prefix),
                query,
                None,
            )
            .await;
        self.update_peer_status(peer_id, result.is_ok());
        result
    }

    async fn query_value<F>(
        &self,
        peer_id: &AdnlNodeIdShort,
        query: &TLObject,
        check: F,
    ) -> Result<Option<(ton::dht::keydescription::KeyDescription, TLObject)>>
    where
        F: Fn(&TLObject) -> bool,
    {
        Ok(match self.query(peer_id, query).await? {
            Some(answer) => match parse_answer::<ton::dht::ValueResult>(answer)? {
                ton::dht::ValueResult::Dht_ValueFound(answer) => {
                    let value = answer.value.only();
                    let object = deserialize(&value.value)?;
                    if check(&object) {
                        Some((value.key, object))
                    } else {
                        None
                    }
                }
                ton::dht::ValueResult::Dht_ValueNotFound(answer) => {
                    for node in answer.nodes.nodes.0.into_iter() {
                        self.add_peer(node)?;
                    }
                    None
                }
            },
            None => None,
        })
    }

    async fn find_value<F>(
        self: &Arc<Self>,
        key: ton::dht::key::Key,
        check: F,
        all: bool,
        external_iter: &mut Option<ExternalDhtIter>,
    ) -> Result<Vec<(ton::dht::keydescription::KeyDescription, TLObject)>>
    where
        F: Fn(&TLObject) -> bool + Copy + Send + 'static,
    {
        let key_id = hash(key);
        let iter = external_iter.get_or_insert_with(|| ExternalDhtIter::with_key_id(self, key_id));
        if iter.key_id != key_id {
            return Err(DhtNodeError::KeyMismatch.into());
        }

        let mut result = Vec::new();
        let query = Arc::new(TLObject::new(ton::rpc::dht::FindValue {
            key: ton::int256(key_id),
            k: 6,
        }));

        let max_tasks = self.options.max_dht_tasks;

        let mut response_collector = LimitedResponseCollector::new(max_tasks);

        let mut known_peers_cache_version = self.known_peers.version();
        loop {
            while let Some((_, peer_id)) = iter.order.pop() {
                let dht = self.clone();
                let query = query.clone();
                let response_tx = match response_collector.make_request() {
                    Some(tx) => tx,
                    None => break,
                };

                tokio::spawn(async move {
                    match dht.query_value(&peer_id, &query, check).await {
                        Ok(found) => response_tx.send(found),
                        Err(e) => {
                            tracing::warn!("find_value error: {e}");
                            response_tx.send(None);
                        }
                    }
                });
            }

            let mut finished = false;
            loop {
                match response_collector.wait(!all).await {
                    Some(Some(response)) => result.push(response),
                    Some(_) => {}
                    None => finished = true,
                }

                if all || result.is_empty() {
                    let new_cache_version = self.known_peers.version();
                    if known_peers_cache_version != new_cache_version {
                        iter.update(self);
                        known_peers_cache_version = new_cache_version;
                    }
                }

                if finished || !all || result.len() < max_tasks {
                    break;
                }
            }

            if finished || all && result.len() >= max_tasks || !all && !result.is_empty() {
                break;
            }
        }

        if iter.order.is_empty() {
            external_iter.take();
        }

        Ok(result)
    }

    async fn store_value<FK, FV>(
        self: &Arc<Self>,
        key: ton::dht::key::Key,
        value: ton::dht::value::Value,
        check_type: FK,
        check_all: bool,
        check_values: FV,
    ) -> Result<bool>
    where
        FK: Fn(&TLObject) -> bool + Copy + Send + 'static,
        FV: Fn(Vec<(ton::dht::keydescription::KeyDescription, TLObject)>) -> Result<bool>,
    {
        let query = Arc::new(TLObject::new(ton::rpc::dht::Store { value }));

        let mut response_collector = ResponseCollector::new();

        let mut iter = ExternalPeersCacheIter::new();
        while iter.get(&self.known_peers).is_some() {
            while let Some(peer_id) = iter.get(&self.known_peers) {
                iter.bump();

                let dht = self.clone();
                let query = query.clone();
                let response_tx = response_collector.make_request();
                tokio::spawn(async move {
                    let response = match dht.query(&peer_id, &query).await {
                        Ok(Some(answer)) => match parse_answer::<ton::dht::Stored>(answer) {
                            Ok(_) => Some(()),
                            Err(_) => None,
                        },
                        Ok(None) => None,
                        Err(_) => None,
                    };
                    response_tx.send(response);
                });
            }

            while response_collector.wait(false).await.is_some() {}

            let values = self
                .find_value(key.clone(), check_type, check_all, &mut None)
                .await?;
            if check_values(values)? {
                return Ok(true);
            }

            iter.bump();
        }

        Ok(false)
    }

    fn sign_local_node(&self) -> ton::dht::node::Node {
        let node = ton::dht::node::Node {
            id: self.node_key.full_id().as_old_tl().into_boxed(),
            addr_list: self.adnl.build_address_list(None),
            version: now() as i32,
            signature: Default::default(),
        };
        self.node_key.sign_boxed(node, |node, signature| {
            let mut node = node.only();
            node.signature = signature;
            node
        })
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
    async fn try_consume_query(
        &self,
        _local_id: &AdnlNodeIdShort,
        _peer_id: &AdnlNodeIdShort,
        query: TLObject,
    ) -> Result<QueryConsumingResult> {
        let query = match query.downcast::<ton::rpc::dht::Ping>() {
            Ok(query) => return QueryConsumingResult::consume(self.process_ping(&query)),
            Err(query) => query,
        };

        let query = match query.downcast::<ton::rpc::dht::FindNode>() {
            Ok(query) => return QueryConsumingResult::consume(self.process_find_node(&query)),
            Err(query) => query,
        };

        let query = match query.downcast::<ton::rpc::dht::FindValue>() {
            Ok(query) => {
                return QueryConsumingResult::consume_boxed(self.process_find_value(&query)?)
            }
            Err(query) => query,
        };

        let query = match query.downcast::<ton::rpc::dht::GetSignedAddressList>() {
            Ok(_) => return QueryConsumingResult::consume(self.process_get_signed_address_list()),
            Err(query) => query,
        };

        let query = match query.downcast::<ton::rpc::dht::Store>() {
            Ok(query) => return QueryConsumingResult::consume_boxed(self.process_store(query)?),
            Err(query) => query,
        };

        tracing::warn!("Unexpected DHT query");
        Ok(QueryConsumingResult::Rejected(query))
    }

    async fn try_consume_query_bundle(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        mut queries: Vec<TLObject>,
    ) -> Result<QueryBundleConsumingResult> {
        if queries.len() != 2 {
            return Ok(QueryBundleConsumingResult::Rejected(queries));
        }

        let peer = match queries.remove(0).downcast::<ton::rpc::dht::Query>() {
            Ok(query) => query.node,
            Err(query) => {
                queries.insert(0, query);
                return Ok(QueryBundleConsumingResult::Rejected(queries));
            }
        };

        self.add_peer(peer)?;

        let query = queries.remove(0);
        match self.try_consume_query(local_id, peer_id, query).await? {
            QueryConsumingResult::Consumed(answer) => {
                Ok(QueryBundleConsumingResult::Consumed(answer))
            }
            QueryConsumingResult::Rejected(_) => Err(DhtNodeError::UnexpectedQuery.into()),
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

pub struct ExternalDhtIter {
    max_tasks: usize,
    iter: Option<ExternalPeersCacheIter>,
    key_id: StorageKey,
    order: Vec<(u8, AdnlNodeIdShort)>,
}

impl ExternalDhtIter {
    fn with_key_id(dht: &DhtNode, key_id: StorageKey) -> Self {
        let mut result = Self {
            max_tasks: dht.options.max_dht_tasks,
            iter: None,
            key_id,
            order: Vec::new(),
        };
        result.update(dht);
        result
    }

    fn update(&mut self, dht: &DhtNode) {
        let mut next = match &self.iter {
            Some(iter) => iter.get(&dht.known_peers),
            None => dht.get_known_peer(&mut self.iter),
        };

        while let Some(peer) = next {
            let affinity = get_affinity(peer.as_slice(), &self.key_id);

            let add = match self.order.last() {
                Some((top_affinity, _)) => {
                    *top_affinity <= affinity || self.order.len() < self.max_tasks
                }
                None => true,
            };

            if add {
                self.order.push((affinity, peer))
            }

            next = dht.get_known_peer(&mut self.iter);
        }

        self.order.sort_unstable_by_key(|(affinity, _)| *affinity);

        if let Some((top_affinity, _)) = self.order.last() {
            let mut drop_to = 0;

            while self.order.len() - drop_to > self.max_tasks {
                if self.order[drop_to].0 < *top_affinity {
                    drop_to += 1;
                } else {
                    break;
                }
            }

            self.order.drain(0..drop_to);
        }
    }
}

const DHT_KEY_ADDRESS: &str = "address";
const DHT_KEY_NODES: &str = "nodes";

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
}
