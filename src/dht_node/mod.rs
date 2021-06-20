use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use ton_api::ton::{self, TLObject};

use self::buckets::*;
use self::storage::*;
use crate::adnl_node::AdnlNode;
use crate::overlay_node::MAX_PEERS;
use crate::subscriber::*;
use crate::utils::*;
use ton_api::IntoBoxed;

mod buckets;
mod storage;

pub struct DhtNode {
    adnl: Arc<AdnlNode>,
    node_key: Arc<StoredAdnlNodeKey>,
    known_peers: PeersCache,

    buckets: Buckets,
    storage: Storage,

    query_prefix: Vec<u8>,
}

impl DhtNode {
    pub fn with_adnl_node(adnl: Arc<AdnlNode>, key_tag: usize) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;

        let mut dht_node = Self {
            adnl,
            node_key,
            known_peers: PeersCache::with_capacity(MAX_PEERS),
            buckets: Buckets::default(),
            storage: Storage::default(),
            query_prefix: Vec::new(),
        };

        let query = ton::rpc::dht::Query {
            node: dht_node.sign_local_node()?,
        };
        serialize_inplace(&mut dht_node.query_prefix, &query)?;

        Ok(Arc::new(dht_node))
    }

    pub fn add_peer(&self, peer: &ton::dht::node::Node) -> Result<Option<AdnlNodeIdShort>> {
        use dashmap::mapref::entry::Entry;

        todo!();

        let peer_full_id = AdnlNodeIdFull::try_from(&peer.id)?;
        let peer_id = peer_full_id.compute_short_id()?;
        let peer_ip_address = parse_address_list(&peer.addr_list)?;

        let is_new_peer =
            self.adnl
                .add_peer(self.node_key.id(), &peer_id, peer_ip_address, peer_full_id)?;
        if !is_new_peer {
            return Ok(None);
        }

        if self.known_peers.put(peer_id) {
            self.buckets.insert(self.node_key.id(), &peer_id, peer);
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
        for node in nodes.0.iter() {
            self.add_peer(node)?;
        }
        Ok(true)
    }

    pub async fn find_address(
        self: &Arc<Self>,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<(AdnlAddressUdp, AdnlNodeIdFull)> {
        let mut address_list = self
            .find_value(make_dht_key(peer_id, DHT_KEY_ADDRESS))
            .await?;

        match address_list.pop() {
            Some((key, value)) => parse_dht_value_address(key, value),
            None => Err(DhtNodeError::NoAddressFound.into()),
        }
    }

    pub fn iter_known_peers(&self) -> impl Iterator<Item = &AdnlNodeIdShort> {
        self.known_peers.iter()
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
            None => ton::dht::valueresult::ValueNotFound { nodes: todo!() }.into_boxed(),
        };

        Ok(result)
    }

    fn process_get_signed_address_list(&self) -> Result<ton::dht::node::Node> {
        self.sign_local_node()
    }

    fn process_store(&self, query: &ton::rpc::dht::Store) -> Result<ton::dht::Stored> {
        todo!();

        Ok(ton::dht::Stored::Dht_Stored)
    }

    async fn query(&self, peer_id: &AdnlNodeIdShort, query: &TLObject) -> Result<Option<TLObject>> {
        self.adnl
            .query(self.node_key.id(), peer_id, query, None)
            .await
    }

    async fn query_with_prefix(
        &self,
        peer_id: &AdnlNodeIdShort,
        query: &TLObject,
    ) -> Result<Option<TLObject>> {
        self.adnl
            .query_with_prefix(
                self.node_key.id(),
                peer_id,
                Some(&self.query_prefix),
                query,
                None,
            )
            .await
    }

    async fn find_value(
        self: &Arc<Self>,
        key: ton::dht::key::Key,
    ) -> Result<Vec<(ton::dht::keydescription::KeyDescription, TLObject)>> {
        let key = hash(key)?;

        //let mut result = Vec::new();
        let query = TLObject::new(ton::rpc::dht::FindValue {
            key: ton::int256(key),
            k: 6,
        });

        todo!()
    }

    fn sign_local_node(&self) -> Result<ton::dht::node::Node> {
        let node = ton::dht::node::Node {
            id: self.node_key.full_id().as_tl().into_boxed(),
            addr_list: self.adnl.build_address_list(None),
            version: now(),
            signature: Default::default(),
        };
        sign_boxed(node, &self.node_key, |node, signature| {
            let mut node = node.only();
            node.signature.0 = signature;
            node
        })
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
            Ok(_) => return QueryConsumingResult::consume(self.process_get_signed_address_list()?),
            Err(query) => query,
        };

        let query = match query.downcast::<ton::rpc::dht::Store>() {
            Ok(query) => return QueryConsumingResult::consume_boxed(self.process_store(&query)?),
            Err(query) => query,
        };

        log::warn!("Unexpected DHT query");
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

        self.add_peer(&peer)?;

        let query = queries.remove(0);
        match self.try_consume_query(local_id, peer_id, query).await? {
            QueryConsumingResult::Consumed(answer) => {
                Ok(QueryBundleConsumingResult::Consumed(answer))
            }
            QueryConsumingResult::Rejected(_) => Err(DhtNodeError::UnexpectedQuery.into()),
        }
    }
}

fn sign_boxed<T, F>(data: T, key: &StoredAdnlNodeKey, f: F) -> Result<T>
where
    T: IntoBoxed,
    F: FnOnce(T::Boxed, Vec<u8>) -> T,
{
    let data = data.into_boxed();
    let mut buffer = serialize(&data)?;
    let signature = key.sign(&buffer);
    buffer.truncate(0);
    buffer.extend_from_slice(signature.as_ref());
    Ok(f(data, buffer))
}

const DHT_KEY_ADDRESS: &str = "address";

#[derive(thiserror::Error, Debug)]
enum DhtNodeError {
    #[error("No address found")]
    NoAddressFound,
    #[error("Unexpected DHT query")]
    UnexpectedQuery,
}
