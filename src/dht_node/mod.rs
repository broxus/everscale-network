use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use ton_api::ton::{self, TLObject};

use crate::adnl_node::AdnlNode;
use crate::overlay_node::MAX_PEERS;
use crate::utils::*;

pub struct DhtNode {
    adnl: Arc<AdnlNode>,
    node_key: Arc<StoredAdnlNodeKey>,
    known_peers: PeersCache,

    buckets: DashMap<u8, DashMap<AdnlNodeIdShort, ton::dht::node::Node>>,
    storage: DashMap<AdnlNodeIdShort, ton::dht::value::Value>,

    query_prefix: Vec<u8>,
}

impl DhtNode {
    pub fn with_adnl_node(adnl: Arc<AdnlNode>, key_tag: usize) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;

        let mut dht_node = Self {
            adnl,
            node_key,
            known_peers: PeersCache::with_capacity(MAX_PEERS),
            buckets: DashMap::new(),
            storage: DashMap::new(),
            query_prefix: Vec::new(),
        };

        todo!()
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
            let affinity = get_affinity(self.node_key.id(), &peer_id);
            let bucket = self.buckets.entry(affinity).or_default();
            match bucket.entry(peer_id) {
                Entry::Occupied(entry) => {
                    if entry.get().version < peer.version {
                        entry.replace_entry(peer.clone());
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(peer.clone());
                }
            }
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
            self.add_peer(node);
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
}

const DHT_KEY_ADDRESS: &str = "address";

#[derive(thiserror::Error, Debug)]
enum DhtNodeError {
    #[error("No address found")]
    NoAddressFound,
}
