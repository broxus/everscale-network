use std::convert::TryFrom;
use std::hash::BuildHasherDefault;
use std::sync::Arc;

use anyhow::Result;
use ton_api::ton::{self, TLObject};
use ton_api::IntoBoxed;

use self::overlay_shard::{
    CatchainUpdate, IncomingBroadcastInfo, OutgoingBroadcastInfo, OverlayShard,
};
pub use self::overlay_shard::{OverlayShardMetrics, OverlayShardOptions};
use crate::adnl_node::*;
use crate::rldp_node::*;
use crate::subscriber::*;
use crate::utils::*;

mod broadcast_receiver;
mod overlay_shard;

pub struct OverlayNode {
    adnl: Arc<AdnlNode>,
    node_key: Arc<StoredAdnlNodeKey>,
    shards: FxDashMap<OverlayIdShort, Arc<OverlayShard>>,
    subscribers: FxDashMap<OverlayIdShort, Arc<dyn OverlaySubscriber>>,
    zero_state_file_hash: [u8; 32],
}

impl OverlayNode {
    pub fn new(
        adnl: Arc<AdnlNode>,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        Ok(Arc::new(Self {
            adnl,
            node_key,
            shards: Default::default(),
            subscribers: Default::default(),
            zero_state_file_hash,
        }))
    }

    pub fn metrics(&self) -> impl Iterator<Item = (OverlayIdShort, OverlayShardMetrics)> + '_ {
        self.shards.iter().map(|item| (*item.id(), item.metrics()))
    }

    pub fn adnl(&self) -> &Arc<AdnlNode> {
        &self.adnl
    }

    pub fn add_subscriber(
        &self,
        overlay_id: OverlayIdShort,
        subscriber: Arc<dyn OverlaySubscriber>,
    ) -> bool {
        use dashmap::mapref::entry::Entry;

        match self.subscribers.entry(overlay_id) {
            Entry::Vacant(entry) => {
                entry.insert(subscriber);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub fn add_private_peers(
        &self,
        local_id: &AdnlNodeIdShort,
        peers: &[(AdnlAddressUdp, ed25519_dalek::PublicKey)],
    ) -> Result<Vec<AdnlNodeIdShort>> {
        let mut new_peers = Vec::new();

        for (peer_ip_address, public_key) in peers {
            let (peer_full_id, peer_id) = public_key.compute_node_ids()?;

            let is_new_peer = self.adnl.add_peer(
                PeerContext::PrivateOverlay,
                local_id,
                &peer_id,
                *peer_ip_address,
                peer_full_id,
            )?;

            if is_new_peer {
                new_peers.push(peer_id);
            }
        }

        Ok(new_peers)
    }

    pub fn delete_private_peers(
        &self,
        local_id: &AdnlNodeIdShort,
        peers: &[AdnlNodeIdShort],
    ) -> Result<bool> {
        let mut changed = false;
        for peer_id in peers {
            changed |= self.adnl.delete_peer(local_id, peer_id)?;
        }
        Ok(changed)
    }

    pub fn add_public_peer(
        &self,
        overlay_id: &OverlayIdShort,
        ip_address: AdnlAddressUdp,
        node: ton::overlay::node::Node,
    ) -> Result<Option<AdnlNodeIdShort>> {
        let shard = self.get_overlay_shard(overlay_id)?;
        if shard.is_private() {
            return Err(OverlayNodeError::PublicPeerToPrivateOverlay.into());
        }

        if let Err(e) = verify_node(overlay_id, &node) {
            log::warn!("Error during overlay peer verification: {:?}", e);
            return Ok(None);
        }

        let peer_id_full = AdnlNodeIdFull::try_from(&node.id)?;
        let peer_id = peer_id_full.compute_short_id()?;

        let is_new_peer = self.adnl.add_peer(
            PeerContext::PublicOverlay,
            self.node_key.id(),
            &peer_id,
            ip_address,
            peer_id_full,
        )?;
        if is_new_peer {
            shard.add_public_peer(&peer_id, node);
            Ok(Some(peer_id))
        } else {
            Ok(None)
        }
    }

    pub fn add_public_peers<I>(
        &self,
        overlay_id: &OverlayIdShort,
        nodes: I,
    ) -> Result<Vec<AdnlNodeIdShort>>
    where
        I: IntoIterator<Item = (AdnlAddressUdp, ton::overlay::node::Node)>,
    {
        let shard = self.get_overlay_shard(overlay_id)?.clone();
        if shard.is_private() {
            return Err(OverlayNodeError::PublicPeerToPrivateOverlay.into());
        }

        let mut result = Vec::new();
        for (ip_address, node) in nodes {
            if let Err(e) = verify_node(overlay_id, &node) {
                log::debug!("Error during overlay peer verification: {:?}", e);
                continue;
            }

            let peer_id_full = AdnlNodeIdFull::try_from(&node.id)?;
            let peer_id = peer_id_full.compute_short_id()?;

            let is_new_peer = self.adnl.add_peer(
                PeerContext::PublicOverlay,
                self.node_key.id(),
                &peer_id,
                ip_address,
                peer_id_full,
            )?;
            if is_new_peer {
                shard.add_public_peer(&peer_id, node);
                result.push(peer_id);
                log::trace!("Node id: {}, address: {}", peer_id, ip_address);
            }
        }

        Ok(result)
    }

    pub fn delete_public_peer(
        &self,
        overlay_id: &OverlayIdShort,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<bool> {
        let shard = self.get_overlay_shard(overlay_id)?;
        if shard.is_private() {
            return Err(OverlayNodeError::PublicPeerToPrivateOverlay.into());
        }
        Ok(shard.delete_public_peer(peer_id))
    }

    pub fn write_cached_peers(
        &self,
        overlay_id: &OverlayIdShort,
        amount: usize,
        dst: &PeersCache,
    ) -> Result<()> {
        self.get_overlay_shard(overlay_id)?
            .write_cached_peers(amount, dst);
        Ok(())
    }

    pub fn get_query_prefix(&self, overlay_id: &OverlayIdShort) -> Result<Vec<u8>> {
        Ok(self.get_overlay_shard(overlay_id)?.query_prefix().clone())
    }

    pub fn add_public_overlay(
        &self,
        overlay_id: &OverlayIdShort,
        options: OverlayShardOptions,
    ) -> Result<bool> {
        self.add_overlay_shard(overlay_id, None, options)
    }

    pub fn add_private_overlay(
        &self,
        overlay_id: &OverlayIdShort,
        overlay_key: &Arc<StoredAdnlNodeKey>,
        peers: &[AdnlNodeIdShort],
        options: OverlayShardOptions,
    ) -> Result<bool> {
        if !self.add_overlay_shard(overlay_id, Some(overlay_key.clone()), options)? {
            return Ok(false);
        }

        self.get_overlay_shard(overlay_id)?.add_known_peers(peers);
        Ok(true)
    }

    pub fn delete_private_overlay(&self, overlay_id: &OverlayIdShort) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        match self.shards.entry(*overlay_id) {
            Entry::Occupied(entry) => {
                if !entry.get().is_private() {
                    return Err(OverlayNodeError::DeletingPublicOverlay.into());
                }
                entry.remove();
                Ok(true)
            }
            Entry::Vacant(_) => Ok(false),
        }
    }

    pub async fn wait_for_broadcast(
        &self,
        overlay_id: &OverlayIdShort,
    ) -> Result<IncomingBroadcastInfo> {
        let shard = self.get_overlay_shard(overlay_id)?.clone();
        Ok(shard.wait_for_broadcast().await)
    }

    pub async fn wait_for_peers(
        &self,
        overlay_id: &OverlayIdShort,
    ) -> Result<Vec<ton::overlay::node::Node>> {
        let shard = self.get_overlay_shard(overlay_id)?.clone();
        Ok(shard.wait_for_peers().await)
    }

    pub async fn wait_for_catchain(&self, overlay_id: &OverlayIdShort) -> Result<CatchainUpdate> {
        let shard = self.get_overlay_shard(overlay_id)?.clone();
        Ok(shard.wait_for_catchain().await)
    }

    pub fn compute_overlay_id(&self, workchain: i32, shard: i64) -> Result<OverlayIdFull> {
        compute_overlay_id(workchain, shard, self.zero_state_file_hash)
    }

    pub fn compute_overlay_short_id(&self, workchain: i32, shard: i64) -> Result<OverlayIdShort> {
        self.compute_overlay_id(workchain, shard)
            .and_then(|id| id.compute_short_id())
    }

    pub fn get_signed_node(&self, overlay_id: &OverlayIdShort) -> Result<ton::overlay::node::Node> {
        let shard = self.get_overlay_shard(overlay_id)?;
        self.sign_local_node(shard.value())
    }

    pub fn broadcast(
        &self,
        overlay_id: &OverlayIdShort,
        data: &[u8],
        source: Option<&Arc<StoredAdnlNodeKey>>,
    ) -> Result<OutgoingBroadcastInfo> {
        const ORDINARY_BROADCAST_MAX_SIZE: usize = 768;

        let shard = self.get_overlay_shard(overlay_id)?;

        let local_id = match shard.overlay_key() {
            Some(overlay_key) => overlay_key.id(),
            None => self.node_key.id(),
        };

        let key = match source {
            Some(key) => key,
            None => &self.node_key,
        };

        if data.len() <= ORDINARY_BROADCAST_MAX_SIZE {
            shard.send_broadcast(local_id, data, key)
        } else {
            shard.send_fec_broadcast(local_id, data, key)
        }
    }

    pub fn send_message(
        &self,
        overlay_id: &OverlayIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
    ) -> Result<()> {
        let shard = self.get_overlay_shard(overlay_id)?;
        let local_id = match shard.overlay_key() {
            Some(overlay_id) => overlay_id.id(),
            None => self.node_key.id(),
        };

        let mut buffer = Vec::with_capacity(shard.message_prefix().len() + data.len());
        buffer.extend_from_slice(shard.message_prefix());
        buffer.extend_from_slice(data);
        self.adnl.send_custom_message(local_id, peer_id, &buffer)
    }

    pub async fn get_random_peers(
        &self,
        overlay_id: &OverlayIdShort,
        peer_id: &AdnlNodeIdShort,
        timeout: Option<u64>,
    ) -> Result<Option<Vec<ton::overlay::node::Node>>> {
        let shard = self.get_overlay_shard(overlay_id)?.clone();

        let query = TLObject::new(ton::rpc::overlay::GetRandomPeers {
            peers: self.prepare_random_peers(&shard)?,
        });
        let answer = self.query(overlay_id, peer_id, &query, timeout).await?;
        match answer {
            Some(answer) => {
                let answer: ton::overlay::Nodes = parse_answer(answer)?;
                log::trace!("Got random peers from {}", peer_id);
                Ok(Some(self.process_nodes(overlay_id, answer.only())))
            }
            None => {
                log::trace!("No random peers from {}", peer_id);
                Ok(None)
            }
        }
    }

    pub async fn query(
        &self,
        overlay_id: &OverlayIdShort,
        peer_id: &AdnlNodeIdShort,
        query: &TLObject,
        timeout: Option<u64>,
    ) -> Result<Option<TLObject>> {
        let shard = self.get_overlay_shard(overlay_id)?.clone();
        let local_id = match shard.overlay_key() {
            Some(overlay_key) => overlay_key.id(),
            None => self.node_key.id(),
        };

        self.adnl
            .query_with_prefix(
                local_id,
                peer_id,
                Some(shard.query_prefix()),
                query,
                timeout,
            )
            .await
    }

    pub async fn query_via_rldp(
        &self,
        overlay_id: &OverlayIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
        rldp: &Arc<RldpNode>,
        max_answer_size: Option<i64>,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let shard = self.get_overlay_shard(overlay_id)?.clone();
        let local_id = match shard.overlay_key() {
            Some(overlay_key) => overlay_key.id(),
            None => self.node_key.id(),
        };
        rldp.query(local_id, peer_id, data, max_answer_size, roundtrip)
            .await
    }

    fn add_overlay_shard(
        &self,
        overlay_id: &OverlayIdShort,
        overlay_key: Option<Arc<StoredAdnlNodeKey>>,
        options: OverlayShardOptions,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        Ok(match self.shards.entry(*overlay_id) {
            Entry::Vacant(entry) => {
                entry.insert(OverlayShard::new(
                    self.adnl.clone(),
                    *overlay_id,
                    overlay_key,
                    options,
                )?);
                true
            }
            Entry::Occupied(_) => false,
        })
    }

    fn get_overlay_shard(
        &self,
        overlay_id: &OverlayIdShort,
    ) -> Result<
        dashmap::mapref::one::Ref<OverlayIdShort, Arc<OverlayShard>, BuildHasherDefault<FxHasher>>,
    > {
        match self.shards.get(overlay_id) {
            Some(shard) => Ok(shard),
            None => Err(OverlayNodeError::UnknownOverlay.into()),
        }
    }

    fn process_nodes(
        &self,
        overlay_id: &OverlayIdShort,
        nodes: ton::overlay::nodes::Nodes,
    ) -> Vec<ton::overlay::node::Node> {
        log::trace!("-------- Got random peers");

        let mut result = Vec::new();

        for node in nodes.nodes.0 {
            let suitable_key = matches!(&node.id, ton::PublicKey::Pub_Ed25519(id) if &id.key.0 != self.node_key.full_id().public_key().as_bytes());
            if !suitable_key {
                continue;
            }

            log::trace!("{:?}", node);
            if let Err(e) = verify_node(overlay_id, &node) {
                log::warn!("Error during overlay peer verification: {:?}", e);
                continue;
            }

            result.push(node);
        }

        result
    }

    fn process_get_random_peers(
        &self,
        shard: &OverlayShard,
        query: ton::rpc::overlay::GetRandomPeers,
    ) -> Result<ton::overlay::nodes::Nodes> {
        let peers = self.process_nodes(shard.id(), query.peers);
        shard.push_peers(peers);
        self.prepare_random_peers(shard)
    }

    fn prepare_random_peers(&self, shard: &OverlayShard) -> Result<ton::overlay::nodes::Nodes> {
        let mut result = vec![self.sign_local_node(shard)?];
        shard.write_random_peers(MAX_RANDOM_PEERS, &mut result);
        Ok(ton::overlay::nodes::Nodes {
            nodes: result.into(),
        })
    }

    fn sign_local_node(&self, shard: &OverlayShard) -> Result<ton::overlay::node::Node> {
        let key = match shard.overlay_key() {
            Some(overlay_key) => overlay_key,
            None => &self.node_key,
        };
        let version = now();

        let signature = serialize_boxed(ton::overlay::node::tosign::ToSign {
            id: key.id().as_tl(),
            overlay: ton::int256(shard.id().into()),
            version,
        })?;
        let signature = key.sign(&signature);

        Ok(ton::overlay::node::Node {
            id: key.full_id().as_tl().into_boxed(),
            overlay: ton::int256(shard.id().into()),
            version,
            signature: ton::bytes(signature.to_bytes().to_vec()),
        })
    }
}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {
    async fn try_consume_custom(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
    ) -> Result<bool> {
        let bundle = match deserialize_view::<PublicOverlayQueryBundleView>(data) {
            Ok(bundle) => bundle,
            Err(_) => return Ok(false),
        };

        let overlay_id = OverlayIdShort::from(*bundle.message.overlay);
        let shard = self.get_overlay_shard(&overlay_id)?.clone();

        match bundle.broadcast {
            OverlayBroadcastView::Broadcast(broadcast) => {
                shard
                    .receive_broadcast(local_id, peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            OverlayBroadcastView::BroadcastFec(broadcast) => {
                shard
                    .receive_fec_broadcast(local_id, peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            _ => Err(OverlayNodeError::UnsupportedOverlayBroadcastMessage.into()),
        }

        /* UNUSED UNTIL VALIDATOR LOGIC WILL BE NEEDED

        // Extract messages
        let catchain_update = match bundle.remove(0).downcast::<ton::catchain::Update>() {
            Ok(ton::catchain::Update::Catchain_BlockUpdate(message)) => *message,
            _ => return Err(OverlayNodeError::UnsupportedPrivateOverlayMessage.into()),
        };

        let validator_session_update = match bundle
            .remove(0)
            .downcast::<ton::validator_session::BlockUpdate>(
        ) {
            Ok(ton::validator_session::BlockUpdate::ValidatorSession_BlockUpdate(
                message,
            )) => *message,
            _ => return Err(OverlayNodeError::UnsupportedPrivateOverlayMessage.into()),
        };

        // Notify waiters
        shard.push_catchain(CatchainUpdate {
            peer_id: *peer_id,
            catchain_update,
            validator_session_update,
        });

        // Done
        Ok(true)

        */
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

        let overlay_id = match queries.remove(0).downcast::<ton::rpc::overlay::Query>() {
            Ok(query) => query.into(),
            Err(query) => {
                queries.insert(0, query);
                return Ok(QueryBundleConsumingResult::Rejected(queries));
            }
        };

        let query = match queries
            .remove(0)
            .downcast::<ton::rpc::overlay::GetRandomPeers>()
        {
            Ok(query) => {
                let shard = self.get_overlay_shard(&overlay_id)?;
                return QueryBundleConsumingResult::consume(
                    self.process_get_random_peers(shard.value(), query)?,
                );
            }
            Err(query) => query,
        };

        let consumer = match self.subscribers.get(&overlay_id) {
            Some(consumer) => consumer.clone(),
            None => return Err(OverlayNodeError::NoConsumerFound.into()),
        };

        match consumer.try_consume_query(local_id, peer_id, query).await? {
            QueryConsumingResult::Consumed(result) => {
                Ok(QueryBundleConsumingResult::Consumed(result))
            }
            QueryConsumingResult::Rejected(_) => Err(OverlayNodeError::UnsupportedQuery.into()),
        }
    }
}

const MAX_RANDOM_PEERS: usize = 4;

pub const MAX_OVERLAY_PEERS: usize = 65536;

#[derive(thiserror::Error, Debug)]
enum OverlayNodeError {
    #[error("Unsupported overlay broadcast message")]
    UnsupportedOverlayBroadcastMessage,
    #[error("Unknown overlay")]
    UnknownOverlay,
    #[error("Cannot add public peer to private overlay")]
    PublicPeerToPrivateOverlay,
    #[error("Cannot delete public overlay")]
    DeletingPublicOverlay,
    #[error("No consumer for message in overlay")]
    NoConsumerFound,
    #[error("Unsupported query")]
    UnsupportedQuery,
}
