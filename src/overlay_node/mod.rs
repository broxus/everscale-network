use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use ton_api::ton::{self, TLObject};

use self::overlay_shard::*;
use crate::adnl_node::*;
use crate::subscriber::*;
use crate::utils::*;

mod broadcast_receiver;
mod overlay_shard;

pub struct OverlayNode {
    adnl: Arc<AdnlNode>,
    local_id: AdnlNodeIdShort,
    node_key: Arc<StoredAdnlNodeKey>,
    shards: DashMap<OverlayIdShort, Arc<OverlayShard>>,
    subscribers: DashMap<OverlayIdShort, Arc<dyn OverlaySubscriber>>,
    zero_state_file_hash: [u8; 32],
}

impl OverlayNode {
    pub fn with_adnl_node_and_zero_state(
        adnl: Arc<AdnlNode>,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        Ok(Arc::new(Self {
            adnl,
            local_id: node_key.id().compute_short_id()?,
            node_key,
            shards: Default::default(),
            subscribers: Default::default(),
            zero_state_file_hash,
        }))
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

            let is_new_peer =
                self.adnl
                    .add_peer(local_id, &peer_id, *peer_ip_address, peer_full_id)?;

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
        node: &ton::overlay::node::Node,
    ) -> Result<Option<AdnlNodeIdShort>> {
        let shard = self.get_overlay_shard(overlay_id)?;
        if shard.is_private() {
            return Err(OverlayNodeError::PublicPeerToPrivateOverlay.into());
        }

        if let Err(e) = verify_node(overlay_id, node) {
            log::warn!("Error during overlay peer verification: {:?}", e);
            return Ok(None);
        }

        let peer_id_full = AdnlNodeIdFull::try_from(&node.id)?;
        let peer_id = peer_id_full.compute_short_id()?;

        let is_new_peer = self
            .adnl
            .add_peer(&self.local_id, &peer_id, ip_address, peer_id_full)?;
        if is_new_peer {
            shard.add_public_peer(&peer_id, node);
            Ok(Some(peer_id))
        } else {
            Ok(None)
        }
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

    pub fn add_public_overlay(&self, overlay_id: &OverlayIdShort) -> Result<bool> {
        self.add_overlay_shard(overlay_id, None)
    }

    pub fn add_private_overlay(
        &self,
        overlay_id: &OverlayIdShort,
        overlay_key: &Arc<StoredAdnlNodeKey>,
        peers: &[AdnlNodeIdShort],
    ) -> Result<bool> {
        if !self.add_overlay_shard(overlay_id, Some(overlay_key.clone()))? {
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

    pub fn compute_overlay_id(&self, workchain: i32, shard: i64) -> Result<OverlayIdFull> {
        compute_overlay_id(workchain, shard, self.zero_state_file_hash)
    }

    pub fn compute_overlay_short_id(&self, workchain: i32, shard: i64) -> Result<OverlayIdShort> {
        self.compute_overlay_id(workchain, shard)
            .and_then(|id| id.compute_short_id())
    }

    fn add_overlay_shard(
        &self,
        overlay_id: &OverlayIdShort,
        overlay_key: Option<Arc<StoredAdnlNodeKey>>,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        Ok(match self.shards.entry(*overlay_id) {
            Entry::Vacant(entry) => {
                entry.insert(OverlayShard::new(
                    self.adnl.clone(),
                    *overlay_id,
                    overlay_key,
                )?);
                true
            }
            Entry::Occupied(_) => false,
        })
    }

    fn get_overlay_shard(
        &self,
        overlay_id: &OverlayIdShort,
    ) -> Result<dashmap::mapref::one::Ref<OverlayIdShort, Arc<OverlayShard>>> {
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
            let suitable_key = matches!(&node.id, ton::PublicKey::Pub_Ed25519(id) if &id.key.0 != self.node_key.id().public_key().as_bytes());
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
}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {
    async fn try_consume_custom(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
    ) -> Result<bool> {
        let mut bundle = deserialize_bundle(data)?;
        let bundle_type = match bundle.len() {
            2 => QueryBundleType::Public,
            3 => QueryBundleType::Private,
            _ => return Ok(false),
        };

        let overlay_id = match bundle.remove(0).downcast::<ton::overlay::Message>() {
            Ok(message) => {
                let id: OverlayIdShort = message.into();
                id
            }
            Err(e) => {
                log::debug!("Unsupported overlay message: {:?}", e);
                return Ok(false);
            }
        };

        let shard = self.get_overlay_shard(&overlay_id)?;

        match bundle_type {
            QueryBundleType::Public => {
                match bundle.remove(0).downcast::<ton::overlay::Broadcast>() {
                    Ok(ton::overlay::Broadcast::Overlay_Broadcast(broadcast)) => {
                        shard
                            .receive_broadcast(local_id, peer_id, *broadcast, data)
                            .await?;
                        Ok(true)
                    }
                    Ok(ton::overlay::Broadcast::Overlay_BroadcastFec(broadcast)) => {
                        shard
                            .receive_fec_broadcast(local_id, peer_id, *broadcast, data)
                            .await?;
                        Ok(true)
                    }
                    Ok(_) => Err(OverlayNodeError::UnsupportedOverlayBroadcastMessage.into()),
                    Err(_) => Err(OverlayNodeError::UnsupportedOverlayMessage.into()),
                }
            }
            QueryBundleType::Private => {
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

                // TODO: handle messages

                Ok(true)
            }
        }
    }

    async fn try_consume_query_bundle(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        queries: Vec<TLObject>,
    ) -> Result<QueryBundleConsumingResult> {
        todo!()
    }
}

enum QueryBundleType {
    Public,
    Private,
}

#[derive(thiserror::Error, Debug)]
pub enum OverlayNodeError {
    #[error("Unsupported private overlay message")]
    UnsupportedPrivateOverlayMessage,
    #[error("Unsupported overlay message")]
    UnsupportedOverlayMessage,
    #[error("Unsupported overlay broadcast message")]
    UnsupportedOverlayBroadcastMessage,
    #[error("Unknown overlay")]
    UnknownOverlay,
    #[error("Cannot add public peer to private overlay")]
    PublicPeerToPrivateOverlay,
    #[error("Cannot delete public overlay")]
    DeletingPublicOverlay,
}
