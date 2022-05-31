use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tl_proto::{BoxedConstructor, TlRead};

pub use self::overlay_shard::{
    IncomingBroadcastInfo, OutgoingBroadcastInfo, OverlayShard, OverlayShardMetrics,
    OverlayShardOptions, ReceivedPeersMap,
};
use crate::adnl_node::*;
use crate::proto;
use crate::subscriber::*;
use crate::utils::*;

mod broadcast_receiver;
mod overlay_shard;

/// P2P messages distribution layer group
pub struct OverlayNode {
    /// Underlying ADNL node
    adnl: Arc<AdnlNode>,
    /// Local ADNL key
    node_key: Arc<StoredAdnlNodeKey>,
    /// Overlay shards
    shards: FxDashMap<OverlayIdShort, Arc<OverlayShard>>,
    /// Overlay query subscribers
    subscribers: FxDashMap<OverlayIdShort, Arc<dyn OverlaySubscriber>>,
    /// Overlay group "seed"
    zero_state_file_hash: [u8; 32],
}

impl OverlayNode {
    pub fn new(
        adnl: Arc<AdnlNode>,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?.clone();
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

    /// Underlying ADNL node
    pub fn adnl(&self) -> &Arc<AdnlNode> {
        &self.adnl
    }

    /// Add overlay queries subscriber
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

    /// Creates new overlay shard
    pub fn add_public_overlay(
        &self,
        overlay_id: &OverlayIdShort,
        options: OverlayShardOptions,
    ) -> (Arc<OverlayShard>, bool) {
        use dashmap::mapref::entry::Entry;

        match self.shards.entry(*overlay_id) {
            Entry::Vacant(entry) => {
                let overlay_shard = OverlayShard::new(
                    self.adnl.clone(),
                    self.node_key.clone(),
                    *overlay_id,
                    options,
                );
                entry.insert(overlay_shard.clone());
                (overlay_shard, true)
            }
            Entry::Occupied(entry) => (entry.get().clone(), false),
        }
    }

    /// Returns overlay by specified id
    pub fn get_overlay(&self, overlay_id: &OverlayIdShort) -> Result<Arc<OverlayShard>> {
        match self.shards.get(overlay_id) {
            Some(shard) => Ok(shard.clone()),
            None => Err(OverlayNodeError::UnknownOverlay.into()),
        }
    }

    /// Computes full overlay id using zero state file hash
    pub fn compute_overlay_id(&self, workchain: i32) -> OverlayIdFull {
        compute_overlay_id(workchain, self.zero_state_file_hash)
    }

    /// Computes short overlay id using zero state file hash
    pub fn compute_overlay_short_id(&self, workchain: i32) -> OverlayIdShort {
        self.compute_overlay_id(workchain).compute_short_id()
    }
}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {
    async fn try_consume_custom(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        constructor: u32,
        data: &[u8],
    ) -> Result<bool> {
        if constructor != proto::overlay::Message::TL_ID {
            return Ok(false);
        }

        let mut offset = 4; // skip `overlay::Message` constructor
        let overlay_id = OverlayIdShort::from(<[u8; 32]>::read_from(data, &mut offset)?);
        let broadcast = proto::overlay::Broadcast::read_from(data, &mut offset)?;

        // TODO: check that offset == data.len()

        let shard = self.get_overlay(&overlay_id)?;
        match broadcast {
            proto::overlay::Broadcast::Broadcast(broadcast) => {
                shard
                    .receive_broadcast(local_id, peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            proto::overlay::Broadcast::BroadcastFec(broadcast) => {
                shard
                    .receive_fec_broadcast(local_id, peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            _ => Err(OverlayNodeError::UnsupportedOverlayBroadcastMessage.into()),
        }
    }

    async fn try_consume_query<'a>(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        constructor: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        if constructor != proto::rpc::OverlayQuery::TL_ID {
            return Ok(QueryConsumingResult::Rejected(query));
        }

        let mut offset = 4; // skip `rpc::OverlqyQuery` constructor
        let overlay_id = OverlayIdShort::from(<[u8; 32]>::read_from(&query, &mut offset)?);

        let constructor = u32::read_from(&query, &mut std::convert::identity(offset))?;
        if constructor == proto::rpc::OverlayGetRandomPeers::TL_ID {
            let query = proto::rpc::OverlayGetRandomPeers::read_from(&query, &mut offset)?;
            let shard = self.get_overlay(&overlay_id)?;
            return QueryConsumingResult::consume(
                shard.process_get_random_peers(query).into_boxed_writer(),
            );
        }

        let consumer = match self.subscribers.get(&overlay_id) {
            Some(consumer) => consumer.clone(),
            None => return Err(OverlayNodeError::NoConsumerFound.into()),
        };

        match consumer
            .try_consume_query(local_id, peer_id, constructor, query)
            .await?
        {
            QueryConsumingResult::Consumed(result) => Ok(QueryConsumingResult::Consumed(result)),
            QueryConsumingResult::Rejected(_) => Err(OverlayNodeError::UnsupportedQuery.into()),
        }
    }
}

/// Max allowed known peer count
pub const MAX_OVERLAY_PEERS: usize = 65536;

#[derive(thiserror::Error, Debug)]
enum OverlayNodeError {
    #[error("Unsupported overlay broadcast message")]
    UnsupportedOverlayBroadcastMessage,
    #[error("Unknown overlay")]
    UnknownOverlay,
    #[error("No consumer for message in overlay")]
    NoConsumerFound,
    #[error("Unsupported query")]
    UnsupportedQuery,
}
