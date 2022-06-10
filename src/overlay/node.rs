use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tl_proto::{BoxedConstructor, TlRead};

use super::overlay_id::{IdFull, IdShort};
use super::overlay_shard::{OverlayShardMetrics, Shard, ShardOptions};
use crate::adnl;
use crate::proto;
use crate::subscriber::*;
use crate::utils::*;

/// P2P messages distribution layer group
pub struct Node {
    /// Underlying ADNL node
    adnl: Arc<adnl::Node>,
    /// Local ADNL key
    node_key: Arc<adnl::Key>,
    /// Shared state
    state: Arc<OverlayNodeState>,
    /// Overlay group "seed"
    zero_state_file_hash: [u8; 32],
}

impl Node {
    pub fn new(
        adnl: Arc<adnl::Node>,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?.clone();
        let state = Arc::new(OverlayNodeState::default());

        adnl.add_query_subscriber(state.clone())?;
        adnl.add_message_subscriber(state.clone())?;

        Ok(Arc::new(Self {
            adnl,
            node_key,
            state,
            zero_state_file_hash,
        }))
    }

    pub fn query_subscriber(&self) -> Arc<dyn QuerySubscriber> {
        self.state.clone()
    }

    pub fn metrics(&self) -> impl Iterator<Item = (IdShort, OverlayShardMetrics)> + '_ {
        self.state
            .shards
            .iter()
            .map(|item| (*item.id(), item.metrics()))
    }

    /// Underlying ADNL node
    pub fn adnl(&self) -> &Arc<adnl::Node> {
        &self.adnl
    }

    /// Add overlay queries subscriber
    pub fn add_overlay_subscriber(
        &self,
        overlay_id: IdShort,
        subscriber: Arc<dyn QuerySubscriber>,
    ) -> bool {
        use dashmap::mapref::entry::Entry;

        match self.state.subscribers.entry(overlay_id) {
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
        overlay_id: &IdShort,
        options: ShardOptions,
    ) -> (Arc<Shard>, bool) {
        use dashmap::mapref::entry::Entry;

        match self.state.shards.entry(*overlay_id) {
            Entry::Vacant(entry) => {
                let overlay_shard = Shard::new(self.node_key.clone(), *overlay_id, options);
                entry.insert(overlay_shard.clone());
                (overlay_shard, true)
            }
            Entry::Occupied(entry) => (entry.get().clone(), false),
        }
    }

    /// Returns overlay by specified id
    #[inline(always)]
    pub fn get_overlay(&self, overlay_id: &IdShort) -> Result<Arc<Shard>> {
        self.state.get_overlay(overlay_id)
    }

    /// Computes full overlay id using zero state file hash
    pub fn compute_overlay_id(&self, workchain: i32) -> IdFull {
        IdFull::for_shard_overlay(workchain, &self.zero_state_file_hash)
    }

    /// Computes short overlay id using zero state file hash
    pub fn compute_overlay_short_id(&self, workchain: i32) -> IdShort {
        self.compute_overlay_id(workchain).compute_short_id()
    }
}

#[derive(Default)]
struct OverlayNodeState {
    /// Overlay shards
    shards: FxDashMap<IdShort, Arc<Shard>>,
    /// Overlay query subscribers
    subscribers: FxDashMap<IdShort, Arc<dyn QuerySubscriber>>,
}

impl OverlayNodeState {
    fn get_overlay(&self, overlay_id: &IdShort) -> Result<Arc<Shard>> {
        match self.shards.get(overlay_id) {
            Some(shard) => Ok(shard.clone()),
            None => Err(OverlayNodeError::UnknownOverlay.into()),
        }
    }
}

#[async_trait::async_trait]
impl MessageSubscriber for OverlayNodeState {
    async fn try_consume_custom<'a>(
        &self,
        ctx: SubscriberContext<'a>,
        constructor: u32,
        data: &'a [u8],
    ) -> Result<bool> {
        if constructor != proto::overlay::Message::TL_ID {
            return Ok(false);
        }

        let mut offset = 4; // skip `overlay::Message` constructor
        let overlay_id = IdShort::from(<[u8; 32]>::read_from(data, &mut offset)?);
        let broadcast = proto::overlay::Broadcast::read_from(data, &mut offset)?;

        // TODO: check that offset == data.len()

        let shard = self.get_overlay(&overlay_id)?;
        match broadcast {
            proto::overlay::Broadcast::Broadcast(broadcast) => {
                shard
                    .receive_broadcast(ctx.adnl, ctx.local_id, ctx.peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            proto::overlay::Broadcast::BroadcastFec(broadcast) => {
                shard
                    .receive_fec_broadcast(ctx.adnl, ctx.local_id, ctx.peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            _ => Err(OverlayNodeError::UnsupportedOverlayBroadcastMessage.into()),
        }
    }
}

#[async_trait::async_trait]
impl QuerySubscriber for OverlayNodeState {
    async fn try_consume_query<'a>(
        &self,
        ctx: SubscriberContext<'a>,
        constructor: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        if constructor != proto::rpc::OverlayQuery::TL_ID {
            return Ok(QueryConsumingResult::Rejected(query));
        }

        let mut offset = 4; // skip `rpc::OverlayQuery` constructor
        let overlay_id = IdShort::from(<[u8; 32]>::read_from(&query, &mut offset)?);

        let constructor = u32::read_from(&query, &mut std::convert::identity(offset))?;
        if constructor == proto::rpc::OverlayGetRandomPeers::TL_ID {
            let query = proto::rpc::OverlayGetRandomPeers::read_from(&query, &mut offset)?;
            let shard = self.get_overlay(&overlay_id)?;
            return QueryConsumingResult::consume(
                shard.process_get_random_peers(query).into_boxed(),
            );
        }

        let consumer = match self.subscribers.get(&overlay_id) {
            Some(consumer) => consumer.clone(),
            None => return Err(OverlayNodeError::NoConsumerFound.into()),
        };

        match consumer.try_consume_query(ctx, constructor, query).await? {
            QueryConsumingResult::Consumed(result) => Ok(QueryConsumingResult::Consumed(result)),
            QueryConsumingResult::Rejected(_) => Err(OverlayNodeError::UnsupportedQuery.into()),
        }
    }
}

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
