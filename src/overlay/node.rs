use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tl_proto::{BoxedConstructor, TlRead};

use super::overlay::{Overlay, OverlayMetrics, OverlayOptions};
use super::overlay_id::IdShort;
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
    state: Arc<NodeState>,
}

impl Node {
    pub fn new(adnl: Arc<adnl::Node>, key_tag: usize) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?.clone();
        let state = Arc::new(NodeState::default());

        adnl.add_query_subscriber(state.clone())?;
        adnl.add_message_subscriber(state.clone())?;

        Ok(Arc::new(Self {
            adnl,
            node_key,
            state,
        }))
    }

    pub fn query_subscriber(&self) -> Arc<dyn QuerySubscriber> {
        self.state.clone()
    }

    pub fn metrics(&self) -> impl Iterator<Item = (IdShort, OverlayMetrics)> + '_ {
        self.state
            .overlays
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

    /// Creates new overlay
    pub fn add_public_overlay(
        &self,
        overlay_id: &IdShort,
        options: OverlayOptions,
    ) -> (Arc<Overlay>, bool) {
        use dashmap::mapref::entry::Entry;

        match self.state.overlays.entry(*overlay_id) {
            Entry::Vacant(entry) => {
                let overlay = Overlay::new(self.node_key.clone(), *overlay_id, options);
                entry.insert(overlay.clone());
                (overlay, true)
            }
            Entry::Occupied(entry) => (entry.get().clone(), false),
        }
    }

    /// Returns overlay by specified id
    #[inline(always)]
    pub fn get_overlay(&self, overlay_id: &IdShort) -> Result<Arc<Overlay>> {
        self.state.get_overlay(overlay_id)
    }
}

#[derive(Default)]
struct NodeState {
    /// Overlays by ids
    overlays: FxDashMap<IdShort, Arc<Overlay>>,
    /// Overlay query subscribers
    subscribers: FxDashMap<IdShort, Arc<dyn QuerySubscriber>>,
}

impl NodeState {
    fn get_overlay(&self, overlay_id: &IdShort) -> Result<Arc<Overlay>> {
        match self.overlays.get(overlay_id) {
            Some(overlay) => Ok(overlay.clone()),
            None => Err(NodeError::UnknownOverlay.into()),
        }
    }
}

#[async_trait::async_trait]
impl MessageSubscriber for NodeState {
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

        let overlay = self.get_overlay(&overlay_id)?;
        match broadcast {
            proto::overlay::Broadcast::Broadcast(broadcast) => {
                overlay
                    .receive_broadcast(ctx.adnl, ctx.local_id, ctx.peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            proto::overlay::Broadcast::BroadcastFec(broadcast) => {
                overlay
                    .receive_fec_broadcast(ctx.adnl, ctx.local_id, ctx.peer_id, broadcast, data)
                    .await?;
                Ok(true)
            }
            _ => Err(NodeError::UnsupportedOverlayBroadcastMessage.into()),
        }
    }
}

#[async_trait::async_trait]
impl QuerySubscriber for NodeState {
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
            let overlay = self.get_overlay(&overlay_id)?;
            return QueryConsumingResult::consume(
                overlay.process_get_random_peers(query).into_boxed(),
            );
        }

        let consumer = match self.subscribers.get(&overlay_id) {
            Some(consumer) => consumer.clone(),
            None => return Err(NodeError::NoConsumerFound.into()),
        };

        match consumer.try_consume_query(ctx, constructor, query).await? {
            QueryConsumingResult::Consumed(result) => Ok(QueryConsumingResult::Consumed(result)),
            QueryConsumingResult::Rejected(_) => Err(NodeError::UnsupportedQuery.into()),
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum NodeError {
    #[error("Unsupported overlay broadcast message")]
    UnsupportedOverlayBroadcastMessage,
    #[error("Unknown overlay")]
    UnknownOverlay,
    #[error("No consumer for message in overlay")]
    NoConsumerFound,
    #[error("Unsupported query")]
    UnsupportedQuery,
}
