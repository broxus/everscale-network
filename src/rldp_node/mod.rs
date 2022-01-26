use std::sync::Arc;

use anyhow::{Context, Result};
use ton_api::ton;

pub use self::decoder::RaptorQDecoder;
pub use self::encoder::RaptorQEncoder;
use self::peer::*;
use self::transfers_cache::*;
use crate::adnl_node::AdnlNode;
use crate::subscriber::*;
use crate::utils::*;

mod decoder;
mod encoder;
mod incoming_transfer;
mod outgoing_transfer;
mod peer;
mod transfers_cache;

pub struct RldpNode {
    options: RldpNodeOptions,
    peers: FxDashMap<AdnlNodeIdShort, Arc<RldpPeer>>,
    transfers: TransfersCache,
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub struct RldpNodeOptions {
    /// Default: 16
    pub max_peer_queries: u32,
}

impl Default for RldpNodeOptions {
    fn default() -> Self {
        Self {
            max_peer_queries: 16,
        }
    }
}

impl RldpNode {
    pub fn new(
        adnl: Arc<AdnlNode>,
        subscribers: Vec<Arc<dyn Subscriber>>,
        options: RldpNodeOptions,
    ) -> Arc<Self> {
        Arc::new(Self {
            peers: Default::default(),
            transfers: TransfersCache::new(adnl, subscribers),
            options,
        })
    }

    pub fn metrics(&self) -> RldpNodeMetrics {
        RldpNodeMetrics {
            peer_count: self.peers.len(),
            transfers_cache_len: self.transfers.len(),
        }
    }

    pub async fn query(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
        max_answer_size: Option<i64>,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let (query_id, query) = make_query(data, max_answer_size)?;

        let peer = self
            .peers
            .entry(*peer_id)
            .or_insert_with(|| Arc::new(RldpPeer::new(self.options.max_peer_queries)))
            .value()
            .clone();

        let result = {
            let _guard = peer.begin_query().await;
            self.transfers
                .query(local_id, peer_id, query.as_slice(), roundtrip)
                .await
        };

        match result? {
            (Some(answer), roundtrip) => match deserialize_view(answer.as_slice()) {
                Ok(RldpMessageView::Answer {
                    query_id: answer_id,
                    data,
                }) if answer_id == &query_id => Ok((Some(data.to_vec()), roundtrip)),
                Ok(RldpMessageView::Answer { .. }) => Err(RldpNodeError::QueryIdMismatch),
                Ok(RldpMessageView::Message { .. }) => {
                    Err(RldpNodeError::UnexpectedAnswer("RldpMessageView::Message"))
                }
                Ok(RldpMessageView::Query { .. }) => {
                    Err(RldpNodeError::UnexpectedAnswer("RldpMessageView::Query"))
                }
                Err(e) => Err(RldpNodeError::InvalidPacketContent(e)),
            }
            .with_context(|| format!("RLDP query from peer {} failed", peer_id)),
            (None, roundtrip) => Ok((None, roundtrip)),
        }
    }
}

#[async_trait::async_trait]
impl Subscriber for RldpNode {
    async fn try_consume_custom(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
    ) -> Result<bool> {
        let message = match deserialize_view(data) {
            Ok(message) => message,
            Err(_) => return Ok(false),
        };

        self.transfers
            .handle_message(local_id, peer_id, message)
            .await?;

        Ok(true)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RldpNodeMetrics {
    pub peer_count: usize,
    pub transfers_cache_len: usize,
}

pub struct MessagePart {
    fec_type: Option<ton::fec::type_::RaptorQ>,
    part: i32,
    total_size: i64,
    seqno: i32,
    data: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
enum RldpNodeError {
    #[error("Unexpected answer: {0}")]
    UnexpectedAnswer(&'static str),
    #[error("Invalid packet content: {0:?}")]
    InvalidPacketContent(PacketContentsError),
    #[error("Unknown query id")]
    QueryIdMismatch,
}
