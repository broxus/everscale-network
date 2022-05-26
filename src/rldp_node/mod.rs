use std::sync::Arc;

use anyhow::{Context, Result};

pub use self::decoder::RaptorQDecoder;
pub use self::encoder::RaptorQEncoder;
use self::peer::*;
use self::transfers_cache::*;
use crate::adnl_node::AdnlNode;
use crate::proto;
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
#[serde(default)]
pub struct RldpNodeOptions {
    /// Default: 10485760 (10 MB)
    pub max_answer_size: u32,
    /// Default: 16
    pub max_peer_queries: u32,
    /// Default: false
    pub force_compression: bool,
}

impl Default for RldpNodeOptions {
    fn default() -> Self {
        Self {
            max_answer_size: 10 * 1024 * 1024,
            max_peer_queries: 16,
            force_compression: false,
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
            transfers: TransfersCache::new(
                adnl,
                subscribers,
                options.max_answer_size,
                options.force_compression,
            ),
            options,
        })
    }

    #[inline(always)]
    pub fn options(&self) -> &RldpNodeOptions {
        &self.options
    }

    pub fn metrics(&self) -> RldpNodeMetrics {
        RldpNodeMetrics {
            peer_count: self.peers.len(),
            transfers_cache_len: self.transfers.len(),
        }
    }

    #[tracing::instrument(level = "debug", name = "rldp_query", skip(self, data))]
    pub async fn query(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        mut data: Vec<u8>,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        if self.options.force_compression {
            if let Err(e) = compression::compress(&mut data) {
                tracing::warn!("Failed to compress RLDP query: {e:?}");
            }
        }

        let (query_id, query) = make_query(&data, self.options.max_answer_size);
        drop(data);

        let peer = self
            .peers
            .entry(*peer_id)
            .or_insert_with(|| Arc::new(RldpPeer::new(self.options.max_peer_queries)))
            .value()
            .clone();

        let result = {
            let _guard = peer.begin_query().await;
            self.transfers
                .query(local_id, peer_id, query, roundtrip)
                .await
        };

        match result? {
            (Some(answer), roundtrip) => match tl_proto::deserialize(&answer) {
                Ok(proto::rldp::Message::Answer {
                    query_id: answer_id,
                    data,
                }) if answer_id == &query_id => Ok((
                    Some(compression::decompress(data).unwrap_or_else(|| data.to_vec())),
                    roundtrip,
                )),
                Ok(proto::rldp::Message::Answer { .. }) => Err(RldpNodeError::QueryIdMismatch),
                Ok(proto::rldp::Message::Message { .. }) => {
                    Err(RldpNodeError::UnexpectedAnswer("RldpMessageView::Message"))
                }
                Ok(proto::rldp::Message::Query { .. }) => {
                    Err(RldpNodeError::UnexpectedAnswer("RldpMessageView::Query"))
                }
                Err(e) => Err(RldpNodeError::InvalidPacketContent(e)),
            }
            .with_context(|| format!("RLDP query from peer {peer_id} failed")),
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
        let message = match tl_proto::deserialize(data) {
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
    fec_type: proto::rldp::RaptorQFecType,
    part: u32,
    total_size: u64,
    seqno: u32,
    data: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
enum RldpNodeError {
    #[error("Unexpected answer: {0}")]
    UnexpectedAnswer(&'static str),
    #[error("Invalid packet content: {0:?}")]
    InvalidPacketContent(tl_proto::TlError),
    #[error("Unknown query id")]
    QueryIdMismatch,
}
