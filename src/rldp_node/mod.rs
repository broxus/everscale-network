use std::sync::Arc;

use anyhow::Result;
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
    peers: DashMap<AdnlNodeIdShort, Arc<RldpPeer>>,
    transfers: TransfersCache,
}

impl RldpNode {
    pub fn with_adnl_node(adnl: Arc<AdnlNode>, subscribers: Vec<Arc<dyn Subscriber>>) -> Arc<Self> {
        Arc::new(Self {
            peers: Default::default(),
            transfers: TransfersCache::new(adnl, subscribers),
        })
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

        let peer = self.peers.entry(*peer_id).or_default().value().clone();

        peer.begin_query().await;

        let result = self
            .transfers
            .query(local_id, peer_id, query.as_slice(), roundtrip)
            .await;

        peer.end_query().await;

        match result? {
            (Some(answer), roundtrip) => {
                match deserialize(answer.as_slice())?.downcast::<ton::rldp::Message>() {
                    Ok(ton::rldp::Message::Rldp_Answer(answer))
                        if answer.query_id.0 == query_id =>
                    {
                        Ok((Some(answer.data.to_vec()), roundtrip))
                    }
                    Ok(ton::rldp::Message::Rldp_Answer(_)) => {
                        Err(RldpNodeError::QueryIdMismatch.into())
                    }
                    _ => Err(RldpNodeError::UnexpectedAnswer.into()),
                }
            }
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
        let message = match deserialize(data) {
            Ok(message) => match message.downcast::<ton::rldp::MessagePart>() {
                Ok(message) => message,
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };

        self.transfers
            .handle_message(local_id, peer_id, message)
            .await?;

        Ok(true)
    }
}

#[derive(thiserror::Error, Debug)]
enum RldpNodeError {
    #[error("Unexpected answer")]
    UnexpectedAnswer,
    #[error("Unknown query id")]
    QueryIdMismatch,
}
