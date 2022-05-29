use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tl_proto::{TlRead, TlWrite};

use super::node_id::*;
use crate::proto;
use crate::subscriber::*;
use crate::utils::compression;

pub async fn process_adnl_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    query: &[u8],
) -> Result<QueryProcessingResult<Vec<u8>>> {
    process_query(local_id, peer_id, subscribers, Cow::Borrowed(query)).await
}

pub async fn process_rldp_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    mut query: OwnedRldpMessageQuery,
    force_compression: bool,
) -> Result<QueryProcessingResult<Vec<u8>>> {
    let answer_compression = match compression::decompress(&query.data) {
        Some(decompressed) => {
            query.data = decompressed;
            true
        }
        None => force_compression,
    };

    match process_query(local_id, peer_id, subscribers, Cow::Owned(query.data)).await? {
        QueryProcessingResult::Processed(answer) => Ok(match answer {
            Some(mut answer) => {
                if answer_compression {
                    if let Err(e) = compression::compress(&mut answer) {
                        tracing::warn!("Failed to compress RLDP answer: {e:?}");
                    }
                }
                if answer.len() > query.max_answer_size as usize {
                    return Err(QueryError::AnswerSizeExceeded.into());
                }

                QueryProcessingResult::Processed(Some(tl_proto::serialize(
                    proto::rldp::Message::Answer {
                        query_id: &query.query_id,
                        data: &answer,
                    },
                )))
            }
            None => QueryProcessingResult::Processed(None),
        }),
        _ => Ok(QueryProcessingResult::Rejected),
    }
}

pub struct OwnedRldpMessageQuery {
    pub query_id: [u8; 32],
    pub max_answer_size: u64,
    pub data: Vec<u8>,
}

impl OwnedRldpMessageQuery {
    pub fn from_data(mut data: Vec<u8>) -> Option<Self> {
        #[derive(TlRead, TlWrite)]
        #[tl(boxed, id = 0x8a794d69)]
        struct Query {
            #[tl(size_hint = 32)]
            query_id: [u8; 32],
            max_answer_size: u64,
            timeout: u32,
        }

        let mut offset = 0;
        let params = Query::read_from(&data, &mut offset).ok()?;
        unsafe {
            let remaining = data.len() - offset;
            std::ptr::copy(data.as_ptr().add(offset), data.as_mut_ptr(), remaining);
            data.set_len(remaining);
        };

        Some(Self {
            query_id: params.query_id,
            max_answer_size: params.max_answer_size,
            data,
        })
    }
}

async fn process_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    mut query: Cow<'_, [u8]>,
) -> Result<QueryProcessingResult<Vec<u8>>> {
    let constructor = u32::read_from(&query, &mut 0)?;

    for subscriber in subscribers {
        query = match subscriber
            .try_consume_query(local_id, peer_id, constructor, query)
            .await?
        {
            QueryConsumingResult::Consumed(answer) => {
                return Ok(QueryProcessingResult::Processed(answer))
            }
            QueryConsumingResult::Rejected(query) => query,
        };
    }

    Ok(QueryProcessingResult::Rejected)
}

pub enum QueryProcessingResult<T> {
    Processed(Option<T>),
    Rejected,
}

/// Query id wrapper used for printing
pub struct ShortQueryId<'a>(pub &'a QueryId);

impl std::fmt::Display for ShortQueryId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        ))
    }
}

pub type QueryId = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum QueryError {
    #[error("Answer size exceeded")]
    AnswerSizeExceeded,
}
