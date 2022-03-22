use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use ton_api::{ton, BoxedSerialize, IntoBoxed, Serializer};

use super::node_id::*;
use super::{deserialize_bundle, serialize};
use crate::subscriber::*;
use crate::utils::compression;

pub fn build_query(
    prefix: Option<&[u8]>,
    query: &ton::TLObject,
) -> Result<(QueryId, ton::adnl::Message)> {
    use rand::Rng;

    let query_id: QueryId = rand::thread_rng().gen();
    let query = match prefix {
        Some(prefix) => {
            let mut prefix = prefix.to_vec();
            Serializer::new(&mut prefix).write_boxed(query)?;
            prefix
        }
        None => serialize(query)?,
    };

    Ok((
        query_id,
        ton::adnl::message::message::Query {
            query_id: ton::int256(query_id),
            query: ton::bytes(query),
        }
        .into_boxed(),
    ))
}

pub async fn process_message_custom(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    data: &[u8],
) -> Result<bool> {
    for subscriber in subscribers.iter() {
        if subscriber
            .try_consume_custom(local_id, peer_id, data)
            .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn process_message_adnl_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    query_id: &QueryId,
    query: &[u8],
) -> Result<QueryProcessingResult<ton::adnl::Message>> {
    match process_query(local_id, peer_id, subscribers, Cow::Borrowed(query)).await? {
        QueryProcessingResult::Processed(answer) => convert_answer(answer, |answer| {
            ton::adnl::message::message::Answer {
                query_id: ton::int256(*query_id),
                answer: ton::bytes(answer),
            }
            .into_boxed()
        })
        .map(QueryProcessingResult::Processed),
        _ => Ok(QueryProcessingResult::Rejected),
    }
}

pub async fn process_message_rldp_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    ton::rldp::message::Query {
        query_id, mut data, ..
    }: ton::rldp::message::Query,
    force_compression: bool,
) -> Result<QueryProcessingResult<ton::rldp::message::Answer>> {
    let answer_compression = match compression::decompress(&data.0) {
        Some(decompressed) => {
            data.0 = decompressed;
            true
        }
        None => force_compression,
    };

    match process_query(local_id, peer_id, subscribers, Cow::Owned(data.0)).await? {
        QueryProcessingResult::Processed(answer) => convert_answer(answer, move |mut answer| {
            if answer_compression {
                if let Err(e) = compression::compress(&mut answer) {
                    log::warn!("Failed to compress RLDP answer: {:?}", e);
                }
            }

            ton::rldp::message::Answer {
                query_id,
                data: ton::bytes(answer),
            }
        })
        .map(QueryProcessingResult::Processed),
        _ => Ok(QueryProcessingResult::Rejected),
    }
}

async fn process_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    query: Cow<'_, [u8]>,
) -> Result<QueryProcessingResult<QueryAnswer>> {
    let mut queries = deserialize_bundle(&query)?;
    drop(query);

    if queries.len() == 1 {
        let mut query = queries.remove(0);
        for subscriber in subscribers.iter() {
            query = match subscriber
                .try_consume_query(local_id, peer_id, query)
                .await?
            {
                QueryConsumingResult::Consumed(answer) => {
                    return Ok(QueryProcessingResult::Processed(answer))
                }
                QueryConsumingResult::Rejected(query) => query,
            };
        }
    } else {
        for subscriber in subscribers.iter() {
            queries = match subscriber
                .try_consume_query_bundle(local_id, peer_id, queries)
                .await?
            {
                QueryBundleConsumingResult::Consumed(answer) => {
                    return Ok(QueryProcessingResult::Processed(answer));
                }
                QueryBundleConsumingResult::Rejected(queries) => queries,
            };
        }
    }

    Ok(QueryProcessingResult::Rejected)
}

pub enum QueryProcessingResult<T> {
    Processed(Option<T>),
    Rejected,
}

pub fn parse_answer<T>(answer: ton::TLObject) -> Result<T>
where
    T: BoxedSerialize + serde::Serialize + Send + Sync + 'static,
{
    match answer.downcast::<T>() {
        Ok(answer) => Ok(answer),
        Err(_) => Err(QueryError::UnsupportedResponse.into()),
    }
}

fn convert_answer<A, F>(answer: Option<QueryAnswer>, convert: F) -> Result<Option<A>>
where
    F: Fn(Vec<u8>) -> A,
{
    Ok(match answer {
        Some(QueryAnswer::Object(x)) => Some(serialize(&x)?),
        Some(QueryAnswer::Raw(x)) => Some(x),
        None => None,
    }
    .map(convert))
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
    #[error("Unsupported response")]
    UnsupportedResponse,
}
