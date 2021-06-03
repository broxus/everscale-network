use std::sync::Arc;

use anyhow::Result;
use ton_api::{ton, IntoBoxed, Serializer};

use super::node_id::*;
use super::{deserialize_bundle, serialize, NoFailure};
use crate::subscriber::*;

pub fn build_query(
    prefix: Option<&[u8]>,
    query: &ton::TLObject,
) -> Result<(QueryId, ton::adnl::Message)> {
    use rand::Rng;

    let query_id: QueryId = rand::thread_rng().gen();
    let query = match prefix {
        Some(prefix) => {
            let mut prefix = prefix.to_vec();
            Serializer::new(&mut prefix).write_boxed(query).convert()?;
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
    custom: &ton::adnl::message::message::Custom,
) -> Result<bool> {
    for subscriber in subscribers.iter() {
        if subscriber
            .try_consume_custom(local_id, peer_id, &custom.data)
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
    query: &ton::adnl::message::message::Query,
) -> Result<QueryProcessingResult<ton::adnl::Message>> {
    match process_query(local_id, peer_id, subscribers, query.query.as_ref()).await? {
        QueryProcessingResult::Processed(answer) => convert_answer(answer, |answer| {
            ton::adnl::message::message::Answer {
                query_id: query.query_id,
                answer: ton::bytes(answer),
            }
            .into_boxed()
        })
        .map(QueryProcessingResult::Processed),
        _ => Ok(QueryProcessingResult::Rejected),
    }
}

async fn process_query(
    local_id: &AdnlNodeIdShort,
    peer_id: &AdnlNodeIdShort,
    subscribers: &[Arc<dyn Subscriber>],
    query: &[u8],
) -> Result<QueryProcessingResult<QueryAnswer>> {
    let mut queries = deserialize_bundle(query)?;

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
