use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tl_proto::TlRead;

use crate::utils::*;

#[async_trait::async_trait]
pub trait Subscriber: Send + Sync {
    async fn try_consume_custom(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        constructor: u32,
        data: &[u8],
    ) -> Result<bool> {
        let _ = local_id;
        let _ = peer_id;
        let _ = constructor;
        let _ = data;
        Ok(false)
    }

    async fn try_consume_query<'a>(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        constructor: u32,
        data: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        let _ = local_id;
        let _ = peer_id;
        let _ = constructor;
        Ok(QueryConsumingResult::Rejected(data))
    }
}

#[async_trait::async_trait]
pub trait OverlaySubscriber: Send + Sync {
    async fn try_consume_query<'a>(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        constructor: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult>;
}

/// Subscriber response for consumed query
pub enum QueryConsumingResult<'a> {
    /// Query is accepted and processed
    Consumed(Option<Vec<u8>>),
    /// Query rejected and will be processed by the next subscriber
    Rejected(Cow<'a, [u8]>),
}

impl QueryConsumingResult<'_> {
    pub fn consume<T>(answer: T) -> Result<Self>
    where
        T: tl_proto::TlWrite,
    {
        let _ = tl_proto::TlAssert::<T>::BOXED_WRITE;
        Ok(Self::Consumed(Some(tl_proto::serialize(answer))))
    }
}

pub async fn process_query(
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
