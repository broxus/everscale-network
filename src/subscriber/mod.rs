use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tl_proto::TlRead;

use crate::adnl;

/// ADNL custom messages subscriber
#[async_trait::async_trait]
pub trait MessageSubscriber: Send + Sync {
    async fn try_consume_custom<'a>(
        &self,
        ctx: SubscriberContext<'a>,
        constructor: u32,
        data: &'a [u8],
    ) -> Result<bool>;
}

/// ADNL, RLDP or overlay queries subscriber
#[async_trait::async_trait]
pub trait QuerySubscriber: Send + Sync {
    async fn try_consume_query<'a>(
        &self,
        ctx: SubscriberContext<'a>,
        constructor: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>>;
}

/// Message or query context.
///
/// See [`MessageSubscriber::try_consume_custom`] and [`QuerySubscriber::try_consume_query`]
#[derive(Copy, Clone)]
pub struct SubscriberContext<'a> {
    pub adnl: &'a Arc<adnl::Node>,
    pub local_id: &'a adnl::NodeIdShort,
    pub peer_id: &'a adnl::NodeIdShort,
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
        T: tl_proto::TlWrite<Repr = tl_proto::Boxed>,
    {
        Ok(Self::Consumed(Some(tl_proto::serialize(answer))))
    }
}

pub(crate) async fn process_query<'a>(
    ctx: SubscriberContext<'a>,
    subscribers: &[Arc<dyn QuerySubscriber>],
    mut query: Cow<'_, [u8]>,
) -> Result<QueryProcessingResult<Vec<u8>>> {
    let constructor = u32::read_from(&query, &mut 0)?;

    for subscriber in subscribers {
        query = match subscriber
            .try_consume_query(ctx, constructor, query)
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

pub(crate) enum QueryProcessingResult<T> {
    Processed(Option<T>),
    Rejected,
}
