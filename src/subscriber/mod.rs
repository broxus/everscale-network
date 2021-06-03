mod ping_subscriber;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use ton_api::ton::TLObject;
use ton_api::{BoxedSerialize, IntoBoxed};

pub use self::ping_subscriber::AdnlPingSubscriber;
use crate::node_id::*;

#[async_trait::async_trait]
pub trait Subscriber: Send + Sync {
    async fn poll(&self, _start: &Arc<Instant>) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    async fn try_consume_custom(
        &self,
        _local_id: &AdnlNodeIdShort,
        _peer_id: &AdnlNodeIdShort,
        _data: &[u8],
    ) -> Result<bool> {
        Ok(false)
    }

    async fn try_consume_query(
        &self,
        _local_id: &AdnlNodeIdShort,
        _peer_id: &AdnlNodeIdShort,
        query: TLObject,
    ) -> Result<QueryConsumingResult> {
        Ok(QueryConsumingResult::Rejected(query))
    }

    async fn try_consume_query_bundle(
        &self,
        _local_id: &AdnlNodeIdShort,
        _peer_id: &AdnlNodeIdShort,
        queries: Vec<TLObject>,
    ) -> Result<QueryBundleConsumingResult> {
        Ok(QueryBundleConsumingResult::Rejected(queries))
    }
}

pub enum QueryConsumingResult {
    Consumed(Option<QueryAnswer>),
    Rejected(TLObject),
}

pub enum QueryBundleConsumingResult {
    Consumed(Option<QueryAnswer>),
    Rejected(Vec<TLObject>),
}

impl QueryConsumingResult {
    pub fn consume<A: IntoBoxed>(answer: A) -> Result<Self>
    where
        <A as IntoBoxed>::Boxed: serde::Serialize + Send + Sync + 'static,
    {
        Ok(Self::Consumed(Some(QueryAnswer::Object(TLObject::new(
            answer.into_boxed(),
        )))))
    }

    pub fn consume_boxed<A>(answer: A) -> Result<Self>
    where
        A: BoxedSerialize + serde::Serialize + Send + Sync + 'static,
    {
        Ok(Self::Consumed(Some(QueryAnswer::Object(TLObject::new(
            answer,
        )))))
    }
}

pub enum QueryAnswer {
    Object(TLObject),
    Raw(Vec<u8>),
}
