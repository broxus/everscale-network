use anyhow::Result;
use ton_api::ton::TLObject;
use ton_api::{BoxedSerialize, IntoBoxed};

use crate::node_id::*;

#[async_trait::async_trait]
pub trait Subscriber: Send + Sync {
    async fn try_consume_custom(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
    ) -> Result<bool>;

    async fn try_consume_query(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        query: TLObject,
    ) -> Result<QueryConsumingResult>;

    async fn try_consume_query_bundle(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        queries: Vec<TLObject>,
    ) -> Result<QueryBundleConsumingResult>;
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
