use anyhow::Result;
use ton_api::ton::TLObject;
use ton_api::{BoxedSerialize, IntoBoxed};

pub use self::ping_subscriber::AdnlPingSubscriber;
use crate::utils::*;

mod ping_subscriber;

#[async_trait::async_trait]
pub trait Subscriber: Send + Sync {
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

#[async_trait::async_trait]
pub trait OverlaySubscriber: Send + Sync {
    async fn try_consume_query(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        query: TLObject,
    ) -> Result<QueryConsumingResult>;
}

pub enum QueryConsumingResult {
    Consumed(Option<QueryAnswer>),
    Rejected(TLObject),
}

pub enum QueryBundleConsumingResult {
    Consumed(Option<QueryAnswer>),
    Rejected(Vec<TLObject>),
}

macro_rules! impl_consume {
    ($consuming_result:ident) => {
        impl $consuming_result {
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
    };
}

impl_consume!(QueryConsumingResult);
impl_consume!(QueryBundleConsumingResult);

pub enum QueryAnswer {
    Object(TLObject),
    Raw(Vec<u8>),
}
