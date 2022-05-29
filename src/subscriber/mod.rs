use std::borrow::Cow;

use anyhow::Result;

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

pub enum QueryConsumingResult<'a> {
    Consumed(Option<Vec<u8>>),
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
