use std::borrow::Cow;

use anyhow::Result;

use crate::proto;
use crate::subscriber::{QueryConsumingResult, QuerySubscriber, SubscriberContext};

pub struct AdnlPingSubscriber;

#[async_trait::async_trait]
impl QuerySubscriber for AdnlPingSubscriber {
    async fn try_consume_query<'a>(
        &self,
        _: SubscriberContext<'a>,
        constructor: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        if constructor == proto::rpc::AdnlPing::TL_ID {
            let proto::rpc::AdnlPing { value } = tl_proto::deserialize(&query)?;
            QueryConsumingResult::consume(proto::adnl::Pong { value })
        } else {
            Ok(QueryConsumingResult::Rejected(query))
        }
    }
}
