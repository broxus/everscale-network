use std::borrow::Cow;

use anyhow::Result;

use super::{QueryConsumingResult, Subscriber};
use crate::proto;
use crate::utils::*;

pub struct AdnlPingSubscriber;

#[async_trait::async_trait]
impl Subscriber for AdnlPingSubscriber {
    async fn try_consume_query<'a>(
        &self,
        _: &AdnlNodeIdShort,
        _: &AdnlNodeIdShort,
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
