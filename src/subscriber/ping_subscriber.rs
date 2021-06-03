use anyhow::Result;
use ton_api::ton;

use crate::node_id::*;
use crate::subscriber::*;

pub struct AdnlPingSubscriber;

#[async_trait::async_trait]
impl Subscriber for AdnlPingSubscriber {
    async fn try_consume_query(
        &self,
        _local_id: &AdnlNodeIdShort,
        _peer_id: &AdnlNodeIdShort,
        query: ton::TLObject,
    ) -> Result<QueryConsumingResult> {
        match query.downcast::<ton::rpc::adnl::Ping>() {
            Ok(ping) => QueryConsumingResult::consume(ton::adnl::pong::Pong { value: ping.value }),
            Err(query) => Ok(QueryConsumingResult::Rejected(query)),
        }
    }
}
