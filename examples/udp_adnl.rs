use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use everscale_crypto::ed25519;
use tiny_adnl::utils::*;
use tiny_adnl::{
    AdnlKeystore, AdnlNode, AdnlNodeOptions, PeerContext, QueryAnswer, QueryConsumingResult,
};
use ton_api::ton;

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger::init();

    let adnl_node_options = AdnlNodeOptions::default();

    let first_key = ed25519::SecretKey::generate(&mut rand::thread_rng());

    let left_node = AdnlNode::new(
        AdnlAddressUdp::localhost(20000),
        AdnlKeystore::from_tagged_keys([(first_key.to_bytes(), 0)])?,
        adnl_node_options,
        None,
    );
    let left_node_id = *left_node.key_by_tag(0)?.id();

    let right_node = AdnlNode::new(
        AdnlAddressUdp::localhost(20001),
        AdnlKeystore::from_tagged_keys([(first_key.to_bytes(), 0)])?,
        adnl_node_options,
        None,
    );

    let right_node_full_id = *right_node.key_by_tag(0)?.full_id();
    let right_node_id = right_node_full_id.compute_short_id();

    left_node.add_peer(
        PeerContext::AdnlPacket,
        &left_node_id,
        &left_node_id,
        right_node.ip_address(),
        right_node_full_id,
    )?;

    left_node.start(Vec::new())?;
    right_node.start(vec![Arc::new(Service)])?;

    let iterations = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..200 {
        let left_node = left_node.clone();
        let query = example_request();
        let iterations = iterations.clone();
        handles.push(tokio::spawn(async move {
            loop {
                query_data(&left_node, &left_node_id, &right_node_id, &query).await;
                iterations.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    tokio::select! {
        _ = futures_util::future::join_all(handles) => {},
        _ = tokio::time::sleep(Duration::from_secs(10)) => {},
    }

    let throughput = (serialize(&example_request()).len() + serialize(&example_response()).len())
        * iterations.load(Ordering::Relaxed);

    println!("Total throughput: {} MB/s", throughput as f64 / 1048576.0);

    Ok(())
}

async fn query_data(
    left_node: &Arc<AdnlNode>,
    left_node_id: &AdnlNodeIdShort,
    right_node_id: &AdnlNodeIdShort,
    query: &ton::TLObject,
) {
    let response = left_node
        .query(left_node_id, right_node_id, query, None)
        .await
        .unwrap();
    if response.is_none() {
        println!("Packet lost");
    }
}

struct Service;

#[async_trait::async_trait]
impl tiny_adnl::Subscriber for Service {
    async fn try_consume_query(
        &self,
        _: &AdnlNodeIdShort,
        _: &AdnlNodeIdShort,
        _: ton::TLObject,
    ) -> Result<QueryConsumingResult> {
        Ok(QueryConsumingResult::Consumed(Some(QueryAnswer::Object(
            example_response(),
        ))))
    }
}

fn example_request() -> ton::TLObject {
    ton::TLObject::new(ton::rpc::ton_node::DownloadNextBlockFull {
        prev_block: Default::default(),
    })
}

fn example_response() -> ton::TLObject {
    ton::TLObject::new(ton::ton_node::DataFull::TonNode_DataFull(Box::new(
        ton::ton_node::datafull::DataFull {
            id: Default::default(),
            proof: vec![1u8; 128].into(),
            block: vec![1u8; 128].into(),
            is_link: Default::default(),
        },
    )))
}
