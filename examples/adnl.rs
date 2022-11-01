use std::borrow::Cow;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use everscale_crypto::ed25519;
use everscale_network::adnl;
use everscale_network::{QueryConsumingResult, QuerySubscriber, SubscriberContext};
use tl_proto::{TlRead, TlWrite};

#[tokio::main]
async fn main() -> Result<()> {
    // tracing_subscriber::fmt::init();

    let adnl_node_options = adnl::NodeOptions::default();

    let left_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
    let left_node = adnl::Node::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        adnl::Keystore::builder()
            .with_tagged_keys([(left_key.to_bytes(), 0)])?
            .build(),
        adnl_node_options,
        None,
    )?;
    let left_node_id = *left_node.key_by_tag(0)?.id();

    let right_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
    let right_node = adnl::Node::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        adnl::Keystore::builder()
            .with_tagged_keys([(right_key.to_bytes(), 0)])?
            .build(),
        adnl_node_options,
        None,
    )?;
    right_node.add_query_subscriber(Arc::new(Service))?;

    let right_node_id_full = *right_node.key_by_tag(0)?.full_id();
    let right_node_id = right_node_id_full.compute_short_id();

    left_node.add_peer(
        adnl::NewPeerContext::AdnlPacket,
        &left_node_id,
        &right_node_id,
        right_node.socket_addr(),
        right_node_id_full,
    )?;

    left_node.start()?;
    right_node.start()?;

    let iterations = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..200 {
        let left_node = left_node.clone();
        let query = example_request();
        let iterations = iterations.clone();
        handles.push(tokio::spawn(async move {
            let e = loop {
                match query_data::<_, DataFull>(&left_node, &left_node_id, &right_node_id, query)
                    .await
                {
                    Ok(_) => {
                        iterations.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => break e,
                }
            };
            println!("Error: {e:?}");
        }));
    }

    tokio::select! {
        _ = futures_util::future::join_all(handles) => {},
        _ = tokio::time::sleep(Duration::from_secs(10)) => {},
    }

    left_node.shutdown();

    let throughput = (tl_proto::serialize(example_request()).len()
        + tl_proto::serialize(example_response()).len())
        * iterations.load(Ordering::Relaxed);

    println!("Total throughput: {} MB/s", throughput as f64 / 1048576.0);

    Ok(())
}

async fn query_data<Q, A>(
    left_node: &Arc<adnl::Node>,
    left_node_id: &adnl::NodeIdShort,
    right_node_id: &adnl::NodeIdShort,
    query: Q,
) -> Result<()>
where
    Q: TlWrite,
    for<'a> A: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
{
    match left_node
        .query::<Q, A>(left_node_id, right_node_id, query, None)
        .await?
    {
        Some(_) => {}
        None => println!("Packet lost"),
    };
    Ok(())
}

struct Service;

#[async_trait::async_trait]
impl QuerySubscriber for Service {
    async fn try_consume_query<'a>(
        &self,
        _: SubscriberContext<'a>,
        _: u32,
        _: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        QueryConsumingResult::consume(example_response())
    }
}

fn example_request() -> DownloadNextBlockFull {
    DownloadNextBlockFull {
        prev_block: Default::default(),
    }
}

fn example_response() -> DataFull {
    DataFull {
        id: Default::default(),
        proof: vec![1u8; 128],
        block: vec![1u8; 128],
        is_link: false,
    }
}

#[derive(Copy, Clone, TlRead, TlWrite)]
#[tl(boxed, id = 0x6ea0374a)]
struct DownloadNextBlockFull {
    prev_block: BlockId,
}

#[derive(Clone, TlRead, TlWrite)]
#[tl(boxed, id = 0xbe589f93)]
struct DataFull {
    id: BlockId,
    proof: Vec<u8>,
    block: Vec<u8>,
    is_link: bool,
}

#[derive(Default, Copy, Clone, TlRead, TlWrite)]
struct BlockId {
    workchain: i32,
    shard: u64,
    seqno: u32,
    root_hash: [u8; 32],
    file_hash: [u8; 32],
}
