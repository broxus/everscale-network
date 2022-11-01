use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use everscale_crypto::ed25519;
use everscale_network::{adnl, rldp};
use everscale_network::{NetworkBuilder, QueryConsumingResult, QuerySubscriber, SubscriberContext};
use rand::Rng;
use tl_proto::{TlRead, TlWrite};

#[tokio::main]
async fn main() -> Result<()> {
    let adnl_node_options = adnl::NodeOptions::default();
    let rldp_node_options = rldp::NodeOptions {
        max_peer_queries: 10000,
        force_compression: true,
        ..Default::default()
    };

    let build_node = |service| -> Result<(Arc<adnl::Node>, Arc<rldp::Node>)> {
        let key = ed25519::SecretKey::generate(&mut rand::thread_rng());
        let (adnl, rldp) = NetworkBuilder::with_adnl(
            (Ipv4Addr::LOCALHOST, 0),
            adnl::Keystore::builder()
                .with_tagged_key(key.to_bytes(), 0)?
                .build(),
            adnl_node_options,
        )
        .with_rldp_ext(rldp_node_options, vec![service])
        .build()?;

        Ok((adnl, rldp))
    };

    let (left_adnl, left_rldp) = build_node(Arc::new(Service))?;
    let (right_adnl, _right_rldp) = build_node(Arc::new(Service))?;

    let left_node_id = *left_adnl.key_by_tag(0)?.id();

    let right_node_id_full = *right_adnl.key_by_tag(0)?.full_id();
    let right_node_id = right_node_id_full.compute_short_id();

    left_adnl.add_peer(
        adnl::NewPeerContext::AdnlPacket,
        &left_node_id,
        &right_node_id,
        right_adnl.socket_addr(),
        right_node_id_full,
    )?;

    let iterations = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..200 {
        let left_rldp = left_rldp.clone();
        let query = example_request();
        let iterations = iterations.clone();
        handles.push(tokio::spawn(async move {
            let e = loop {
                let query = tl_proto::serialize(query);
                match left_rldp
                    .query(&left_node_id, &right_node_id, query, None)
                    .await
                {
                    Ok((Some(_), _)) => {
                        iterations.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok((None, _)) => println!("Packet lost"),
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

    let throughput = (tl_proto::serialize(example_request()).len()
        + tl_proto::serialize(example_response()).len())
        * iterations.load(Ordering::Relaxed);

    println!(
        "Total throughput: {} MB/s ({})",
        throughput as f64 / 1048576.0,
        iterations.load(Ordering::Relaxed)
    );

    Ok(())
}

struct Service;

#[async_trait::async_trait]
impl QuerySubscriber for Service {
    async fn try_consume_query<'a>(
        &self,
        _: SubscriberContext<'a>,
        _: u32,
        query: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        let _req = tl_proto::deserialize::<RpcGetArchiveSlice>(query.as_ref())?;
        Ok(QueryConsumingResult::Consumed(Some(example_response())))
    }
}

fn example_request() -> RpcGetArchiveSlice {
    RpcGetArchiveSlice {
        archive_id: 123123,
        offset: 0,
        max_size: 2 << 21,
    }
}

fn example_response() -> Vec<u8> {
    static DATA: once_cell::race::OnceBox<Vec<u8>> = once_cell::race::OnceBox::new();
    DATA.get_or_init(|| {
        let mut rng = rand::thread_rng();
        Box::new(std::iter::repeat_with(|| rng.gen()).take(2 << 21).collect())
    })
    .clone()
}

#[derive(Copy, Clone, Debug, TlRead, TlWrite)]
#[tl(boxed, id = 0x203b5168, size_hint = 20)]
pub struct RpcGetArchiveSlice {
    pub archive_id: u64,
    pub offset: u64,
    pub max_size: u32,
}
