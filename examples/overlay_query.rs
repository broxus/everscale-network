use std::borrow::Cow;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use anyhow::{Context, Result};
use everscale_network::{
    adnl, overlay, NetworkBuilder, QueryConsumingResult, QuerySubscriber, SubscriberContext,
};
use rand::Rng;
use tl_proto::{TlRead, TlWrite};

const KEY_TAG: usize = 0;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let overlay_id = Default::default();

    let (adnl, _rldp, overlay) = NetworkBuilder::with_adnl(
        (Ipv4Addr::LOCALHOST, 0),
        make_keystore()?,
        Default::default(),
    )
    .with_rldp(Default::default())
    .with_overlay(KEY_TAG)
    .build()?;

    let (shard, _) = overlay.add_public_overlay(&overlay_id, Default::default());

    let subscriber = Arc::new(OverlaySubscriber);
    overlay.add_overlay_subscriber(overlay_id, subscriber);

    send_query(overlay_id, shard.sign_local_node(), adnl.socket_addr()).await?;

    Ok(())
}

async fn send_query(
    overlay_id: overlay::IdShort,
    other: everscale_network::proto::overlay::NodeOwned,
    addr: SocketAddrV4,
) -> Result<()> {
    let (adnl, _rldp, overlay) = NetworkBuilder::with_adnl(
        (Ipv4Addr::LOCALHOST, 0),
        make_keystore()?,
        Default::default(),
    )
    .with_rldp(Default::default())
    .with_overlay(KEY_TAG)
    .build()?;

    let (shard, _) = overlay.add_public_overlay(&overlay_id, Default::default());
    let peer_id = shard
        .add_public_peer(&adnl, addr, other.as_equivalent_ref())?
        .context("failed to add overlay peer")?;

    let pong: everscale_network::proto::adnl::Pong = adnl
        .query(
            shard.overlay_key().id(),
            &peer_id,
            everscale_network::proto::rpc::AdnlPing { value: 123 },
            None,
        )
        .await?
        .context("no ping response")?;
    tracing::info!("PONG: {pong:?}");

    let answer = shard
        .adnl_query(&adnl, &peer_id, RpcGetCapabilities, None)
        .await?
        .context("no answer")?;
    tracing::info!("response: {}", hex::encode(&answer));

    let parsed = tl_proto::deserialize::<Capabilities>(&answer)?;
    tracing::info!("answer: {parsed:?}");

    Ok(())
}

fn make_keystore() -> Result<adnl::Keystore> {
    Ok(adnl::Keystore::builder()
        .with_tagged_key(rand::thread_rng().gen(), KEY_TAG)?
        .build())
}

struct OverlaySubscriber;

#[async_trait::async_trait]
impl QuerySubscriber for OverlaySubscriber {
    async fn try_consume_query<'a>(
        &self,
        _: SubscriberContext<'a>,
        constructor: u32,
        _: Cow<'a, [u8]>,
    ) -> Result<QueryConsumingResult<'a>> {
        if constructor == RpcGetCapabilities::TL_ID {
            QueryConsumingResult::consume(Capabilities {
                version: 2,
                capabilities: 1,
            })
        } else {
            Ok(QueryConsumingResult::Consumed(None))
        }
    }
}

#[derive(TlWrite, TlRead)]
#[tl(
    boxed,
    id = "tonNode.getCapabilities",
    scheme_inline = "tonNode.getCapabilities = tonNode.Capabilities;"
)]
pub struct RpcGetCapabilities;

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(
    boxed,
    id = "tonNode.capabilities",
    size_hint = 12,
    scheme_inline = "tonNode.capabilities version:int capabilities:long = tonNode.Capabilities;"
)]
pub struct Capabilities {
    pub version: u32,
    pub capabilities: u64,
}
