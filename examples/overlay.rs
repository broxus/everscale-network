use std::time::Duration;

use anyhow::{Context, Result};

use everscale_network::{adnl, overlay, NetworkBuilder};
use rand::Rng;

use self::util::global_config;

mod util;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    const KEY_TAG: usize = 0;

    let global_config =
        serde_json::from_str::<util::global_config::GlobalConfig>(include_str!("mainnet.json"))?;

    // Resolve public ip
    let my_ip = public_ip::addr_v4()
        .await
        .context("failed to resolve public ip address")?;

    // Create and fill keystore
    let keystore = adnl::Keystore::builder()
        .with_tagged_key(rand::thread_rng().gen(), KEY_TAG)?
        .build();

    // Create basic network parts
    let (adnl, dht, _rldp, overlay) =
        NetworkBuilder::with_adnl((my_ip, 30000), keystore, Default::default())
            .with_dht(KEY_TAG, Default::default())
            .with_rldp(Default::default())
            .with_overlay(KEY_TAG)
            .build()?;

    // Fill static nodes
    for global_config::DhtNode(peer) in global_config.dht_nodes {
        dht.add_dht_peer(peer)?;
    }

    // Initialize network
    adnl.start()?;

    let new_dht_nodes = dht.find_more_dht_nodes().await?;
    tracing::info!("found {new_dht_nodes} DHT nodes");

    // Add masterchain overlay
    let mc_overlay_id =
        overlay::IdFull::for_workchain_overlay(-1, &global_config.zero_state.file_hash)
            .compute_short_id();
    let (workchain_overlay, _) = overlay.add_public_overlay(&mc_overlay_id, Default::default());

    // Populate overlay with nodes
    let overlay_nodes = dht
        .find_overlay_nodes(&mc_overlay_id)
        .await
        .context("failed to find overlay nodes")?;
    tracing::info!("found {} overlay nodes", overlay_nodes.len());

    for (ip, node) in overlay_nodes {
        workchain_overlay.add_public_peer(&adnl, ip, node.as_equivalent_ref())?;
    }

    // Broadcast something
    workchain_overlay.broadcast(
        &adnl,
        vec![0; 10],
        None,
        overlay::BroadcastTarget::RandomNeighbours,
    );

    // NOTE: broadcast is just fire-and-forget, so wait a bit
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Done
    Ok(())
}
