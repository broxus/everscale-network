use anyhow::{Context, Result};
use everscale_network::{adnl, NetworkBuilder};
use rand::Rng;
use tl_proto::{TlRead, TlWrite};

use self::util::global_config;

mod util;

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x11223344)]
struct MyCustomData {
    counter: u32,
}

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
    let (_adnl, dht) = NetworkBuilder::with_adnl((my_ip, 30000), keystore, Default::default())
        .with_dht(KEY_TAG, Default::default())
        .build()?;

    // Fill static nodes
    for global_config::DhtNode(peer) in global_config.dht_nodes {
        dht.add_dht_peer(peer)?;
    }

    tracing::info!("searching DHT nodes");
    let new_dht_nodes = dht.find_more_dht_nodes().await?;
    tracing::info!("found {new_dht_nodes} DHT nodes");

    // Store some data in DHT
    let stored = dht
        .entry(dht.key().id(), "some_value")
        .with_data(MyCustomData { counter: 0 })
        .with_ttl(3600)
        .sign_and_store(dht.key())?
        .then_check(|_, MyCustomData { counter }| Ok(counter == 0))
        .await?;
    assert!(stored);

    Ok(())
}
