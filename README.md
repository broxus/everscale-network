## everscale-network &emsp; [![Latest Version]][crates.io] [![Workflow badge]][Workflow] [![License Apache badge]][License Apache] [![Docs badge]][Docs]

Implementation of the network part of the Everscale blockchain.

### Network stack

```text
           ┌─────────────────────┐
           │            Overlay  │ - Overlay: Virtual subnetwork
┌──────────┼──────────┐          │ - DHT: Kademlia-like Distributed Hash Table
│    DHT   │   RLDP   │          │ - RLDP: Reliable Large Datagram Protocol
├──────────┴──────────┴──────────┤
│              ADNL              │ - ADNL: Abstract Data Network Layer
├────────────────────────────────┤
│              UDP               │ - underlying transport protocol
└────────────────────────────────┘
 ```

### Example

```rust
use std::net::SocketAddrV4;

use anyhow::Result;
use everscale_network::{adnl, NetworkBuilder};
use tl_proto::TlWrite;

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x11223344)]
struct MyCustomData {
    counter: u32,
}

async fn example() -> Result<()> {
    const DHT_KEY_TAG: usize = 0;

    // NOTE: our ip address must be accessible from other peers
    let socket_addr = "1.2.3.4:10000".parse::<SocketAddrV4>()?;

    // Create and fill keystore
    let keystore = adnl::Keystore::builder()
        .with_tagged_key([1u8; 32], DHT_KEY_TAG)?
        .build();

    // Create basic network parts
    let (_adnl, dht) = NetworkBuilder::with_adnl(socket_addr, keystore, Default::default())
        .with_dht(DHT_KEY_TAG, Default::default())
        .build()?;

    // Store some data in DHT
    let stored = dht
        .entry(&[0u8; 32], "some_value")
        .with_data(MyCustomData { counter: 0 })
        .with_ttl(3600)
        .sign_and_store(dht.key())?
        .then_check(|_, MyCustomData { counter }| Ok(counter == 0))
        .await?;
    assert!(stored);

    Ok(())
}
```

For more information you can check the [docs](https://docs.rs/everscale-network) or the [examples](https://github.com/broxus/everscale-network/tree/master/examples).

### Minimum Rust version

The current minimum required Rust version is 1.60.

### License

This project is licensed under the [License Apache].

[Latest Version]: https://img.shields.io/crates/v/everscale-network.svg
[crates.io]: https://crates.io/crates/everscale-network
[Workflow badge]: https://img.shields.io/github/workflow/status/broxus/everscale-network/master
[Workflow]: https://github.com/broxus/everscale-network/actions?query=workflow%3Amaster
[License Apache badge]: https://img.shields.io/github/license/broxus/everscale-network
[License Apache]: https://opensource.org/licenses/Apache-2.0
[Docs badge]: https://docs.rs/everscale-network/badge.svg
[Docs]: https://docs.rs/everscale-network
