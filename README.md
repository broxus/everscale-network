## everscale-network &emsp; [![Latest Version]][crates.io] [![everscale-network: rustc 1.60+]][Rust 1.60] [![Workflow badge]][Workflow] [![License Apache badge]][License Apache]

Implementation of the network part of the Everscale blockchain.

### Network stack

```text
┌────────────────────────────────┐
│  Network                       │ - Network: Blockchain-specific network interface
│          ┌─────────────────────┤
│          │            Overlay  │ - Overlay: Virtual subnetwork
├──────────┼──────────┐          │ - DHT: Kademlia-like Distributed Hash Table
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
use everscale_network::{Keystore, NetworkBuilder};
use tl_proto::TlWrite;

#[derive(TlWrite)]
#[tl(boxed, id = 0x11223344)]
struct MyCustomData {
    counter: u32,
}

async fn example() -> Result<()> {
    const DHT_KEY_TAG: usize = 0;

    // NOTE: our ip address must be accessible from other peers
    let socket_addr = "1.2.3.4:10000".parse::<SocketAddrV4>()?;

    // Create and fill keystore
    let keystore = Keystore::builder()
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

### Minimum Rust version

The current minimum required Rust version is 1.60.

### License

This project is licensed under the [License Apache].

[Latest Version]: https://img.shields.io/crates/v/everscale-network.svg
[crates.io]: https://crates.io/crates/everscale-network
[everscale-network: rustc 1.60+]: https://img.shields.io/badge/rustc-1.60+-lightgray.svg
[Rust 1.60]: https://blog.rust-lang.org/2022/04/07/Rust-1.60.0.html
[Workflow badge]: https://img.shields.io/github/workflow/status/broxus/everscale-network/master
[Workflow]: https://github.com/broxus/everscale-network/actions?query=workflow%3Amaster
[License Apache badge]: https://img.shields.io/github/license/broxus/everscale-network
[License Apache]: https://opensource.org/licenses/Apache-2.0
