//! ## ADNL - Abstract Datagram Network Layer
//!
//! ADNL is a UDP-based data transfer protocol. It is a base layer for other protocols, used
//! in Everscale. It provides no guarantees of reliability, so it should only be used for
//! small data transfers. There is a support for multipart transfers, but the user must be
//! prepared, that some parts of them may be lost and full transfer will be lost.
//!
//! #### Brief overview
//!
//! Each peer has its own keypair. In most cases it is a ed25519 keypair
//! (see [`KeyPair`]). The public key of this keypair is also called
//! a **full peer id** ([`NodeIdFull`]). The hash of the TL representation
//! of its full id is a **short peer id** ([`NodeIdShort`]).
//!
//! Each peer remembers unix timestamp (in seconds) at the moment of initialization.
//! It is called **reinit date** and used to describe peer's state "version".
//! If other peers see that the reinit date of peer `A` has changed, they must treat
//! peer `A` as a completely new peer.
//!
//! ADNL maintains a state for each peer it has communicated with. This state contains
//! unique channel keypair, reinit date of the remote peer and sequence numbers of packets
//! for both directions.
//!
//! Communication between peers is done by sending packets through UDP. Each packet length must be
//! less than MTU (*1500 bytes*). Packets are encrypted with a shared secret key and have some basic
//! integrity checks (checksum), ordering (sequence numbers, timings) and deduplication
//! (short packets history). Packet can contain multiple ADNL messages ([`Message`]) and must
//! address a specific peer by specifying its short or full peer id.
//!
//! #### Packet versions
//!
//! - **Handshake packet**: when peer `A` sends its first message to the peer `B` it wraps it into
//!   a handshake packet. For each packet peer `A` generates new keypair.
//!   It computes shared secret using `x25519(random_secret_key, peer_B_public_key)` and uses it
//!   to encrypt data. When peer `B` receives this packet it computes shared secret using
//!   `x25519(peer_B_secret_key, random_public_key)` and uses it to decrypt data. So handshake
//!   packet contains peer `B` short id, public key of the random keypair, checksum and encrypted data.
//!
//! - **Channel packet**: after channel has been established, each peer will use a smaller packet
//!   structure called channel packet. Instead of generating a new keypair for each packet it will
//!   use shared secret from the channel to encrypt and decrypt data. Channel packet contains
//!   channel id, checksum and encrypted data.
//!
//! #### Message types
//!
//! - **`Nop`** - an empty message that is only used by the other peer to update the state of our peer.
//! - **`Custom`** - a one-way message that just contains a raw data. Mostly used by RLDP or other
//!   protocols on top of ADNL.
//! - **`Query`** - a request to the other peer which in most cases requires a response.
//! - **`Answer`** - a response to the **`Query`** message.
//! - **`CreateChannel`** - a special message with the info about newly created channel. Remote peer
//!   should also create a channel and send a confirmation about this.
//! - **`ConfirmChannel`** - channel confirmation to the **`CreateChannel`** message.
//! - **`Part`** - special message that is used to split a large message across multiple packets.
//!   After all message parts are received, the data is combined and deserialized into the original
//!   message. Will mostly be used for large **`Custom`**, **`Query`** or **`Answer`** messages.
//!
//! #### Channels
//!
//! Communication using only handshake packets is quite inefficient, so there is a some kind of
//! short-lived connections. When new remove peer is added, the channel keypair is also generated.
//! With the first packet, peer `A` sends a **`CreateChannel`** message where it specifies channel
//! public key from its side (and the date of its creation). Peer `B` replies with a **`ConfirmChannel`**
//! message where it specifies same values and the channel public key from its side.
//!
//! Each peer can now create four shared secrets: two for encryption and two for decryption. Why two?
//! Because there are two versions of channels - ordinary and priority. There is not a lot of difference
//! between them, but some nodes could handle packet from the priority channel first.
//!
//! When remove peer is inactive for some time, and any query to it completes with timeout, the channel
//! is regenerated.
//!
//! [`KeyPair`]: everscale_crypto::ed25519::KeyPair
//! [`NodeIdFull`]: NodeIdFull
//! [`NodeIdShort`]: NodeIdShort
//! [`Message`]: crate::proto::adnl::Message

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{Context, Result};
use frunk_core::hlist::{HCons, HNil};
use frunk_core::indices::Here;

pub use self::keystore::{Key, Keystore};
pub use self::node::{Node, NodeMetrics, NodeOptions};
pub use self::node_id::{ComputeNodeIds, NodeIdFull, NodeIdShort};
pub use self::peer::{NewPeerContext, PeerFilter};
pub use self::peers_set::PeersSet;

use crate::util::{DeferredInitialization, NetworkBuilder};

mod channel;
mod encryption;
mod handshake;
mod keystore;
mod node;
mod node_id;
mod packet_view;
mod peer;
mod peers_set;
mod ping_subscriber;
mod queries_cache;
mod socket;
mod transfer;

pub(crate) type Deferred = Result<Arc<Node>>;

impl DeferredInitialization for Deferred {
    type Initialized = Arc<Node>;

    fn initialize(self) -> Result<Self::Initialized> {
        let adnl = self?;
        adnl.start()?;
        Ok(adnl)
    }
}

impl NetworkBuilder<HNil, (Here, Here)> {
    /// Creates a basic network layer that is an ADNL node
    ///
    /// See [`with_adnl_ext`] if you need a node with a peer filter
    ///
    /// [`with_adnl_ext`]: fn@crate::util::NetworkBuilder::with_adnl_ext
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    ///
    /// use everscale_network::{adnl, NetworkBuilder};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn Error>> {
    ///     let keystore = adnl::Keystore::builder()
    ///         .with_tagged_key([0; 32], 0)?
    ///         .build();
    ///
    ///     let options = adnl::NodeOptions::default();
    ///
    ///     let adnl = NetworkBuilder::with_adnl("127.0.0.1:10000", keystore, options).build()?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn with_adnl<T>(
        addr: T,
        keystore: Keystore,
        options: NodeOptions,
    ) -> NetworkBuilder<HCons<Deferred, HNil>, (Here, Here)>
    where
        T: ToSocketAddrs,
    {
        NetworkBuilder(
            HCons {
                head: parse_socket_addr(addr)
                    .and_then(|addr| Node::new(addr, keystore, options, None)),
                tail: HNil,
            },
            Default::default(),
        )
    }

    /// Creates a basic network layer that is an ADNL node with additional filter
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    /// use std::net::SocketAddrV4;
    /// use std::sync::Arc;
    ///
    /// use everscale_network::{adnl, NetworkBuilder};
    ///
    /// struct MyFilter;
    ///
    /// impl adnl::PeerFilter for MyFilter {
    ///     fn check(
    ///         &self,
    ///         ctx: adnl::NewPeerContext,
    ///         addr: SocketAddrV4,
    ///         peer_id: &adnl::NodeIdShort,
    ///     ) -> bool {
    ///         // Allow only non-loopback IPs
    ///         !addr.ip().is_loopback()
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn Error>> {
    ///     let keystore = adnl::Keystore::builder()
    ///         .with_tagged_key([0; 32], 0)?
    ///         .build();
    ///
    ///     let options = adnl::NodeOptions::default();
    ///
    ///     let peer_filter = Arc::new(MyFilter);
    ///
    ///     let adnl = NetworkBuilder::with_adnl_ext("127.0.0.1:10000", keystore, options, peer_filter)
    ///         .build()?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn with_adnl_ext<T>(
        addr: T,
        keystore: Keystore,
        options: NodeOptions,
        peer_filter: Arc<dyn PeerFilter>,
    ) -> NetworkBuilder<HCons<Deferred, HNil>, (Here, Here)>
    where
        T: ToSocketAddrs,
    {
        NetworkBuilder(
            HCons {
                head: parse_socket_addr(addr)
                    .and_then(|addr| Node::new(addr, keystore, options, Some(peer_filter))),
                tail: HNil,
            },
            Default::default(),
        )
    }
}

fn parse_socket_addr<T: ToSocketAddrs>(addr: T) -> Result<SocketAddrV4> {
    match addr
        .to_socket_addrs()
        .context("Failed to parse socket addr")?
        .next()
    {
        Some(SocketAddr::V4(addr)) => Ok(addr),
        Some(SocketAddr::V6(_)) => anyhow::bail!("IPv6 is not supported"),
        None => anyhow::bail!("Invalid ip address"),
    }
}
