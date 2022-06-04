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
//! a **full peer id** ([`AdnlNodeIdFull`]). The hash of the TL representation
//! of its full id is a **short peer id** ([`AdnlNodeIdShort`]).
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
//! [`AdnlNodeIdFull`]: crate::utils::AdnlNodeIdFull
//! [`AdnlNodeIdShort`]: crate::utils::AdnlNodeIdShort
//! [`Message`]: crate::proto::adnl::Message

pub use self::keystore::Keystore;
pub use self::node::{AdnlNode, AdnlNodeMetrics, AdnlNodeOptions};
pub use self::peer::{AdnlPeerFilter, NewPeerContext};

mod channel;
mod encryption;
mod handshake;
mod keystore;
mod node;
mod packet_view;
mod peer;
mod ping_subscriber;
mod queries_cache;
mod socket;
mod transfer;
