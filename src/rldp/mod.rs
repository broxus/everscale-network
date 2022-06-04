//! ## RLDP - Reliable Large Datagram Protocol
//!
//! A reliable arbitrary-size datagram protocol built upon the ADNL, called RLDP, is used instead
//! of a TCP-like protocol. This reliable datagram protocol can be employed, for instance,
//! to send RPC queries to remote hosts and receive answers from them.
//!
//! TODO

pub use node::{RldpNode, RldpNodeMetrics, RldpNodeOptions};

pub(crate) mod decoder;
pub(crate) mod encoder;
mod incoming_transfer;
mod node;
mod outgoing_transfer;
mod transfers_cache;
