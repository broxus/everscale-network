#![allow(clippy::too_many_arguments)]

//! Implementation of the network part of the Everscale blockchain.

macro_rules! ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return Err(err),
        }
    };
}

// Re-export TL-proto crate
pub use everscale_crypto as crypto;
pub use tl_proto as tl;

pub use subscriber::{MessageSubscriber, QueryConsumingResult, QuerySubscriber, SubscriberContext};
pub use util::NetworkBuilder;

pub mod adnl;
#[cfg(feature = "dht")]
pub mod dht;
pub mod overlay;
pub mod proto;
#[cfg(feature = "rldp")]
pub mod rldp;
mod subscriber;
pub mod util;
