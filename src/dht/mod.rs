//! ## DHT - Kademlia-like Distributed Hash Table
//!
//! TODO

use std::borrow::Borrow;

pub use node::{DhtNode, DhtNodeMetrics, DhtNodeOptions};

mod buckets;
pub mod futures;
mod node;
mod peers_iter;
mod storage;
pub mod streams;

pub fn make_dht_key<'a, T>(id: &'a T, name: &'a str) -> crate::proto::dht::Key<'a>
where
    T: Borrow<[u8; 32]>,
{
    crate::proto::dht::Key {
        id: id.borrow(),
        name: name.as_bytes(),
        idx: 0,
    }
}

const DHT_KEY_ADDRESS: &str = "address";
const DHT_KEY_NODES: &str = "nodes";
