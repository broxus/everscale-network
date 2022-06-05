//! ## DHT - Kademlia-like Distributed Hash Table
//!
//! TODO

pub use entry::DhtEntry;
pub use node::{DhtNode, DhtNodeMetrics, DhtNodeOptions};

mod buckets;
mod entry;
pub mod futures;
mod node;
mod peers_iter;
mod storage;
pub mod streams;

const DHT_KEY_ADDRESS: &str = "address";
const DHT_KEY_NODES: &str = "nodes";

pub const MAX_DHT_PEERS: usize = 65536;
