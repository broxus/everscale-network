use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
pub use rustc_hash::{FxHashMap, FxHashSet};

pub use self::dht::*;
pub use self::keystore::*;
pub use self::node_id::*;
pub use self::overlay::*;
pub use self::packed_socket_addr::*;
pub use self::packet_view::*;
pub use self::packets_history::*;
pub use self::peers_cache::*;
pub use self::queries_cache::*;
pub use self::response_collector::*;
pub use self::socket::*;
pub use self::updated_at::*;

pub mod compression;
mod dht;
mod keystore;
mod node_id;
mod overlay;
mod packed_socket_addr;
mod packet_view;
mod packets_history;
mod peers_cache;
mod queries_cache;
mod response_collector;
mod socket;
mod updated_at;

pub type FxDashSet<K> = dashmap::DashSet<K, BuildHasherDefault<FxHasher>>;
pub type FxDashMap<K, V> = dashmap::DashMap<K, V, BuildHasherDefault<FxHasher>>;

pub fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

pub fn ordered_boundaries<T>(min: T, max: T) -> (T, T)
where
    T: Ord,
{
    if min > max {
        (max, min)
    } else {
        (min, max)
    }
}
