//! # Basic primitives and helpers

use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
pub use rustc_hash::{FxHashMap, FxHashSet};

pub use self::node_id::*;
pub use self::overlay_id::*;
pub use self::packed_socket_addr::*;
pub use self::packets_history::*;
pub use self::peers_cache::*;
pub use self::updated_at::*;

#[cfg(feature = "rldp")]
pub mod compression;
mod node_id;
mod overlay_id;
mod packed_socket_addr;
mod packets_history;
mod peers_cache;
mod updated_at;

pub type FxDashSet<K> = dashmap::DashSet<K, BuildHasherDefault<FxHasher>>;
pub type FxDashMap<K, V> = dashmap::DashMap<K, V, BuildHasherDefault<FxHasher>>;

pub fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}
