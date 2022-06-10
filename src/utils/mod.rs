//! # Basic primitives and helpers

use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
pub use rustc_hash::{FxHashMap, FxHashSet};

pub use self::deferred_initialization::*;
pub use self::network_builder::*;
pub use self::packed_socket_addr::*;
pub use self::packets_history::*;
pub use self::updated_at::*;

mod deferred_initialization;
mod network_builder;
mod packed_socket_addr;
mod packets_history;
mod updated_at;

pub type FxDashSet<K> = dashmap::DashSet<K, BuildHasherDefault<FxHasher>>;
pub type FxDashMap<K, V> = dashmap::DashMap<K, V, BuildHasherDefault<FxHasher>>;

pub fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}
