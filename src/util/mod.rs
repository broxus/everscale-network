//! # Basic primitives and helpers

use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
pub use rustc_hash::{FxHashMap, FxHashSet};

pub use self::address_list::*;
pub use self::deferred_initialization::*;
pub use self::fast_rand::*;
pub use self::network_builder::*;
pub use self::packets_history::*;
pub use self::updated_at::*;

mod address_list;
mod deferred_initialization;
mod fast_rand;
mod network_builder;
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
