//! # Basic primitives and helpers

use std::collections::{HashMap, HashSet};

pub use self::network_builder::{
    DeferredInitialization, DeferredInitializationList, NetworkBuilder,
};

pub(crate) use self::address_list::*;
pub(crate) use self::fast_rand::*;
pub(crate) use self::packets_history::*;
pub(crate) use self::updated_at::*;

mod address_list;
mod fast_rand;
mod network_builder;
mod packets_history;
mod updated_at;

pub(crate) type FastHashSet<K> = HashSet<K, FastHasherState>;
pub(crate) type FastHashMap<K, V> = HashMap<K, V, FastHasherState>;
pub(crate) type FastDashSet<K> = dashmap::DashSet<K, FastHasherState>;
pub(crate) type FastDashMap<K, V> = dashmap::DashMap<K, V, FastHasherState>;
pub(crate) type FastHasherState = ahash::RandomState;

pub(crate) fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}
