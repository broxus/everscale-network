//! # Basic primitives and helpers

use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;

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

pub(crate) type FxDashSet<K> = dashmap::DashSet<K, BuildHasherDefault<FxHasher>>;
pub(crate) type FxDashMap<K, V> = dashmap::DashMap<K, V, BuildHasherDefault<FxHasher>>;

pub(crate) fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}
