use dashmap::DashMap;
use ton_api::ton;

use crate::utils::*;

#[derive(Default)]
pub struct Storage {
    storage: DashMap<StorageKey, ton::dht::value::Value>,
}

impl Storage {
    pub fn get(&self, key: &StorageKey) -> Option<ton::dht::value::Value> {
        match self.storage.get(key) {
            Some(item) if item.ttl > now() => Some(item.value().clone()),
            _ => None,
        }
    }
}

pub type StorageKey = [u8; 32];
