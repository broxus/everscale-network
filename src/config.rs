use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;

use crate::address_list::AdnlAddressUdp;
use crate::node_id::*;

pub struct AdnlNodeConfig {
    ip_address: AdnlAddressUdp,
    keys: DashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>>,
    tags: DashMap<usize, AdnlNodeIdShort>,
}

impl AdnlNodeConfig {
    pub fn from_ip_address_and_keys(
        ip_address: AdnlAddressUdp,
        keys: Vec<(ed25519_dalek::SecretKey, usize)>,
    ) -> Result<Self> {
        let result = AdnlNodeConfig {
            ip_address,
            keys: Default::default(),
            tags: Default::default(),
        };

        for (key, tag) in keys {
            result.add_key(key, tag)?;
        }

        Ok(result)
    }

    pub fn ip_address(&self) -> AdnlAddressUdp {
        self.ip_address
    }

    pub fn key_by_id(&self, id: &AdnlNodeIdShort) -> Result<Arc<StoredAdnlNodeKey>> {
        if let Some(key) = self.keys.get(id) {
            Ok(key.clone())
        } else {
            Err(AdnlNodeConfigError::KeyIdNotFound(*id).into())
        }
    }

    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<StoredAdnlNodeKey>> {
        if let Some(id) = self.tags.get(&tag) {
            self.key_by_id(id.value())
        } else {
            Err(AdnlNodeConfigError::KeyTagNotFound(tag).into())
        }
    }

    pub fn keys(&self) -> &DashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>> {
        &self.keys
    }

    pub fn add_key(&self, key: ed25519_dalek::SecretKey, tag: usize) -> Result<AdnlNodeIdShort> {
        use dashmap::mapref::entry::Entry;

        let (full_id, short_id) = key.compute_node_ids()?;

        match self.tags.entry(tag) {
            Entry::Vacant(entry) => {
                entry.insert(short_id);
                match self.keys.entry(short_id) {
                    Entry::Vacant(entry) => {
                        entry.insert(Arc::new(StoredAdnlNodeKey {
                            full_id,
                            private_key: key,
                        }));
                        Ok(short_id)
                    }
                    Entry::Occupied(_) => Err(AdnlNodeConfigError::DuplicatedKey(short_id).into()),
                }
            }
            Entry::Occupied(entry) => {
                if entry.get() == &short_id {
                    Ok(short_id)
                } else {
                    Err(AdnlNodeConfigError::DuplicatedKeyTag(tag).into())
                }
            }
        }
    }

    pub fn delete_key(&self, key: &AdnlNodeIdShort, tag: usize) -> Result<bool> {
        let removed_key = self.keys.remove(key);
        if let Some((_, ref removed)) = self.tags.remove(&tag) {
            if removed != key {
                return Err(AdnlNodeConfigError::UnexpectedKey.into());
            }
        }
        Ok(removed_key.is_some())
    }
}

pub struct StoredAdnlNodeKey {
    full_id: AdnlNodeIdFull,
    private_key: ed25519_dalek::SecretKey,
}

impl StoredAdnlNodeKey {
    pub fn id(&self) -> &AdnlNodeIdFull {
        &self.full_id
    }

    pub fn private_key(&self) -> &ed25519_dalek::SecretKey {
        &self.private_key
    }
}

#[derive(thiserror::Error, Debug)]
enum AdnlNodeConfigError {
    #[error("Duplicated key tag {} in node config", .0)]
    DuplicatedKeyTag(usize),
    #[error("Duplicated key {} in node", .0)]
    DuplicatedKey(AdnlNodeIdShort),
    #[error("Key is not found: {}", .0)]
    KeyIdNotFound(AdnlNodeIdShort),
    #[error("Key tag not found: {}", .0)]
    KeyTagNotFound(usize),
    #[error("Unexpected key")]
    UnexpectedKey,
}
