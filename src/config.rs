use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;

use crate::address_list::AdnlAddressUdp;
use crate::node_id::*;

pub struct AdnlNodeConfig {
    ip_address: AdnlAddressUdp,
    keys: DashMap<AdnlNodeIdShort, StoredAdnlNodeKey>,
    tags: DashMap<usize, AdnlNodeIdShort>,
}

impl AdnlNodeConfig {
    pub fn from_ip_address_and_keys(
        ip_address: AdnlAddressUdp,
        keys: Vec<(ed25519_dalek::SecretKey, usize)>,
    ) -> Self {
        todo!()
    }

    pub fn add_key(&self, key: ed25519_dalek::SecretKey, tag: usize) -> Result<AdnlNodeIdShort> {
        use dashmap::mapref::entry::Entry;

        let (full_id, short_id) = key.compute_node_ids()?;

        match self.tags.entry(tag) {
            Entry::Vacant(entry) => {
                entry.insert(short_id);
                match self.keys.entry(short_id) {
                    Entry::Vacant(entry) => {
                        entry.insert(StoredAdnlNodeKey {
                            full_id,
                            private_key: key,
                        });
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
}
