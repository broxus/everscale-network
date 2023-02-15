use std::collections::hash_map;
use std::sync::Arc;

use anyhow::Result;
use everscale_crypto::ed25519;

use super::node_id::{ComputeNodeIds, NodeIdFull, NodeIdShort};
use crate::util::FastHashMap;

/// Tagged keystore for ADNL keys
#[derive(Default)]
pub struct Keystore {
    keys: FastHashMap<NodeIdShort, Arc<Key>>,
    tags: FastHashMap<usize, NodeIdShort>,
}

impl Keystore {
    pub fn builder() -> KeystoreBuilder {
        KeystoreBuilder::default()
    }

    /// Searches key by its short id
    pub fn key_by_id(&self, id: &NodeIdShort) -> Result<&Arc<Key>, KeystoreError> {
        if let Some(key) = self.keys.get(id) {
            Ok(key)
        } else {
            Err(KeystoreError::KeyIdNotFound(*id))
        }
    }

    /// Searches key by its tag
    pub fn key_by_tag(&self, tag: usize) -> Result<&Arc<Key>, KeystoreError> {
        if let Some(id) = self.tags.get(&tag) {
            self.key_by_id(id)
        } else {
            Err(KeystoreError::KeyTagNotFound(tag))
        }
    }

    /// Returns inner keys table
    #[inline(always)]
    pub fn keys(&self) -> &FastHashMap<NodeIdShort, Arc<Key>> {
        &self.keys
    }

    /// Adds a new key with the specified tag
    ///
    /// NOTE: duplicate keys or tags will cause this method to fail
    pub fn add_key(&mut self, key: [u8; 32], tag: usize) -> Result<NodeIdShort, KeystoreError> {
        let secret_key = ed25519::SecretKey::from_bytes(key);
        let (_, short_id) = secret_key.compute_node_ids();

        match self.tags.entry(tag) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(short_id);
                match self.keys.entry(short_id) {
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(Arc::new(secret_key.into()));
                        Ok(short_id)
                    }
                    hash_map::Entry::Occupied(_) => Err(KeystoreError::DuplicatedKey(tag)),
                }
            }
            hash_map::Entry::Occupied(entry) => {
                if entry.get() == &short_id {
                    Ok(short_id)
                } else {
                    Err(KeystoreError::DuplicatedKeyTag(tag))
                }
            }
        }
    }
}

#[derive(Default)]
pub struct KeystoreBuilder {
    keystore: Keystore,
}

impl KeystoreBuilder {
    pub fn build(self) -> Keystore {
        self.keystore
    }

    /// Adds a new key with the specified tag
    ///
    /// NOTE: duplicate keys or tags will cause this method to fail
    pub fn with_tagged_key(mut self, key: [u8; 32], tag: usize) -> Result<Self, KeystoreError> {
        self.keystore.add_key(key, tag)?;
        Ok(self)
    }

    /// Creates a new keystore from tagged secret keys
    pub fn with_tagged_keys<I>(mut self, keys: I) -> Result<Self, KeystoreError>
    where
        I: IntoIterator<Item = ([u8; 32], usize)>,
    {
        for (key, tag) in keys {
            self.keystore.add_key(key, tag)?;
        }
        Ok(self)
    }
}

/// ADNL key with precomputed node IDs
pub struct Key {
    short_id: NodeIdShort,
    full_id: NodeIdFull,
    secret_key: ed25519::ExpandedSecretKey,
}

impl Key {
    /// Constructs new key from the secret key bytes
    pub fn from_bytes(secret_key: [u8; 32]) -> Self {
        ed25519::SecretKey::from_bytes(secret_key).into()
    }

    /// Returns short key id
    #[inline(always)]
    pub fn id(&self) -> &NodeIdShort {
        &self.short_id
    }

    /// Returns full key id
    #[inline(always)]
    pub fn full_id(&self) -> &NodeIdFull {
        &self.full_id
    }

    /// Returns inner secret key (as expanded)
    #[inline(always)]
    pub fn secret_key(&self) -> &ed25519::ExpandedSecretKey {
        &self.secret_key
    }

    /// Signs serializable boxed data
    #[inline(always)]
    pub fn sign<T: tl_proto::TlWrite<Repr = tl_proto::Boxed>>(&self, data: T) -> [u8; 64] {
        self.secret_key.sign(data, self.full_id.public_key())
    }
}

impl From<ed25519::SecretKey> for Key {
    fn from(secret_key: ed25519::SecretKey) -> Self {
        let (full_id, short_id) = secret_key.compute_node_ids();
        Self {
            short_id,
            full_id,
            secret_key: ed25519::ExpandedSecretKey::from(&secret_key),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KeystoreError {
    #[error("Duplicated key tag {0}")]
    DuplicatedKeyTag(usize),
    #[error("Duplicated secret key {0}")]
    DuplicatedKey(usize),
    #[error("Key is not found: {0}")]
    KeyIdNotFound(NodeIdShort),
    #[error("Key tag not found: {0}")]
    KeyTagNotFound(usize),
    #[error("Unexpected key")]
    UnexpectedKey,
}
