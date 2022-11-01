use std::convert::TryFrom;
use std::ops::Deref;

use anyhow::Result;
use smallvec::SmallVec;
use tl_proto::{BoxedConstructor, HashWrapper, TlWrite};

use super::KEY_NODES;
use crate::adnl;
use crate::overlay;
use crate::proto;
use crate::util::*;

pub struct StorageOptions {
    pub max_key_name_len: usize,
    pub max_key_index: u32,
}

/// Local DHT data storage
pub struct Storage {
    storage: FxDashMap<StorageKeyId, proto::dht::ValueOwned>,
    options: StorageOptions,
}

impl Storage {
    pub fn new(options: StorageOptions) -> Self {
        Self {
            storage: Default::default(),
            options,
        }
    }

    /// Returns number of stored values
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// Returns total size of stored values in bytes
    pub fn total_size(&self) -> usize {
        self.storage.iter().map(|item| item.value.len()).sum()
    }

    /// Returns value reference by key
    pub fn get_ref(
        &self,
        key: &StorageKeyId,
    ) -> Option<impl Deref<Target = proto::dht::ValueOwned> + '_> {
        match self.storage.get(key) {
            Some(item) if item.ttl as u32 > now() => Some(item),
            _ => None,
        }
    }

    /// Inserts value into the local storage
    ///
    /// NOTE: Values with `UpdateRule::Anybody` can't be inserted
    pub fn insert(&self, value: proto::dht::Value<'_>) -> Result<bool> {
        if value.ttl <= now() {
            return Err(StorageError::ValueExpired.into());
        }

        if !(0..=self.options.max_key_name_len).contains(&value.key.key.name.len())
            || value.key.key.idx > self.options.max_key_index
        {
            return Err(StorageError::InvalidKey.into());
        }

        if value.key.key.id != &tl_proto::hash(value.key.id) {
            return Err(StorageError::InvalidKey.into());
        }

        match value.key.update_rule {
            proto::dht::UpdateRule::Signature => self.insert_signed_value(value),
            proto::dht::UpdateRule::OverlayNodes => self.insert_overlay_nodes(value),
            _ => Err(StorageError::UnsupportedUpdateRule.into()),
        }
    }

    /// Removes all outdated value
    pub fn gc(&self) {
        let now = now();
        self.storage.retain(|_, value| value.ttl > now);
    }

    /// Inserts signed value into the storage
    fn insert_signed_value(&self, mut value: proto::dht::Value<'_>) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        let full_id = adnl::NodeIdFull::try_from(value.key.id)?;

        let key_signature = std::mem::take(&mut value.key.signature);
        full_id.verify(value.key.as_boxed(), key_signature)?;
        value.key.signature = key_signature;

        let value_signature = std::mem::take(&mut value.signature);
        full_id.verify(value.as_boxed(), value_signature)?;
        value.signature = value_signature;

        let key = tl_proto::hash_as_boxed(value.key.key);
        Ok(match self.storage.entry(key) {
            Entry::Occupied(mut entry) if entry.get().ttl < value.ttl => {
                entry.insert(value.as_equivalent_owned());
                true
            }
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(value.as_equivalent_owned());
                true
            }
        })
    }

    /// Special case of inserting overlay nodes value.
    ///
    /// It requires empty signatures and special update rule
    fn insert_overlay_nodes(&self, value: proto::dht::Value) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        if !value.signature.is_empty() || !value.key.signature.is_empty() {
            return Err(StorageError::InvalidSignatureValue.into());
        }

        let overlay_id = match value.key.id {
            everscale_crypto::tl::PublicKey::Overlay { .. } => {
                overlay::IdShort::from(tl_proto::hash(value.key.id))
            }
            _ => return Err(StorageError::InvalidKeyDescription.into()),
        };

        let required_key = proto::dht::Key {
            id: overlay_id.as_slice(),
            name: KEY_NODES.as_ref(),
            idx: 0,
        };
        if value.key.key != required_key {
            return Err(StorageError::InvalidDhtKey.into());
        }

        let mut new_nodes = deserialize_overlay_nodes(value.value)?;
        new_nodes.retain(|node| {
            if overlay_id.verify_overlay_node(node).is_err() {
                tracing::warn!("Bad overlay node: {node:?}");
                false
            } else {
                true
            }
        });
        if new_nodes.is_empty() {
            return Err(StorageError::EmptyOverlayNodes.into());
        }

        let key = tl_proto::hash_as_boxed(value.key.key);
        match self.storage.entry(key) {
            Entry::Occupied(mut entry) => {
                let value = {
                    let old_nodes = match entry.get().ttl as u32 {
                        old_ttl if old_ttl < now() => None,
                        old_ttl if old_ttl > value.ttl => return Ok(false),
                        _ => Some(deserialize_overlay_nodes(&entry.get().value)?),
                    };
                    make_overlay_nodes_value(value, new_nodes, old_nodes)
                };
                entry.insert(value);
            }
            Entry::Vacant(entry) => {
                entry.insert(make_overlay_nodes_value(value, new_nodes, None));
            }
        }

        Ok(true)
    }
}

// Merges old and new overlay nodes and returns updated value
fn make_overlay_nodes_value<'a, 'b, const N: usize>(
    value: proto::dht::Value<'a>,
    new_nodes: SmallVec<[proto::overlay::Node<'a>; N]>,
    old_nodes: Option<SmallVec<[proto::overlay::Node<'b>; N]>>,
) -> proto::dht::ValueOwned {
    use std::collections::hash_map::Entry;

    let mut result = match old_nodes {
        Some(nodes) => nodes
            .into_iter()
            .map(|item| (HashWrapper(item.id), item))
            .collect::<FxHashMap<_, _>>(),
        None => Default::default(),
    };

    for node in new_nodes {
        match result.entry(HashWrapper(node.id)) {
            Entry::Occupied(mut entry) => {
                if entry.get().version < node.version {
                    entry.insert(node);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(node);
            }
        }
    }

    let capacity = result
        .values()
        .map(|item| item.max_size_hint())
        .sum::<usize>();

    let mut stored_value = Vec::with_capacity(4 + 4 + capacity);
    stored_value.extend_from_slice(&proto::overlay::Nodes::TL_ID.to_le_bytes());
    stored_value.extend_from_slice(&(result.len() as u32).to_le_bytes());
    for node in result.into_values() {
        node.write_to(&mut stored_value);
    }

    proto::dht::ValueOwned {
        key: value.key.as_equivalent_owned(),
        value: stored_value.into(),
        ttl: value.ttl,
        signature: value.signature.to_vec().into(),
    }
}

fn deserialize_overlay_nodes(
    data: &[u8],
) -> tl_proto::TlResult<SmallVec<[proto::overlay::Node; 5]>> {
    match tl_proto::deserialize_as_boxed(data) {
        Ok(proto::overlay::Nodes { nodes }) => Ok(nodes),
        Err(e) => Err(e),
    }
}

pub type StorageKeyId = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum StorageError {
    #[error("Unsupported update rule")]
    UnsupportedUpdateRule,
    #[error("Invalid signature value")]
    InvalidSignatureValue,
    #[error("Invalid key description for OverlayNodes")]
    InvalidKeyDescription,
    #[error("Invalid DHT key")]
    InvalidDhtKey,
    #[error("Empty overlay nodes list")]
    EmptyOverlayNodes,
    #[error("Value expired")]
    ValueExpired,
    #[error("Invalid key")]
    InvalidKey,
}
