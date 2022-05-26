use std::convert::TryFrom;

use anyhow::Result;
use ton_api::ton;

use super::DHT_KEY_NODES;
use crate::utils::*;

#[derive(Default)]
pub struct Storage {
    storage: FxDashMap<StorageKey, ton::dht::value::Value>,
}

impl Storage {
    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn total_size(&self) -> usize {
        self.storage.iter().map(|item| item.value.0.len()).sum()
    }

    pub fn get(&self, key: &StorageKey) -> Option<ton::dht::value::Value> {
        match self.storage.get(key) {
            Some(item) if item.ttl as u32 > now() => Some(item.value().clone()),
            _ => None,
        }
    }

    pub fn insert_signed_value(
        &self,
        key: StorageKey,
        value: ton::dht::value::Value,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        let full_id = AdnlNodeIdFull::try_from(&value.key.id)?;
        full_id.verify_boxed(&value.key, |k| &mut k.signature)?;
        full_id.verify_boxed(&value, |v| &mut v.signature)?;

        Ok(match self.storage.entry(key) {
            Entry::Occupied(mut entry) if entry.get().ttl < value.ttl => {
                entry.insert(value);
                true
            }
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(value);
                true
            }
        })
    }

    pub fn insert_overlay_nodes(
        &self,
        key: StorageKey,
        value: ton::dht::value::Value,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        if !value.signature.is_empty() || !value.key.signature.is_empty() {
            return Err(StorageError::InvalidSignatureValue.into());
        }

        let overlay_id = match value.key.id {
            ton::PublicKey::Pub_Overlay(_) => OverlayIdShort::from(hash_boxed(&value.key.id)),
            _ => return Err(StorageError::InvalidKeyDescription.into()),
        };

        if make_dht_key(&overlay_id, DHT_KEY_NODES) != value.key.key {
            return Err(StorageError::InvalidDhtKey.into());
        }

        let new_nodes = deserialize_overlay_nodes(&value.value)?
            .into_iter()
            .filter(|node| {
                if verify_node(&overlay_id, node).is_err() {
                    tracing::warn!("Bad overlay node: {node:?}");
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();
        if new_nodes.is_empty() {
            return Err(StorageError::EmptyOverlayNodes.into());
        }

        match self.storage.entry(key) {
            Entry::Occupied(mut entry) => {
                let old_nodes = match entry.get().ttl as u32 {
                    old_ttl if old_ttl < now() => None,
                    old_ttl if old_ttl > value.ttl as u32 => return Ok(false),
                    _ => {
                        let nodes = deserialize_overlay_nodes(&entry.get().value)?;
                        Some(nodes)
                    }
                };

                entry.insert(make_overlay_nodes_value(value, new_nodes, old_nodes));
            }
            Entry::Vacant(entry) => {
                entry.insert(make_overlay_nodes_value(value, new_nodes, None));
            }
        }

        Ok(true)
    }
}

fn make_overlay_nodes_value(
    mut value: ton::dht::value::Value,
    new_nodes: Vec<ton::overlay::node::Node>,
    old_nodes: Option<Vec<ton::overlay::node::Node>>,
) -> ton::dht::value::Value {
    use std::collections::hash_map::Entry;

    let mut result = match old_nodes {
        Some(nodes) => nodes
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect::<FxHashMap<_, _>>(),
        None => Default::default(),
    };

    for node in new_nodes {
        match result.entry(node.id.clone()) {
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

    value.value = ton::bytes(serialize_boxed(ton::overlay::nodes::Nodes {
        nodes: result
            .into_iter()
            .map(|(_, node)| node)
            .collect::<Vec<_>>()
            .into(),
    }));

    value
}

fn deserialize_overlay_nodes(data: &[u8]) -> Result<Vec<ton::overlay::node::Node>> {
    let nodes = deserialize(data)?
        .downcast::<ton::overlay::Nodes>()
        .map_err(|_| StorageError::InvalidOverlayNodes)?;
    Ok(nodes.only().nodes.0)
}

pub type StorageKey = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum StorageError {
    #[error("Invalid signature value")]
    InvalidSignatureValue,
    #[error("Invalid key description for OverlayNodes")]
    InvalidKeyDescription,
    #[error("Invalid DHT key")]
    InvalidDhtKey,
    #[error("Invalid overlay nodes")]
    InvalidOverlayNodes,
    #[error("Empty overlay nodes list")]
    EmptyOverlayNodes,
}
