use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use either::Either;
use smallvec::SmallVec;

use super::DHT_KEY_NODES;
use crate::proto::*;
use crate::utils::*;

#[derive(Default)]
pub struct Storage {
    storage: FxDashMap<StorageKey, Arc<OwnedDhtValue>>,
}

impl Storage {
    pub fn get(&self, key: &StorageKey) -> Option<Arc<OwnedDhtValue>> {
        match self.storage.get(key) {
            Some(item) if item.ttl > now() => Some(item.value().clone()),
            _ => None,
        }
    }

    pub fn insert_signed_value<V, S>(
        &self,
        key: StorageKey,
        value: &DhtValueView<'_, V, S>,
    ) -> Result<bool>
    where
        V: WriteToPacket,
        S: DataSignature + WriteToPacket + AsOwned<Owned = OwnedSignature>,
    {
        use dashmap::mapref::entry::Entry;

        let full_id = AdnlNodeIdFull::try_from(value.key.id)?;
        full_id.verify(value.key.wrap(), &value.key.signature)?;
        full_id.verify(value.wrap(), &value.signature)?;

        Ok(match self.storage.entry(key) {
            Entry::Occupied(entry) if entry.get().ttl < value.ttl => {
                entry.replace_entry(Arc::new(value.as_owned()?));
                true
            }
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(value.as_owned()?));
                true
            }
        })
    }

    pub fn insert_overlay_nodes(&self, key: StorageKey, value: &OwnedDhtValue) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        if !value.signature.is_empty() || !value.key.signature.is_empty() {
            return Err(StorageError::InvalidSignatureValue.into());
        }

        let overlay_id = match &value.key.id {
            OwnedPublicKey::Overlay { .. } => OverlayIdShort::from(hash(value.key.id.as_view())?),
            _ => return Err(StorageError::InvalidKeyDescription.into()),
        };

        if make_dht_key(&overlay_id, DHT_KEY_NODES) != value.key.key.as_view() {
            return Err(StorageError::InvalidDhtKey.into());
        }

        let mut new_nodes = deserialize_overlay_nodes(value.value.as_slice())?
            .into_iter()
            .filter(|node: &OverlayNodeView<SignatureRef>| {
                if verify_node(&overlay_id, node).is_err() {
                    log::warn!("Bad overlay node: {:?}", node);
                    false
                } else {
                    true
                }
            })
            .peekable();
        if new_nodes.peek().is_none() {
            return Err(StorageError::EmptyOverlayNodes.into());
        }

        match self.storage.entry(key) {
            Entry::Occupied(entry) => {
                let old_nodes = match entry.get().ttl {
                    old_ttl if old_ttl < now() => Either::Left(std::iter::empty()),
                    old_ttl if old_ttl > value.ttl => return Ok(false),
                    _ => Either::Right(
                        deserialize_overlay_nodes(entry.get().value.as_slice())?.into_iter(),
                    ),
                };

                let mut item = value.clone();
                item.value = IntermediateBytes(OwnedRawBytes(make_overlay_nodes_value(
                    new_nodes, old_nodes,
                )?));

                entry.replace_entry(Arc::new(item));
            }
            Entry::Vacant(entry) => {
                let mut item = value.clone();
                item.value = IntermediateBytes(OwnedRawBytes(make_overlay_nodes_value(
                    new_nodes,
                    std::iter::empty(),
                )?));

                entry.insert(Arc::new(item));
            }
        }

        Ok(true)
    }
}

fn make_overlay_nodes_value<'a, I1, I2>(mut new_nodes: I1, old_nodes: I2) -> Result<Vec<u8>>
where
    I1: Iterator<Item = OverlayNodeView<'a, SignatureRef<'a>>>,
    I2: Iterator<Item = OverlayNodeView<'a, SignatureRef<'a>>>,
{
    use std::collections::hash_map::Entry;

    let mut result = old_nodes
        .map(|item| (item.id, item))
        .collect::<FxHashMap<_, _>>();

    new_nodes.for_each(|node| match result.entry(node.id) {
        Entry::Occupied(mut entry) => {
            if entry.get().version < node.version {
                entry.insert(node);
            }
        }
        Entry::Vacant(entry) => {
            entry.insert(node);
        }
    });

    let nodes = result
        .into_iter()
        .map(|(_, node)| node)
        .collect::<SmallVec<_>>();

    let nodes = serialize_view(OverlayNodesView { nodes }.wrap())?;
    Ok(nodes)
}

fn deserialize_overlay_nodes(
    data: &[u8],
) -> PacketContentsResult<SmallVec<[OverlayNodeView<SignatureRef>; 16]>> {
    deserialize_view::<BoxedWrapper<OverlayNodesView<SignatureRef>>>(data).map(|data| data.0.nodes)
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
