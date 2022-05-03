use std::collections::hash_map;
use std::sync::Arc;

use anyhow::Result;

use crate::utils::*;

pub struct AdnlKeystore {
    keys: FxHashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>>,
    tags: FxHashMap<usize, AdnlNodeIdShort>,
}

impl AdnlKeystore {
    pub fn from_tagged_keys<I>(keys: I) -> Result<Self>
    where
        I: IntoIterator<Item = (ed25519_dalek::SecretKey, usize)>,
    {
        let mut result = AdnlKeystore {
            keys: Default::default(),
            tags: Default::default(),
        };

        for (key, tag) in keys {
            result.add_key(key, tag)?;
        }

        Ok(result)
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
            self.key_by_id(id)
        } else {
            Err(AdnlNodeConfigError::KeyTagNotFound(tag).into())
        }
    }

    pub fn keys(&self) -> &FxHashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>> {
        &self.keys
    }

    pub fn add_key(
        &mut self,
        key: ed25519_dalek::SecretKey,
        tag: usize,
    ) -> Result<AdnlNodeIdShort> {
        let (full_id, short_id) = key.compute_node_ids();

        match self.tags.entry(tag) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(short_id);
                match self.keys.entry(short_id) {
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(Arc::new(StoredAdnlNodeKey::from_id_and_private_key(
                            short_id, full_id, &key,
                        )));
                        Ok(short_id)
                    }
                    hash_map::Entry::Occupied(_) => {
                        Err(AdnlNodeConfigError::DuplicatedKey(short_id).into())
                    }
                }
            }
            hash_map::Entry::Occupied(entry) => {
                if entry.get() == &short_id {
                    Ok(short_id)
                } else {
                    Err(AdnlNodeConfigError::DuplicatedKeyTag(tag).into())
                }
            }
        }
    }

    pub fn delete_key(&mut self, key: &AdnlNodeIdShort, tag: usize) -> Result<bool> {
        let removed_key = self.keys.remove(key);
        if let Some(ref removed) = self.tags.remove(&tag) {
            if removed != key {
                return Err(AdnlNodeConfigError::UnexpectedKey.into());
            }
        }
        Ok(removed_key.is_some())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() -> Result<()> {
        let mut first_peer_config = AdnlKeystore::from_tagged_keys(Vec::new())?;

        let first_peer_key = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng());
        let first_peer_id = first_peer_config.add_key(first_peer_key, 1)?;
        let first_peer = first_peer_config.key_by_tag(1).unwrap();

        let text = "Hello world";

        for version in [None, Some(0)] {
            let mut packet = text.as_bytes().to_vec();
            println!("Packet decoded: {}", hex::encode(&packet));

            build_handshake_packet(&first_peer_id, first_peer.full_id(), &mut packet, version)?;
            println!("Packet encoded: {}", hex::encode(&packet));

            println!("Packet decoded: {}", hex::encode(packet.as_slice()));

            let mut buffer = packet.as_mut_slice().into();
            let (_, parsed_version) =
                parse_handshake_packet(first_peer_config.keys(), &mut buffer)?.unwrap();
            assert_eq!(parsed_version, version);

            println!("Packet decoded: {}", hex::encode(buffer.as_slice()));

            assert_eq!(buffer.as_slice(), text.as_bytes());
        }

        Ok(())
    }
}
