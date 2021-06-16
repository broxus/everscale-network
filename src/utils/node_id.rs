use std::convert::{TryFrom, TryInto};

use anyhow::Result;
use ton_api::ton;

use super::hash;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AdnlNodeIdFull(ed25519_dalek::PublicKey);

impl AdnlNodeIdFull {
    pub fn new(public_key: ed25519_dalek::PublicKey) -> Self {
        Self(public_key)
    }

    pub fn public_key(&self) -> &ed25519_dalek::PublicKey {
        &self.0
    }

    pub fn as_tl(&self) -> ton::pub_::publickey::Ed25519 {
        ton::pub_::publickey::Ed25519 {
            key: ton::int256(self.0.to_bytes()),
        }
    }

    pub fn compute_short_id(&self) -> Result<AdnlNodeIdShort> {
        let hash = hash(self.as_tl())?;
        Ok(AdnlNodeIdShort::new(hash))
    }
}

impl std::fmt::Display for AdnlNodeIdFull {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl From<ed25519_dalek::PublicKey> for AdnlNodeIdFull {
    fn from(key: ed25519_dalek::PublicKey) -> Self {
        Self::new(key)
    }
}

impl TryFrom<&ton::PublicKey> for AdnlNodeIdFull {
    type Error = anyhow::Error;

    fn try_from(public_key: &ton::PublicKey) -> Result<Self> {
        match public_key {
            ton::PublicKey::Pub_Ed25519(public_key) => {
                let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key.key.0).unwrap();
                Ok(Self::new(public_key))
            }
            _ => Err(AdnlNodeIdError::UnsupportedPublicKey.into()),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct AdnlNodeIdShort([u8; 32]);

impl AdnlNodeIdShort {
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        for b in &self.0 {
            if b != &0 {
                return false;
            }
        }
        true
    }

    pub fn as_tl(&self) -> ton::adnl::id::short::Short {
        ton::adnl::id::short::Short {
            id: ton::int256(self.0),
        }
    }
}

impl std::fmt::Display for AdnlNodeIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl PartialEq<[u8]> for AdnlNodeIdShort {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<[u8; 32]> for AdnlNodeIdShort {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.eq(other)
    }
}

impl From<AdnlNodeIdShort> for [u8; 32] {
    fn from(id: AdnlNodeIdShort) -> Self {
        id.0
    }
}

pub trait ComputeNodeIds {
    fn compute_node_ids(&self) -> Result<(AdnlNodeIdFull, AdnlNodeIdShort)>;
}

impl ComputeNodeIds for ed25519_dalek::SecretKey {
    fn compute_node_ids(&self) -> Result<(AdnlNodeIdFull, AdnlNodeIdShort)> {
        let public_key = ed25519_dalek::PublicKey::from(self);
        let full_id = AdnlNodeIdFull::new(public_key);
        let short_id = full_id.compute_short_id()?;
        Ok((full_id, short_id))
    }
}

impl ComputeNodeIds for ed25519_dalek::PublicKey {
    fn compute_node_ids(&self) -> Result<(AdnlNodeIdFull, AdnlNodeIdShort)> {
        let full_id = AdnlNodeIdFull::new(self.clone());
        let short_id = full_id.compute_short_id()?;
        Ok((full_id, short_id))
    }
}

#[derive(thiserror::Error, Debug)]
enum AdnlNodeIdError {
    #[error("Unsupported public key")]
    UnsupportedPublicKey,
}

pub struct StoredAdnlNodeKey {
    full_id: AdnlNodeIdFull,
    private_key: ed25519_dalek::ExpandedSecretKey,
    private_key_part: [u8; 32],
}

impl StoredAdnlNodeKey {
    pub fn from_id_and_private_key(
        full_id: AdnlNodeIdFull,
        private_key: &ed25519_dalek::SecretKey,
    ) -> Self {
        let private_key = ed25519_dalek::ExpandedSecretKey::from(private_key);
        let private_key_part = private_key.to_bytes()[0..32].try_into().unwrap();

        Self {
            full_id,
            private_key,
            private_key_part,
        }
    }

    pub fn id(&self) -> &AdnlNodeIdFull {
        &self.full_id
    }

    pub fn private_key(&self) -> &ed25519_dalek::ExpandedSecretKey {
        &self.private_key
    }

    pub fn private_key_part(&self) -> &[u8; 32] {
        &self.private_key_part
    }
}
