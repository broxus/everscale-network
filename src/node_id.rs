use ton_api::ton;
use ton_types::UInt256;

use crate::utils::*;

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

    pub fn compute_short_id(&self) -> AdnlNodeIdShort {
        let hash = hash(self.as_tl()).unwrap();
        AdnlNodeIdShort::new(hash.into())
    }
}

impl std::fmt::Display for AdnlNodeIdFull {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0.as_bytes()))
    }
}

impl From<ed25519_dalek::PublicKey> for AdnlNodeIdFull {
    fn from(key: ed25519_dalek::PublicKey) -> Self {
        Self(key)
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct AdnlNodeIdShort(UInt256);

impl AdnlNodeIdShort {
    pub fn new(hash: UInt256) -> Self {
        Self(hash)
    }

    pub fn as_slice(&self) -> &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.0.as_slice()
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn as_tl(&self) -> ton::adnl::id::short::Short {
        ton::adnl::id::short::Short {
            id: ton::int256(*self.0.as_slice()),
        }
    }
}

impl std::fmt::Display for AdnlNodeIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0.to_hex_string())
    }
}
