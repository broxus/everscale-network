use std::convert::{TryFrom, TryInto};

use anyhow::Result;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::Verifier;
use rand::Rng;
use sha2::Sha512;
use ton_api::ton;

use super::{hash, serialize_boxed};
use crate::protocol::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AdnlNodeIdFull(ed25519_dalek::PublicKey);

impl AdnlNodeIdFull {
    pub fn new(public_key: ed25519_dalek::PublicKey) -> Self {
        Self(public_key)
    }

    pub fn public_key(&self) -> &ed25519_dalek::PublicKey {
        &self.0
    }

    pub fn as_tl(&self) -> PublicKeyView {
        PublicKeyView::Ed25519 {
            key: self.0.as_bytes(),
        }
    }

    pub fn verify(&self, message: &[u8], other_signature: &[u8]) -> Result<()> {
        let other_signature = ed25519_dalek::Signature::from_bytes(other_signature)?;
        self.0.verify(message, &other_signature)?;
        Ok(())
    }

    pub fn verify_boxed<T, F>(&self, data: &T, extractor: F) -> Result<()>
    where
        T: BoxedConstructor,
        F: FnOnce(&T) -> &[u8],
    {
        let mut data = data.clone();
        let signature = std::mem::take(&mut extractor(&mut data).0);
        let buffer = serialize_boxed(data)?;
        self.verify(&buffer, &signature)
    }

    pub fn compute_short_id(&self) -> Result<AdnlNodeIdShort> {
        Ok(AdnlNodeIdShort(hash(self.as_tl())?))
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

impl<'a> TryFrom<PublicKeyView<'a>> for AdnlNodeIdFull {
    type Error = anyhow::Error;

    fn try_from(value: PublicKeyView<'a>) -> Result<Self, Self::Error> {
        match value {
            PublicKeyView::Ed25519 { key } => {
                let public_key = ed25519_dalek::PublicKey::from_bytes(key).unwrap();
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

    pub fn random() -> Self {
        Self(rand::thread_rng().gen())
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

impl From<AdnlNodeIdShort> for ton::int256 {
    fn from(id: AdnlNodeIdShort) -> Self {
        ton::int256(id.0)
    }
}

impl AsRef<[u8; 32]> for AdnlNodeIdShort {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
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
        let full_id = AdnlNodeIdFull::new(*self);
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
    short_id: AdnlNodeIdShort,
    full_id: AdnlNodeIdFull,
    private_key_part: curve25519_dalek::scalar::Scalar,
    private_key_nonce: [u8; 32],
}

impl StoredAdnlNodeKey {
    pub fn from_id_and_private_key(
        short_id: AdnlNodeIdShort,
        full_id: AdnlNodeIdFull,
        private_key: &ed25519_dalek::SecretKey,
    ) -> Self {
        use sha2::Digest;

        let mut h: Sha512 = Sha512::default();

        h.update(private_key.as_bytes());
        let h = h.finalize();

        let mut private_key_part: [u8; 32] = h.as_slice()[..32].try_into().unwrap();
        private_key_part[0] &= 248;
        private_key_part[31] &= 63;
        private_key_part[31] |= 64;

        let private_key_part = curve25519_dalek::scalar::Scalar::from_bits(private_key_part);
        let private_key_nonce = h.as_slice()[32..].try_into().unwrap();

        Self {
            short_id,
            full_id,
            private_key_part,
            private_key_nonce,
        }
    }

    pub fn id(&self) -> &AdnlNodeIdShort {
        &self.short_id
    }

    pub fn full_id(&self) -> &AdnlNodeIdFull {
        &self.full_id
    }

    pub fn private_key_part(&self) -> &[u8; 32] {
        self.private_key_part.as_bytes()
    }

    pub fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        self.sign_writeable(RawPacketData(data))
    }

    #[allow(non_snake_case)]
    pub fn sign_writeable<T>(&self, data: T) -> Result<[u8; 64]>
    where
        T: WriteToPacket,
    {
        use curve25519_dalek::constants;
        use curve25519_dalek::edwards::*;
        use sha2::Digest;

        let mut h: Sha512 = Sha512::new();
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.update(&self.private_key_nonce);
        data.write_to(&mut h)?;

        r = Scalar::from_hash(h);
        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(self.full_id.public_key());
        data.write_to(&mut h)?;

        k = Scalar::from_hash(h);
        s = &(&k * &self.private_key_part) + &r;

        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes[..32].copy_from_slice(&R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&s.as_bytes()[..]);
        Ok(signature_bytes)
    }
}
