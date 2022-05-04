use std::convert::TryFrom;

use anyhow::Result;
use everscale_crypto::ed25519;
use rand::Rng;
use ton_api::{ton, IntoBoxed};

use super::tl_view::PublicKeyView;
use super::{hash, serialize, serialize_boxed};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AdnlNodeIdFull(ed25519::PublicKey);

impl AdnlNodeIdFull {
    pub const fn new(public_key: ed25519::PublicKey) -> Self {
        Self(public_key)
    }

    #[inline(always)]
    pub const fn public_key(&self) -> &ed25519::PublicKey {
        &self.0
    }

    #[inline(always)]
    pub fn as_tl(&self) -> ton::pub_::publickey::Ed25519 {
        ton::pub_::publickey::Ed25519 {
            key: ton::int256(self.0.to_bytes()),
        }
    }

    pub fn verify(
        &self,
        message: &[u8],
        other_signature: &[u8],
    ) -> Result<(), AdnlNodeIdFullError> {
        let other_signature = <[u8; 64]>::try_from(other_signature)
            .map_err(|_| AdnlNodeIdFullError::InvalidSignature)?;

        if self.0.verify_raw(message, &other_signature) {
            Ok(())
        } else {
            Err(AdnlNodeIdFullError::InvalidSignature)
        }
    }

    pub fn verify_boxed<T, F>(&self, data: &T, extractor: F) -> Result<(), AdnlNodeIdFullError>
    where
        T: IntoBoxed + Clone,
        F: FnOnce(&mut T) -> &mut ton::bytes,
    {
        let mut data = data.clone();
        let signature = std::mem::take(&mut extractor(&mut data).0);
        let buffer = serialize_boxed(data);
        self.verify(&buffer, &signature)
    }

    pub fn compute_short_id(&self) -> AdnlNodeIdShort {
        AdnlNodeIdShort::new(hash(self.as_tl()))
    }
}

impl From<ed25519::PublicKey> for AdnlNodeIdFull {
    fn from(key: ed25519::PublicKey) -> Self {
        Self::new(key)
    }
}

impl TryFrom<&ton::PublicKey> for AdnlNodeIdFull {
    type Error = anyhow::Error;

    fn try_from(public_key: &ton::PublicKey) -> Result<Self> {
        match public_key {
            ton::PublicKey::Pub_Ed25519(public_key) => {
                let public_key = ed25519::PublicKey::from_bytes(public_key.key.0)
                    .ok_or(AdnlNodeIdError::InvalidPublicKey)?;
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
                let public_key = ed25519::PublicKey::from_bytes(*key)
                    .ok_or(AdnlNodeIdError::InvalidPublicKey)?;
                Ok(Self::new(public_key))
            }
            _ => Err(AdnlNodeIdError::UnsupportedPublicKey.into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdnlNodeIdFullError {
    #[error("Invalid signature")]
    InvalidSignature,
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct AdnlNodeIdShort([u8; 32]);

impl AdnlNodeIdShort {
    pub const fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub fn random() -> Self {
        Self(rand::thread_rng().gen())
    }

    pub const fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self == &[0; 32]
    }

    pub const fn as_tl(&self) -> ton::adnl::id::short::Short {
        ton::adnl::id::short::Short {
            id: ton::int256(self.0),
        }
    }
}

impl std::fmt::Display for AdnlNodeIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(&self.0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

impl std::fmt::Debug for AdnlNodeIdShort {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
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
    fn compute_node_ids(&self) -> (AdnlNodeIdFull, AdnlNodeIdShort);
}

impl ComputeNodeIds for ed25519::SecretKey {
    fn compute_node_ids(&self) -> (AdnlNodeIdFull, AdnlNodeIdShort) {
        let public_key = ed25519::PublicKey::from(self);
        let full_id = AdnlNodeIdFull::new(public_key);
        let short_id = full_id.compute_short_id();
        (full_id, short_id)
    }
}

impl ComputeNodeIds for ed25519::PublicKey {
    fn compute_node_ids(&self) -> (AdnlNodeIdFull, AdnlNodeIdShort) {
        let full_id = AdnlNodeIdFull::new(*self);
        let short_id = full_id.compute_short_id();
        (full_id, short_id)
    }
}

#[derive(thiserror::Error, Debug)]
enum AdnlNodeIdError {
    #[error("Unsupported public key")]
    UnsupportedPublicKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

pub struct StoredAdnlNodeKey {
    short_id: AdnlNodeIdShort,
    full_id: AdnlNodeIdFull,
    private_key: ed25519::ExpandedSecretKey,
}

impl StoredAdnlNodeKey {
    pub fn from_id_and_private_key(
        short_id: AdnlNodeIdShort,
        full_id: AdnlNodeIdFull,
        private_key: &ed25519::SecretKey,
    ) -> Self {
        let private_key = ed25519::ExpandedSecretKey::from(private_key);

        Self {
            short_id,
            full_id,
            private_key,
        }
    }

    #[inline(always)]
    pub fn id(&self) -> &AdnlNodeIdShort {
        &self.short_id
    }

    #[inline(always)]
    pub fn full_id(&self) -> &AdnlNodeIdFull {
        &self.full_id
    }

    #[inline(always)]
    pub fn private_key(&self) -> &ed25519::ExpandedSecretKey {
        &self.private_key
    }

    #[inline(always)]
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.private_key.sign_raw(data, self.full_id.public_key())
    }

    pub fn sign_boxed<T, F, R>(&self, data: T, inserter: F) -> R
    where
        T: IntoBoxed,
        F: FnOnce(T::Boxed, ton::bytes) -> R,
    {
        let data = data.into_boxed();
        let mut buffer = serialize(&data);
        let signature = self.sign(&buffer);
        buffer.truncate(0);
        buffer.extend_from_slice(signature.as_ref());
        inserter(data, ton::bytes(buffer))
    }
}
