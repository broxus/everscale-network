use std::borrow::Borrow;
use std::convert::TryFrom;

use everscale_crypto::{ed25519, tl};
use rand::Rng;

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
    pub fn as_tl(&self) -> tl::PublicKey {
        self.0.as_tl()
    }

    pub fn verify<T: tl_proto::TlWrite<Repr = tl_proto::Boxed>>(
        &self,
        message: T,
        other_signature: &[u8],
    ) -> Result<(), AdnlNodeIdFullError> {
        let other_signature = <[u8; 64]>::try_from(other_signature)
            .map_err(|_| AdnlNodeIdFullError::InvalidSignature)?;

        if self.0.verify(message, &other_signature) {
            Ok(())
        } else {
            Err(AdnlNodeIdFullError::InvalidSignature)
        }
    }

    pub fn compute_short_id(&self) -> AdnlNodeIdShort {
        AdnlNodeIdShort::new(tl_proto::hash(self.0.as_tl()))
    }
}

impl From<ed25519::PublicKey> for AdnlNodeIdFull {
    fn from(key: ed25519::PublicKey) -> Self {
        Self::new(key)
    }
}

impl<'a> TryFrom<tl::PublicKey<'a>> for AdnlNodeIdFull {
    type Error = AdnlNodeIdFullError;

    fn try_from(value: tl::PublicKey<'a>) -> Result<Self, Self::Error> {
        match value {
            tl::PublicKey::Ed25519 { key } => {
                let public_key = ed25519::PublicKey::from_bytes(*key)
                    .ok_or(AdnlNodeIdFullError::InvalidPublicKey)?;
                Ok(Self::new(public_key))
            }
            _ => Err(AdnlNodeIdFullError::UnsupportedPublicKey),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdnlNodeIdFullError {
    #[error("Unsupported public key")]
    UnsupportedPublicKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
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

impl Borrow<[u8; 32]> for AdnlNodeIdShort {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'a> Borrow<[u8; 32]> for &'a AdnlNodeIdShort {
    fn borrow(&self) -> &[u8; 32] {
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
    pub fn sign<T: tl_proto::TlWrite<Repr = tl_proto::Boxed>>(&self, data: T) -> [u8; 64] {
        self.private_key.sign(data, self.full_id.public_key())
    }
}
