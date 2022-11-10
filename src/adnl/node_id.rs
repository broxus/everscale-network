use std::borrow::Borrow;
use std::convert::TryFrom;

use everscale_crypto::{ed25519, tl};
use rand::Rng;

/// Full ADNL node id.
///
/// See [`everscale_crypto::tl::PublicKey::Ed25519`]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NodeIdFull(ed25519::PublicKey);

impl NodeIdFull {
    /// Constructs full node id from a valid ED25519 public key
    pub const fn new(public_key: ed25519::PublicKey) -> Self {
        Self(public_key)
    }

    /// Returns inner public key
    #[inline(always)]
    pub const fn public_key(&self) -> &ed25519::PublicKey {
        &self.0
    }

    /// Represents public key as a TL structure
    #[inline(always)]
    pub fn as_tl(&self) -> tl::PublicKey {
        self.0.as_tl()
    }

    /// Verifies the signature of an arbitrary serializable data
    pub fn verify<T: tl_proto::TlWrite<Repr = tl_proto::Boxed>>(
        &self,
        data: T,
        other_signature: &[u8],
    ) -> Result<(), NodeIdFullError> {
        match <[u8; 64]>::try_from(other_signature) {
            Ok(other_signature) if self.0.verify(data, &other_signature) => Ok(()),
            _ => Err(NodeIdFullError::InvalidSignature),
        }
    }

    /// Hashes inner public key
    pub fn compute_short_id(&self) -> NodeIdShort {
        NodeIdShort::new(tl_proto::hash(self.0.as_tl()))
    }
}

impl From<ed25519::PublicKey> for NodeIdFull {
    fn from(key: ed25519::PublicKey) -> Self {
        Self::new(key)
    }
}

impl<'a> TryFrom<tl::PublicKey<'a>> for NodeIdFull {
    type Error = NodeIdFullError;

    fn try_from(value: tl::PublicKey<'a>) -> Result<Self, Self::Error> {
        match value {
            tl::PublicKey::Ed25519 { key } => match ed25519::PublicKey::from_bytes(*key) {
                Some(public_key) => Ok(Self::new(public_key)),
                None => Err(NodeIdFullError::InvalidPublicKey),
            },
            _ => Err(NodeIdFullError::UnsupportedPublicKey),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NodeIdFullError {
    #[error("Unsupported public key")]
    UnsupportedPublicKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Short ADNL node id.
#[derive(Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct NodeIdShort([u8; 32]);

impl NodeIdShort {
    /// Constructs short node id from public key hash
    #[inline(always)]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Generates random short node id
    pub fn random() -> Self {
        Self(rand::thread_rng().gen())
    }

    /// Returns inner bytes
    #[inline(always)]
    pub const fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self == &[0; 32]
    }
}

impl std::fmt::Display for NodeIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(self.0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

impl std::fmt::Debug for NodeIdShort {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl PartialEq<[u8]> for NodeIdShort {
    #[inline(always)]
    fn eq(&self, other: &[u8]) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<[u8; 32]> for NodeIdShort {
    #[inline(always)]
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.eq(other)
    }
}

impl From<NodeIdShort> for [u8; 32] {
    #[inline(always)]
    fn from(id: NodeIdShort) -> Self {
        id.0
    }
}

impl From<&NodeIdShort> for [u8; 32] {
    #[inline(always)]
    fn from(id: &NodeIdShort) -> Self {
        id.0
    }
}

impl From<[u8; 32]> for NodeIdShort {
    #[inline(always)]
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl Borrow<[u8; 32]> for NodeIdShort {
    #[inline(always)]
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'a> Borrow<[u8; 32]> for &'a NodeIdShort {
    #[inline(always)]
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Abstract trait to compute all node ids
pub trait ComputeNodeIds {
    fn compute_node_ids(&self) -> (NodeIdFull, NodeIdShort);
}

impl ComputeNodeIds for ed25519::SecretKey {
    fn compute_node_ids(&self) -> (NodeIdFull, NodeIdShort) {
        let public_key = ed25519::PublicKey::from(self);
        let full_id = NodeIdFull::new(public_key);
        let short_id = full_id.compute_short_id();
        (full_id, short_id)
    }
}

impl ComputeNodeIds for ed25519::PublicKey {
    fn compute_node_ids(&self) -> (NodeIdFull, NodeIdShort) {
        let full_id = NodeIdFull::new(*self);
        let short_id = full_id.compute_short_id();
        (full_id, short_id)
    }
}
