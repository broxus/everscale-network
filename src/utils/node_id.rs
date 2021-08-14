use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};

use anyhow::Result;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use sha2::Sha512;
use ton_api::ton;

use super::hash;
use crate::proto::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AdnlNodeIdFull(PublicKeyHelper);

impl AdnlNodeIdFull {
    pub fn public_key(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_tl(&self) -> PublicKeyView {
        PublicKeyView::Ed25519 {
            key: self.0.as_bytes(),
        }
    }

    #[allow(non_snake_case)]
    pub fn verify<T, V, S>(&self, message: T, signature: S) -> Result<()>
    where
        T: Borrow<V>,
        V: UpdateSignatureHasher,
        S: AsRef<[u8]>,
    {
        use sha2::Digest;

        let signature = SignatureHelper::from_bytes(signature.as_ref())?;

        let mut h: Sha512 = Sha512::new();
        let minus_A: EdwardsPoint = -self.0.point;

        h.update(signature.R.as_bytes());
        h.update(self.0.compressed.as_bytes());
        message.borrow().update_hasher(&mut h)?;

        let k = Scalar::from_hash(h);
        let R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &minus_A, &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err(AdnlNodeIdError::InvalidSignature.into())
        }
    }

    pub fn compute_short_id(&self) -> Result<AdnlNodeIdShort> {
        Ok(AdnlNodeIdShort(hash(self.as_tl())?))
    }
}

impl std::fmt::Display for AdnlNodeIdFull {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0.as_bytes()))
    }
}

impl<'a> TryFrom<PublicKeyView<'a>> for AdnlNodeIdFull {
    type Error = anyhow::Error;

    fn try_from(value: PublicKeyView<'a>) -> Result<Self, Self::Error> {
        match value {
            PublicKeyView::Ed25519 { key } => Ok(Self(PublicKeyHelper::try_from(*key)?)),
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
        let public_key = PublicKeyHelper::from_secret_key(self);
        let full_id = AdnlNodeIdFull(public_key);
        let short_id = full_id.compute_short_id()?;
        Ok((full_id, short_id))
    }
}

impl ComputeNodeIds for ed25519_dalek::PublicKey {
    fn compute_node_ids(&self) -> Result<(AdnlNodeIdFull, AdnlNodeIdShort)> {
        let full_id = AdnlNodeIdFull(PublicKeyHelper::try_from(self.to_bytes())?);
        let short_id = full_id.compute_short_id()?;
        Ok((full_id, short_id))
    }
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

    #[allow(non_snake_case)]
    pub fn sign<T>(&self, data: T) -> Result<[u8; 64]>
    where
        T: UpdateSignatureHasher,
    {
        use curve25519_dalek::constants;
        use sha2::Digest;

        let mut h: Sha512 = Sha512::new();
        h.update(&self.private_key_nonce);
        data.update_hasher(&mut h)?;

        let r = Scalar::from_hash(h);
        let R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(self.full_id.public_key());
        data.update_hasher(&mut h)?;

        let k = Scalar::from_hash(h);
        let s = &(&k * &self.private_key_part) + &r;

        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes[..32].copy_from_slice(&R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&s.as_bytes()[..]);
        Ok(signature_bytes)
    }
}

#[allow(non_snake_case)]
struct SignatureHelper {
    R: CompressedEdwardsY,
    s: Scalar,
}

impl SignatureHelper {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdnlNodeIdError> {
        if bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(AdnlNodeIdError::InvalidSignature);
        }

        let lower: [u8; 32] = bytes[..32].try_into().unwrap();
        let upper: [u8; 32] = bytes[32..].try_into().unwrap();

        let s = check_scalar(upper)?;

        Ok(Self {
            R: CompressedEdwardsY(lower),
            s,
        })
    }
}

fn check_scalar(bytes: [u8; 32]) -> Result<Scalar, AdnlNodeIdError> {
    if bytes[31] & 240 == 0 {
        return Ok(Scalar::from_bits(bytes));
    }
    Scalar::from_canonical_bytes(bytes).ok_or(AdnlNodeIdError::InvalidSignature)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct PublicKeyHelper {
    compressed: CompressedEdwardsY,
    point: EdwardsPoint,
}

impl PublicKeyHelper {
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self, AdnlNodeIdError> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(AdnlNodeIdError::InvalidPublicKey);
        }

        let bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        bytes.try_into()
    }

    fn from_secret_key(secret_key: &ed25519_dalek::SecretKey) -> Self {
        use sha2::Digest;

        let mut h: Sha512 = Sha512::new();
        h.update(secret_key.as_bytes());
        let hash = h.finalize();

        let mut digest: [u8; 32] = hash.as_slice()[..32].try_into().unwrap();
        Self::from_bits(&mut digest)
    }

    fn from_bits(bits: &mut [u8; 32]) -> Self {
        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let point =
            &Scalar::from_bits(*bits) * &curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();

        PublicKeyHelper { compressed, point }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        self.compressed.as_bytes()
    }
}

impl TryFrom<[u8; 32]> for PublicKeyHelper {
    type Error = AdnlNodeIdError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let compressed = CompressedEdwardsY(bytes);
        let point = compressed
            .decompress()
            .ok_or(AdnlNodeIdError::InvalidPublicKey)?;

        Ok(Self { compressed, point })
    }
}

#[derive(thiserror::Error, Debug)]
enum AdnlNodeIdError {
    #[error("Unsupported public key")]
    UnsupportedPublicKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
}
