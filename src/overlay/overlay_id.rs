use std::borrow::Borrow;
use std::convert::TryFrom;

use anyhow::Result;

use crate::adnl;
use crate::proto;

/// Full overlay id.
///
/// See [`everscale_crypto::tl::PublicKey::Overlay`]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IdFull([u8; 32]);

impl IdFull {
    pub fn for_shard_overlay(workchain: i32, zero_state_file_hash: &[u8; 32]) -> Self {
        Self(tl_proto::hash(proto::overlay::ShardPublicOverlayId {
            workchain,
            shard: 1u64 << 63,
            zero_state_file_hash,
        }))
    }

    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn compute_short_id(&self) -> IdShort {
        let key = everscale_crypto::tl::PublicKey::Overlay { name: &self.0 };
        IdShort(tl_proto::hash(key))
    }
}

/// Short overlay id.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IdShort([u8; 32]);

impl IdShort {
    pub fn verify_overlay_node(&self, node: &proto::overlay::Node) -> Result<()> {
        if node.overlay != &self.0 {
            return Err(OverlayIdError::OverlayIdMismatch.into());
        }

        let full_id = adnl::NodeIdFull::try_from(node.id)?;
        let peer_id = full_id.compute_short_id();

        let node_to_sign = proto::overlay::NodeToSign {
            id: peer_id.as_slice(),
            overlay: node.overlay,
            version: node.version,
        };

        full_id.verify(&node_to_sign, node.signature)?;

        Ok(())
    }

    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq<[u8]> for IdShort {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<[u8; 32]> for IdShort {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.eq(other)
    }
}

impl From<IdShort> for [u8; 32] {
    fn from(id: IdShort) -> Self {
        id.0
    }
}

impl From<&IdShort> for [u8; 32] {
    fn from(id: &IdShort) -> Self {
        id.0
    }
}

impl From<[u8; 32]> for IdShort {
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl Borrow<[u8; 32]> for IdShort {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'a> Borrow<[u8; 32]> for &'a IdShort {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for IdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

#[derive(thiserror::Error, Debug)]
enum OverlayIdError {
    #[error("Overlay id mismatch")]
    OverlayIdMismatch,
}
