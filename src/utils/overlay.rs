use std::borrow::Borrow;
use std::convert::TryFrom;

use anyhow::Result;

use crate::proto;
use crate::utils::AdnlNodeIdFull;

pub fn verify_node(overlay_id: &OverlayIdShort, node: &proto::overlay::Node) -> Result<()> {
    if node.overlay != &overlay_id.0 {
        return Err(OverlayError::OverlayIdMismatch.into());
    }

    let full_id = AdnlNodeIdFull::try_from(node.id)?;
    let peer_id = full_id.compute_short_id();

    let node_to_sign = proto::overlay::NodeToSign {
        id: peer_id.as_slice(),
        overlay: node.overlay,
        version: node.version,
    };

    full_id.verify(&node_to_sign, node.signature)?;

    Ok(())
}

pub fn compute_overlay_id(workchain: i32, zero_state_file_hash: FileHash) -> OverlayIdFull {
    OverlayIdFull(tl_proto::hash(proto::overlay::ShardPublicOverlayId {
        workchain,
        shard: 1u64 << 63,
        zero_state_file_hash: &zero_state_file_hash,
    }))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct OverlayIdFull([u8; 32]);

impl OverlayIdFull {
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn compute_short_id(&self) -> OverlayIdShort {
        let key = everscale_crypto::tl::PublicKey::Overlay { name: &self.0 };
        OverlayIdShort(tl_proto::hash(key))
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct OverlayIdShort([u8; 32]);

impl OverlayIdShort {
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq<[u8]> for OverlayIdShort {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<[u8; 32]> for OverlayIdShort {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.eq(other)
    }
}

impl From<OverlayIdShort> for [u8; 32] {
    fn from(id: OverlayIdShort) -> Self {
        id.0
    }
}

impl From<&OverlayIdShort> for [u8; 32] {
    fn from(id: &OverlayIdShort) -> Self {
        id.0
    }
}

impl From<[u8; 32]> for OverlayIdShort {
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl Borrow<[u8; 32]> for OverlayIdShort {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'a> Borrow<[u8; 32]> for &'a OverlayIdShort {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for OverlayIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&base64::encode(&self.0))
    }
}

pub type FileHash = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum OverlayError {
    #[error("Overlay id mismatch")]
    OverlayIdMismatch,
}
