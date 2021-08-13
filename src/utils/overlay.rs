use std::convert::TryFrom;

use anyhow::Result;
use ton_api::ton;

use super::{hash, serialize_boxed};
use crate::protocol::*;
use crate::utils::AdnlNodeIdFull;

pub fn verify_node(
    overlay_id: &OverlayIdShort,
    node: &OverlayNodeView<'_, &[u8; 64]>,
) -> Result<()> {
    if node.overlay.0 != overlay_id.0 {
        return Err(OverlayError::OverlayIdMismatch.into());
    }

    let node_id = AdnlNodeIdFull::try_from(&node.id)?;

    let node_to_sign = serialize_boxed(OverlayNodeToSign {
        id: node_id.compute_short_id()?.as_tl(),
        overlay: node.overlay,
        version: node.version,
    })?;

    node_id.verify(&node_to_sign, &node.signature)?;

    Ok(())
}

pub fn compute_overlay_id(
    workchain: i32,
    _shard: i64,
    zero_state_file_hash: &FileHash,
) -> Result<OverlayIdFull> {
    hash(
        ShardPublicOverlayIdView {
            workchain,
            shard: 1i64 << 63, // WHY?!!
            zero_state_file_hash,
        }
        .wrap(),
    )
    .map(OverlayIdFull)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct OverlayIdFull([u8; 32]);

impl OverlayIdFull {
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn compute_short_id(&self) -> Result<OverlayIdShort> {
        hash(PublicKeyView::Overlay { name: &self.0 }).map(OverlayIdShort)
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

impl From<OverlayMessageView<'_>> for OverlayIdShort {
    fn from(message: OverlayMessageView<'_>) -> Self {
        Self(*message.overlay)
    }
}

impl From<ton::rpc::overlay::Query> for OverlayIdShort {
    fn from(query: ton::rpc::overlay::Query) -> Self {
        Self(query.overlay.0)
    }
}

impl From<[u8; 32]> for OverlayIdShort {
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl AsRef<[u8; 32]> for OverlayIdShort {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for OverlayIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&base64::encode(&self.0))
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PrivateOverlayIdShort([u8; 32]);

impl PrivateOverlayIdShort {
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq<[u8]> for PrivateOverlayIdShort {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<[u8; 32]> for PrivateOverlayIdShort {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.eq(other)
    }
}

impl From<PrivateOverlayIdShort> for [u8; 32] {
    fn from(id: PrivateOverlayIdShort) -> Self {
        id.0
    }
}

pub type FileHash = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum OverlayError {
    #[error("Overlay id mismatch")]
    OverlayIdMismatch,
}
