use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::Verifier;
use ton_api::ton;

use super::{hash, serialize, serialize_boxed};
use crate::utils::AdnlNodeIdFull;

pub fn verify_node(overlay_id: &OverlayIdShort, node: &ton::overlay::node::Node) -> Result<()> {
    if node.overlay.0 != overlay_id.0 {
        return Err(OverlayError::OverlayIdMismatch.into());
    }

    let node_id = AdnlNodeIdFull::try_from(&node.id)?;

    let node_to_sign = serialize_boxed(ton::overlay::node::tosign::ToSign {
        id: node_id.compute_short_id()?.as_tl(),
        overlay: node.overlay,
        version: node.version,
    })?;

    let other_signature = ed25519_dalek::Signature::from_bytes(&node.signature)?;
    node_id
        .public_key()
        .verify(&node_to_sign, &other_signature)?;

    Ok(())
}

pub fn compute_overlay_id(
    workchain: i32,
    shard: i64,
    zero_state_file_hash: FileHash,
) -> Result<OverlayIdFull> {
    let overlay = ton::ton_node::shardpublicoverlayid::ShardPublicOverlayId {
        workchain,
        shard,
        zero_state_file_hash: ton::int256(zero_state_file_hash),
    };
    hash(overlay).map(OverlayIdFull)
}

pub fn compute_private_overlay_short_id(
    first_block: &ton::catchain::FirstBlock,
) -> Result<PrivateOverlayIdShort> {
    let first_block = serialize(first_block)?;
    let overlay_id = ton::pub_::publickey::Overlay {
        name: first_block.into(),
    };
    hash(overlay_id).map(PrivateOverlayIdShort)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct OverlayIdFull([u8; 32]);

impl OverlayIdFull {
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn compute_short_id(&self) -> Result<OverlayIdShort> {
        let overlay = ton::pub_::publickey::Overlay {
            name: ton::bytes(self.0.to_vec()),
        };
        hash(overlay).map(OverlayIdShort)
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

impl From<ton::overlay::Message> for OverlayIdShort {
    fn from(message: ton::overlay::Message) -> Self {
        Self(message.only().overlay.0)
    }
}

impl From<ton::rpc::overlay::Query> for OverlayIdShort {
    fn from(query: ton::rpc::overlay::Query) -> Self {
        Self(query.overlay.0)
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
