use std::convert::TryFrom;

use anyhow::Result;
use sha2::Digest;
use tl_proto::{HashWrapper, TlWrite};
use ton_api::ton;

use super::hash;
use crate::utils::{AdnlNodeIdFull, HashRef};

#[derive(TlWrite)]
#[tl(boxed, id = 0x03d8a8e1)]
pub struct OverlayNodeToSign<'tl> {
    pub id: HashRef<'tl>,
    pub overlay: HashRef<'tl>,
    pub version: u32,
}

pub fn verify_node(overlay_id: &OverlayIdShort, node: &ton::overlay::node::Node) -> Result<()> {
    if node.overlay.0 != overlay_id.0 {
        return Err(OverlayError::OverlayIdMismatch.into());
    }

    let full_id = AdnlNodeIdFull::try_from(&node.id)?;
    let peer_id = full_id.compute_short_id();

    let node_to_sign = OverlayNodeToSign {
        id: peer_id.as_slice(),
        overlay: &node.overlay.0,
        version: node.version as u32,
    };

    full_id.verify(&node_to_sign, &node.signature)?;

    Ok(())
}

pub fn compute_overlay_id(workchain: i32, zero_state_file_hash: FileHash) -> OverlayIdFull {
    #[derive(TlWrite)]
    #[tl(boxed, id = 0x4d9ed329)]
    struct ShardPublicOverlayId<'tl> {
        workchain: i32,
        shard: u64,
        zero_state_file_hash: HashRef<'tl>,
    }

    let mut hash = sha2::Sha256::new();
    HashWrapper(ShardPublicOverlayId {
        workchain,
        shard: 1u64 << 63,
        zero_state_file_hash: &zero_state_file_hash,
    })
    .update_hasher(&mut hash);

    OverlayIdFull(hash.finalize().into())
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct OverlayIdFull([u8; 32]);

impl OverlayIdFull {
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn compute_short_id(&self) -> OverlayIdShort {
        let overlay = ton::pub_::publickey::Overlay {
            name: ton::bytes(self.0.to_vec()),
        };
        OverlayIdShort(hash(overlay))
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
