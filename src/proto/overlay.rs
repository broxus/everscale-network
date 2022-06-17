use bytes::Bytes;
use smallvec::SmallVec;
use tl_proto::{BoxedConstructor, TlRead, TlWrite};

use super::{rldp, HashRef};

#[derive(TlWrite, TlRead)]
pub struct Nodes<'tl> {
    pub nodes: SmallVec<[Node<'tl>; 5]>,
}

impl BoxedConstructor for Nodes<'_> {
    const TL_ID: u32 = tl_proto::id!("overlay.nodes", scheme = "scheme.tl");
}

#[derive(Clone, TlWrite, TlRead)]
pub struct NodesOwned {
    pub nodes: SmallVec<[NodeOwned; 5]>,
}

impl BoxedConstructor for NodesOwned {
    const TL_ID: u32 = Nodes::TL_ID;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TlWrite, TlRead)]
pub struct Node<'tl> {
    pub id: everscale_crypto::tl::PublicKey<'tl>,
    #[tl(size_hint = 32)]
    pub overlay: HashRef<'tl>,
    #[tl(size_hint = 4)]
    pub version: u32,
    pub signature: &'tl [u8],
}

impl Node<'_> {
    pub fn as_equivalent_owned(&self) -> NodeOwned {
        NodeOwned {
            id: self.id.as_equivalent_owned(),
            overlay: *self.overlay,
            version: self.version,
            signature: self.signature.to_vec().into(),
        }
    }
}

#[derive(Debug, Clone, TlWrite, TlRead)]
pub struct NodeOwned {
    pub id: everscale_crypto::tl::PublicKeyOwned,
    pub overlay: [u8; 32],
    pub version: u32,
    pub signature: Bytes,
}

impl NodeOwned {
    pub fn as_equivalent_ref(&self) -> Node {
        Node {
            id: self.id.as_equivalent_ref(),
            overlay: &self.overlay,
            version: self.version,
            signature: &self.signature,
        }
    }
}

#[derive(TlWrite)]
#[tl(boxed, id = "overlay.node.toSign", scheme = "scheme.tl")]
pub struct NodeToSign<'tl> {
    pub id: HashRef<'tl>,
    pub overlay: HashRef<'tl>,
    pub version: u32,
}

#[derive(TlWrite)]
#[tl(boxed, id = "tonNode.shardPublicOverlayId", scheme = "scheme.tl")]
pub struct ShardPublicOverlayId<'tl> {
    pub workchain: i32,
    pub shard: u64,
    pub zero_state_file_hash: HashRef<'tl>,
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = "overlay.message", scheme = "scheme.tl", size_hint = 32)]
pub struct Message<'tl> {
    pub overlay: HashRef<'tl>,
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum Broadcast<'tl> {
    #[tl(id = "overlay.broadcast")]
    Broadcast(OverlayBroadcast<'tl>),
    #[tl(id = "overlay.broadcastFec")]
    BroadcastFec(OverlayBroadcastFec<'tl>),
    #[tl(id = "overlay.broadcastFecShort")]
    BroadcastFecShort {
        src: everscale_crypto::tl::PublicKey<'tl>,
        certificate: Certificate<'tl>,
        #[tl(size_hint = 32)]
        broadcast_hash: HashRef<'tl>,
        #[tl(size_hint = 32)]
        part_data_hash: HashRef<'tl>,
        seqno: u32,
        signature: &'tl [u8],
    },
    #[tl(id = "overlay.broadcastNotFound", size_hint = 0)]
    BroadcastNotFound,
    #[tl(id = "overlay.fec.completed", size_hint = 32)]
    FecCompleted { hash: HashRef<'tl> },
    #[tl(id = "overlay.fec.received", size_hint = 32)]
    FecReceived { hash: HashRef<'tl> },
    #[tl(id = "overlay.unicast")]
    Unicast { data: &'tl [u8] },
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
pub struct OverlayBroadcast<'tl> {
    pub src: everscale_crypto::tl::PublicKey<'tl>,
    pub certificate: Certificate<'tl>,
    pub flags: u32,
    pub data: &'tl [u8],
    pub date: u32,
    pub signature: &'tl [u8],
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
pub struct OverlayBroadcastFec<'tl> {
    pub src: everscale_crypto::tl::PublicKey<'tl>,
    pub certificate: Certificate<'tl>,
    #[tl(size_hint = 32)]
    pub data_hash: HashRef<'tl>,
    pub data_size: u32,
    pub flags: u32,
    pub data: &'tl [u8],
    pub seqno: u32,
    pub fec: rldp::RaptorQFecType,
    pub date: u32,
    pub signature: &'tl [u8],
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum Certificate<'tl> {
    #[tl(id = "overlay.certificate")]
    Certificate {
        issued_by: everscale_crypto::tl::PublicKey<'tl>,
        expire_at: u32,
        max_size: u32,
        signature: &'tl [u8],
    },
    #[tl(id = "overlay.emptyCertificate", size_hint = 0)]
    EmptyCertificate,
}
