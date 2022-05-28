use smallvec::SmallVec;
use tl_proto::{BoxedConstructor, TlRead, TlWrite};

use super::{rldp, HashRef};

#[derive(TlWrite, TlRead)]
pub struct Nodes<'tl> {
    pub nodes: SmallVec<[Node<'tl>; 5]>,
}

impl BoxedConstructor for Nodes<'_> {
    const TL_ID: u32 = 0xe487290e;
}

#[derive(TlWrite, TlRead)]
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
            signature: self.signature.to_vec(),
        }
    }
}

#[derive(Debug, Clone, TlWrite, TlRead)]
pub struct NodeOwned {
    pub id: everscale_crypto::tl::PublicKeyOwned,
    pub overlay: [u8; 32],
    pub version: u32,
    pub signature: Vec<u8>,
}

impl NodeOwned {
    pub fn as_equivalent_ref(&self) -> Node {
        Node {
            id: self.id.as_equivalent_ref(),
            overlay: &self.overlay,
            version: self.version,
            signature: self.signature.as_slice(),
        }
    }
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x03d8a8e1)]
pub struct NodeToSign<'tl> {
    pub id: HashRef<'tl>,
    pub overlay: HashRef<'tl>,
    pub version: u32,
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x4d9ed329)]
pub struct ShardPublicOverlayId<'tl> {
    pub workchain: i32,
    pub shard: u64,
    pub zero_state_file_hash: HashRef<'tl>,
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = 0x75252420, size_hint = 32)]
pub struct Message<'tl> {
    pub overlay: HashRef<'tl>,
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(boxed)]
pub enum Broadcast<'tl> {
    #[tl(id = 0xb15a2b6b)]
    Broadcast(OverlayBroadcast<'tl>),
    #[tl(id = 0xbad7c36a)]
    BroadcastFec(OverlayBroadcastFec<'tl>),
    #[tl(id = 0xf1881342)]
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
    #[tl(id = 0x95863624, size_hint = 0)]
    BroadcastNotFound,
    #[tl(id = 0x09d76914, size_hint = 32)]
    FecCompleted { hash: HashRef<'tl> },
    #[tl(id = 0xd55c14ec, size_hint = 32)]
    FecReceived { hash: HashRef<'tl> },
    #[tl(id = 0x33534e24)]
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
#[tl(boxed)]
pub enum Certificate<'tl> {
    #[tl(id = 0xe09ed731)]
    Certificate {
        issued_by: everscale_crypto::tl::PublicKey<'tl>,
        expire_at: u32,
        max_size: u32,
        signature: &'tl [u8],
    },
    #[tl(id = 0x32dabccf, size_hint = 0)]
    EmptyCertificate,
}
