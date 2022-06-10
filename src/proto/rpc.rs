use tl_proto::{TlRead, TlWrite};

use super::{dht, overlay, HashRef};

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = 0x1faaa1bf, size_hint = 8)]
pub struct AdnlPing {
    pub value: u64,
}

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = 0xccfd8443, size_hint = 32)]
pub struct OverlayQuery<'tl> {
    pub overlay: HashRef<'tl>,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x48ee64ab)]
pub struct OverlayGetRandomPeers<'tl> {
    pub peers: overlay::Nodes<'tl>,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x48ee64ab)]
pub struct OverlayGetRandomPeersOwned {
    pub peers: overlay::NodesOwned,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0xcbeb3f18, size_hint = 8)]
pub struct DhtPing {
    pub random_id: u64,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x6ce2ce6b, size_hint = 36)]
pub struct DhtFindNode<'tl> {
    pub key: HashRef<'tl>,
    pub k: u32,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0xae4b6011, size_hint = 36)]
pub struct DhtFindValue<'tl> {
    pub key: HashRef<'tl>,
    pub k: u32,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0xa97948ed, size_hint = 0)]
pub struct DhtGetSignedAddressList;

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x34934212)]
pub struct DhtStore<'tl> {
    pub value: dht::Value<'tl>,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = 0x7d530769)]
pub struct DhtQuery<'tl> {
    pub node: dht::Node<'tl>,
}
