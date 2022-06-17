use tl_proto::{TlRead, TlWrite};

use super::{dht, overlay, HashRef};

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = "adnl.ping", size_hint = 8, scheme = "scheme.tl")]
pub struct AdnlPing {
    pub value: u64,
}

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = "overlay.query", size_hint = 32, scheme = "scheme.tl")]
pub struct OverlayQuery<'tl> {
    pub overlay: HashRef<'tl>,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "overlay.getRandomPeers", scheme = "scheme.tl")]
pub struct OverlayGetRandomPeers<'tl> {
    pub peers: overlay::Nodes<'tl>,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "overlay.getRandomPeers", scheme = "scheme.tl")]
pub struct OverlayGetRandomPeersOwned {
    pub peers: overlay::NodesOwned,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "dht.ping", size_hint = 8, scheme = "scheme.tl")]
pub struct DhtPing {
    pub random_id: u64,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "dht.findNode", size_hint = 36, scheme = "scheme.tl")]
pub struct DhtFindNode<'tl> {
    pub key: HashRef<'tl>,
    pub k: u32,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "dht.findValue", size_hint = 36, scheme = "scheme.tl")]
pub struct DhtFindValue<'tl> {
    pub key: HashRef<'tl>,
    pub k: u32,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "dht.getSignedAddressList", scheme = "scheme.tl")]
pub struct DhtGetSignedAddressList;

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "dht.store", scheme = "scheme.tl")]
pub struct DhtStore<'tl> {
    pub value: dht::Value<'tl>,
}

#[derive(TlWrite, TlRead)]
#[tl(boxed, id = "dht.query", scheme = "scheme.tl")]
pub struct DhtQuery<'tl> {
    pub node: dht::Node<'tl>,
}
