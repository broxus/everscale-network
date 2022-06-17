use bytes::Bytes;
use smallvec::SmallVec;
use tl_proto::{BoxedConstructor, BoxedWrapper, TlRead, TlWrite};

use super::{adnl, HashRef};

#[derive(TlRead)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum ValueResult<'tl> {
    #[tl(id = "dht.valueFound")]
    ValueFound(BoxedWrapper<Value<'tl>>),
    #[tl(id = "dht.valueNotFound")]
    ValueNotFound(NodesOwned),
}

#[derive(TlWrite)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum ValueResultOwned {
    #[tl(id = "dht.valueFound")]
    ValueFound(BoxedWrapper<ValueOwned>),
    #[tl(id = "dht.valueNotFound")]
    ValueNotFound(NodesOwned),
}

#[derive(TlWrite, TlRead)]
pub struct Nodes<'tl> {
    pub nodes: SmallVec<[Node<'tl>; 5]>,
}

impl BoxedConstructor for Nodes<'_> {
    const TL_ID: u32 = tl_proto::id!("dht.nodes", scheme = "scheme.tl");
}

#[derive(TlWrite, TlRead)]
pub struct NodesOwned {
    pub nodes: Vec<NodeOwned>,
}

impl BoxedConstructor for NodesOwned {
    const TL_ID: u32 = Nodes::TL_ID;
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
pub struct Node<'tl> {
    pub id: everscale_crypto::tl::PublicKey<'tl>,
    pub addr_list: adnl::AddressList,
    pub version: u32,
    pub signature: &'tl [u8],
}

impl BoxedConstructor for Node<'_> {
    const TL_ID: u32 = tl_proto::id!("dht.node", scheme = "scheme.tl");
}

impl Node<'_> {
    pub fn as_equivalent_owned(&self) -> NodeOwned {
        NodeOwned {
            id: self.id.as_equivalent_owned(),
            addr_list: self.addr_list,
            version: self.version,
            signature: self.signature.to_vec().into(),
        }
    }
}

#[derive(Debug, Clone, TlWrite, TlRead)]
pub struct NodeOwned {
    pub id: everscale_crypto::tl::PublicKeyOwned,
    pub addr_list: adnl::AddressList,
    pub version: u32,
    pub signature: Bytes,
}

impl BoxedConstructor for NodeOwned {
    const TL_ID: u32 = Node::TL_ID;
}

impl NodeOwned {
    pub fn as_equivalent_ref(&self) -> Node {
        Node {
            id: self.id.as_equivalent_ref(),
            addr_list: self.addr_list,
            version: self.version,
            signature: &self.signature,
        }
    }
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
pub struct Value<'tl> {
    pub key: KeyDescription<'tl>,
    pub value: &'tl [u8],
    pub ttl: u32,
    pub signature: &'tl [u8],
}

impl BoxedConstructor for Value<'_> {
    const TL_ID: u32 = tl_proto::id!("dht.value", scheme = "scheme.tl");
}

impl Value<'_> {
    pub fn as_equivalent_owned(&self) -> ValueOwned {
        ValueOwned {
            key: self.key.as_equivalent_owned(),
            value: self.value.to_vec().into(),
            ttl: self.ttl,
            signature: self.signature.to_vec().into(),
        }
    }
}

#[derive(Debug, Clone, TlWrite, TlRead)]
pub struct ValueOwned {
    pub key: KeyDescriptionOwned,
    pub value: Bytes,
    pub ttl: u32,
    pub signature: Bytes,
}

impl BoxedConstructor for ValueOwned {
    const TL_ID: u32 = Value::TL_ID;
}

impl ValueOwned {
    pub fn as_equivalent_ref(&self) -> Value {
        Value {
            key: self.key.as_equivalent_ref(),
            value: &self.value,
            ttl: self.ttl,
            signature: &self.signature,
        }
    }
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
pub struct KeyDescription<'tl> {
    pub key: Key<'tl>,
    pub id: everscale_crypto::tl::PublicKey<'tl>,
    pub update_rule: UpdateRule,
    pub signature: &'tl [u8],
}

impl BoxedConstructor for KeyDescription<'_> {
    const TL_ID: u32 = tl_proto::id!("dht.keyDescription", scheme = "scheme.tl");
}

impl KeyDescription<'_> {
    pub fn as_equivalent_owned(&self) -> KeyDescriptionOwned {
        KeyDescriptionOwned {
            key: self.key.as_equivalent_owned(),
            id: self.id.as_equivalent_owned(),
            update_rule: self.update_rule,
            signature: self.signature.to_vec().into(),
        }
    }
}

#[derive(Debug, Clone, TlWrite, TlRead)]
pub struct KeyDescriptionOwned {
    pub key: KeyOwned,
    pub id: everscale_crypto::tl::PublicKeyOwned,
    pub update_rule: UpdateRule,
    pub signature: Bytes,
}

impl BoxedConstructor for KeyDescriptionOwned {
    const TL_ID: u32 = KeyDescription::TL_ID;
}

impl KeyDescriptionOwned {
    pub fn as_equivalent_ref(&self) -> KeyDescription<'_> {
        KeyDescription {
            key: self.key.as_equivalent_ref(),
            id: self.id.as_equivalent_ref(),
            update_rule: self.update_rule,
            signature: &self.signature,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TlWrite, TlRead)]
pub struct Key<'tl> {
    #[tl(size_hint = 32)]
    pub id: HashRef<'tl>,
    pub name: &'tl [u8],
    pub idx: u32,
}

impl BoxedConstructor for Key<'_> {
    const TL_ID: u32 = tl_proto::id!("dht.key", scheme = "scheme.tl");
}

impl Key<'_> {
    pub fn as_equivalent_owned(&self) -> KeyOwned {
        KeyOwned {
            id: *self.id,
            name: self.name.to_vec().into(),
            idx: self.idx,
        }
    }
}

#[derive(Debug, Clone, TlWrite, TlRead)]
pub struct KeyOwned {
    #[tl(size_hint = 32)]
    pub id: [u8; 32],
    pub name: Bytes,
    pub idx: u32,
}

impl BoxedConstructor for KeyOwned {
    const TL_ID: u32 = Key::TL_ID;
}

impl KeyOwned {
    pub fn as_equivalent_ref(&self) -> Key {
        Key {
            id: &self.id,
            name: &self.name,
            idx: self.idx,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TlWrite, TlRead)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum UpdateRule {
    #[tl(id = "dht.updateRule.anybody", size_hint = 0)]
    Anybody,
    #[tl(id = "dht.updateRule.overlayNodes", size_hint = 0)]
    OverlayNodes,
    #[tl(id = "dht.updateRule.signature", size_hint = 0)]
    Signature,
}

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = "dht.pong", size_hint = 8, scheme = "scheme.tl")]
pub struct Pong {
    pub random_id: u64,
}

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = "dht.stored", size_hint = 0, scheme = "scheme.tl")]
pub struct Stored;
