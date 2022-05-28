use smallvec::SmallVec;
use tl_proto::{BoxedConstructor, TlRead, TlWrite};

use super::{adnl, HashRef};

#[derive(TlWrite, TlRead)]
#[tl(boxed)]
pub enum ValueResult<'tl> {
    #[tl(id = 0xe40cf774)]
    ValueFound(Value<'tl>),
    #[tl(id = 0xa2620568)]
    ValueNotFound(NodesOwned),
}

#[derive(TlWrite, TlRead)]
#[tl(boxed)]
pub enum ValueResultOwned {
    #[tl(id = 0xe40cf774)]
    ValueFound(ValueOwned),
    #[tl(id = 0xa2620568)]
    ValueNotFound(NodesOwned),
}

#[derive(TlWrite, TlRead)]
pub struct Nodes<'tl> {
    pub nodes: SmallVec<[Node<'tl>; 5]>,
}

impl BoxedConstructor for Nodes<'_> {
    const TL_ID: u32 = 0x7974a0be;
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
    const TL_ID: u32 = 0x84533248;
}

impl Node<'_> {
    pub fn as_equivalent_owned(&self) -> NodeOwned {
        NodeOwned {
            id: self.id.as_equivalent_owned(),
            addr_list: self.addr_list,
            version: self.version,
            signature: self.signature.to_vec(),
        }
    }
}

#[derive(Clone, TlWrite, TlRead)]
pub struct NodeOwned {
    pub id: everscale_crypto::tl::PublicKeyOwned,
    pub addr_list: adnl::AddressList,
    pub version: u32,
    pub signature: Vec<u8>,
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
            signature: self.signature.as_slice(),
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
    const TL_ID: u32 = 0x90ad27cb;
}

impl Value<'_> {
    pub fn as_equivalent_owned(&self) -> ValueOwned {
        ValueOwned {
            key: self.key.as_equivalent_owned(),
            value: self.value.to_vec(),
            ttl: self.ttl,
            signature: self.signature.to_vec(),
        }
    }
}

#[derive(Clone, TlWrite, TlRead)]
pub struct ValueOwned {
    pub key: KeyDescriptionOwned,
    pub value: Vec<u8>,
    pub ttl: u32,
    pub signature: Vec<u8>,
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
    const TL_ID: u32 = 0x281d4e05;
}

impl KeyDescription<'_> {
    pub fn as_equivalent_owned(&self) -> KeyDescriptionOwned {
        KeyDescriptionOwned {
            key: self.key.as_equivalent_owned(),
            id: self.id.as_equivalent_owned(),
            update_rule: self.update_rule,
            signature: self.signature.to_vec(),
        }
    }
}

#[derive(Clone, TlWrite, TlRead)]
pub struct KeyDescriptionOwned {
    pub key: KeyOwned,
    pub id: everscale_crypto::tl::PublicKeyOwned,
    pub update_rule: UpdateRule,
    pub signature: Vec<u8>,
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
            signature: self.signature.as_slice(),
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
    const TL_ID: u32 = 0xf667de8f;
}

impl Key<'_> {
    pub fn as_equivalent_owned(&self) -> KeyOwned {
        KeyOwned {
            id: *self.id,
            name: self.name.to_vec(),
            idx: self.idx,
        }
    }
}

#[derive(Clone, TlWrite, TlRead)]
pub struct KeyOwned {
    #[tl(size_hint = 32)]
    pub id: [u8; 32],
    pub name: Vec<u8>,
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
#[tl(boxed)]
pub enum UpdateRule {
    #[tl(id = 0x61578e14, size_hint = 0)]
    Anybody,
    #[tl(id = 0x26779383, size_hint = 0)]
    OverlayNodes,
    #[tl(id = 0xcc9f31f7, size_hint = 0)]
    Signature,
}

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = 0x5a8aef81, size_hint = 8)]
pub struct Pong {
    pub random_id: u64,
}

#[derive(Copy, Clone, TlWrite, TlRead)]
#[tl(boxed, id = 0x7026fb08, size_hint = 0)]
pub struct Stored;
