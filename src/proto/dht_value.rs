use std::io::Write;

use smallvec::SmallVec;

use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Clone)]
pub struct OwnedDhtValue {
    pub key: OwnedDhtKeyDescription,
    pub value: IntermediateBytes<OwnedRawBytes>,
    pub ttl: i32,
    pub signature: OwnedSignature,
}

#[derive(Debug, Clone)]
pub struct DhtValueView<'a, V, S> {
    pub key: DhtKeyDescriptionView<'a, S>,
    pub value: IntermediateBytes<V>,
    pub ttl: i32,
    pub signature: S,
}

impl<V, S> AsOwned for DhtValueView<'_, V, S>
where
    V: WriteToPacket,
    S: DataSignature + AsOwned<Owned = OwnedSignature>,
{
    type Owned = std::io::Result<OwnedDhtValue>;

    fn as_owned(&self) -> Self::Owned {
        Ok(OwnedDhtValue {
            key: self.key.as_owned(),
            value: self.value.as_owned_raw_bytes()?,
            ttl: self.ttl,
            signature: self.signature.as_owned(),
        })
    }
}

impl<V, S> BoxedConstructor for DhtValueView<'_, V, S>
where
    V: WriteToPacket,
    S: DataSignature + WriteToPacket,
{
    const ID: u32 = ID_DHT_VALUE;
}

impl<V, S> UpdateSignatureHasher for BoxedWrapper<&DhtValueView<'_, V, S>>
where
    V: WriteToPacket,
    S: WriteToPacket + DataSignature,
{
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write,
    {
        DhtValueView::<V, S>::ID.write_to(hasher)?;
        self.0.key.write_to(hasher)?;
        self.0.value.write_to(hasher)?;
        self.0.ttl.write_to(hasher)?;
        write_bytes(&[], hasher)
    }
}

impl<'a, V, S> ReadFromPacket<'a> for DhtValueView<'a, V, S>
where
    V: ReadFromPacket<'a>,
    S: ReadFromPacket<'a> + DataSignature,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            key: DhtKeyDescriptionView::read_from(packet, offset)?,
            value: IntermediateBytes::read_from(packet, offset)?,
            ttl: i32::read_from(packet, offset)?,
            signature: S::read_from(packet, offset)?,
        })
    }
}

impl<V, S> WriteToPacket for DhtValueView<'_, V, S>
where
    V: WriteToPacket,
    S: WriteToPacket + DataSignature,
{
    fn max_size_hint(&self) -> usize {
        self.key.max_size_hint()
            + self.value.max_size_hint()
            + self.ttl.max_size_hint()
            + self.signature.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.key.write_to(packet)?;
        self.value.write_to(packet)?;
        self.ttl.write_to(packet)?;
        self.signature.write_to(packet)
    }
}

const ID_DHT_VALUE: u32 = 0x90ad27cb;

#[derive(Debug, Clone)]
pub struct OwnedDhtKeyDescription {
    pub key: OwnedDhtKey,
    pub id: OwnedPublicKey,
    pub update_rule: DhtUpdateRuleView,
    pub signature: OwnedSignature,
}

#[derive(Debug, Clone)]
pub struct DhtKeyDescriptionView<'a, S> {
    pub key: DhtKeyView<'a>,
    pub id: PublicKeyView<'a>,
    pub update_rule: DhtUpdateRuleView,
    pub signature: S,
}

impl<S> AsOwned for DhtKeyDescriptionView<'_, S>
where
    S: DataSignature + AsOwned<Owned = OwnedSignature>,
{
    type Owned = OwnedDhtKeyDescription;

    fn as_owned(&self) -> Self::Owned {
        Self::Owned {
            key: self.key.as_owned(),
            id: self.id.as_owned(),
            update_rule: self.update_rule,
            signature: self.signature.as_owned(),
        }
    }
}

impl<S> BoxedConstructor for DhtKeyDescriptionView<'_, S>
where
    S: WriteToPacket + DataSignature,
{
    const ID: u32 = ID_DHT_KEY_DESCRIPTION;
}

impl<S> UpdateSignatureHasher for BoxedWrapper<&DhtKeyDescriptionView<'_, S>>
where
    S: WriteToPacket + DataSignature,
{
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write,
    {
        DhtKeyDescriptionView::<S>::ID.write_to(hasher)?;
        self.0.key.write_to(hasher)?;
        self.0.id.write_to(hasher)?;
        self.0.update_rule.write_to(hasher)?;
        write_bytes(&[], hasher)
    }
}

impl<'a, S> ReadFromPacket<'a> for DhtKeyDescriptionView<'a, S>
where
    S: ReadFromPacket<'a> + DataSignature,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            key: DhtKeyView::read_from(packet, offset)?,
            id: PublicKeyView::read_from(packet, offset)?,
            update_rule: DhtUpdateRuleView::read_from(packet, offset)?,
            signature: S::read_from(packet, offset)?,
        })
    }
}

impl<S> WriteToPacket for DhtKeyDescriptionView<'_, S>
where
    S: WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        self.key.max_size_hint()
            + self.id.max_size_hint()
            + self.update_rule.max_size_hint()
            + self.signature.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.key.write_to(packet)?;
        self.id.write_to(packet)?;
        self.update_rule.write_to(packet)?;
        self.signature.write_to(packet)
    }
}

const ID_DHT_KEY_DESCRIPTION: u32 = 0x281d4e05;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DhtUpdateRuleView {
    Anybody,
    OverlayNodes,
    Signature,
}

impl<'a> ReadFromPacket<'a> for DhtUpdateRuleView {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_DHT_UPDATE_RULE_ANYBODY => Ok(Self::Anybody),
            ID_DHT_UPDATE_RULE_OVERLAY_NODES => Ok(Self::OverlayNodes),
            ID_DHT_UPDATE_RULE_SIGNATURE => Ok(Self::Signature),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for DhtUpdateRuleView {
    fn max_size_hint(&self) -> usize {
        4
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Anybody => ID_DHT_UPDATE_RULE_ANYBODY.write_to(packet),
            Self::OverlayNodes => ID_DHT_UPDATE_RULE_OVERLAY_NODES.write_to(packet),
            Self::Signature => ID_DHT_UPDATE_RULE_SIGNATURE.write_to(packet),
        }
    }
}

const ID_DHT_UPDATE_RULE_ANYBODY: u32 = 0x61578e14;
const ID_DHT_UPDATE_RULE_OVERLAY_NODES: u32 = 0x26779383;
const ID_DHT_UPDATE_RULE_SIGNATURE: u32 = 0xcc9f31f7;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OwnedDhtKey {
    pub id: [u8; 32],
    pub name: SmallVec<[u8; 16]>,
    pub idx: i32,
}

impl OwnedDhtKey {
    pub fn as_view(&self) -> DhtKeyView {
        DhtKeyView {
            id: &self.id,
            name: self.name.as_slice(),
            idx: self.idx,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DhtKeyView<'a> {
    pub id: HashRef<'a>,
    pub name: &'a [u8],
    pub idx: i32,
}

impl AsOwned for DhtKeyView<'_> {
    type Owned = OwnedDhtKey;

    fn as_owned(&self) -> Self::Owned {
        Self::Owned {
            id: *self.id,
            name: self.name.into(),
            idx: self.idx,
        }
    }
}

impl BoxedConstructor for DhtKeyView<'_> {
    const ID: u32 = ID_DHT_KEY;
}

impl<'a> ReadFromPacket<'a> for DhtKeyView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            id: read_fixed_bytes(packet, offset)?,
            name: read_bytes(packet, offset)?,
            idx: i32::read_from(packet, offset)?,
        })
    }
}

impl WriteToPacket for DhtKeyView<'_> {
    fn max_size_hint(&self) -> usize {
        self.id.max_size_hint() + self.name.max_size_hint() + self.idx.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.id.write_to(packet)?;
        self.name.write_to(packet)?;
        self.idx.write_to(packet)
    }
}

const ID_DHT_KEY: u32 = 0xf667de8f;
