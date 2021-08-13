use std::borrow::Borrow;
use std::io::Write;

use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Clone)]
pub struct DhtValueView<'a, V, S> {
    pub key: DhtKeyDescriptionView<'a, S>,
    pub value: IntermediateBytes<V>,
    pub ttl: i32,
    pub signature: S,
}

impl<V, S> BoxedConstructor for DhtValueView<'_, V, S> {
    const ID: u32 = 0x90ad27cb;
}

impl<'a, V, S> ReadFromPacket<'a> for DhtValueView<'a, V, S>
where
    V: ReadFromPacket<'a>,
    S: ReadFromPacket<'a>,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            key: DhtKeyDescriptionView::read_from(packet, offset)?,
            value: V::read_from(packet, offset)?,
            ttl: i32::read_from(packet, offset)?,
            signature: S::read_from(packet, offset)?,
        })
    }
}

impl<V, S> WriteToPacket for DhtValueView<'_, V, S>
where
    V: WriteToPacket,
    S: WriteToPacket,
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

#[derive(Debug, Clone)]
pub struct DhtKeyDescriptionView<'a, S> {
    pub key: DhtKeyView<'a>,
    pub id: PublicKeyView<'a>,
    pub update_rule: DhtUpdateRuleView,
    pub signature: S,
}

impl<S> BoxedConstructor for DhtKeyDescriptionView<'_, S> {
    const ID: u32 = 0x281d4e05;
}

impl<T, S> UpdateSignatureHasher for BoxedWrapper<T, DhtKeyDescriptionView<'_, S>>
where
    T: Borrow<DhtKeyDescriptionView<'_, S>>,
{
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write,
    {
        Self
        self.inner().id.write_to()
    }
}

impl<'a, S> ReadFromPacket<'a> for DhtKeyDescriptionView<'a, S>
where
    S: ReadFromPacket<'a>,
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

pub enum DhtUpdateRuleView {
    Anybody,
    OverlayNodes,
    Signature,
}

impl<'a> ReadFromPacket<'a> for DhtUpdateRuleView {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x61578e14 => Ok(Self::Anybody),
            0x26779383 => Ok(Self::OverlayNodes),
            0xcc9f31f7 => Ok(Self::Signature),
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
            Self::Anybody => 0x61578e14u32.write_to(packet),
            Self::OverlayNodes => 0x26779383u32.write_to(packet),
            Self::Signature => 0xcc9f31f7.write_to(packet),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DhtKeyView<'a> {
    pub id: HashRef<'a>,
    pub name: &'a [u8],
    pub idx: i32,
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
