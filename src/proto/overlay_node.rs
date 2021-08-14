use std::io::Write;

use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Clone)]
pub struct OwnedOverlayNode {
    pub id: OwnedPublicKey,
    pub overlay: [u8; 32],
    pub version: i32,
    pub signature: OwnedSignature,
}

#[derive(Debug, Copy, Clone)]
pub struct OverlayNodeView<'a, S> {
    pub id: PublicKeyView<'a>,
    pub overlay: HashRef<'a>,
    pub version: i32,
    pub signature: S,
}

impl<S> AsOwned for OverlayNodeView<'_, S>
where
    S: DataSignature + AsOwned<Owned = OwnedSignature>,
{
    type Owned = OwnedOverlayNode;

    fn as_owned(&self) -> OwnedOverlayNode {
        OwnedOverlayNode {
            id: self.id.as_owned(),
            overlay: *self.overlay,
            version: self.version,
            signature: self.signature.as_owned(),
        }
    }
}

impl<S> BoxedConstructor for OverlayNodeView<'_, S>
where
    S: WriteToPacket + DataSignature,
{
    const ID: u32 = ID_OVERLAY_NODE;
}

impl<S> UpdateSignatureHasher for BoxedWrapper<&OverlayNodeView<'_, S>>
where
    S: WriteToPacket + DataSignature,
{
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write,
    {
        OverlayNodeView::<S>::ID.write_to(hasher)?;
        self.0.id.write_to(hasher)?;
        self.0.overlay.write_to(hasher)?;
        self.0.version.write_to(hasher)?;
        write_bytes(&[], hasher)
    }
}

impl<'a, S> ReadFromPacket<'a> for OverlayNodeView<'a, S>
where
    S: ReadFromPacket<'a> + DataSignature,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            id: PublicKeyView::read_from(packet, offset)?,
            overlay: HashRef::read_from(packet, offset)?,
            version: i32::read_from(packet, offset)?,
            signature: S::read_from(packet, offset)?,
        })
    }
}

impl<S> WriteToPacket for OverlayNodeView<'_, S>
where
    S: WriteToPacket + DataSignature,
{
    fn max_size_hint(&self) -> usize {
        self.id.max_size_hint()
            + self.overlay.max_size_hint()
            + self.version.max_size_hint()
            + self.signature.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.id.write_to(packet)?;
        self.overlay.write_to(packet)?;
        self.version.write_to(packet)?;
        self.signature.write_to(packet)
    }
}

const ID_OVERLAY_NODE: u32 = 0xb86b8a83;
