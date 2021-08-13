use std::io::Write;

use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Copy, Clone)]
pub struct OverlayNodeView<'a, S> {
    pub id: PublicKeyView<'a>,
    pub overlay: HashRef<'a>,
    pub version: i32,
    pub signature: S,
}

impl<'a, S> ReadFromPacket<'a> for OverlayNodeView<'a, S>
where
    S: ReadFromPacket<'a>,
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
    S: WriteToPacket,
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
