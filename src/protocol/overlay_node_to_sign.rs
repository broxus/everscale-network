use std::io::Write;

use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub struct OverlayNodeToSign<'a> {
    pub id: HashRef<'a>,
    pub overlay: HashRef<'a>,
    pub version: i32,
}

impl<'a> ReadFromPacket<'a> for OverlayNodeToSign<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            id: read_fixed_bytes(packet, offset)?,
            overlay: read_fixed_bytes(packet, offset)?,
            version: i32::read_from(packet, offset)?,
        })
    }
}

impl WriteToPacket for OverlayNodeToSign<'_> {
    fn max_size_hint(&self) -> usize {
        self.id.max_size_hint() + self.overlay.max_size_hint() + self.version.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.id.write_to(packet)?;
        self.overlay.write_to(packet)?;
        self.version.write_to(packet)
    }
}
