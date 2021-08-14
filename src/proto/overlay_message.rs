use std::io::Write;

use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub struct OverlayMessageView<'a> {
    pub overlay: HashRef<'a>,
}

impl Boxed for OverlayMessageView<'_> {}

impl<'a> ReadFromPacket<'a> for OverlayMessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_OVERLAY_MESSAGE => Ok(Self {
                overlay: read_fixed_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for OverlayMessageView<'_> {
    fn max_size_hint(&self) -> usize {
        // 4 bytes constructor id, 32 bytes overlay id
        4 + 32
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        ID_OVERLAY_MESSAGE.write_to(packet)?;
        self.overlay.write_to(packet)
    }
}

const ID_OVERLAY_MESSAGE: u32 = 0x75252420;
