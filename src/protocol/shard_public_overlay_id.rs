use super::prelude::*;
use std::io::Write;

#[derive(Debug, Copy, Clone)]
pub struct ShardPublicOverlayIdView<'a> {
    pub workchain: i32,
    pub shard: i64,
    pub zero_state_file_hash: HashRef<'a>,
}

impl BoxedConstructor for ShardPublicOverlayIdView<'_> {
    const ID: u32 = 0x4d9ed329;
}

impl<'a> ReadFromPacket<'a> for ShardPublicOverlayIdView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            workchain: i32::read_from(packet, offset)?,
            shard: i64::read_from(packet, offset)?,
            zero_state_file_hash: read_fixed_bytes(packet, offset)?,
        })
    }
}

impl WriteToPacket for ShardPublicOverlayIdView<'_> {
    fn max_size_hint(&self) -> usize {
        self.workchain.max_size_hint()
            + self.shard.max_size_hint()
            + self.zero_state_file_hash.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.workchain.write_to(packet)?;
        self.shard.write_to(packet)?;
        self.zero_state_file_hash.write_to(packet)
    }
}
