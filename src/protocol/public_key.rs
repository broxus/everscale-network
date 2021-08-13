use std::io::Write;

use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum PublicKeyView<'a> {
    Aes { key: HashRef<'a> },
    Ed25519 { key: HashRef<'a> },
    Overlay { name: &'a [u8] },
    Unencoded { data: &'a [u8] },
}

impl<'a> ReadFromPacket<'a> for PublicKeyView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x2dbcadd4 => Ok(Self::Aes {
                key: read_fixed_bytes(packet, offset)?,
            }),
            0x4813b4c6 => Ok(Self::Ed25519 {
                key: read_fixed_bytes(packet, offset)?,
            }),
            0x34ba45cb => Ok(Self::Overlay {
                name: read_bytes(packet, offset)?,
            }),
            0xb61f450a => Ok(Self::Unencoded {
                data: read_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for PublicKeyView<'_> {
    #[inline]
    fn max_size_hint(&self) -> usize {
        match self {
            Self::Aes { key } => key.max_size_hint(),
            Self::Ed25519 { key } => key.max_size_hint(),
            Self::Overlay { name } => name.max_size_hint(),
            Self::Unencoded { data } => data.max_size_hint(),
        }
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Aes { key } => key.write_to(packet),
            Self::Ed25519 { key } => key.write_to(packet),
            Self::Overlay { name } => name.write_to(packet),
            Self::Unencoded { data } => data.write_to(packet),
        }
    }
}
