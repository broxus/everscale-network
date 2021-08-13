use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum FecTypeView {
    RaptorQ {
        data_size: i32,
        symbol_size: i32,
        symbols_count: i32,
    },
    Online {
        data_size: i32,
        symbol_size: i32,
        symbols_count: i32,
    },
    RoundRobin {
        data_size: i32,
        symbol_size: i32,
        symbols_count: i32,
    },
}

impl<'a> ReadFromPacket<'a> for FecTypeView {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x8b93a7e0 => Ok(Self::RaptorQ {
                data_size: i32::read_from(packet, offset)?,
                symbol_size: i32::read_from(packet, offset)?,
                symbols_count: i32::read_from(packet, offset)?,
            }),
            0x0127660c => Ok(Self::Online {
                data_size: i32::read_from(packet, offset)?,
                symbol_size: i32::read_from(packet, offset)?,
                symbols_count: i32::read_from(packet, offset)?,
            }),
            0x32f528e4 => Ok(Self::RoundRobin {
                data_size: i32::read_from(packet, offset)?,
                symbol_size: i32::read_from(packet, offset)?,
                symbols_count: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}
