use std::io::Write;

use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum FecType {
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

impl Boxed for FecType {}

impl<'a> ReadFromPacket<'a> for FecType {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_FEC_TYPE_RAPTORQ => Ok(Self::RaptorQ {
                data_size: i32::read_from(packet, offset)?,
                symbol_size: i32::read_from(packet, offset)?,
                symbols_count: i32::read_from(packet, offset)?,
            }),
            ID_FEC_TYPE_ONLINE => Ok(Self::Online {
                data_size: i32::read_from(packet, offset)?,
                symbol_size: i32::read_from(packet, offset)?,
                symbols_count: i32::read_from(packet, offset)?,
            }),
            ID_FEC_TYPE_ROUND_ROBIN => Ok(Self::RoundRobin {
                data_size: i32::read_from(packet, offset)?,
                symbol_size: i32::read_from(packet, offset)?,
                symbols_count: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for FecType {
    fn max_size_hint(&self) -> usize {
        // 4 bytes constructor, 4x3 bytes for values
        16
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            FecType::RaptorQ {
                data_size,
                symbol_size,
                symbols_count,
            } => {
                ID_FEC_TYPE_RAPTORQ.write_to(packet)?;
                data_size.write_to(packet)?;
                symbol_size.write_to(packet)?;
                symbols_count.write_to(packet)
            }
            FecType::Online {
                data_size,
                symbol_size,
                symbols_count,
            } => {
                ID_FEC_TYPE_ONLINE.write_to(packet)?;
                data_size.write_to(packet)?;
                symbol_size.write_to(packet)?;
                symbols_count.write_to(packet)
            }
            FecType::RoundRobin {
                data_size,
                symbol_size,
                symbols_count,
            } => {
                ID_FEC_TYPE_ROUND_ROBIN.write_to(packet)?;
                data_size.write_to(packet)?;
                symbol_size.write_to(packet)?;
                symbols_count.write_to(packet)
            }
        }
    }
}

const ID_FEC_TYPE_RAPTORQ: u32 = 0x8b93a7e0;
const ID_FEC_TYPE_ONLINE: u32 = 0x0127660c;
const ID_FEC_TYPE_ROUND_ROBIN: u32 = 0x32f528e4;
