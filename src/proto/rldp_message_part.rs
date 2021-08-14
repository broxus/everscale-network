use std::io::Write;

use super::fec_type::*;
use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum RldpMessagePartView<'a> {
    MessagePart {
        transfer_id: HashRef<'a>,
        fec_type: FecType,
        part: i32,
        total_size: i64,
        seqno: i32,
        data: &'a [u8],
    },
    Confirm {
        transfer_id: HashRef<'a>,
        part: i32,
        seqno: i32,
    },
    Complete {
        transfer_id: HashRef<'a>,
        part: i32,
    },
}

impl Boxed for RldpMessagePartView<'_> {}

impl<'a> ReadFromPacket<'a> for RldpMessagePartView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_RLDP_MESSAGE_PART_MESSAGE_PART => Ok(Self::MessagePart {
                transfer_id: read_fixed_bytes(packet, offset)?,
                fec_type: FecType::read_from(packet, offset)?,
                part: i32::read_from(packet, offset)?,
                total_size: i64::read_from(packet, offset)?,
                seqno: i32::read_from(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            ID_RLDP_MESSAGE_PART_CONFIRM => Ok(Self::Confirm {
                transfer_id: read_fixed_bytes(packet, offset)?,
                part: i32::read_from(packet, offset)?,
                seqno: i32::read_from(packet, offset)?,
            }),
            ID_RLDP_MESSAGE_PART_COMPLETE => Ok(Self::Complete {
                transfer_id: read_fixed_bytes(packet, offset)?,
                part: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for RldpMessagePartView<'_> {
    fn max_size_hint(&self) -> usize {
        4 + match self {
            Self::MessagePart {
                transfer_id,
                fec_type,
                part,
                total_size,
                seqno,
                data,
            } => {
                transfer_id.max_size_hint()
                    + fec_type.max_size_hint()
                    + part.max_size_hint()
                    + total_size.max_size_hint()
                    + seqno.max_size_hint()
                    + data.max_size_hint()
            }
            Self::Confirm {
                transfer_id,
                part,
                seqno,
            } => transfer_id.max_size_hint() + part.max_size_hint() + seqno.max_size_hint(),
            Self::Complete { transfer_id, part } => {
                transfer_id.max_size_hint() + part.max_size_hint()
            }
        }
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::MessagePart {
                transfer_id,
                fec_type,
                part,
                total_size,
                seqno,
                data,
            } => {
                ID_RLDP_MESSAGE_PART_MESSAGE_PART.write_to(packet)?;
                transfer_id.write_to(packet)?;
                fec_type.write_to(packet)?;
                part.write_to(packet)?;
                total_size.write_to(packet)?;
                seqno.write_to(packet)?;
                data.write_to(packet)
            }
            Self::Confirm {
                transfer_id,
                part,
                seqno,
            } => {
                ID_RLDP_MESSAGE_PART_CONFIRM.write_to(packet)?;
                transfer_id.write_to(packet)?;
                part.write_to(packet)?;
                seqno.write_to(packet)
            }
            Self::Complete { transfer_id, part } => {
                ID_RLDP_MESSAGE_PART_COMPLETE.write_to(packet)?;
                transfer_id.write_to(packet)?;
                part.write_to(packet)
            }
        }
    }
}

const ID_RLDP_MESSAGE_PART_MESSAGE_PART: u32 = 0x185c22cc;
const ID_RLDP_MESSAGE_PART_CONFIRM: u32 = 0xf582dc58;
const ID_RLDP_MESSAGE_PART_COMPLETE: u32 = 0xbc0cb2bf;
