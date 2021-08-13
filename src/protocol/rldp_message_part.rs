use super::fec_type::*;
use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum RldpMessagePartView<'a> {
    MessagePart {
        transfer_id: HashRef<'a>,
        fec_type: FecTypeView,
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

impl<'a> ReadFromPacket<'a> for RldpMessagePartView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x185c22cc => Ok(Self::MessagePart {
                transfer_id: read_fixed_bytes(packet, offset)?,
                fec_type: FecTypeView::read_from(packet, offset)?,
                part: i32::read_from(packet, offset)?,
                total_size: i64::read_from(packet, offset)?,
                seqno: i32::read_from(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            0xf582dc58 => Ok(Self::Confirm {
                transfer_id: read_fixed_bytes(packet, offset)?,
                part: i32::read_from(packet, offset)?,
                seqno: i32::read_from(packet, offset)?,
            }),
            0xbc0cb2bf => Ok(Self::Complete {
                transfer_id: read_fixed_bytes(packet, offset)?,
                part: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}
