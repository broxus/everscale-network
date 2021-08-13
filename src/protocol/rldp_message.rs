use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum RldpMessageView<'a> {
    Message {
        id: HashRef<'a>,
        data: &'a [u8],
    },
    Answer {
        query_id: HashRef<'a>,
        data: &'a [u8],
    },
    Query {
        query_id: HashRef<'a>,
        max_answer_size: i64,
        timeout: i32,
        data: &'a [u8],
    },
}

impl<'a> ReadFromPacket<'a> for RldpMessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x7d1bcd1e => Ok(Self::Message {
                id: read_fixed_bytes(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            0xa3fc5c03 => Ok(Self::Answer {
                query_id: read_fixed_bytes(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            0x8a794d69 => Ok(Self::Query {
                query_id: read_fixed_bytes(packet, offset)?,
                max_answer_size: i64::read_from(packet, offset)?,
                timeout: i32::read_from(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}
