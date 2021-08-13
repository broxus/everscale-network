use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum MessageView<'a> {
    Answer {
        query_id: HashRef<'a>,
        answer: &'a [u8],
    },
    ConfirmChannel {
        key: HashRef<'a>,
        peer_key: HashRef<'a>,
        date: i32,
    },
    CreateChannel {
        key: HashRef<'a>,
        date: i32,
    },
    Custom {
        data: &'a [u8],
    },
    Nop,
    Part {
        hash: HashRef<'a>,
        total_size: i32,
        offset: i32,
        data: &'a [u8],
    },
    Query {
        query_id: HashRef<'a>,
        query: &'a [u8],
    },
    Reinit {
        date: i32,
    },
}

impl<'a> ReadFromPacket<'a> for MessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x0fac8416 => Ok(Self::Answer {
                query_id: read_fixed_bytes(packet, offset)?,
                answer: read_bytes(packet, offset)?,
            }),
            0x204818f5 => Ok(Self::Custom {
                data: read_bytes(packet, offset)?,
            }),
            0x60dd1d69 => Ok(Self::ConfirmChannel {
                key: read_fixed_bytes(packet, offset)?,
                peer_key: read_fixed_bytes(packet, offset)?,
                date: i32::read_from(packet, offset)?,
            }),
            0xfd452d39 => Ok(Self::Part {
                hash: read_fixed_bytes(packet, offset)?,
                total_size: i32::read_from(packet, offset)?,
                offset: i32::read_from(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            0xe673c3bb => Ok(Self::CreateChannel {
                key: read_fixed_bytes(packet, offset)?,
                date: i32::read_from(packet, offset)?,
            }),
            0xb48bf97a => Ok(Self::Query {
                query_id: read_fixed_bytes(packet, offset)?,
                query: read_bytes(packet, offset)?,
            }),
            0x17f8dfda => Ok(Self::Nop),
            0x10c20520 => Ok(Self::Reinit {
                date: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}
