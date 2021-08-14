use std::io::Write;

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

impl Boxed for RldpMessageView<'_> {}

impl<'a> ReadFromPacket<'a> for RldpMessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_RLDP_MESSAGE_MESSAGE => Ok(Self::Message {
                id: read_fixed_bytes(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            ID_RLDP_MESSAGE_ANSWER => Ok(Self::Answer {
                query_id: read_fixed_bytes(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            ID_RLDP_MESSAGE_QUERY => Ok(Self::Query {
                query_id: read_fixed_bytes(packet, offset)?,
                max_answer_size: i64::read_from(packet, offset)?,
                timeout: i32::read_from(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for RldpMessageView<'_> {
    fn max_size_hint(&self) -> usize {
        4 + match self {
            Self::Message { id, data } => id.max_size_hint() + data.max_size_hint(),
            Self::Answer { query_id, data } => query_id.max_size_hint() + data.max_size_hint(),
            Self::Query {
                query_id,
                max_answer_size,
                timeout,
                data,
            } => {
                query_id.max_size_hint()
                    + max_answer_size.max_size_hint()
                    + timeout.max_size_hint()
                    + data.max_size_hint()
            }
        }
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Message { id, data } => {
                ID_RLDP_MESSAGE_MESSAGE.write_to(packet)?;
                id.write_to(packet)?;
                data.write_to(packet)
            }
            Self::Answer { query_id, data } => {
                ID_RLDP_MESSAGE_ANSWER.write_to(packet)?;
                query_id.write_to(packet)?;
                data.write_to(packet)
            }
            Self::Query {
                query_id,
                max_answer_size,
                timeout,
                data,
            } => {
                ID_RLDP_MESSAGE_QUERY.write_to(packet)?;
                query_id.write_to(packet)?;
                max_answer_size.write_to(packet)?;
                timeout.write_to(packet)?;
                data.write_to(packet)
            }
        }
    }
}

const ID_RLDP_MESSAGE_MESSAGE: u32 = 0x7d1bcd1e;
const ID_RLDP_MESSAGE_ANSWER: u32 = 0xa3fc5c03;
const ID_RLDP_MESSAGE_QUERY: u32 = 0x8a794d69;
