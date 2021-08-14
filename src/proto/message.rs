use std::io::Write;

use super::prelude::*;

#[derive(Debug, Copy, Clone)]
pub enum MessageView<'a> {
    Answer {
        query_id: HashRef<'a>,
        answer: &'a [u8],
    },
    Custom {
        data: &'a [u8],
    },
    ConfirmChannel {
        key: HashRef<'a>,
        peer_key: HashRef<'a>,
        date: i32,
    },
    Part {
        hash: HashRef<'a>,
        total_size: i32,
        offset: i32,
        data: &'a [u8],
    },
    CreateChannel {
        key: HashRef<'a>,
        date: i32,
    },
    Query {
        query_id: HashRef<'a>,
        query: &'a [u8],
    },
    Nop,
    Reinit {
        date: i32,
    },
}

impl Boxed for MessageView<'_> {}

impl<'a> ReadFromPacket<'a> for MessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_MESSAGE_ANSWER => Ok(Self::Answer {
                query_id: read_fixed_bytes(packet, offset)?,
                answer: read_bytes(packet, offset)?,
            }),
            ID_MESSAGE_CUSTOM => Ok(Self::Custom {
                data: read_bytes(packet, offset)?,
            }),
            ID_MESSAGE_CONFIRM_CHANNEL => Ok(Self::ConfirmChannel {
                key: read_fixed_bytes(packet, offset)?,
                peer_key: read_fixed_bytes(packet, offset)?,
                date: i32::read_from(packet, offset)?,
            }),
            ID_MESSAGE_PART => Ok(Self::Part {
                hash: read_fixed_bytes(packet, offset)?,
                total_size: i32::read_from(packet, offset)?,
                offset: i32::read_from(packet, offset)?,
                data: read_bytes(packet, offset)?,
            }),
            ID_MESSAGE_CREATE_CHANNEL => Ok(Self::CreateChannel {
                key: read_fixed_bytes(packet, offset)?,
                date: i32::read_from(packet, offset)?,
            }),
            ID_MESSAGE_QUERY => Ok(Self::Query {
                query_id: read_fixed_bytes(packet, offset)?,
                query: read_bytes(packet, offset)?,
            }),
            ID_MESSAGE_NOP => Ok(Self::Nop),
            ID_MESSAGE_REINIT => Ok(Self::Reinit {
                date: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for MessageView<'_> {
    fn max_size_hint(&self) -> usize {
        4 + match self {
            MessageView::Answer { query_id, answer } => {
                query_id.max_size_hint() + answer.max_size_hint()
            }
            MessageView::Custom { data } => data.max_size_hint(),
            MessageView::ConfirmChannel {
                key,
                peer_key,
                date,
            } => key.max_size_hint() + peer_key.max_size_hint() + date.max_size_hint(),
            MessageView::Part {
                hash,
                total_size,
                offset,
                data,
            } => {
                hash.max_size_hint()
                    + total_size.max_size_hint()
                    + offset.max_size_hint()
                    + data.max_size_hint()
            }
            MessageView::CreateChannel { key, date } => key.max_size_hint() + date.max_size_hint(),
            MessageView::Query { query_id, query } => {
                query_id.max_size_hint() + query.max_size_hint()
            }
            MessageView::Nop => 0,
            MessageView::Reinit { date } => date.max_size_hint(),
        }
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            MessageView::Answer { query_id, answer } => {
                ID_MESSAGE_ANSWER.write_to(packet)?;
                query_id.write_to(packet)?;
                answer.write_to(packet)
            }
            MessageView::Custom { data } => {
                ID_MESSAGE_CUSTOM.write_to(packet)?;
                data.write_to(packet)
            }
            MessageView::ConfirmChannel {
                key,
                peer_key,
                date,
            } => {
                ID_MESSAGE_CONFIRM_CHANNEL.write_to(packet)?;
                key.write_to(packet)?;
                peer_key.write_to(packet)?;
                date.write_to(packet)
            }
            MessageView::Part {
                hash,
                total_size,
                offset,
                data,
            } => {
                ID_MESSAGE_PART.write_to(packet)?;
                hash.write_to(packet)?;
                total_size.write_to(packet)?;
                offset.write_to(packet)?;
                data.write_to(packet)
            }
            MessageView::CreateChannel { key, date } => {
                ID_MESSAGE_CREATE_CHANNEL.write_to(packet)?;
                key.write_to(packet)?;
                date.write_to(packet)
            }
            MessageView::Query { query_id, query } => {
                ID_MESSAGE_QUERY.write_to(packet)?;
                query_id.write_to(packet)?;
                query.write_to(packet)
            }
            MessageView::Nop => ID_MESSAGE_NOP.write_to(packet),
            MessageView::Reinit { date } => {
                ID_MESSAGE_REINIT.write_to(packet)?;
                date.write_to(packet)
            }
        }
    }
}

const ID_MESSAGE_ANSWER: u32 = 0x0fac8416;
const ID_MESSAGE_CUSTOM: u32 = 0x204818f5;
const ID_MESSAGE_CONFIRM_CHANNEL: u32 = 0x60dd1d69;
const ID_MESSAGE_PART: u32 = 0xfd452d39;
const ID_MESSAGE_CREATE_CHANNEL: u32 = 0xe673c3bb;
const ID_MESSAGE_QUERY: u32 = 0xb48bf97a;
const ID_MESSAGE_NOP: u32 = 0x17f8dfda;
const ID_MESSAGE_REINIT: u32 = 0x10c20520;
