use std::convert::TryFrom;

use smallvec::SmallVec;

#[derive(Debug, Clone)]
pub struct PacketContentsView<'a> {
    pub from: Option<PublicKeyView<'a>>,
    pub from_short: Option<HashRef<'a>>,
    pub message: Option<MessageView<'a>>,
    pub messages: Option<SmallVec<[MessageView<'a>; 4]>>,
    pub address: Option<AddressListView<'a>>,
    pub seqno: Option<i64>,
    pub confirm_seqno: Option<i64>,
    pub recv_addr_list_version: Option<i32>,
    pub recv_priority_addr_list_version: Option<i32>,
    pub reinit_date: Option<i32>,
    pub dst_reinit_date: Option<i32>,
    pub signature: Option<&'a [u8]>,
}

impl<'a> TryFrom<&'a [u8]> for PacketContentsView<'a> {
    type Error = anyhow::Error;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        let mut offset = 0;
        let view = Self::read_from(packet, &mut offset)?;
        Ok(view)
    }
}

impl<'a> ReadFromPacket<'a> for PacketContentsView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let constructor = u32::read_from(packet, offset)?;
        if constructor != 0xd142cd89 {
            return Err(PacketContentsError::UnknownConstructor);
        }

        read_bytes(packet, offset)?; // skip rand1

        let flags = u32::read_from(packet, offset)?;

        let from = read_optional(packet, offset, flags & 0x0001 != 0)?;
        let from_short = read_optional(packet, offset, flags & 0x0002 != 0)?;

        let message = read_optional(packet, offset, flags & 0x0004 != 0)?;
        let messages = read_optional(packet, offset, flags & 0x0008 != 0)?;

        let address = read_optional(packet, offset, flags & 0x0010 != 0)?;
        read_optional::<AddressListView>(packet, offset, flags & 0x0020 != 0)?; // skip `priority_address`

        let seqno = read_optional(packet, offset, flags & 0x0040 != 0)?;
        let confirm_seqno = read_optional(packet, offset, flags & 0x0080 != 0)?;

        let recv_addr_list_version = read_optional(packet, offset, flags & 0x0100 != 0)?;
        let recv_priority_addr_list_version = read_optional(packet, offset, flags & 0x0200 != 0)?;

        let reinit_date = read_optional(packet, offset, flags & 0x0400 != 0)?;
        let dst_reinit_date = read_optional(packet, offset, flags & 0x0400 != 0)?;

        let signature = read_optional(packet, offset, flags & 0x0800 != 0)?;

        read_bytes(packet, offset)?; // skip rand2

        Ok(Self {
            from,
            from_short,
            message,
            messages,
            address,
            seqno,
            confirm_seqno,
            recv_addr_list_version,
            recv_priority_addr_list_version,
            reinit_date,
            dst_reinit_date,
            signature,
        })
    }
}

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

impl<'a> TryFrom<&'a [u8]> for MessageView<'a> {
    type Error = anyhow::Error;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        let mut offset = 0;
        let view = Self::read_from(packet, &mut offset)?;
        Ok(view)
    }
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

#[derive(Debug, Copy, Clone)]
pub struct AddressListView<'a> {
    /// Single address instead of list, because only one is always passed
    pub address: Option<AddressView<'a>>,
    pub version: i32,
    pub reinit_date: i32,
    pub priority: i32,
    pub expire_at: i32,
}

impl<'a> ReadFromPacket<'a> for AddressListView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let address_count = i32::read_from(packet, offset)?;
        let mut address = None;
        for _ in 0..address_count {
            let item = AddressView::read_from(packet, offset)?;
            if address.is_none() {
                address = Some(item);
            }
        }

        let version = i32::read_from(packet, offset)?;
        let reinit_date = i32::read_from(packet, offset)?;
        let priority = i32::read_from(packet, offset)?;
        let expire_at = i32::read_from(packet, offset)?;

        Ok(Self {
            address,
            version,
            reinit_date,
            priority,
            expire_at,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AddressView<'a> {
    Tunnel {
        to: HashRef<'a>,
        pubkey: PublicKeyView<'a>,
    },
    Udp {
        ip: i32,
        port: i32,
    },
    Udp6 {
        ip: &'a [u8; 16],
        port: i32,
    },
}

impl<'a> ReadFromPacket<'a> for AddressView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x670da6e7 => Ok(Self::Udp {
                ip: i32::read_from(packet, offset)?,
                port: i32::read_from(packet, offset)?,
            }),
            0xe31d63fa => Ok(Self::Udp6 {
                ip: read_fixed_bytes(packet, offset)?,
                port: i32::read_from(packet, offset)?,
            }),
            0x092b02eb => Ok(Self::Tunnel {
                to: read_fixed_bytes(packet, offset)?,
                pubkey: PublicKeyView::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

macro_rules! impl_read_for_primitive {
    ($type:ident) => {
        impl ReadFromPacket<'_> for $type {
            #[inline]
            fn read_from(packet: &[u8], offset: &mut usize) -> PacketContentsResult<Self> {
                if packet.len() < *offset + std::mem::size_of::<$type>() {
                    Err(PacketContentsError::UnexpectedEof)
                } else {
                    let value = $type::from_le_bytes(unsafe {
                        *(packet.as_ptr().add(*offset) as *const [u8; std::mem::size_of::<$type>()])
                    });
                    *offset += std::mem::size_of::<$type>();
                    Ok(value)
                }
            }
        }
    };
}

impl_read_for_primitive!(u32);
impl_read_for_primitive!(i32);
impl_read_for_primitive!(i64);

#[inline]
fn read_optional<'a, T>(
    packet: &'a [u8],
    offset: &mut usize,
    flag: bool,
) -> PacketContentsResult<Option<T>>
where
    T: ReadFromPacket<'a>,
{
    Ok(if flag {
        Some(T::read_from(packet, offset)?)
    } else {
        None
    })
}

impl<'a, T, const N: usize> ReadFromPacket<'a> for SmallVec<[T; N]>
where
    [T; N]: smallvec::Array,
    <[T; N] as smallvec::Array>::Item: ReadFromPacket<'a>,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let len = i32::read_from(packet, offset)?;
        let mut items = SmallVec::<[T; N]>::with_capacity(len as usize);
        for _ in 0..len {
            items.push(ReadFromPacket::read_from(packet, offset)?);
        }
        Ok(items)
    }
}

impl<'a, const N: usize> ReadFromPacket<'a> for &'a [u8; N] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_fixed_bytes(packet, offset)
    }
}

impl<'a> ReadFromPacket<'a> for &'a [u8] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_bytes(packet, offset)
    }
}

trait ReadFromPacket<'a>: Sized {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self>;
}

#[inline]
fn read_fixed_bytes<'a, const N: usize>(
    packet: &'a [u8],
    offset: &mut usize,
) -> PacketContentsResult<&'a [u8; N]> {
    if packet.len() < *offset + N {
        Err(PacketContentsError::UnexpectedEof)
    } else {
        let ptr = unsafe { &*(packet.as_ptr().add(*offset) as *const [u8; N]) };
        *offset += N;
        Ok(ptr)
    }
}

#[inline]
fn read_bytes<'a>(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<&'a [u8]> {
    let packet_len = packet.len();
    let current_offset = *offset;

    if packet_len <= current_offset {
        return Err(PacketContentsError::UnexpectedEof);
    }

    let first_bytes = packet[current_offset];
    let (len, have_read) = if first_bytes != 254 {
        (first_bytes as usize, 1)
    } else {
        if packet_len < current_offset + 4 {
            return Err(PacketContentsError::UnexpectedEof);
        }

        let mut len = packet[current_offset + 1] as usize;
        len |= (packet[current_offset + 2] as usize) << 8;
        len |= (packet[current_offset + 3] as usize) << 16;
        (len, 4)
    };

    let remainder = {
        let excess = (have_read + len) % 4;
        if excess == 0 {
            0
        } else {
            4 - excess
        }
    };

    if packet_len < current_offset + have_read + len + remainder {
        return Err(PacketContentsError::UnexpectedEof);
    }

    let result =
        unsafe { std::slice::from_raw_parts(packet.as_ptr().add(current_offset + have_read), len) };

    *offset += have_read + len + remainder;
    Ok(result)
}

type HashRef<'a> = &'a [u8; 32];

type PacketContentsResult<T> = Result<T, PacketContentsError>;

#[derive(thiserror::Error, Debug)]
enum PacketContentsError {
    #[error("Unexpected packet EOF")]
    UnexpectedEof,
    #[error("Unknown constructor")]
    UnknownConstructor,
}
