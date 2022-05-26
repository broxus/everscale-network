use smallvec::SmallVec;
use tl_proto::{TlError, TlPacket, TlRead, TlResult, TlWrite};

use super::HashRef;
use crate::utils::PacketView;

#[derive(Clone)]
pub struct OutgoingPacketContents<'tl> {
    /// 7 or 3 random bytes
    pub rand1: &'tl [u8],
    pub from: Option<everscale_crypto::tl::PublicKey<'tl>>,
    pub messages: OutgoingMessages<'tl>,
    pub address: AddressList<'tl>,
    pub seqno: u64,
    pub confirm_seqno: u64,
    pub reinit_dates: Option<ReinitDates>,
    pub signature: Option<&'tl [u8]>,
    /// 3 or 7 random bytes
    pub rand2: &'tl [u8],
}

impl<'tl> TlWrite for OutgoingPacketContents<'tl> {
    fn max_size_hint(&self) -> usize {
        8 // rand1 (1 byte length, 7 bytes data)
            + 4 // flags
            + self.from.max_size_hint()
            + self.messages.max_size_hint()
            + self.address.max_size_hint()
            + 8 // seqno
            + 8 // confirm_seqno
            + self.reinit_dates.max_size_hint()
            + self.signature.max_size_hint()
            + 4 // rand2 (1 byte length, 3 bytes data)
    }

    fn write_to<P>(&self, packet: &mut P)
    where
        P: TlPacket,
    {
        const DEFAULT_FLAGS: u32 = (0b1 << 4) | (0b1 << 6) | (0b1 << 7);

        let flags = DEFAULT_FLAGS
            | (self.from.is_some() as u32)
            | if self.messages.is_single() {
                0b1 << 2
            } else {
                0b1 << 3
            }
            | ((self.reinit_dates.is_some() as u32) << 10)
            | ((self.signature.is_some() as u32) << 11);

        packet.write_u32(0xd142cd89); // constructor
        self.rand1.write_to(packet);
        packet.write_u32(flags);
        self.from.write_to(packet);
        self.messages.write_to(packet);
        self.address.write_to(packet);
        self.seqno.write_to(packet);
        self.confirm_seqno.write_to(packet);
        self.reinit_dates.write_to(packet);
        self.signature.write_to(packet);
        self.rand2.write_to(packet);
    }
}

#[derive(Copy, Clone)]
pub enum OutgoingMessages<'a> {
    Single(&'a [u8]),
    Pair(&'a [u8]),
}

impl OutgoingMessages<'_> {
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }
}

impl<'tl> TlWrite for OutgoingMessages<'tl> {
    #[inline(always)]
    fn max_size_hint(&self) -> usize {
        match self {
            Self::Single(raw) => raw.len(),
            Self::Pair(raw) => 4 + raw.len(),
        }
    }

    #[inline(always)]
    fn write_to<P>(&self, packet: &mut P)
    where
        P: TlPacket,
    {
        match self {
            Self::Single(raw) => packet.write_raw_slice(raw),
            Self::Pair(raw) => {
                packet.write_u32(2);
                packet.write_raw_slice(raw);
            }
        }
    }
}

#[derive(Clone)]
pub struct IncomingPacketContents<'tl> {
    pub from: Option<everscale_crypto::tl::PublicKey<'tl>>,
    pub from_short: Option<HashRef<'tl>>,

    pub messages: SmallVec<[Message<'tl>; 2]>,
    pub address: Option<AddressList<'tl>>,

    pub seqno: Option<u64>,
    pub confirm_seqno: Option<u64>,

    pub reinit_dates: Option<ReinitDates>,

    pub signature: Option<PacketContentsSignature>,
}

impl<'tl> TlRead<'tl> for IncomingPacketContents<'tl> {
    fn read_from(packet: &'tl [u8], offset: &mut usize) -> TlResult<Self> {
        #[inline(always)]
        fn read_optional<'tl, T: TlRead<'tl>, const N: usize>(
            flags: u32,
            packet: &'tl [u8],
            offset: &mut usize,
        ) -> TlResult<Option<T>> {
            Ok(if flags & (0b1 << N) != 0 {
                Some(T::read_from(packet, offset)?)
            } else {
                None
            })
        }

        if u32::read_from(packet, offset)? != 0xd142cd89 {
            return Err(TlError::UnknownConstructor);
        }

        <&[u8] as TlRead>::read_from(packet, offset)?; // rand1

        let flags_offset = *offset as u16;
        let flags = u32::read_from(packet, offset)?;

        let from = read_optional::<everscale_crypto::tl::PublicKey, 0>(flags, packet, offset)?;
        let from_short = read_optional::<HashRef, 1>(flags, packet, offset)?;

        let message = read_optional::<Message, 2>(flags, packet, offset)?;
        let messages = read_optional::<SmallVec<[Message<'tl>; 2]>, 3>(flags, packet, offset)?;

        let address = read_optional::<AddressList, 4>(flags, packet, offset)?;
        read_optional::<AddressList, 5>(flags, packet, offset)?; // priority_address

        let seqno = read_optional::<u64, 6>(flags, packet, offset)?;
        let confirm_seqno = read_optional::<u64, 7>(flags, packet, offset)?;

        read_optional::<u32, 8>(flags, packet, offset)?; // recv_addr_list_version
        read_optional::<u32, 9>(flags, packet, offset)?; // recv_priority_addr_list_version

        let reinit_dates = read_optional::<ReinitDates, 10>(flags, packet, offset)?;

        let signature = if flags & (0b1 << 11) != 0 {
            let signature_start = *offset as u16;
            let signature = <&[u8]>::read_from(packet, offset)?;
            let signature_end = *offset as u16;

            if signature.len() != 64 {
                return Err(TlError::UnexpectedEof);
            }

            Some(PacketContentsSignature {
                signature: signature.try_into().unwrap(),
                flags_offset,
                signature_start,
                signature_end,
            })
        } else {
            None
        };

        <&[u8] as TlRead>::read_from(packet, offset)?; // rand2

        Ok(Self {
            from,
            from_short,
            messages: match (messages, message) {
                (Some(messages), None) => messages,
                (None, Some(message)) => {
                    let mut messages = SmallVec::with_capacity(1);
                    messages.push(message);
                    messages
                }
                (Some(mut messages), Some(message)) => {
                    messages.insert(0, message);
                    messages
                }
                (None, None) => return Err(TlError::UnexpectedEof),
            },
            address,
            seqno,
            confirm_seqno,
            reinit_dates,
            signature,
        })
    }
}

#[derive(Copy, Clone)]
pub struct PacketContentsSignature {
    signature: [u8; 64],
    flags_offset: u16,
    signature_start: u16,
    signature_end: u16,
}

impl PacketContentsSignature {
    /// Modifies the content of the packet even though the PacketView
    /// is passed as a constant reference
    ///
    /// # Safety
    ///
    /// * Must be called only once on same packet
    ///
    pub unsafe fn extract<'a>(self, packet: &'a PacketView<'_>) -> Option<(&'a [u8], [u8; 64])> {
        let origin = packet.as_slice().as_ptr() as *mut u8;
        let packet: &mut [u8] = std::slice::from_raw_parts_mut(origin, packet.len());

        // `packet` before:
        // [............_*__.................|__________________|.........]
        // flags_offset ^     signature_start ^    signature_end ^

        // NOTE: `flags_offset + 1` is used because flags are stored in LE bytes order and
        // we need the second byte (signature mask - 0x0800)
        let (signature_len, remaining) = match (packet.len() as u16, self.flags_offset + 1) {
            (packet_len, flags_offset)
                if flags_offset < packet_len
                    && self.signature_start < self.signature_end
                    && self.signature_end < packet_len =>
            {
                packet[flags_offset as usize] &= 0xf7; // reset signature bit

                (
                    self.signature_end - self.signature_start, // signature len
                    packet_len - self.signature_end,           // remaining
                )
            }
            _ => return None,
        };

        let src = origin.add(self.signature_end as usize);
        let dst = origin.add(self.signature_start as usize);
        std::ptr::copy(src, dst, remaining as usize);

        // `packet` after:
        // [............_0__.................||.........]-----removed-----]
        // flags_offset ^     signature_start ^

        Some((
            std::slice::from_raw_parts(origin, packet.len() - signature_len as usize),
            self.signature,
        ))
    }
}

#[derive(Debug, Copy, Clone, TlWrite, TlRead)]
#[tl(size_hint = 8)]
pub struct ReinitDates {
    pub local: u32,
    pub target: u32,
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum Message<'tl> {
    #[tl(id = 0x0fac8416)]
    Answer {
        #[tl(size_hint = 32)]
        query_id: HashRef<'tl>,
        answer: &'tl [u8],
    },

    #[tl(id = 0x204818f5)]
    Custom { data: &'tl [u8] },

    #[tl(id = 0x60dd1d69, size_hint = 68)]
    ConfirmChannel {
        key: HashRef<'tl>,
        peer_key: HashRef<'tl>,
        date: u32,
    },

    #[tl(id = 0xfd452d39)]
    Part {
        #[tl(size_hint = 32)]
        hash: HashRef<'tl>,
        total_size: u32,
        offset: u32,
        data: &'tl [u8],
    },

    #[tl(id = 0xe673c3bb, size_hint = 36)]
    CreateChannel { key: HashRef<'tl>, date: u32 },

    #[tl(id = 0xb48bf97a)]
    Query {
        #[tl(size_hint = 32)]
        query_id: HashRef<'tl>,
        query: &'tl [u8],
    },

    #[tl(id = 0x17f8dfda, size_hint = 0)]
    Nop,

    #[tl(id = 0x10c20520, size_hint = 4)]
    Reinit { date: u32 },
}

#[derive(Debug, Copy, Clone)]
pub struct AddressList<'tl> {
    /// Single address instead of list, because only one is always passed
    pub address: Option<Address<'tl>>,
    pub version: u32,
    pub reinit_date: u32,
    pub priority: u32,
    pub expire_at: u32,
}

impl TlWrite for AddressList<'_> {
    fn max_size_hint(&self) -> usize {
        // 4 bytes - address vector size
        // optional address size
        // 4 bytes - version
        // 4 bytes - reinit_date
        // 4 bytes - priority
        // 4 bytes - expire_at
        20 + self.address.max_size_hint()
    }

    fn write_to<P>(&self, packet: &mut P)
    where
        P: TlPacket,
    {
        u32::write_to(&(self.address.is_some() as u32), packet);
        self.address.write_to(packet);
        self.version.write_to(packet);
        self.reinit_date.write_to(packet);
        self.priority.write_to(packet);
        self.expire_at.write_to(packet);
    }
}

impl<'tl> TlRead<'tl> for AddressList<'tl> {
    fn read_from(packet: &'tl [u8], offset: &mut usize) -> TlResult<Self> {
        let address_count = u32::read_from(packet, offset)?;
        let mut address = None;
        for _ in 0..address_count {
            let item = Address::read_from(packet, offset)?;
            if address.is_none() {
                address = Some(item);
            }
        }

        let version = u32::read_from(packet, offset)?;
        let reinit_date = u32::read_from(packet, offset)?;
        let priority = u32::read_from(packet, offset)?;
        let expire_at = u32::read_from(packet, offset)?;

        Ok(Self {
            address,
            version,
            reinit_date,
            priority,
            expire_at,
        })
    }
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum Address<'tl> {
    #[tl(id = 0x670da6e7, size_hint = 8)]
    Udp { ip: u32, port: u32 },
    #[tl(id = 0xe31d63fa, size_hint = 20)]
    Udp6 { ip: &'tl [u8; 16], port: u32 },
    #[tl(id = 0x092b02eb)]
    Tunnel {
        #[tl(size_hint = 32)]
        to: HashRef<'tl>,
        pubkey: everscale_crypto::tl::PublicKey<'tl>,
    },
}
