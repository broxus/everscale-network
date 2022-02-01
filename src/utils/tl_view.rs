use std::convert::TryInto;

use smallvec::SmallVec;

use crate::utils::PacketView;

pub fn deserialize_view<'a, T>(packet: &'a [u8]) -> PacketContentsResult<T>
where
    T: ReadFromPacket<'a>,
{
    let mut offset = 0;
    let view = T::read_from(packet, &mut offset)?;
    Ok(view)
}

#[derive(Debug)]
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
}

impl<'a> PacketContentsView<'a> {
    pub fn read_from_packet(
        packet: &'a [u8],
    ) -> PacketContentsResult<(Self, Option<PacketContentsSignature>)> {
        let offset = &mut 0usize;

        let constructor = u32::read_from(packet, offset)?;
        if constructor != 0xd142cd89 {
            return Err(PacketContentsError::UnknownConstructor);
        }

        read_bytes(packet, offset)?; // skip rand1

        let flags_offset = *offset;
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

        let signature = if flags & 0x0800 != 0 {
            let signature_start = *offset;
            let signature = <&[u8]>::read_from(packet, offset)?;
            let signature_end = *offset;

            if signature.len() != 64 {
                return Err(PacketContentsError::InvalidSignature);
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

        read_bytes(packet, offset)?; // skip rand2

        Ok((
            Self {
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
            },
            signature,
        ))
    }
}

impl Clone for PacketContentsView<'_> {
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            from_short: self.from_short,
            message: self.message,
            messages: self
                .messages
                .as_ref()
                .map(|items| SmallVec::from_slice(items)),
            address: self.address,
            seqno: self.seqno,
            confirm_seqno: self.confirm_seqno,
            recv_addr_list_version: self.recv_addr_list_version,
            recv_priority_addr_list_version: self.recv_priority_addr_list_version,
            reinit_date: self.reinit_date,
            dst_reinit_date: self.dst_reinit_date,
        }
    }
}

pub struct PacketContentsSignature {
    signature: [u8; 64],
    flags_offset: usize,
    signature_start: usize,
    signature_end: usize,
}

impl PacketContentsSignature {
    /// Modifies the content of the packet even though the PacketView
    /// is passed as a constant reference
    ///
    /// # Safety
    ///
    /// * Must be called only once on same packet
    ///
    pub unsafe fn extract<'a>(
        self,
        packet: &'a PacketView<'_>,
    ) -> PacketContentsResult<(&'a [u8], [u8; 64])> {
        let origin = packet.as_slice().as_ptr() as *mut u8;
        let packet: &mut [u8] = std::slice::from_raw_parts_mut(origin, packet.len());

        // `packet` before:
        // [............_*__.................|__________________|.........]
        // flags_offset ^     signature_start ^    signature_end ^

        // NOTE: `flags_offset + 1` is used because flags are stored in LE bytes order and
        // we need the second byte (signature mask - 0x0800)
        let (signature_len, remaining) = match (packet.len(), self.flags_offset + 1) {
            (packet_len, flags_offset)
                if flags_offset < packet_len
                    && self.signature_start < self.signature_end
                    && self.signature_end < packet_len =>
            {
                packet[flags_offset] &= 0xf7; // reset signature bit

                (
                    self.signature_end - self.signature_start, // signature len
                    packet_len - self.signature_end,           // remaining
                )
            }
            _ => return Err(PacketContentsError::InvalidSignature),
        };

        let src = origin.add(self.signature_end);
        let dst = origin.add(self.signature_start);
        std::ptr::copy(src, dst, remaining);

        // `packet` after:
        // [............_0__.................||.........]-----removed-----]
        // flags_offset ^     signature_start ^

        Ok((
            std::slice::from_raw_parts(origin, remaining - signature_len),
            self.signature,
        ))
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PublicOverlayQueryBundleView<'a> {
    pub message: OverlayMessageView<'a>,
    pub broadcast: OverlayBroadcastView<'a>,
}

impl<'a> ReadFromPacket<'a> for PublicOverlayQueryBundleView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            message: OverlayMessageView::read_from(packet, offset)?,
            broadcast: OverlayBroadcastView::read_from(packet, offset)?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OverlayMessageView<'a> {
    pub overlay: HashRef<'a>,
}

impl<'a> ReadFromPacket<'a> for OverlayMessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x75252420 => Ok(Self {
                overlay: read_fixed_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum OverlayBroadcastView<'a> {
    Broadcast(OverlayBroadcastViewBroadcast<'a>),
    BroadcastFec(OverlayBroadcastViewBroadcastFec<'a>),
    BroadcastFecShort {
        src: PublicKeyView<'a>,
        certificate: CertificateView<'a>,
        broadcast_hash: HashRef<'a>,
        part_data_hash: HashRef<'a>,
        seqno: i32,
        signature: &'a [u8],
    },
    BroadcastNotFound,
    FecCompleted {
        hash: HashRef<'a>,
    },
    FecReceived {
        hash: HashRef<'a>,
    },
    Unicast {
        data: &'a [u8],
    },
}

impl<'a> ReadFromPacket<'a> for OverlayBroadcastView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0xb15a2b6b => Ok(Self::Broadcast(OverlayBroadcastViewBroadcast::read_from(
                packet, offset,
            )?)),
            0xbad7c36a => Ok(Self::BroadcastFec(
                OverlayBroadcastViewBroadcastFec::read_from(packet, offset)?,
            )),
            0xf1881342 => Ok(Self::BroadcastFecShort {
                src: PublicKeyView::read_from(packet, offset)?,
                certificate: CertificateView::read_from(packet, offset)?,
                broadcast_hash: read_fixed_bytes(packet, offset)?,
                part_data_hash: read_fixed_bytes(packet, offset)?,
                seqno: i32::read_from(packet, offset)?,
                signature: read_bytes(packet, offset)?,
            }),
            0x95863624 => Ok(Self::BroadcastNotFound),
            0x09d76914 => Ok(Self::FecCompleted {
                hash: read_fixed_bytes(packet, offset)?,
            }),
            0xd55c14ec => Ok(Self::FecReceived {
                hash: read_fixed_bytes(packet, offset)?,
            }),
            0x33534e24 => Ok(Self::Unicast {
                data: read_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OverlayBroadcastViewBroadcast<'a> {
    pub src: PublicKeyView<'a>,
    pub certificate: CertificateView<'a>,
    pub flags: i32,
    pub data: &'a [u8],
    pub date: i32,
    pub signature: &'a [u8],
}

impl<'a> ReadFromPacket<'a> for OverlayBroadcastViewBroadcast<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            src: PublicKeyView::read_from(packet, offset)?,
            certificate: CertificateView::read_from(packet, offset)?,
            flags: i32::read_from(packet, offset)?,
            data: read_bytes(packet, offset)?,
            date: i32::read_from(packet, offset)?,
            signature: read_bytes(packet, offset)?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OverlayBroadcastViewBroadcastFec<'a> {
    pub src: PublicKeyView<'a>,
    pub certificate: CertificateView<'a>,
    pub data_hash: HashRef<'a>,
    pub data_size: i32,
    pub flags: i32,
    pub data: &'a [u8],
    pub seqno: i32,
    pub fec: FecTypeView,
    pub date: i32,
    pub signature: &'a [u8],
}

impl<'a> ReadFromPacket<'a> for OverlayBroadcastViewBroadcastFec<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            src: PublicKeyView::read_from(packet, offset)?,
            certificate: CertificateView::read_from(packet, offset)?,
            data_hash: read_fixed_bytes(packet, offset)?,
            data_size: i32::read_from(packet, offset)?,
            flags: i32::read_from(packet, offset)?,
            data: read_bytes(packet, offset)?,
            seqno: i32::read_from(packet, offset)?,
            fec: FecTypeView::read_from(packet, offset)?,
            date: i32::read_from(packet, offset)?,
            signature: read_bytes(packet, offset)?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CertificateView<'a> {
    Certificate {
        issued_by: PublicKeyView<'a>,
        expire_at: i32,
        max_size: i32,
        signature: &'a [u8],
    },
    EmptyCertificate,
}

impl<'a> ReadFromPacket<'a> for CertificateView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0xe09ed731 => Ok(Self::Certificate {
                issued_by: PublicKeyView::read_from(packet, offset)?,
                expire_at: i32::read_from(packet, offset)?,
                max_size: i32::read_from(packet, offset)?,
                signature: read_bytes(packet, offset)?,
            }),
            0x32dabccf => Ok(Self::EmptyCertificate),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CatchainUpdateView<'a> {
    pub block: CatchainBlockView<'a>,
}

impl<'a> ReadFromPacket<'a> for CatchainUpdateView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x236758c4 => Ok(Self {
                block: CatchainBlockView::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CatchainBlockView<'a> {
    pub incarnation: HashRef<'a>,
    pub src: i32,
    pub height: i32,
    pub data: CatchainBlockDataView<'a>,
    pub signature: &'a [u8],
}

impl<'a> ReadFromPacket<'a> for CatchainBlockView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            incarnation: read_fixed_bytes(packet, offset)?,
            src: i32::read_from(packet, offset)?,
            height: i32::read_from(packet, offset)?,
            data: CatchainBlockDataView::read_from(packet, offset)?,
            signature: read_bytes(packet, offset)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CatchainBlockDataView<'a> {
    pub prev: CatchainBlockDepView<'a>,
    // TODO: determine optimal size on stack
    pub deps: SmallVec<[CatchainBlockDepView<'a>; 4]>,
}

impl<'a> ReadFromPacket<'a> for CatchainBlockDataView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            prev: CatchainBlockDepView::read_from(packet, offset)?,
            deps: ReadFromPacket::read_from(packet, offset)?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CatchainBlockDepView<'a> {
    pub src: i32,
    pub height: i32,
    pub data_hash: HashRef<'a>,
    pub signature: &'a [u8],
}

impl<'a> ReadFromPacket<'a> for CatchainBlockDepView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            src: i32::read_from(packet, offset)?,
            height: i32::read_from(packet, offset)?,
            data_hash: read_fixed_bytes(packet, offset)?,
            signature: read_bytes(packet, offset)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorSessionBlockUpdateView<'a> {
    pub ts: i64,
    // TODO: determine optimal size on stack
    pub actions: SmallVec<[ValidatorSessionRoundMessageView<'a>; 4]>,
    pub state: i32,
}

impl<'a> ReadFromPacket<'a> for ValidatorSessionBlockUpdateView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x9283ce37 => Ok(Self {
                ts: i64::read_from(packet, offset)?,
                actions: ReadFromPacket::read_from(packet, offset)?,
                state: i32::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ValidatorSessionRoundMessageView<'a> {
    ApprovedBlock {
        round: i32,
        candidate: HashRef<'a>,
        signature: &'a [u8],
    },
    Commit {
        round: i32,
        candidate: HashRef<'a>,
        signature: &'a [u8],
    },
    Empty {
        round: i32,
        attempt: i32,
    },
    Precommit {
        round: i32,
        attempt: i32,
        candidate: HashRef<'a>,
    },
    RejectedBlock {
        round: i32,
        candidate: HashRef<'a>,
        reason: &'a [u8],
    },
    SubmittedBlock {
        round: i32,
        root_hash: HashRef<'a>,
        file_hash: HashRef<'a>,
        collated_data_file_hash: HashRef<'a>,
    },
    Vote {
        round: i32,
        attempt: i32,
        candidate: HashRef<'a>,
    },
    VoteFor {
        round: i32,
        attempt: i32,
        candidate: HashRef<'a>,
    },
}

impl<'a> ReadFromPacket<'a> for ValidatorSessionRoundMessageView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            0x04a5b581 => Ok(Self::ApprovedBlock {
                round: i32::read_from(packet, offset)?,
                candidate: read_fixed_bytes(packet, offset)?,
                signature: read_bytes(packet, offset)?,
            }),
            0xac129ef5 => Ok(Self::Commit {
                round: i32::read_from(packet, offset)?,
                candidate: read_fixed_bytes(packet, offset)?,
                signature: read_bytes(packet, offset)?,
            }),
            0x4a201fa9 => Ok(Self::Empty {
                round: i32::read_from(packet, offset)?,
                attempt: i32::read_from(packet, offset)?,
            }),
            0xa854b552 => Ok(Self::Precommit {
                round: i32::read_from(packet, offset)?,
                attempt: i32::read_from(packet, offset)?,
                candidate: read_fixed_bytes(packet, offset)?,
            }),
            0x95884e6b => Ok(Self::RejectedBlock {
                round: i32::read_from(packet, offset)?,
                candidate: read_fixed_bytes(packet, offset)?,
                reason: read_bytes(packet, offset)?,
            }),
            0x127624b6 => Ok(Self::SubmittedBlock {
                round: i32::read_from(packet, offset)?,
                root_hash: read_fixed_bytes(packet, offset)?,
                file_hash: read_fixed_bytes(packet, offset)?,
                collated_data_file_hash: read_fixed_bytes(packet, offset)?,
            }),
            0x9a3251c7 => Ok(Self::Vote {
                round: i32::read_from(packet, offset)?,
                attempt: i32::read_from(packet, offset)?,
                candidate: read_fixed_bytes(packet, offset)?,
            }),
            0x61f0fe2f => Ok(Self::VoteFor {
                round: i32::read_from(packet, offset)?,
                attempt: i32::read_from(packet, offset)?,
                candidate: read_fixed_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

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

pub trait ReadFromPacket<'a>: Sized {
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
pub enum PacketContentsError {
    #[error("Unexpected packet EOF")]
    UnexpectedEof,
    #[error("Unknown constructor")]
    UnknownConstructor,
    #[error("Invalid signature")]
    InvalidSignature,
}
