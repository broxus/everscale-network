use super::fec_type::*;
use super::prelude::*;
use super::public_key::*;

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
