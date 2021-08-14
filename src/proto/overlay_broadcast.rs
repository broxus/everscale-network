use std::io::Write;

use super::fec_type::*;
use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Copy, Clone)]
pub enum OverlayBroadcastView<'a> {
    Broadcast(OverlayBroadcastViewBroadcast<'a>),
    BroadcastFec(OverlayBroadcastViewBroadcastFec<'a>),
    BroadcastFecShort(OverlayBroadcastViewBroadcastFecShort<'a>),
    BroadcastNotFound,
    FecCompleted { hash: HashRef<'a> },
    FecReceived { hash: HashRef<'a> },
    Unicast { data: &'a [u8] },
}

impl Boxed for OverlayBroadcastView<'_> {}

impl<'a> ReadFromPacket<'a> for OverlayBroadcastView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_OVERLAY_BROADCAST_BROADCAST => Ok(Self::Broadcast(
                OverlayBroadcastViewBroadcast::read_from(packet, offset)?,
            )),
            ID_OVERLAY_BROADCAST_BROADCAST_FEC => Ok(Self::BroadcastFec(
                OverlayBroadcastViewBroadcastFec::read_from(packet, offset)?,
            )),
            ID_OVERLAY_BROADCAST_BROADCAST_FEC_SHORT => Ok(Self::BroadcastFecShort(
                OverlayBroadcastViewBroadcastFecShort::read_from(packet, offset)?,
            )),
            ID_OVERLAY_BROADCAST_BROADCAST_NOT_FOUND => Ok(Self::BroadcastNotFound),
            ID_OVERLAY_BROADCAST_FEC_COMPLETED => Ok(Self::FecCompleted {
                hash: read_fixed_bytes(packet, offset)?,
            }),
            ID_OVERLAY_BROADCAST_FEC_RECEIVED => Ok(Self::FecReceived {
                hash: read_fixed_bytes(packet, offset)?,
            }),
            ID_OVERLAY_BROADCAST_UNICAST => Ok(Self::Unicast {
                data: read_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for OverlayBroadcastView<'_> {
    fn max_size_hint(&self) -> usize {
        4 + match self {
            Self::Broadcast(b) => b.max_size_hint(),
            Self::BroadcastFec(b) => b.max_size_hint(),
            Self::BroadcastFecShort(b) => b.max_size_hint(),
            Self::BroadcastNotFound => 0,
            Self::FecCompleted { hash } => hash.max_size_hint(),
            Self::FecReceived { hash } => hash.max_size_hint(),
            Self::Unicast { data } => data.max_size_hint(),
        }
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Broadcast(b) => {
                ID_OVERLAY_BROADCAST_BROADCAST.write_to(packet)?;
                b.write_to(packet)
            }
            Self::BroadcastFec(b) => {
                ID_OVERLAY_BROADCAST_BROADCAST_FEC.write_to(packet)?;
                b.write_to(packet)
            }
            Self::BroadcastFecShort(b) => {
                ID_OVERLAY_BROADCAST_BROADCAST_FEC_SHORT.write_to(packet)?;
                b.write_to(packet)
            }
            Self::BroadcastNotFound => ID_OVERLAY_BROADCAST_BROADCAST_NOT_FOUND.write_to(packet),
            Self::FecCompleted { hash } => {
                ID_OVERLAY_BROADCAST_FEC_COMPLETED.write_to(packet)?;
                hash.write_to(packet)
            }
            Self::FecReceived { hash } => {
                ID_OVERLAY_BROADCAST_FEC_RECEIVED.write_to(packet)?;
                hash.write_to(packet)
            }
            Self::Unicast { data } => {
                ID_OVERLAY_BROADCAST_UNICAST.write_to(packet)?;
                data.write_to(packet)
            }
        }
    }
}

const ID_OVERLAY_BROADCAST_BROADCAST: u32 = 0xb15a2b6b;
const ID_OVERLAY_BROADCAST_BROADCAST_FEC: u32 = 0xbad7c36a;
const ID_OVERLAY_BROADCAST_BROADCAST_FEC_SHORT: u32 = 0xf1881342;
const ID_OVERLAY_BROADCAST_BROADCAST_NOT_FOUND: u32 = 0x95863624;
const ID_OVERLAY_BROADCAST_FEC_COMPLETED: u32 = 0x09d76914;
const ID_OVERLAY_BROADCAST_FEC_RECEIVED: u32 = 0xd55c14ec;
const ID_OVERLAY_BROADCAST_UNICAST: u32 = 0x33534e24;

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

impl WriteToPacket for OverlayBroadcastViewBroadcast<'_> {
    fn max_size_hint(&self) -> usize {
        self.src.max_size_hint()
            + self.certificate.max_size_hint()
            + self.flags.max_size_hint()
            + self.data.max_size_hint()
            + self.date.max_size_hint()
            + self.signature.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.src.write_to(packet)?;
        self.certificate.write_to(packet)?;
        self.flags.write_to(packet)?;
        self.data.write_to(packet)?;
        self.date.write_to(packet)?;
        self.signature.write_to(packet)
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
    pub fec: FecType,
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
            fec: FecType::read_from(packet, offset)?,
            date: i32::read_from(packet, offset)?,
            signature: read_bytes(packet, offset)?,
        })
    }
}

impl WriteToPacket for OverlayBroadcastViewBroadcastFec<'_> {
    fn max_size_hint(&self) -> usize {
        self.src.max_size_hint()
            + self.certificate.max_size_hint()
            + self.data_hash.max_size_hint()
            + self.data_size.max_size_hint()
            + self.flags.max_size_hint()
            + self.data.max_size_hint()
            + self.seqno.max_size_hint()
            + self.fec.max_size_hint()
            + self.date.max_size_hint()
            + self.signature.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.src.write_to(packet)?;
        self.certificate.write_to(packet)?;
        self.data_hash.write_to(packet)?;
        self.data_size.write_to(packet)?;
        self.flags.write_to(packet)?;
        self.data.write_to(packet)?;
        self.seqno.write_to(packet)?;
        self.fec.write_to(packet)?;
        self.date.write_to(packet)?;
        self.signature.write_to(packet)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OverlayBroadcastViewBroadcastFecShort<'a> {
    pub src: PublicKeyView<'a>,
    pub certificate: CertificateView<'a>,
    pub broadcast_hash: HashRef<'a>,
    pub part_data_hash: HashRef<'a>,
    pub seqno: i32,
    pub signature: &'a [u8],
}

impl<'a> ReadFromPacket<'a> for OverlayBroadcastViewBroadcastFecShort<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(Self {
            src: PublicKeyView::read_from(packet, offset)?,
            certificate: CertificateView::read_from(packet, offset)?,
            broadcast_hash: read_fixed_bytes(packet, offset)?,
            part_data_hash: read_fixed_bytes(packet, offset)?,
            seqno: i32::read_from(packet, offset)?,
            signature: read_bytes(packet, offset)?,
        })
    }
}

impl WriteToPacket for OverlayBroadcastViewBroadcastFecShort<'_> {
    fn max_size_hint(&self) -> usize {
        self.src.max_size_hint()
            + self.certificate.max_size_hint()
            + self.broadcast_hash.max_size_hint()
            + self.part_data_hash.max_size_hint()
            + self.seqno.max_size_hint()
            + self.signature.max_size_hint()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.src.write_to(packet)?;
        self.certificate.write_to(packet)?;
        self.broadcast_hash.write_to(packet)?;
        self.part_data_hash.write_to(packet)?;
        self.seqno.write_to(packet)?;
        self.signature.write_to(packet)
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

impl Boxed for CertificateView<'_> {}

impl<'a> ReadFromPacket<'a> for CertificateView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_CERTIFICATE_CERTIFICATE => Ok(Self::Certificate {
                issued_by: PublicKeyView::read_from(packet, offset)?,
                expire_at: i32::read_from(packet, offset)?,
                max_size: i32::read_from(packet, offset)?,
                signature: read_bytes(packet, offset)?,
            }),
            ID_CERTIFICATE_EMPTY_CERTIFICATE => Ok(Self::EmptyCertificate),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for CertificateView<'_> {
    fn max_size_hint(&self) -> usize {
        4 + match self {
            CertificateView::Certificate {
                issued_by,
                expire_at,
                max_size,
                signature,
            } => {
                issued_by.max_size_hint()
                    + expire_at.max_size_hint()
                    + max_size.max_size_hint()
                    + signature.max_size_hint()
            }
            CertificateView::EmptyCertificate => 0,
        }
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            CertificateView::Certificate {
                issued_by,
                expire_at,
                max_size,
                signature,
            } => {
                ID_CERTIFICATE_CERTIFICATE.write_to(packet)?;
                issued_by.write_to(packet)?;
                expire_at.write_to(packet)?;
                max_size.write_to(packet)?;
                signature.write_to(packet)
            }
            CertificateView::EmptyCertificate => ID_CERTIFICATE_EMPTY_CERTIFICATE.write_to(packet),
        }
    }
}

const ID_CERTIFICATE_CERTIFICATE: u32 = 0xe09ed731;
const ID_CERTIFICATE_EMPTY_CERTIFICATE: u32 = 0x32dabccf;
