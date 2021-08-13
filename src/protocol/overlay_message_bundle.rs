use smallvec::SmallVec;

use super::overlay_broadcast::*;
use super::prelude::*;

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
