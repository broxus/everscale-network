use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use rand::Rng;

use super::encoder::*;
use super::transfers_cache::TransferId;
use crate::proto;

pub struct OutgoingTransfer {
    buffer: Vec<u8>,
    transfer_id: TransferId,
    data: Vec<u8>,
    current_message_part: u32,
    encoder: Option<RaptorQEncoder>,
    state: Arc<OutgoingTransferState>,
}

impl OutgoingTransfer {
    pub fn new(data: Vec<u8>, transfer_id: Option<TransferId>) -> Self {
        let transfer_id = transfer_id.unwrap_or_else(|| rand::thread_rng().gen());

        Self {
            buffer: Vec::new(),
            transfer_id,
            data,
            current_message_part: 0,
            encoder: None,
            state: Default::default(),
        }
    }

    #[inline(always)]
    pub fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Encodes next part of the message. Returns packet count which is required to be sent.
    pub fn start_next_part(&mut self) -> Result<Option<u32>> {
        if self.is_finished() {
            return Ok(None);
        }

        let total = self.data.len();
        let part = self.state.part() as usize;
        let processed = part * SLICE;
        if processed >= total {
            return Ok(None);
        }

        self.current_message_part = part as u32;

        let chunk_size = std::cmp::min(total - processed, SLICE);
        let encoder = self.encoder.insert(RaptorQEncoder::with_data(
            &self.data[processed..processed + chunk_size],
        ));

        let packet_count = encoder.params().packet_count;
        Ok(if packet_count > 0 {
            Some(packet_count)
        } else {
            None
        })
    }

    pub fn prepare_chunk(&mut self) -> Result<&[u8]> {
        let encoder = match &mut self.encoder {
            Some(encoder) => encoder,
            None => return Err(OutgoingTransferError::EncoderIsNotReady.into()),
        };

        let mut seqno_out = self.state.seqno_out();
        let previous_seqno_out = seqno_out;

        let data = encoder.encode(&mut seqno_out)?;

        let seqno_in = self.state.seqno_in();

        let mut next_seqno_out = seqno_out;
        if seqno_out - seqno_in <= WINDOW {
            if previous_seqno_out == seqno_out {
                next_seqno_out += 1;
            }
            self.state.set_seqno_out(next_seqno_out);
        }

        tl_proto::serialize_into(
            proto::rldp::MessagePart::MessagePart {
                transfer_id: &self.transfer_id,
                fec_type: *encoder.params(),
                part: self.current_message_part,
                total_size: self.data.len() as u64,
                seqno: seqno_out,
                data: &data,
            },
            &mut self.buffer,
        );
        Ok(&self.buffer)
    }

    pub fn is_finished(&self) -> bool {
        self.state.has_reply() && ((self.state.part() as usize + 1) * SLICE >= self.data.len())
    }

    pub fn is_finished_or_next_part(&self, part: u32) -> Result<bool> {
        if self.is_finished() {
            Ok(true)
        } else {
            match self.state.part() {
                x if x == part => Ok(false),
                x if x == part + 1 => Ok(true),
                _ => Err(OutgoingTransferError::PartMismatch.into()),
            }
        }
    }

    pub fn state(&self) -> &Arc<OutgoingTransferState> {
        &self.state
    }
}

#[derive(Default)]
pub struct OutgoingTransferState {
    part: AtomicU32,
    has_reply: AtomicBool,
    seqno_out: AtomicU32,
    seqno_in: AtomicU32,
}

impl OutgoingTransferState {
    pub fn part(&self) -> u32 {
        self.part.load(Ordering::Acquire)
    }

    pub fn set_part(&self, part: u32) {
        let _ = self
            .part
            .compare_exchange(part - 1, part, Ordering::Release, Ordering::Relaxed);
    }

    pub fn has_reply(&self) -> bool {
        self.has_reply.load(Ordering::Acquire)
    }

    pub fn set_reply(&self) {
        self.has_reply.store(true, Ordering::Release);
    }

    pub fn seqno_out(&self) -> u32 {
        self.seqno_out.load(Ordering::Acquire)
    }

    pub fn set_seqno_out(&self, seqno: u32) {
        self.seqno_out.fetch_max(seqno, Ordering::Release);
    }

    pub fn seqno_in(&self) -> u32 {
        self.seqno_in.load(Ordering::Acquire)
    }

    pub fn set_seqno_in(&self, seqno: u32) {
        if seqno > self.seqno_out() {
            return;
        }
        self.seqno_in.fetch_max(seqno, Ordering::Release);
    }
}

const WINDOW: u32 = 1000;
const SLICE: usize = 2000000;

#[derive(thiserror::Error, Debug)]
enum OutgoingTransferError {
    #[error("Encoder is not ready")]
    EncoderIsNotReady,
    #[error("Part mismatch")]
    PartMismatch,
}
