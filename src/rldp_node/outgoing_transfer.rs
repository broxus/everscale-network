use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use rand::Rng;
use ton_api::{ton, IntoBoxed};

use super::encoder::*;
use super::TransferId;
use crate::utils::*;

pub struct OutgoingTransfer {
    data: Vec<u8>,
    buffer: Vec<u8>,
    encoder: Option<RaptorQEncoder>,
    message: ton::rldp::MessagePart,
    state: Arc<OutgoingTransferState>,
}

impl OutgoingTransfer {
    pub fn new(data: Vec<u8>, transfer_id: Option<TransferId>) -> Self {
        let transfer_id = transfer_id.unwrap_or_else(|| rand::thread_rng().gen());

        let message = ton::rldp::messagepart::MessagePart {
            transfer_id: ton::int256(transfer_id),
            fec_type: ton::fec::type_::RaptorQ {
                data_size: 0,
                symbol_size: MAX_TRANSMISSION_UNIT as i32,
                symbols_count: 0,
            }
            .into_boxed(),
            part: 0,
            total_size: 0,
            seqno: 0,
            data: Default::default(),
        }
        .into_boxed();

        Self {
            data,
            buffer: Vec::new(),
            encoder: None,
            message,
            state: Default::default(),
        }
    }

    pub fn message(&mut self) -> &mut ton::rldp::messagepart::MessagePart {
        match &mut self.message {
            ton::rldp::MessagePart::Rldp_MessagePart(message) => message,
            // SAFETY: `self.message` is only initialized in `OutgoingTransfer::new`
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    pub fn start_next_part(&mut self) -> Result<Option<u32>> {
        if self.is_finished() {
            return Ok(None);
        }

        let part = self.state.part() as usize;
        let processed = part * SLICE;
        let total = self.data.len();
        if processed >= total {
            return Ok(None);
        }

        let chunk_size = std::cmp::min(total - processed, SLICE);
        let encoder = RaptorQEncoder::with_data(&self.data[processed..processed + chunk_size]);

        let message = self.message();
        message.part = part as i32;
        message.total_size = total as i64;

        let result = encoder.params().symbols_count;
        match &mut message.fec_type {
            ton::fec::Type::Fec_RaptorQ(fec_type) => {
                fec_type.data_size = encoder.params().data_size;
                fec_type.symbols_count = result;
            }
            _ => return Err(OutgoingTransferError::UnsupportedFecType.into()),
        }

        self.encoder = Some(encoder);
        Ok((result > 0).then(|| result as u32))
    }

    pub fn prepare_chunk(&mut self) -> Result<&[u8]> {
        let encoder = match &mut self.encoder {
            Some(encoder) => encoder,
            None => return Err(OutgoingTransferError::EncoderIsNotReady.into()),
        };

        let mut seqno_out = self.state.seqno_out();
        let previous_seqno_out = seqno_out;

        let chunk = encoder.encode(&mut seqno_out)?;

        let message = self.message();
        message.seqno = seqno_out as i32;
        message.data = ton::bytes(chunk);

        let seqno_in = self.state.seqno_in();
        if seqno_out - seqno_in <= WINDOW {
            if previous_seqno_out == seqno_out {
                seqno_out += 1;
            }
            self.state.set_seqno_out(seqno_out);
        }

        serialize_inplace(&mut self.buffer, &self.message);

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
        let seqno_out = self.seqno_out();
        if seqno > seqno_out {
            let _ = self.seqno_out.compare_exchange(
                seqno_out,
                seqno,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }

    pub fn seqno_in(&self) -> u32 {
        self.seqno_in.load(Ordering::Acquire)
    }

    pub fn set_seqno_in(&self, seqno: u32) {
        if seqno > self.seqno_out() {
            return;
        }

        let seqno_in = self.seqno_in();
        if seqno > seqno_in {
            let _ = self.seqno_in.compare_exchange(
                seqno_in,
                seqno,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

const WINDOW: u32 = 1000;
const SLICE: usize = 2000000;

#[derive(thiserror::Error, Debug)]
enum OutgoingTransferError {
    #[error("Encoder is not ready")]
    EncoderIsNotReady,
    #[error("Unsupported FEC type")]
    UnsupportedFecType,
    #[error("Part mismatch")]
    PartMismatch,
}
