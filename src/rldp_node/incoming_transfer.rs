use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use ton_api::{ton, IntoBoxed};

use super::decoder::*;
use super::{MessagePart, TransferId};
use crate::utils::*;

pub struct IncomingTransfer {
    buffer: Vec<u8>,
    complete: ton::rldp::MessagePart,
    confirm: ton::rldp::MessagePart,
    confirm_count: usize,
    data: Vec<u8>,
    decoder: Option<RaptorQDecoder>,
    part: u32,
    state: Arc<IncomingTransferState>,
    total_size: Option<usize>,
}

impl IncomingTransfer {
    pub fn new(transfer_id: TransferId) -> Self {
        Self {
            buffer: Vec::new(),
            complete: ton::rldp::messagepart::Complete {
                transfer_id: ton::int256(transfer_id),
                part: 0,
            }
            .into_boxed(),
            confirm: ton::rldp::messagepart::Confirm {
                transfer_id: ton::int256(transfer_id),
                part: 0,
                seqno: 0,
            }
            .into_boxed(),
            confirm_count: 0,
            data: Vec::new(),
            decoder: None,
            part: 0,
            state: Default::default(),
            total_size: None,
        }
    }

    pub fn complete(&mut self) -> &mut ton::rldp::messagepart::Complete {
        match &mut self.complete {
            ton::rldp::MessagePart::Rldp_Complete(message) => message,
            // SAFETY: `self.complete` is only initialized in `IncomingTransfer::new`
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    pub fn confirm(&mut self) -> &mut ton::rldp::messagepart::Confirm {
        match &mut self.confirm {
            ton::rldp::MessagePart::Rldp_Confirm(message) => message,
            // SAFETY: `self.confirm` is only initialized in `IncomingTransfer::new`
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    pub fn total_size(&self) -> Option<usize> {
        self.total_size
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn process_chunk(&mut self, message: MessagePart) -> Result<Option<&[u8]>> {
        // Check FEC type
        let fec_type = match message.fec_type {
            Some(fec_type) => fec_type,
            None => return Err(IncomingTransferError::UnsupportedFecType.into()),
        };

        // Initialize `total_size` on first message
        let total_size = match self.total_size {
            Some(total_size) if total_size != message.total_size as usize => {
                return Err(IncomingTransferError::TotalSizeMismatch.into())
            }
            Some(total_size) => total_size,
            None => {
                let total_size = message.total_size as usize;
                self.total_size = Some(total_size);
                self.data.reserve_exact(total_size);
                total_size
            }
        };

        // Check message part
        let decoder = match (message.part as u32).cmp(&self.part) {
            std::cmp::Ordering::Equal => match &mut self.decoder {
                Some(decoder) if decoder.params() != &fec_type => {
                    return Err(IncomingTransferError::PacketParametersMismatch.into())
                }
                Some(decoder) => decoder,
                None => self
                    .decoder
                    .get_or_insert_with(|| RaptorQDecoder::with_params(fec_type)),
            },
            std::cmp::Ordering::Less => {
                self.complete().part = message.part;
                serialize_inplace(&mut self.buffer, &self.complete)?;
                return Ok(Some(self.buffer.as_slice()));
            }
            std::cmp::Ordering::Greater => return Ok(None),
        };

        // Decode message data
        match decoder.decode(message.seqno as u32, message.data) {
            Some(data) if data.len() + self.data.len() > total_size => {
                Err(IncomingTransferError::TooBigTransferSize.into())
            }
            Some(mut data) => {
                self.data.append(&mut data);

                // Reset decoder
                if self.data.len() < total_size {
                    self.decoder = None;
                    self.part += 1;
                    self.confirm_count = 0;
                }

                self.complete().part = message.part;
                serialize_inplace(&mut self.buffer, &self.complete)?;
                Ok(Some(self.buffer.as_slice()))
            }
            None if self.confirm_count == 9 => {
                let max_seqno = decoder.seqno() as i32;
                let confirm = self.confirm();
                confirm.part = message.part;
                confirm.seqno = max_seqno;
                self.confirm_count = 0;
                serialize_inplace(&mut self.buffer, &self.confirm)?;
                Ok(Some(self.buffer.as_slice()))
            }
            None => {
                self.confirm_count += 1;
                Ok(None)
            }
        }
    }

    pub fn state(&self) -> &Arc<IncomingTransferState> {
        &self.state
    }
}

#[derive(Default)]
pub struct IncomingTransferState {
    updates: AtomicU32,
}

impl IncomingTransferState {
    pub fn updates(&self) -> u32 {
        self.updates.load(Ordering::Acquire)
    }

    pub fn increase_updates(&self) {
        self.updates.fetch_add(1, Ordering::Release);
    }
}

#[derive(thiserror::Error, Debug)]
enum IncomingTransferError {
    #[error("Unsupported FEC type")]
    UnsupportedFecType,
    #[error("Total packet size mismatch")]
    TotalSizeMismatch,
    #[error("Packet parameters mismatch")]
    PacketParametersMismatch,
    #[error("Too big size for RLDP transfer")]
    TooBigTransferSize,
}
