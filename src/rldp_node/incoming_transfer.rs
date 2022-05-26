use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;

use super::decoder::*;
use super::{MessagePart, TransferId};
use crate::proto;

pub struct IncomingTransfer {
    buffer: Vec<u8>,
    transfer_id: TransferId,
    max_answer_size: u32,
    confirm_count: usize,
    data: Vec<u8>,
    decoder: Option<RaptorQDecoder>,
    part: u32,
    state: Arc<IncomingTransferState>,
    total_size: Option<usize>,
}

impl IncomingTransfer {
    pub fn new(transfer_id: TransferId, max_answer_size: u32) -> Self {
        Self {
            buffer: Vec::new(),
            transfer_id,
            max_answer_size,
            confirm_count: 0,
            data: Vec::new(),
            decoder: None,
            part: 0,
            state: Default::default(),
            total_size: None,
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

    pub fn take_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    pub fn process_chunk(&mut self, message: MessagePart) -> Result<Option<&[u8]>> {
        // Check FEC type
        let fec_type = message.fec_type;

        // Initialize `total_size` on first message
        let total_size = match self.total_size {
            Some(total_size) if total_size != message.total_size as usize => {
                return Err(IncomingTransferError::TotalSizeMismatch.into())
            }
            Some(total_size) => total_size,
            None => {
                let total_size = message.total_size as usize;
                if total_size > self.max_answer_size as usize {
                    return Err(IncomingTransferError::TooBigTransferSize.into());
                }
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
                tl_proto::serialize_into(
                    proto::rldp::MessagePart::Complete {
                        transfer_id: &self.transfer_id,
                        part: message.part,
                    },
                    &mut self.buffer,
                );
                return Ok(Some(&self.buffer));
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

                tl_proto::serialize_into(
                    proto::rldp::MessagePart::Complete {
                        transfer_id: &self.transfer_id,
                        part: message.part,
                    },
                    &mut self.buffer,
                );
                Ok(Some(&self.buffer))
            }
            None if self.confirm_count == 9 => {
                self.confirm_count = 0;
                tl_proto::serialize_into(
                    proto::rldp::MessagePart::Confirm {
                        transfer_id: &self.transfer_id,
                        part: message.part,
                        seqno: decoder.seqno(),
                    },
                    &mut self.buffer,
                );
                Ok(Some(&self.buffer))
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
    #[error("Total packet size mismatch")]
    TotalSizeMismatch,
    #[error("Packet parameters mismatch")]
    PacketParametersMismatch,
    #[error("Too big size for RLDP transfer")]
    TooBigTransferSize,
}
