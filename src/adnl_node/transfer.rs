use std::ops::Deref;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use sha2::Digest;
use ton_api::ton;

use crate::utils::*;

pub type TransferId = [u8; 32];

pub struct Transfer {
    /// Data parts labeled with offset
    parts: DashMap<usize, Vec<u8>>,
    /// Received data length
    received_len: AtomicUsize,
    /// Total data length
    total_len: usize,
    /// Transfer timings used to check its validity
    timings: UpdatedAt,
}

impl Transfer {
    pub fn new(total_len: usize) -> Self {
        Self {
            parts: Default::default(),
            received_len: Default::default(),
            total_len,
            timings: Default::default(),
        }
    }

    pub fn timings(&self) -> &UpdatedAt {
        &self.timings
    }

    pub fn add_part(
        &self,
        offset: usize,
        data: Vec<u8>,
        transfer_id: &TransferId,
    ) -> Result<Option<ton::adnl::Message>> {
        let length = data.len();
        self.parts.insert(offset, data);

        // Increase received length.
        // This part heavily relies on ordering, so hope that it works as expected
        self.received_len.fetch_add(length, Ordering::Release);

        // Check if it is equal to the total length and make sure it will be big enough to fail
        // next check on success
        let mut received = self
            .received_len
            .compare_exchange(
                self.total_len,
                self.total_len * 2,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .unwrap_or_else(|was| was);

        // Handle part
        match received.cmp(&self.total_len) {
            std::cmp::Ordering::Equal => {
                log::debug!(
                    "Finished ADNL transfer ({} of {})",
                    received,
                    self.total_len
                );

                // Combine all parts
                received = 0;
                let mut buffer = Vec::with_capacity(self.total_len);
                while received < self.total_len {
                    if let Some(data) = self.parts.get(&received) {
                        let data = data.value();
                        received += data.len();
                        buffer.extend_from_slice(data);
                    } else {
                        return Err(TransferError::PartMissing.into());
                    }
                }

                // Check hash
                let hash = sha2::Sha256::digest(&buffer);
                if hash.as_slice() != transfer_id {
                    return Err(TransferError::InvalidHash.into());
                }

                // Parse message
                let message = deserialize(&buffer)?
                    .downcast::<ton::adnl::Message>()
                    .map_err(|_| TransferError::InvalidMessage)?;

                // Done
                Ok(Some(message))
            }
            std::cmp::Ordering::Greater => Err(TransferError::ReceivedTooMuch.into()),
            std::cmp::Ordering::Less => {
                log::debug!(
                    "Received ADNL transfer part ({} of {})",
                    received,
                    self.total_len
                );
                Ok(None)
            }
        }
    }
}

pub struct TransferPartRef<'a>(Ref<'a, usize, Vec<u8>>);

impl<'a> Deref for TransferPartRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.value().as_slice()
    }
}

#[derive(thiserror::Error, Debug)]
enum TransferError {
    #[error("Invalid transfer part (received too much)")]
    ReceivedTooMuch,
    #[error("Invalid transfer (part is missing)")]
    PartMissing,
    #[error("Invalid transfer data hash")]
    InvalidHash,
    #[error("Invalid transfer message")]
    InvalidMessage,
}
