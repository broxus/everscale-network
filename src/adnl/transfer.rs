use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};

use once_cell::race::OnceNonZeroUsize;
use sha2::Digest;

use crate::utils::*;

pub type TransferId = [u8; 32];

/// Multipart transfer
///
/// It is used to collect multiple values of ADNL `Part` messages.
///
/// See [crate::proto::adnl::Message]
pub struct Transfer {
    /// Data parts labeled with offset
    parts: FxDashMap<usize, Vec<u8>>,
    /// Received data length
    received_len: AtomicUsize,
    /// Total data length
    total_len: usize,
    /// Transfer timings used to check its validity
    timings: UpdatedAt,
}

impl Transfer {
    /// Creates new multipart transfer with target length in bytes
    pub fn new(total_len: usize) -> Self {
        // SAFETY: expression is always nonzero
        let shard_count = DEFAULT_SHARD_COUNT.get_or_init(|| unsafe {
            NonZeroUsize::new_unchecked(
                (std::thread::available_parallelism().map_or(1, usize::from) * 4)
                    .next_power_of_two(),
            )
        });

        Self {
            parts: FxDashMap::with_capacity_and_hasher_and_shard_amount(
                0,
                Default::default(),
                shard_count.get(),
            ),
            received_len: Default::default(),
            total_len,
            timings: Default::default(),
        }
    }

    /// Returns transfer timings info (when it was last updated)
    #[inline(always)]
    pub fn timings(&self) -> &UpdatedAt {
        &self.timings
    }

    /// Tries to add new part to the transfer at given offset
    ///
    /// Will do nothing if part at given offset already exists
    pub fn add_part(
        &self,
        offset: usize,
        data: Vec<u8>,
        transfer_id: &TransferId,
    ) -> Result<Option<Vec<u8>>, TransferError> {
        let length = data.len();
        if self.parts.insert(offset, data).is_some() {
            return Ok(None);
        }

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
            .unwrap_or_else(std::convert::identity);

        // Handle part
        match received.cmp(&self.total_len) {
            std::cmp::Ordering::Equal => {
                tracing::debug!("Finished ADNL transfer ({received} of {})", self.total_len);

                // Combine all parts
                received = 0;
                let mut buffer = Vec::with_capacity(self.total_len);
                while received < self.total_len {
                    if let Some(data) = self.parts.get(&received) {
                        let data = data.value();
                        received += data.len();
                        buffer.extend_from_slice(data);
                    } else {
                        return Err(TransferError::PartMissing);
                    }
                }

                // Check hash
                let hash = sha2::Sha256::digest(&buffer);
                if hash.as_slice() != transfer_id {
                    return Err(TransferError::InvalidHash);
                }

                // Done
                Ok(Some(buffer))
            }
            std::cmp::Ordering::Greater => Err(TransferError::ReceivedTooMuch),
            std::cmp::Ordering::Less => {
                tracing::trace!(
                    "Received ADNL transfer part ({received} of {})",
                    self.total_len
                );
                Ok(None)
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TransferError {
    #[error("Invalid transfer part (received too much)")]
    ReceivedTooMuch,
    #[error("Invalid transfer (part is missing)")]
    PartMissing,
    #[error("Invalid transfer data hash")]
    InvalidHash,
}

static DEFAULT_SHARD_COUNT: OnceNonZeroUsize = OnceNonZeroUsize::new();
