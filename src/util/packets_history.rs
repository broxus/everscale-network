use std::sync::atomic::{AtomicU64, Ordering};

pub struct PacketsHistory {
    mask: Option<HistoryBits>,
    seqno: AtomicU64,
}

impl PacketsHistory {
    pub fn for_send() -> Self {
        Self {
            mask: None,
            seqno: Default::default(),
        }
    }

    pub fn for_recv() -> Self {
        Self {
            mask: Some(Default::default()),
            seqno: Default::default(),
        }
    }

    pub fn reset(&self) {
        if let Some(mask) = &self.mask {
            loop {
                let index = mask.index.load(Ordering::Acquire);
                if index == IN_TRANSIT {
                    // TODO: yield
                    continue;
                }

                if mask
                    .index
                    .compare_exchange(index, IN_TRANSIT, Ordering::Release, Ordering::Relaxed)
                    .is_err()
                {
                    continue;
                }
                break;
            }

            for i in 0..HISTORY_SIZE {
                let value = if i == HISTORY_SIZE / 2 { 1 } else { 0 };
                mask.bits[i].store(value, Ordering::Release);
            }
        }

        self.seqno.store(0, Ordering::Release);
        if let Some(mask) = &self.mask {
            let _ =
                mask.index
                    .compare_exchange(IN_TRANSIT, 0, Ordering::Release, Ordering::Relaxed);
        }
    }

    pub fn seqno(&self) -> u64 {
        self.seqno.load(Ordering::Acquire)
    }

    pub fn bump_seqno(&self) -> u64 {
        self.seqno.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn deliver_packet(&self, seqno: u64) -> bool {
        let mask = match &self.mask {
            Some(mask) => mask,
            None => loop {
                let last_seqno = self.seqno.load(Ordering::Acquire);
                if last_seqno < seqno
                    && self
                        .seqno
                        .compare_exchange(last_seqno, seqno, Ordering::Release, Ordering::Relaxed)
                        .is_err()
                {
                    continue;
                }
                return true;
            },
        };

        let seqno_masked = seqno & INDEX_MASK;
        let seqno_normalized = seqno & !INDEX_MASK;

        loop {
            let index = mask.index.load(Ordering::Acquire);
            if index == IN_TRANSIT {
                // TODO: yield
                continue;
            }

            let index_masked = index & INDEX_MASK;
            let index_normalized = index & !INDEX_MASK;

            if index_normalized > seqno_normalized + INDEX_MASK + 1 {
                tracing::debug!(seqno, index_normalized, "peer packet is too old");
                return false;
            }

            let mask_bit = 1 << (seqno_masked % 64);
            let mask_offset = match index_normalized.cmp(&seqno_normalized) {
                std::cmp::Ordering::Greater => Some(0),
                std::cmp::Ordering::Equal => Some(HISTORY_SIZE / 2),
                std::cmp::Ordering::Less => None,
            };

            let next_index = match mask_offset {
                Some(mask_offset) => {
                    let mask_offset = mask_offset + seqno_masked as usize / 64;
                    let already_delivered =
                        mask.bits[mask_offset].load(Ordering::Acquire) & mask_bit;
                    if mask.index.load(Ordering::Acquire) != index {
                        continue;
                    }

                    if already_delivered != 0 {
                        tracing::trace!(seqno, "peer packet was already received");
                        return false;
                    }

                    if mask
                        .index
                        .compare_exchange(index, IN_TRANSIT, Ordering::Release, Ordering::Relaxed)
                        .is_err()
                    {
                        continue;
                    }

                    mask.bits[mask_offset].fetch_or(mask_bit, Ordering::Release);

                    index
                }
                None => {
                    if mask
                        .index
                        .compare_exchange(index, IN_TRANSIT, Ordering::Release, Ordering::Relaxed)
                        .is_err()
                    {
                        continue;
                    }

                    if index_normalized + INDEX_MASK + 1 == seqno_normalized {
                        for i in 0..HISTORY_SIZE / 2 {
                            mask.bits[i].store(
                                mask.bits[i + HISTORY_SIZE / 2].load(Ordering::Acquire),
                                Ordering::Release,
                            )
                        }

                        for bits in &mask.bits[HISTORY_SIZE / 2..HISTORY_SIZE] {
                            bits.store(0, Ordering::Relaxed)
                        }
                    } else {
                        for bits in &mask.bits {
                            bits.store(0, Ordering::Release)
                        }
                    }

                    index_normalized
                }
            };

            let last_seqno = self.seqno.load(Ordering::Acquire);
            if last_seqno < seqno {
                self.seqno.store(seqno, Ordering::Release);
            }

            let index_masked = (index_masked + 1) & !INDEX_MASK;
            let _ = mask.index.compare_exchange(
                IN_TRANSIT,
                next_index | index_masked,
                Ordering::Release,
                Ordering::Relaxed,
            );

            break;
        }

        true
    }
}

#[derive(Default)]
struct HistoryBits {
    index: AtomicU64,
    bits: [AtomicU64; HISTORY_SIZE],
}

const INDEX_MASK: u64 = HISTORY_BITS as u64 / 2 - 1;
const IN_TRANSIT: u64 = 0xFFFFFFFFFFFFFFFF;

const HISTORY_BITS: usize = 512;
const HISTORY_SIZE: usize = HISTORY_BITS / 64;
