use parking_lot::RwLock;

#[derive(Debug, Default)]
pub struct AdnlReceivedMask {
    state: RwLock<AdnlReceivedMaskState>,
}

impl AdnlReceivedMask {
    pub fn reset(&self) {
        let mut state = self.state.write();
        *state = Default::default();
    }

    pub fn seqno(&self) -> i64 {
        self.state.read().seqno as i64
    }

    pub fn bump_seqno(&self) -> i64 {
        let mut state = self.state.write();
        state.seqno += 1;
        state.seqno
    }

    #[allow(dead_code)]
    pub fn is_packet_delivered(&self, seqno: i64) -> bool {
        if seqno <= 0 {
            return false;
        }

        let state = self.state.read();
        match seqno {
            seqno if seqno + 64 <= state.seqno => true,
            seqno if seqno > state.seqno => false,
            seqno => (state.mask & (1u64 << (state.seqno - seqno))) > 0,
        }
    }

    pub fn deliver_packet(&self, seqno: i64) -> Result<(), AdnlReceivedMaskError> {
        if seqno <= 0 {
            return Err(AdnlReceivedMaskError::InvalidSeqno);
        }

        let mut state = self.state.write();

        match seqno {
            seqno if seqno + 64 <= state.seqno => {
                return Err(AdnlReceivedMaskError::AlreadyDelivered)
            }
            seqno if seqno <= state.seqno => {
                if (state.mask & (1u64 << (state.seqno - seqno))) > 0 {
                    return Err(AdnlReceivedMaskError::AlreadyDelivered);
                }
            }
            _ => {}
        }

        if seqno <= state.seqno {
            state.mask |= 1u64 << (state.seqno - seqno);
        } else {
            let old = state.seqno;
            state.seqno = seqno;
            if seqno - old >= 64 {
                state.mask = 1;
            } else {
                state.mask <<= seqno - old;
                state.mask |= 1;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
struct AdnlReceivedMaskState {
    seqno: i64,
    mask: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum AdnlReceivedMaskError {
    #[error("Packet already delivered")]
    AlreadyDelivered,
    #[error("Invalid packet seqno")]
    InvalidSeqno,
}
