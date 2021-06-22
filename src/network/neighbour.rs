use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};

use ton_api::ton;

use crate::utils::*;

pub struct Neighbour {
    peer_id: AdnlNodeIdShort,

    last_ping: AtomicU64,

    proto_version: AtomicI32,
    capabilities: AtomicI64,

    roundtrip_adnl: AtomicU64,
    roundtrip_rldp: AtomicU64,

    all_attempts: AtomicU64,
    fail_attempts: AtomicU64,
    penalty_points: AtomicU32,
    active_check: AtomicBool,
    unreliability: AtomicU32,
}

impl Neighbour {
    pub fn new(peer_id: AdnlNodeIdShort) -> Self {
        Self {
            peer_id,
            last_ping: Default::default(),
            proto_version: Default::default(),
            capabilities: Default::default(),
            roundtrip_adnl: Default::default(),
            roundtrip_rldp: Default::default(),
            all_attempts: Default::default(),
            fail_attempts: Default::default(),
            penalty_points: Default::default(),
            active_check: Default::default(),
            unreliability: Default::default(),
        }
    }

    pub fn peer_id(&self) -> &AdnlNodeIdShort {
        &self.peer_id
    }

    pub fn last_ping(&self) -> u64 {
        self.last_ping.load(Ordering::Acquire)
    }

    pub fn set_last_ping(&self, elapsed: u64) {
        self.last_ping.store(elapsed, Ordering::Release)
    }

    pub fn update_proto_version(&self, data: &ton::ton_node::Capabilities) {
        self.proto_version.store(*data.version(), Ordering::Release);
        self.capabilities
            .store(*data.capabilities(), Ordering::Release);
    }

    pub fn query_success(&self, roundtrip: u64, is_rldp: bool) {
        loop {
            let old_unreliability = self.unreliability.load(Ordering::Acquire);
            if old_unreliability > 0 {
                let new_unreliability = old_unreliability - 1;
                if self
                    .unreliability
                    .compare_exchange(
                        old_unreliability,
                        new_unreliability,
                        Ordering::Release,
                        Ordering::Relaxed,
                    )
                    .is_err()
                {
                    continue;
                }
            }
            break;
        }
        if is_rldp {
            self.update_roundtrip_rldp(roundtrip)
        } else {
            self.update_roundtrip_adnl(roundtrip)
        }
    }

    pub fn query_failed(&self, roundtrip: u64, is_rldp: bool) {
        self.unreliability.fetch_add(1, Ordering::Release);
        if is_rldp {
            self.update_roundtrip_rldp(roundtrip)
        } else {
            self.update_roundtrip_adnl(roundtrip)
        }
    }

    pub fn roundtrip_adnl(&self) -> Option<u64> {
        fetch_roundtrip(&self.roundtrip_adnl)
    }

    pub fn roundtrip_rldp(&self) -> Option<u64> {
        fetch_roundtrip(&self.roundtrip_rldp)
    }

    pub fn update_roundtrip_adnl(&self, roundtrip: u64) {
        set_roundtrip(&self.roundtrip_adnl, roundtrip)
    }

    pub fn update_roundtrip_rldp(&self, roundtrip: u64) {
        set_roundtrip(&self.roundtrip_rldp, roundtrip)
    }
}

fn fetch_roundtrip(storage: &AtomicU64) -> Option<u64> {
    let roundtrip = storage.load(Ordering::Acquire);
    if roundtrip == 0 {
        None
    } else {
        Some(roundtrip)
    }
}

fn set_roundtrip(storage: &AtomicU64, roundtrip: u64) {
    let roundtrip_old = storage.load(Ordering::Acquire);
    let roundtrip = if roundtrip_old > 0 {
        (roundtrip_old + roundtrip) / 2
    } else {
        roundtrip
    };
    storage.store(roundtrip, Ordering::Release);
}
