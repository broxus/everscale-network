use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use dashmap::DashMap;

use crate::address_list::*;
use crate::node_id::*;
use crate::received_mask::*;

pub type AdnlPeers = DashMap<AdnlNodeIdShort, AdnlPeer>;

pub struct AdnlPeer {
    id: AdnlNodeIdFull,
    ip_address: AtomicU64,
    receiver_state: AdnlPeerState,
    sender_state: AdnlPeerState,
}

impl AdnlPeer {
    pub fn new(reinit_date: i32, ip_address: AdnlAddressUdp, id: AdnlNodeIdFull) -> Self {
        Self {
            id,
            ip_address: AtomicU64::new(ip_address.into()),
            receiver_state: AdnlPeerState::for_receive_with_reinit_date(reinit_date),
            sender_state: AdnlPeerState::for_send(),
        }
    }

    pub fn id(&self) -> &AdnlNodeIdFull {
        &self.id
    }

    pub fn ip_address(&self) -> AdnlAddressUdp {
        self.ip_address.load(Ordering::Acquire).into()
    }

    pub fn set_ip_address(&self, ip_address: AdnlAddressUdp) {
        self.ip_address.store(ip_address.into(), Ordering::Release);
    }

    pub fn receiver_state(&self) -> &AdnlPeerState {
        &self.receiver_state
    }

    pub fn sender_state(&self) -> &AdnlPeerState {
        &self.sender_state
    }

    pub fn clone_with_reinit(&self) -> Self {
        let reinit_date = self.receiver_state.reinit_date();

        Self {
            id: self.id,
            ip_address: AtomicU64::from(self.ip_address.load(Ordering::Acquire)),
            receiver_state: AdnlPeerState::for_receive_with_reinit_date(reinit_date + 1),
            sender_state: AdnlPeerState::for_send(),
        }
    }
}

pub struct AdnlPeerState {
    mask: AdnlReceivedMask,
    reinit_date: AtomicI32,
}

impl AdnlPeerState {
    fn for_receive_with_reinit_date(reinit_date: i32) -> Self {
        Self {
            mask: Default::default(),
            reinit_date: AtomicI32::new(reinit_date),
        }
    }

    fn for_send() -> Self {
        Self {
            mask: Default::default(),
            reinit_date: Default::default(),
        }
    }

    pub fn mask(&self) -> &AdnlReceivedMask {
        &self.mask
    }

    pub fn reinit_date(&self) -> i32 {
        self.reinit_date.load(Ordering::Acquire)
    }

    pub fn set_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, Ordering::Release)
    }
}
