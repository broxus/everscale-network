use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use everscale_crypto::ed25519;

use crate::utils::*;

pub type AdnlPeers = FxDashMap<AdnlNodeIdShort, AdnlPeer>;

pub struct AdnlPeer {
    id: AdnlNodeIdFull,
    ip_address: AtomicU64,
    channel_key: ed25519::KeyPair,
    receiver_state: AdnlPeerState,
    sender_state: AdnlPeerState,
}

impl AdnlPeer {
    pub fn new(reinit_date: i32, ip_address: AdnlAddressUdp, id: AdnlNodeIdFull) -> Self {
        Self {
            id,
            ip_address: AtomicU64::new(ip_address.into()),
            channel_key: ed25519::KeyPair::generate(&mut rand::thread_rng()),
            receiver_state: AdnlPeerState::for_receive_with_reinit_date(reinit_date),
            sender_state: AdnlPeerState::for_send(),
        }
    }

    #[inline(always)]
    pub fn try_reinit(&self, reinit_date: i32) -> bool {
        let sender_reinit_date = self.sender_state.reinit_date();
        match reinit_date.cmp(&sender_reinit_date) {
            std::cmp::Ordering::Equal => true,
            std::cmp::Ordering::Greater => {
                self.sender_state.set_reinit_date(reinit_date);
                if sender_reinit_date != 0 {
                    self.sender_state.history(false).reset();
                    self.sender_state.history(true).reset();
                    self.receiver_state.history(false).reset();
                    self.receiver_state.history(true).reset();
                }
                true
            }
            std::cmp::Ordering::Less => false,
        }
    }

    #[inline(always)]
    pub fn id(&self) -> &AdnlNodeIdFull {
        &self.id
    }

    pub fn ip_address(&self) -> AdnlAddressUdp {
        self.ip_address.load(Ordering::Acquire).into()
    }

    pub fn channel_key(&self) -> &ed25519::KeyPair {
        &self.channel_key
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

    pub fn reset(&mut self) {
        let reinit_date = self.receiver_state.reinit_date();

        self.channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());
        self.receiver_state = AdnlPeerState::for_receive_with_reinit_date(reinit_date + 1);
        self.sender_state = AdnlPeerState::for_send();
    }
}

pub struct AdnlPeerState {
    ordinary_history: PacketsHistory,
    priority_history: PacketsHistory,
    reinit_date: AtomicI32,
}

impl AdnlPeerState {
    fn for_receive_with_reinit_date(reinit_date: i32) -> Self {
        Self {
            ordinary_history: PacketsHistory::for_recv(),
            priority_history: PacketsHistory::for_recv(),
            reinit_date: AtomicI32::new(reinit_date),
        }
    }

    fn for_send() -> Self {
        Self {
            ordinary_history: PacketsHistory::for_send(),
            priority_history: PacketsHistory::for_send(),
            reinit_date: Default::default(),
        }
    }

    #[inline(always)]
    pub fn history(&self, priority: bool) -> &PacketsHistory {
        if priority {
            &self.priority_history
        } else {
            &self.ordinary_history
        }
    }

    pub fn reinit_date(&self) -> i32 {
        self.reinit_date.load(Ordering::Acquire)
    }

    pub fn set_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, Ordering::Release)
    }
}
