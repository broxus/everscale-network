use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use super::channel::ChannelKey;
use crate::utils::*;

pub type AdnlPeers = FxDashMap<AdnlNodeIdShort, AdnlPeer>;

pub struct AdnlPeer {
    id: AdnlNodeIdFull,
    ip_address: AtomicU64,
    channel_key: ChannelKey,
    receiver_state: AdnlPeerState,
    sender_state: AdnlPeerState,
}

impl AdnlPeer {
    pub fn new(reinit_date: i32, ip_address: AdnlAddressUdp, id: AdnlNodeIdFull) -> Self {
        Self {
            id,
            ip_address: AtomicU64::new(ip_address.into()),
            channel_key: ChannelKey::generate(),
            receiver_state: AdnlPeerState::for_receive_with_reinit_date(reinit_date),
            sender_state: AdnlPeerState::for_send(),
        }
    }

    #[inline(always)]
    pub fn id(&self) -> &AdnlNodeIdFull {
        &self.id
    }

    pub fn ip_address(&self) -> AdnlAddressUdp {
        self.ip_address.load(Ordering::Acquire).into()
    }

    pub fn channel_key(&self) -> &ChannelKey {
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

        self.channel_key = ChannelKey::generate();
        self.receiver_state = AdnlPeerState::for_receive_with_reinit_date(reinit_date + 1);
        self.sender_state = AdnlPeerState::for_send();
    }
}

pub struct AdnlPeerState {
    packets_history: PacketsHistory,
    reinit_date: AtomicI32,
}

impl AdnlPeerState {
    fn for_receive_with_reinit_date(reinit_date: i32) -> Self {
        Self {
            packets_history: PacketsHistory::for_recv(),
            reinit_date: AtomicI32::new(reinit_date),
        }
    }

    fn for_send() -> Self {
        Self {
            packets_history: PacketsHistory::for_send(),
            reinit_date: Default::default(),
        }
    }

    pub fn history(&self) -> &PacketsHistory {
        &self.packets_history
    }

    pub fn reinit_date(&self) -> i32 {
        self.reinit_date.load(Ordering::Acquire)
    }

    pub fn set_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, Ordering::Release)
    }
}
