use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use everscale_crypto::ed25519;

use crate::utils::*;

pub type AdnlPeers = FxDashMap<AdnlNodeIdShort, AdnlPeer>;

/// Remote peer info
pub struct AdnlPeer {
    /// Remove peer public key
    id: AdnlNodeIdFull,
    /// IPv4 address
    ip_address: AtomicU64,
    /// Adnl channel key pair to encrypt messages from our side
    channel_key: ed25519::KeyPair,
    /// Packets receiver state
    receiver_state: AdnlPeerState,
    /// Packets sender state
    sender_state: AdnlPeerState,
}

impl AdnlPeer {
    /// Creates new peer with receiver state initialized with the local reinit date
    pub fn new(local_reinit_date: u32, ip_address: PackedSocketAddr, id: AdnlNodeIdFull) -> Self {
        Self {
            id,
            ip_address: AtomicU64::new(ip_address.into()),
            channel_key: ed25519::KeyPair::generate(&mut rand::thread_rng()),
            receiver_state: AdnlPeerState::for_receive_with_reinit_date(local_reinit_date),
            sender_state: AdnlPeerState::for_send(),
        }
    }

    /// Tries to update peer reinit date
    ///
    /// It is only allowed to update peer reinit date if it is greater or equal to the known one
    #[inline(always)]
    pub fn try_reinit_sender(&self, reinit_date: u32) -> bool {
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

    /// Returns peer full id (public key)
    #[inline(always)]
    pub fn id(&self) -> &AdnlNodeIdFull {
        &self.id
    }

    #[inline(always)]
    pub fn ip_address(&self) -> PackedSocketAddr {
        self.ip_address.load(Ordering::Acquire).into()
    }

    #[inline(always)]
    pub fn set_ip_address(&self, ip_address: PackedSocketAddr) {
        self.ip_address.store(ip_address.into(), Ordering::Release);
    }

    /// Adnl channel key pair to encrypt messages from our side
    #[inline(always)]
    pub fn channel_key(&self) -> &ed25519::KeyPair {
        &self.channel_key
    }

    /// Packets receiver state
    #[inline(always)]
    pub fn receiver_state(&self) -> &AdnlPeerState {
        &self.receiver_state
    }

    /// Packets sender state
    #[inline(always)]
    pub fn sender_state(&self) -> &AdnlPeerState {
        &self.sender_state
    }

    /// Generates new channel key pair and resets receiver/sender states
    ///
    /// NOTE: Receiver state increments its reinit date so the peer will reset states
    /// on the next message (see [`AdnlPeer::try_reinit_sender`])
    pub fn reset(&mut self) {
        let reinit_date = self.receiver_state.reinit_date();

        self.channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());
        self.receiver_state = AdnlPeerState::for_receive_with_reinit_date(reinit_date + 1);
        self.sender_state = AdnlPeerState::for_send();
    }
}

/// Connection side packets histories and reinit date
pub struct AdnlPeerState {
    ordinary_history: PacketsHistory,
    priority_history: PacketsHistory,
    reinit_date: AtomicU32,
}

impl AdnlPeerState {
    fn for_receive_with_reinit_date(reinit_date: u32) -> Self {
        Self {
            ordinary_history: PacketsHistory::for_recv(),
            priority_history: PacketsHistory::for_recv(),
            reinit_date: AtomicU32::new(reinit_date),
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

    pub fn reinit_date(&self) -> u32 {
        self.reinit_date.load(Ordering::Acquire)
    }

    pub fn set_reinit_date(&self, reinit_date: u32) {
        self.reinit_date.store(reinit_date, Ordering::Release)
    }
}

/// The context in which the new peer is added
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum NewPeerContext {
    AdnlPacket,
    Dht,
    PublicOverlay,
}

/// New peers filter
pub trait AdnlPeerFilter: Send + Sync {
    fn check(&self, ctx: NewPeerContext, ip: PackedSocketAddr, peer_id: &AdnlNodeIdShort) -> bool;
}
