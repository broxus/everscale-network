use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use everscale_crypto::ed25519;

use super::node_id::{NodeIdFull, NodeIdShort};
use crate::util::*;

pub type Peers = FxDashMap<NodeIdShort, Peer>;

/// Remote peer info
pub struct Peer {
    /// Remove peer public key
    id: NodeIdFull,
    /// IPv4 address
    addr: AtomicU64,
    /// Adnl channel key pair to encrypt messages from our side
    channel_key: ed25519::KeyPair,
    /// Packets receiver state
    receiver_state: PeerState,
    /// Packets sender state
    sender_state: PeerState,
}

impl Peer {
    /// Creates new peer with receiver state initialized with the local reinit date
    pub fn new(local_reinit_date: u32, addr: SocketAddrV4, id: NodeIdFull) -> Self {
        Self {
            id,
            addr: AtomicU64::new(pack_socket_addr(&addr)),
            channel_key: ed25519::KeyPair::generate(&mut rand::thread_rng()),
            receiver_state: PeerState::for_receive_with_reinit_date(local_reinit_date),
            sender_state: PeerState::for_send(),
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
    pub fn id(&self) -> &NodeIdFull {
        &self.id
    }

    #[inline(always)]
    pub fn addr(&self) -> SocketAddrV4 {
        unpack_socket_addr(self.addr.load(Ordering::Acquire))
    }

    #[inline(always)]
    pub fn set_addr(&self, addr: SocketAddrV4) {
        self.addr.store(pack_socket_addr(&addr), Ordering::Release);
    }

    /// Adnl channel key pair to encrypt messages from our side
    #[inline(always)]
    pub fn channel_key(&self) -> &ed25519::KeyPair {
        &self.channel_key
    }

    /// Packets receiver state
    #[inline(always)]
    pub fn receiver_state(&self) -> &PeerState {
        &self.receiver_state
    }

    /// Packets sender state
    #[inline(always)]
    pub fn sender_state(&self) -> &PeerState {
        &self.sender_state
    }

    /// Generates new channel key pair and resets receiver/sender states
    ///
    /// NOTE: Receiver state increments its reinit date so the peer will reset states
    /// on the next message (see [`AdnlPeer::try_reinit_sender`])
    pub fn reset(&mut self) {
        let reinit_date = self.receiver_state.reinit_date();

        self.channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());
        self.receiver_state = PeerState::for_receive_with_reinit_date(reinit_date + 1);
        self.sender_state = PeerState::for_send();
    }
}

pub fn pack_socket_addr(addr: &SocketAddrV4) -> u64 {
    let mut result = [0; 8];
    result[0..4].copy_from_slice(&addr.ip().octets());
    result[4..6].copy_from_slice(&addr.port().to_le_bytes());
    u64::from_le_bytes(result)
}

#[inline(always)]
pub fn unpack_socket_addr(addr: u64) -> SocketAddrV4 {
    let result = addr.to_le_bytes();
    let addr: [u8; 4] = result[0..4].try_into().unwrap();
    SocketAddrV4::new(
        Ipv4Addr::from(addr),
        u16::from_le_bytes([result[4], result[5]]),
    )
}

/// Connection side packets histories and reinit date
pub struct PeerState {
    ordinary_history: PacketsHistory,
    priority_history: PacketsHistory,
    reinit_date: AtomicU32,
}

impl PeerState {
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
pub trait PeerFilter: Send + Sync {
    fn check(&self, ctx: NewPeerContext, addr: &SocketAddrV4, peer_id: &NodeIdShort) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_addr_pack() {
        let test = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 23123);

        let packed = pack_socket_addr(&test);

        let unpacked = unpack_socket_addr(packed);
        assert_eq!(unpacked, test);
    }
}
