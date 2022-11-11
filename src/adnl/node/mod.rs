use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tl_proto::{TlRead, TlWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use self::receiver::*;
use self::sender::*;
use super::channel::{AdnlChannelId, Channel};
use super::keystore::{Key, Keystore, KeystoreError};
use super::node_id::{NodeIdFull, NodeIdShort};
use super::peer::{NewPeerContext, Peer, PeerFilter, Peers};
use super::ping_subscriber::PingSubscriber;
use super::queries_cache::{QueriesCache, QueryId};
use super::socket::make_udp_socket;
use super::transfer::*;
use crate::proto;
use crate::subscriber::*;
use crate::util::*;

mod receiver;
mod sender;

/// ADNL node configuration
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeOptions {
    /// Minimal ADNL query timeout. Will override the used timeout if it is less.
    ///
    /// Default: `500` ms
    ///
    /// See [`Node::query`], [`Node::query_with_prefix`], [`Node::query_raw`]
    pub query_min_timeout_ms: u64,

    /// Default ADNL query timeout. Will be used if no timeout is specified.
    ///
    /// Default: `5000` ms
    ///
    /// See [`Node::query`], [`Node::query_with_prefix`], [`Node::query_raw`]
    pub query_default_timeout_ms: u64,

    /// ADNL multipart transfer timeout. It will drop the transfer if it is not completed
    /// within this timeout.
    ///
    /// Default: `3` seconds
    pub transfer_timeout_sec: u64,

    /// Permissible time difference between remote and local clocks.
    ///
    /// Default: `60` seconds
    pub clock_tolerance_sec: u32,

    /// Drop channels which had no response for this amount of time.
    ///
    /// Default: `30` seconds
    pub channel_reset_timeout_sec: u32,

    /// How much time address lists from packets should be valid.
    ///
    /// Default: `1000` seconds
    pub address_list_timeout_sec: u32,

    /// Whether to add additional duplicated packets check.
    ///
    /// Default: `false`
    pub packet_history_enabled: bool,

    /// Whether handshake packets signature is mandatory.
    ///
    /// Default: `true`
    pub packet_signature_required: bool,

    /// Whether to use priority channels for queries.
    ///
    /// Default: `true`
    pub force_use_priority_channels: bool,

    /// Whether to use loopback ip to communicate with nodes on the same ip
    ///
    /// Default: `false`
    pub use_loopback_for_neighbours: bool,

    /// ADNL protocol version.
    ///
    /// Default: None
    pub version: Option<u16>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            query_min_timeout_ms: 500,
            query_default_timeout_ms: 5000,
            transfer_timeout_sec: 3,
            clock_tolerance_sec: 60,
            channel_reset_timeout_sec: 30,
            address_list_timeout_sec: 1000,
            packet_history_enabled: false,
            packet_signature_required: true,
            force_use_priority_channels: true,
            use_loopback_for_neighbours: false,
            version: None,
        }
    }
}

/// Unreliable UDP transport layer
pub struct Node {
    /// Socket address of the node
    socket_addr: SocketAddrV4,
    /// Immutable keystore
    keystore: Keystore,
    /// Configuration
    options: NodeOptions,

    /// If specified, peers are only accepted if they match the filter
    peer_filter: Option<Arc<dyn PeerFilter>>,

    /// Known peers for each local node id
    peers: FxHashMap<NodeIdShort, Peers>,

    /// Channels table used to fast search on incoming packets
    channels_by_id: FxDashMap<AdnlChannelId, ChannelReceiver>,
    /// Channels table used to fast search when sending messages
    channels_by_peers: FxDashMap<NodeIdShort, Arc<Channel>>,

    /// Pending transfers of large messages that were split
    incoming_transfers: Arc<FxDashMap<TransferId, Arc<Transfer>>>,

    /// Pending queries
    queries: Arc<QueriesCache>,

    /// Outgoing packets queue
    sender_queue_tx: SenderQueueTx,
    /// Stated used during initialization
    init_state: Mutex<Option<InitializationState>>,

    /// Node start timestamp. Used as reinit date for connections
    start_time: u32,

    /// Token, used to cancel all spawned tasks
    cancellation_token: CancellationToken,
}

impl Node {
    /// Create new ADNL node on the specified address
    pub fn new(
        mut socket_addr: SocketAddrV4,
        keystore: Keystore,
        options: NodeOptions,
        peer_filter: Option<Arc<dyn PeerFilter>>,
    ) -> Result<Arc<Self>> {
        // Bind node socket
        let socket = make_udp_socket(socket_addr.port())?;

        // Update socket addr with auto assigned port (in case of 0)
        if socket_addr.port() == 0 {
            let local_addr = socket.local_addr().context("Failed to select UDP port")?;
            socket_addr.set_port(local_addr.port());
        }

        let (sender_queue_tx, sender_queue_rx) = mpsc::unbounded_channel();

        // Add empty peers map for each local peer
        let mut peers =
            FxHashMap::with_capacity_and_hasher(keystore.keys().len(), Default::default());
        for key in keystore.keys().keys() {
            peers.insert(*key, Default::default());
        }

        Ok(Arc::new(Self {
            socket_addr,
            keystore,
            options,
            peer_filter,
            peers,
            channels_by_id: Default::default(),
            channels_by_peers: Default::default(),
            incoming_transfers: Default::default(),
            queries: Default::default(),
            sender_queue_tx,
            init_state: Mutex::new(Some(InitializationState {
                socket,
                sender_queue_rx,
                message_subscribers: Default::default(),
                query_subscribers: Default::default(),
            })),
            start_time: now(),
            cancellation_token: Default::default(),
        }))
    }

    /// ADNL node options
    #[inline(always)]
    pub fn options(&self) -> &NodeOptions {
        &self.options
    }

    /// Instant metrics
    pub fn metrics(&self) -> NodeMetrics {
        NodeMetrics {
            peer_count: self.peers.values().map(|peers| peers.len()).sum(),
            channels_by_id_len: self.channels_by_id.len(),
            channels_by_peers_len: self.channels_by_peers.len(),
            incoming_transfers_len: self.incoming_transfers.len(),
            query_count: self.queries.len(),
        }
    }

    /// Adds a new message subscriber brefore the node was started
    pub fn add_message_subscriber(
        &self,
        message_subscriber: Arc<dyn MessageSubscriber>,
    ) -> Result<()> {
        let mut init = self.init_state.lock();
        match &mut *init {
            Some(init) => {
                init.message_subscribers.push(message_subscriber);
                Ok(())
            }
            None => Err(NodeError::AlreadyRunning.into()),
        }
    }

    /// Adds a new query subscriber brefore the node was started
    pub fn add_query_subscriber(&self, query_subscriber: Arc<dyn QuerySubscriber>) -> Result<()> {
        let mut init = self.init_state.lock();
        match &mut *init {
            Some(init) => {
                init.query_subscribers.push(query_subscriber);
                Ok(())
            }
            None => Err(NodeError::AlreadyRunning.into()),
        }
    }

    /// Starts listening for incoming packets
    pub fn start(self: &Arc<Self>) -> Result<()> {
        // Consume receiver
        let mut init = match self.init_state.lock().take() {
            Some(init) => init,
            None => return Err(NodeError::AlreadyRunning.into()),
        };

        init.query_subscribers.push(Arc::new(PingSubscriber));

        // Start background logic
        self.start_sender(init.socket.clone(), init.sender_queue_rx);
        self.start_receiver(
            init.socket,
            init.message_subscribers,
            init.query_subscribers,
        );

        // Done
        Ok(())
    }

    /// Stops all spawned listeners
    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
    }

    /// Computes ADNL query timeout, based on the roundtrip and the configured options
    pub fn compute_query_timeout(&self, roundtrip: Option<u64>) -> u64 {
        let timeout = roundtrip.unwrap_or(self.options.query_default_timeout_ms);
        std::cmp::max(self.options.query_min_timeout_ms, timeout)
    }

    /// Socket address of the node
    #[inline(always)]
    pub fn socket_addr(&self) -> SocketAddrV4 {
        self.socket_addr
    }

    /// Node start timestamp
    #[inline(always)]
    pub fn start_time(&self) -> u32 {
        self.start_time
    }

    /// Builds a new address list for the current ADNL node with no expiration date
    pub fn build_address_list(&self) -> proto::adnl::AddressList {
        proto::adnl::AddressList {
            address: Some(proto::adnl::Address::from(&self.socket_addr)),
            version: now(),
            reinit_date: self.start_time,
            expire_at: 0,
        }
    }

    /// Searches for the stored ADNL key by it's short id
    ///
    /// See [`Node::key_by_tag`]
    pub fn key_by_id(&self, id: &NodeIdShort) -> Result<&Arc<Key>, KeystoreError> {
        self.keystore.key_by_id(id)
    }

    /// Searches for the stored ADNL key by it's tag
    ///
    /// See [`Node::key_by_id`]
    pub fn key_by_tag(&self, tag: usize) -> Result<&Arc<Key>, KeystoreError> {
        self.keystore.key_by_tag(tag)
    }

    /// Adds new remote peer. Returns whether the peer was added
    ///
    /// See [`Node::remove_peer`]
    pub fn add_peer(
        &self,
        ctx: NewPeerContext,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        addr: SocketAddrV4,
        peer_id_full: NodeIdFull,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        // Ignore ourself
        if peer_id == local_id || addr == self.socket_addr {
            return Ok(false);
        }

        // Check peer with peer filter (if specified)
        if let Some(filter) = &self.peer_filter {
            if !filter.check(ctx, addr, peer_id) {
                return Ok(false);
            }
        }

        // Search remove peer in known peers
        match self.get_peers(local_id)?.entry(*peer_id) {
            // Update ip if peer is already known
            Entry::Occupied(entry) => entry.get().set_addr(addr),
            // Create new peer state otherwise
            Entry::Vacant(entry) => {
                entry.insert(Peer::new(self.start_time, addr, peer_id_full));
                tracing::trace!(%local_id, %peer_id, %addr, "added ADNL peer");
            }
        };

        Ok(true)
    }

    /// Removes remote peer.
    ///
    /// NOTE: This method will return an error if there is no peers table
    /// for the specified local id.
    ///
    /// See [`Node::add_peer`]
    pub fn remove_peer(&self, local_id: &NodeIdShort, peer_id: &NodeIdShort) -> Result<bool> {
        let peers = self.get_peers(local_id)?;

        self.channels_by_peers
            .remove(peer_id)
            .and_then(|(_, removed)| {
                self.channels_by_id.remove(removed.ordinary_channel_in_id());
                self.channels_by_id.remove(removed.priority_channel_in_id())
            });

        Ok(peers.remove(peer_id).is_some())
    }

    /// Searches for remote peer socket address in the known peers
    pub fn get_peer_address(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
    ) -> Option<SocketAddrV4> {
        let peers = self.get_peers(local_id).ok()?;
        let peer = peers.get(peer_id)?;
        Some(peer.addr())
    }

    /// Matches entries with peer id by socket address
    ///
    /// NOTE: It is a quite expensive method that iterates over all peers
    /// and may block new peers from being added during the execution time.
    /// Use it with caution.
    pub fn match_peer_addresses<T>(
        &self,
        local_id: &NodeIdShort,
        mut entries: FxHashMap<SocketAddrV4, T>,
    ) -> Option<FxHashMap<T, NodeIdShort>>
    where
        T: std::hash::Hash + Eq,
    {
        let peers = self.get_peers(local_id).ok()?;

        let mut result = FxHashMap::with_capacity_and_hasher(entries.len(), Default::default());
        for peer in peers.iter() {
            if let Some(key) = entries.remove(&peer.addr()) {
                result.insert(key, *peer.key());
            }
        }

        Some(result)
    }

    /// ADNL query without prefix to the remote peer.
    ///
    /// NOTE: In case of timeout returns `Ok(None)`
    pub async fn query<Q, A>(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        query: Q,
        timeout: Option<u64>,
    ) -> Result<Option<A>>
    where
        Q: TlWrite,
        for<'a> A: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
    {
        match self
            .query_raw(local_id, peer_id, make_query(None, query), timeout)
            .await?
        {
            Some(answer) => Ok(Some(tl_proto::deserialize(&answer)?)),
            None => Ok(None),
        }
    }

    /// ADNL query with prefix to the remote peer
    ///
    /// NOTE: In case of timeout returns `Ok(None)`
    pub async fn query_with_prefix<Q, A>(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        prefix: &[u8],
        query: Q,
        timeout: Option<u64>,
    ) -> Result<Option<A>>
    where
        Q: TlWrite,
        for<'a> A: TlRead<'a, Repr = tl_proto::Boxed> + 'static,
    {
        match self
            .query_raw(local_id, peer_id, make_query(Some(prefix), query), timeout)
            .await?
        {
            Some(answer) => Ok(Some(tl_proto::deserialize(&answer)?)),
            None => Ok(None),
        }
    }

    /// ADNL query to the remote peer
    ///
    /// NOTE: In case of timeout returns `Ok(None)`
    pub async fn query_raw(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        query: Bytes,
        timeout: Option<u64>,
    ) -> Result<Option<Vec<u8>>> {
        let query_id: QueryId = gen_fast_bytes();

        let pending_query = self.queries.add_query(query_id);
        self.send_message(
            local_id,
            peer_id,
            proto::adnl::Message::Query {
                query_id: &query_id,
                query: &query,
            },
            true,
        )?;
        drop(query);

        let channel = self
            .channels_by_peers
            .get(peer_id)
            .map(|entry| entry.value().clone());

        let timeout = timeout.unwrap_or(self.options.query_default_timeout_ms);
        let answer = tokio::time::timeout(Duration::from_millis(timeout), pending_query.wait())
            .await
            .ok()
            .flatten();

        if answer.is_none() {
            if let Some(channel) = channel {
                if channel.update_drop_timeout(now(), self.options.channel_reset_timeout_sec) {
                    self.reset_peer(local_id, peer_id)?;
                }
            }
        }

        Ok(answer)
    }

    /// Sends a one-way ADNL message
    pub fn send_custom_message(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        data: &[u8],
    ) -> Result<()> {
        self.send_message(
            local_id,
            peer_id,
            proto::adnl::Message::Custom { data },
            self.options.force_use_priority_channels,
        )
    }

    fn get_peers(&self, local_id: &NodeIdShort) -> Result<&Peers> {
        if let Some(peers) = self.peers.get(local_id) {
            Ok(peers)
        } else {
            Err(NodeError::PeersNotFound.into())
        }
    }

    fn reset_peer(&self, local_id: &NodeIdShort, peer_id: &NodeIdShort) -> Result<()> {
        let peers = self.get_peers(local_id)?;
        let mut peer = peers.get_mut(peer_id).ok_or(NodeError::UnknownPeer)?;

        tracing::trace!(%local_id, %peer_id, "resetting peer pair");

        self.channels_by_peers
            .remove(peer_id)
            .and_then(|(_, removed)| {
                self.channels_by_id.remove(removed.ordinary_channel_in_id());
                self.channels_by_id.remove(removed.priority_channel_in_id())
            });

        peer.reset();

        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Cancel all tasks on drop
        self.shutdown()
    }
}

/// Instant ADNL node metrics
#[derive(Debug, Copy, Clone)]
pub struct NodeMetrics {
    /// Total remote peer count for all local keys
    pub peer_count: usize,
    /// Total unique channel count (including priority/remote duplicates)
    pub channels_by_id_len: usize,
    /// Total channel count for each remote peer
    pub channels_by_peers_len: usize,
    /// Current multipart transfer count
    pub incoming_transfers_len: usize,
    /// Current queries cache len
    pub query_count: usize,
}

struct InitializationState {
    socket: Arc<tokio::net::UdpSocket>,
    /// Receiver end of the outgoing packets queue
    sender_queue_rx: SenderQueueRx,
    message_subscribers: Vec<Arc<dyn MessageSubscriber>>,
    query_subscribers: Vec<Arc<dyn QuerySubscriber>>,
}

fn make_query<T>(prefix: Option<&[u8]>, query: T) -> Bytes
where
    T: TlWrite,
{
    let prefix_len = match prefix {
        Some(prefix) => prefix.len(),
        None => 0,
    };
    let mut data = Vec::with_capacity(prefix_len + query.max_size_hint());
    if let Some(prefix) = prefix {
        data.extend_from_slice(prefix);
    }
    query.write_to(&mut data);
    data.into()
}

#[derive(thiserror::Error, Debug)]
enum NodeError {
    #[error("ADNL node is already running")]
    AlreadyRunning,
    #[error("Local id peers not found")]
    PeersNotFound,
    #[error("Unknown peer")]
    UnknownPeer,
}
