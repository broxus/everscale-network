use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tl_proto::{TlRead, TlWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub use self::peer::{AdnlPeerFilter, PeerContext};

use self::channel::{AdnlChannel, AdnlChannelId};
use self::peer::{AdnlPeer, AdnlPeers};
use self::ping_subscriber::AdnlPingSubscriber;
use self::receiver::*;
use self::sender::*;
use self::transfer::*;
use crate::proto;
use crate::subscriber::*;
use crate::utils::*;

mod channel;
mod encryption;
mod handshake;
mod peer;
mod ping_subscriber;
mod receiver;
mod sender;
mod transfer;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdnlNodeOptions {
    /// Minimal ADNL query timeout. Will override the used timeout if it is less.
    ///
    /// Default: `500` ms
    ///
    /// See [`AdnlNode::query`], [`AdnlNode::query_with_prefix`], [`AdnlNode::query_raw`]
    pub query_min_timeout_ms: u64,

    /// Default ADNL query timeout. Will be used if no timeout is specified.
    ///
    /// Default: `5000` ms
    ///
    /// See [`AdnlNode::query`], [`AdnlNode::query_with_prefix`], [`AdnlNode::query_raw`]
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

    /// ADNL protocol version.
    ///
    /// Default: None
    pub version: Option<u16>,
}

impl Default for AdnlNodeOptions {
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
            version: None,
        }
    }
}

/// Unreliable UDP transport layer
pub struct AdnlNode {
    /// IPv4 address of the node
    ip_address: PackedSocketAddr,
    /// Immutable keystore
    keystore: Keystore,
    /// Configuration
    options: AdnlNodeOptions,

    /// If specified, peers are only accepted if they match the filter
    peer_filter: Option<Arc<dyn AdnlPeerFilter>>,

    /// Known peers for each local node id
    peers: FxHashMap<AdnlNodeIdShort, AdnlPeers>,

    /// Channels table used to fast search on incoming packets
    channels_by_id: FxDashMap<AdnlChannelId, ChannelReceiver>,
    /// Channels table used to fast search when sending messages
    channels_by_peers: FxDashMap<AdnlNodeIdShort, Arc<AdnlChannel>>,

    /// Pending transfers of large messages that were split
    incoming_transfers: Arc<FxDashMap<TransferId, Arc<Transfer>>>,

    /// Pending queries
    queries: Arc<QueriesCache>,

    /// Outgoing packets queue
    sender_queue_tx: SenderQueueTx,
    /// Receiver end of the outgoing packets queue (NOTE: used only for initialization)
    sender_queue_rx: Mutex<Option<SenderQueueRx>>,

    /// Node start timestamp. Used as reinit date for connections
    start_time: u32,

    /// Token, used to cancel all spawned tasks
    cancellation_token: CancellationToken,
}

impl AdnlNode {
    /// Create new ADNL node on the specified address
    pub fn new(
        ip_address: PackedSocketAddr,
        keystore: Keystore,
        options: AdnlNodeOptions,
        peer_filter: Option<Arc<dyn AdnlPeerFilter>>,
    ) -> Arc<Self> {
        let (sender_queue_tx, sender_queue_rx) = mpsc::unbounded_channel();

        // Add empty peers map for each local peer
        let mut peers =
            FxHashMap::with_capacity_and_hasher(keystore.keys().len(), Default::default());
        for key in keystore.keys().keys() {
            peers.insert(*key, Default::default());
        }

        Arc::new(Self {
            ip_address,
            keystore,
            options,
            peer_filter,
            peers,
            channels_by_id: Default::default(),
            channels_by_peers: Default::default(),
            incoming_transfers: Default::default(),
            queries: Default::default(),
            sender_queue_tx,
            sender_queue_rx: Mutex::new(Some(sender_queue_rx)),
            start_time: now(),
            cancellation_token: Default::default(),
        })
    }

    /// ADNL node options
    #[inline(always)]
    pub fn options(&self) -> &AdnlNodeOptions {
        &self.options
    }

    /// Instant metrics
    pub fn metrics(&self) -> AdnlNodeMetrics {
        AdnlNodeMetrics {
            peer_count: self.peers.values().map(|peers| peers.len()).sum(),
            channels_by_id_len: self.channels_by_id.len(),
            channels_by_peers_len: self.channels_by_peers.len(),
            incoming_transfers_len: self.incoming_transfers.len(),
            query_count: self.queries.len(),
        }
    }

    /// Starts listening for incoming packets
    pub fn start(self: &Arc<Self>, mut subscribers: Vec<Arc<dyn Subscriber>>) -> Result<()> {
        // Consume receiver
        let sender_queue_rx = match self.sender_queue_rx.lock().take() {
            Some(rx) => rx,
            None => return Err(AdnlNodeError::AlreadyRunning.into()),
        };

        // Bind node socket
        let socket = make_udp_socket(self.ip_address.port())?;

        subscribers.push(Arc::new(AdnlPingSubscriber));
        let subscribers = Arc::new(subscribers);

        // Start background logic
        self.start_sender(socket.clone(), sender_queue_rx);
        self.start_receiver(socket, subscribers);

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

    /// IPv4 address of the node
    #[inline(always)]
    pub fn ip_address(&self) -> PackedSocketAddr {
        self.ip_address
    }

    /// Node start timestamp
    #[inline(always)]
    pub fn start_time(&self) -> u32 {
        self.start_time
    }

    /// Builds new address list for the current ADNL node with no expiration date
    pub fn build_address_list(&self) -> proto::adnl::AddressList {
        proto::adnl::AddressList {
            address: Some(self.ip_address.as_tl()),
            version: now(),
            reinit_date: self.start_time,
            expire_at: 0,
        }
    }

    /// Searches for the stored ADNL key by it's short id
    ///
    /// See [AdnlNode::key_by_tag]
    pub fn key_by_id(
        &self,
        id: &AdnlNodeIdShort,
    ) -> Result<&Arc<StoredAdnlNodeKey>, KeystoreError> {
        self.keystore.key_by_id(id)
    }

    /// Searches for the stored ADNL key by it's tag
    ///
    /// See [AdnlNode::key_by_id]
    pub fn key_by_tag(&self, tag: usize) -> Result<&Arc<StoredAdnlNodeKey>, KeystoreError> {
        self.keystore.key_by_tag(tag)
    }

    /// Adds new remote peer. Returns whether the peer was added
    ///
    /// See [AdnlNode::remove_peer]
    pub fn add_peer(
        &self,
        ctx: PeerContext,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer_ip_address: PackedSocketAddr,
        peer_full_id: AdnlNodeIdFull,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        // Ignore ourself
        if peer_id == local_id && peer_ip_address == self.ip_address {
            return Ok(false);
        }

        // Check peer with peer filter (if specified)
        if let Some(filter) = &self.peer_filter {
            if !filter.check(ctx, peer_ip_address, peer_id) {
                return Ok(false);
            }
        }

        // Search remove peer in known peers
        match self.get_peers(local_id)?.entry(*peer_id) {
            // Update ip if peer is already known
            Entry::Occupied(entry) => entry.get().set_ip_address(peer_ip_address),
            // Create new peer state otherwise
            Entry::Vacant(entry) => {
                entry.insert(AdnlPeer::new(
                    self.start_time,
                    peer_ip_address,
                    peer_full_id,
                ));

                tracing::debug!(
                    "Added ADNL peer {peer_ip_address}. PEER ID {peer_id} -> LOCAL ID {local_id}"
                );
            }
        };

        Ok(true)
    }

    /// Removes remote peer.
    ///
    /// NOTE: This method will return an error if there is no peers table
    /// for the specified local id.
    ///
    /// See [AdnlNode::add_peer]
    pub fn remove_peer(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<bool> {
        let peers = self.get_peers(local_id)?;

        self.channels_by_peers
            .remove(peer_id)
            .and_then(|(_, removed)| {
                self.channels_by_id.remove(removed.ordinary_channel_in_id());
                self.channels_by_id.remove(removed.priority_channel_in_id())
            });

        Ok(peers.remove(peer_id).is_some())
    }

    /// Searches for remote peer ip in the known peers
    pub fn get_peer_ip(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
    ) -> Option<PackedSocketAddr> {
        let peers = self.get_peers(local_id).ok()?;
        let peer = peers.get(peer_id)?;
        Some(peer.ip_address())
    }

    /// ADNL query without prefix to the remote peer.
    ///
    /// NOTE: In case of timeout returns `Ok(None)`
    pub async fn query<Q, A>(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        query: Q,
        timeout: Option<u64>,
    ) -> Result<Option<A>>
    where
        Q: TlWrite,
        for<'a> A: TlRead<'a> + 'static,
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
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        prefix: &[u8],
        query: Q,
        timeout: Option<u64>,
    ) -> Result<Option<A>>
    where
        Q: TlWrite,
        for<'a> A: TlRead<'a> + 'static,
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
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        query: Bytes,
        timeout: Option<u64>,
    ) -> Result<Option<Vec<u8>>> {
        use rand::Rng;

        let query_id: QueryId = rand::thread_rng().gen();

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

        tokio::spawn({
            let queries = self.queries.clone();
            let timeout = timeout.unwrap_or(self.options.query_default_timeout_ms);

            async move {
                tokio::time::sleep(Duration::from_millis(timeout)).await;

                match queries.update_query(query_id, None).await {
                    Ok(true) => { /* dropped query */ }
                    Err(_) => tracing::warn!("Failed to drop query"),
                    _ => { /* do nothing */ }
                }
            }
        });

        let answer = pending_query.wait().await?;
        if answer.is_none() {
            if let Some(channel) = channel {
                if channel.update_drop_timeout(now(), self.options.channel_reset_timeout_sec) {
                    self.reset_peer(local_id, peer_id)?;
                }
            }
        }

        Ok(answer)
    }

    pub fn send_custom_message(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: &[u8],
    ) -> Result<()> {
        self.send_message(
            local_id,
            peer_id,
            proto::adnl::Message::Custom { data },
            self.options.force_use_priority_channels,
        )
    }

    fn get_peers(&self, local_id: &AdnlNodeIdShort) -> Result<&AdnlPeers> {
        if let Some(peers) = self.peers.get(local_id) {
            Ok(peers)
        } else {
            Err(AdnlNodeError::PeersNotFound.into())
        }
    }

    fn reset_peer(&self, local_id: &AdnlNodeIdShort, peer_id: &AdnlNodeIdShort) -> Result<()> {
        let peers = self.get_peers(local_id)?;
        let mut peer = peers.get_mut(peer_id).ok_or(AdnlNodeError::UnknownPeer)?;

        tracing::debug!("Resetting peer pair {local_id} -> {peer_id}");

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

impl Drop for AdnlNode {
    fn drop(&mut self) {
        // Cancel all tasks on drop
        self.shutdown()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AdnlNodeMetrics {
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

pub fn make_query<T>(prefix: Option<&[u8]>, query: T) -> Bytes
where
    T: TlWrite,
{
    match prefix {
        Some(prefix) => {
            let mut data = Vec::with_capacity(prefix.len() + query.max_size_hint());
            data.extend_from_slice(prefix);
            query.write_to(&mut data);
            data
        }
        None => tl_proto::serialize(query),
    }
    .into()
}

#[derive(thiserror::Error, Debug)]
enum AdnlNodeError {
    #[error("ADNL node is already running")]
    AlreadyRunning,
    #[error("Local id peers not found")]
    PeersNotFound,
    #[error("Unknown peer")]
    UnknownPeer,
}
