use std::convert::TryFrom;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use sha2::Digest;
use smallvec::SmallVec;
use tl_proto::{HashWrapper, TlWrite};
use tokio::sync::mpsc;

use super::overlay_id::IdShort;
use super::{broadcast_receiver::*, MAX_OVERLAY_PEERS};
use crate::adnl;
use crate::proto;
use crate::rldp::{self, compression, RaptorQDecoder, RaptorQEncoder};
use crate::util::*;

/// Overlay configuration
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct OverlayOptions {
    /// More persistent list of peers. Used to distribute broadcasts.
    ///
    /// Default: `200`
    pub max_neighbours: u32,

    /// Max simultaneous broadcasts.
    ///
    /// Default: `1000`
    pub max_broadcast_log: u32,

    /// Broadcasts GC interval. Will leave at most `max_broadcast_log` each iteration.
    ///
    /// Default: `1000` ms
    pub broadcast_gc_interval_ms: u64,

    /// Neighbours or random peers update interval.
    ///
    /// Default: `60000` ms
    pub overlay_peers_timeout_ms: u64,

    /// Packets with length bigger than this will be sent using FEC broadcast.
    /// See [`Overlay::broadcast`]
    ///
    /// Default: `768` bytes
    pub max_ordinary_broadcast_len: usize,

    /// Max number of peers to distribute broadcast to.
    ///
    /// Default: `5`
    pub broadcast_target_count: u32,

    /// Max number of peers to redistribute ordinary broadcast to.
    ///
    /// Default: `3`
    pub secondary_broadcast_target_count: u32,

    /// Max number of peers to redistribute FEC broadcast to.
    ///
    /// Default: `3`
    pub secondary_fec_broadcast_target_count: u32,

    /// Number of FEC messages to send in group. There will be a short delay between them.
    ///
    /// Default: `20`
    pub fec_broadcast_wave_len: usize,

    /// Interval between FEC broadcast waves.
    ///
    /// Default: `10` ms
    pub fec_broadcast_wave_interval_ms: u64,

    /// Overlay broadcast timeout. It will be forcefully dropped if not received in this time.
    ///
    /// Default: `60` sec
    pub broadcast_timeout_sec: u64,

    /// Whether requests will be compressed.
    ///
    /// Default: `false`
    pub force_compression: bool,
}

impl Default for OverlayOptions {
    fn default() -> Self {
        Self {
            max_neighbours: 200,
            max_broadcast_log: 1000,
            broadcast_gc_interval_ms: 1000,
            overlay_peers_timeout_ms: 60000,
            max_ordinary_broadcast_len: 768,
            broadcast_target_count: 5,
            secondary_broadcast_target_count: 3,
            secondary_fec_broadcast_target_count: 3,
            fec_broadcast_wave_len: 20,
            fec_broadcast_wave_interval_ms: 10,
            broadcast_timeout_sec: 60,
            force_compression: false,
        }
    }
}

/// P2P messages distribution layer
pub struct Overlay {
    /// Unique overlay id
    id: IdShort,
    /// Local ADNL key
    node_key: Arc<adnl::Key>,
    // Configuration
    options: OverlayOptions,

    /// Broadcasts in progress
    owned_broadcasts: FastDashMap<BroadcastId, Arc<OwnedBroadcast>>,
    /// Broadcasts removal queue
    finished_broadcasts: SegQueue<BroadcastId>,
    /// Broadcasts removal queue len
    finished_broadcast_count: AtomicU32,

    /// New peers to add
    received_peers: Arc<Mutex<ReceivedPeersMap>>,
    /// Complete incoming broadcasts queue
    received_broadcasts: Arc<BroadcastReceiver<IncomingBroadcastInfo>>,

    /// Raw overlay nodes
    nodes: FastDashMap<adnl::NodeIdShort, proto::overlay::NodeOwned>,
    /// Peers to exclude from random selection
    ignored_peers: FastDashSet<adnl::NodeIdShort>,
    /// All known peers
    known_peers: adnl::PeersSet,
    /// Random peers subset
    neighbours: adnl::PeersSet,

    /// Serialized [`proto::rpc::OverlayQuery`] with own overlay id
    query_prefix: Vec<u8>,
    /// Serialized [`proto::overlay::Message`] with own overlay id
    message_prefix: Vec<u8>,
}

impl Overlay {
    /// Create new overlay node on top of the given ADNL node
    pub(super) fn new(
        node_key: Arc<adnl::Key>,
        id: IdShort,
        peers: &[adnl::NodeIdShort],
        options: OverlayOptions,
    ) -> Arc<Self> {
        let query_prefix = tl_proto::serialize(proto::rpc::OverlayQuery {
            overlay: id.as_slice(),
        });
        let message_prefix = tl_proto::serialize(proto::overlay::Message {
            overlay: id.as_slice(),
        });

        let known_peers = adnl::PeersSet::with_peers_and_capacity(peers, MAX_OVERLAY_PEERS);

        let overlay = Arc::new(Self {
            id,
            node_key,
            options,
            owned_broadcasts: FastDashMap::default(),
            finished_broadcasts: SegQueue::new(),
            finished_broadcast_count: AtomicU32::new(0),
            received_peers: Arc::new(Default::default()),
            received_broadcasts: Arc::new(BroadcastReceiver::default()),
            nodes: FastDashMap::default(),
            ignored_peers: FastDashSet::default(),
            known_peers,
            neighbours: adnl::PeersSet::with_capacity(options.max_neighbours),
            query_prefix,
            message_prefix,
        });

        if !peers.is_empty() {
            overlay.update_neighbours(overlay.options.max_neighbours);
        }

        let overlay_ref = Arc::downgrade(&overlay);
        let gc_interval = Duration::from_millis(options.broadcast_gc_interval_ms);
        tokio::spawn(async move {
            let mut peers_timeout = 0;
            while let Some(overlay) = overlay_ref.upgrade() {
                while overlay.finished_broadcast_count.load(Ordering::Acquire)
                    > options.max_broadcast_log
                {
                    if let Some(broadcast_id) = overlay.finished_broadcasts.pop() {
                        overlay.owned_broadcasts.remove(&broadcast_id);
                    }
                    overlay
                        .finished_broadcast_count
                        .fetch_sub(1, Ordering::Release);
                }

                peers_timeout += options.broadcast_gc_interval_ms;
                if peers_timeout > options.overlay_peers_timeout_ms {
                    overlay.update_neighbours(1);
                    peers_timeout = 0;
                }

                tokio::time::sleep(gc_interval).await;
            }
        });

        overlay
    }

    /// Configuration
    #[inline(always)]
    pub fn options(&self) -> &OverlayOptions {
        &self.options
    }

    /// Instant metrics
    pub fn metrics(&self) -> OverlayMetrics {
        OverlayMetrics {
            owned_broadcasts_len: self.owned_broadcasts.len(),
            finished_broadcasts_len: self.finished_broadcast_count.load(Ordering::Acquire),
            node_count: self.nodes.len(),
            known_peers: self.known_peers.len(),
            neighbours: self.neighbours.len(),
            received_broadcasts_data_len: self.received_broadcasts.data_len(),
            received_broadcasts_barrier_count: self.received_broadcasts.barriers_len(),
        }
    }

    /// Short overlay id
    pub fn id(&self) -> &IdShort {
        &self.id
    }

    /// Returns local ADNL key for public overlay
    pub fn overlay_key(&self) -> &Arc<adnl::Key> {
        &self.node_key
    }

    /// Verifies and adds new peer to the overlay. Returns `Some` short peer id
    /// if new peer was successfully added and `None` if peer already existed.
    ///
    /// See [`Overlay::add_public_peers`] for multiple peers.
    pub fn add_public_peer(
        &self,
        adnl: &adnl::Node,
        addr: SocketAddrV4,
        node: proto::overlay::Node<'_>,
    ) -> Result<Option<adnl::NodeIdShort>> {
        if let Err(e) = self.id.verify_overlay_node(&node) {
            tracing::warn!(overlay_id = %self.id, %addr, "invalid public overlay node: {e:?}");
            return Ok(None);
        }

        let peer_id_full = adnl::NodeIdFull::try_from(node.id)?;
        let peer_id = peer_id_full.compute_short_id();

        let is_new_peer = adnl.add_peer(
            adnl::NewPeerContext::PublicOverlay,
            self.overlay_key().id(),
            &peer_id,
            addr,
            peer_id_full,
        )?;
        if is_new_peer {
            self.insert_public_peer(&peer_id, node);
            Ok(Some(peer_id))
        } else {
            Ok(None)
        }
    }

    /// Verifies and adds new peers to the overlay. Returns a list of successfully added peers.
    ///
    /// See [`Overlay::add_public_peer`] for single peer.
    pub fn add_public_peers<'a, I>(
        &self,
        adnl: &adnl::Node,
        nodes: I,
    ) -> Result<Vec<adnl::NodeIdShort>>
    where
        I: IntoIterator<Item = (SocketAddrV4, proto::overlay::Node<'a>)>,
    {
        let local_id = self.overlay_key().id();

        let mut result = Vec::new();
        for (addr, node) in nodes {
            if let Err(e) = self.id.verify_overlay_node(&node) {
                tracing::warn!(overlay_id = %self.id, %addr, "invalid public overlay node: {e:?}");
                continue;
            }

            let peer_id_full = adnl::NodeIdFull::try_from(node.id)?;
            let peer_id = peer_id_full.compute_short_id();

            let is_new_peer = adnl.add_peer(
                adnl::NewPeerContext::PublicOverlay,
                local_id,
                &peer_id,
                addr,
                peer_id_full,
            )?;
            if is_new_peer {
                self.insert_public_peer(&peer_id, node);
                result.push(peer_id);
                tracing::trace!(overlay_id = %self.id, %peer_id, %addr, "new public peer");
            }
        }

        Ok(result)
    }

    /// Removes peer from random peers and adds it to ignored peers
    pub fn remove_public_peer(&self, peer_id: &adnl::NodeIdShort) -> bool {
        if !self.ignored_peers.insert(*peer_id) {
            return false;
        }
        tracing::warn!(overlay_id = %self.id, %peer_id, "removing public overlay peer");
        if self.neighbours.contains(peer_id) {
            self.update_neighbours(self.options.max_neighbours);
        }
        true
    }

    /// Checks whether the specified peer has ever been in this public overlay
    ///
    /// NOTE: Peer might have been excluded. If you need to check whether the
    /// specified peer is still in this overlay use [`Overlay::is_active_public_peer`]
    pub fn is_known_peer(&self, peer_id: &adnl::NodeIdShort) -> bool {
        self.known_peers.contains(peer_id)
    }

    /// Checks whether the specified peer is in the current public overlay
    pub fn is_active_public_peer(&self, peer_id: &adnl::NodeIdShort) -> bool {
        self.known_peers.contains(peer_id) && !self.ignored_peers.contains(peer_id)
    }

    /// Fill `dst` with `amount` peers from known peers
    pub fn write_cached_peers(&self, amount: u32, dst: &adnl::PeersSet) {
        dst.randomly_fill_from(&self.known_peers, amount, Some(&self.ignored_peers));
    }

    /// Serialized [`proto::rpc::OverlayQuery`] with own overlay id
    #[inline(always)]
    pub fn query_prefix(&self) -> &[u8] {
        &self.query_prefix
    }

    /// Serialized [`proto::overlay::Message`] with own overlay id
    #[inline(always)]
    pub fn message_prefix(&self) -> &[u8] {
        &self.message_prefix
    }

    /// Sends direct ADNL message ([`proto::adnl::Message::Custom`]) to the given peer.
    ///
    /// NOTE: Local id ([`Overlay::overlay_key`]) will be used as sender
    pub fn send_message(
        &self,
        adnl: &adnl::Node,
        peer_id: &adnl::NodeIdShort,
        data: &[u8],
    ) -> Result<()> {
        let local_id = self.overlay_key().id();

        let mut buffer = Vec::with_capacity(self.message_prefix().len() + data.len());
        buffer.extend_from_slice(self.message_prefix());
        buffer.extend_from_slice(data);
        adnl.send_custom_message(local_id, peer_id, &buffer)
    }

    /// Sends ADNL query directly to the given peer. In case of timeout returns `Ok(None)`
    ///
    /// NOTE: Local id ([`Overlay::overlay_key`]) will be used as sender
    pub async fn adnl_query<Q>(
        &self,
        adnl: &adnl::Node,
        peer_id: &adnl::NodeIdShort,
        query: Q,
        timeout: Option<u64>,
    ) -> Result<Option<Vec<u8>>>
    where
        Q: TlWrite,
    {
        let local_id = self.overlay_key().id();
        type Value = tl_proto::OwnedRawBytes<tl_proto::Boxed>;
        match adnl
            .query_with_prefix::<Q, Value>(local_id, peer_id, self.query_prefix(), query, timeout)
            .await?
        {
            Some(answer) => Ok(Some(answer.into_inner())),
            None => Ok(None),
        }
    }

    /// Sends RLDP query directly to the given peer. In case of timeout returns `Ok((None, max_timeout))`
    ///
    /// NOTE: Local id ([`Overlay::overlay_key`]) will be used as sender
    pub async fn rldp_query<Q>(
        &self,
        rldp: &rldp::Node,
        peer_id: &adnl::NodeIdShort,
        query: Q,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)>
    where
        Q: TlWrite,
    {
        let local_id = self.overlay_key().id();

        let prefix = self.query_prefix();
        let mut query_data = Vec::with_capacity(prefix.len() + query.max_size_hint());
        query_data.extend_from_slice(prefix);
        query.write_to(&mut query_data);

        rldp.query(local_id, peer_id, query_data, roundtrip).await
    }

    /// Distributes provided message to the neighbours subset.
    ///
    /// See `broadcast_target_count` in [`OverlayOptions`]
    ///
    /// NOTE: If `data` len is greater than
    pub fn broadcast(
        self: &Arc<Self>,
        adnl: &Arc<adnl::Node>,
        data: Vec<u8>,
        source: Option<&Arc<adnl::Key>>,
        target: BroadcastTarget,
    ) -> OutgoingBroadcastInfo {
        let local_id = self.overlay_key().id();

        let key = match source {
            Some(key) => key,
            None => &self.node_key,
        };

        if data.len() <= self.options.max_ordinary_broadcast_len {
            self.send_broadcast(adnl, local_id, data, key, target)
        } else {
            self.send_fec_broadcast(adnl, local_id, data, key, target)
        }
    }

    /// Waits until the next received broadcast.
    ///
    /// NOTE: It is important to keep polling this method because otherwise
    /// received broadcasts queue will consume all the memory.
    pub async fn wait_for_broadcast(&self) -> IncomingBroadcastInfo {
        self.received_broadcasts.pop().await
    }

    /// Take received peers map
    pub fn take_new_peers(&self) -> ReceivedPeersMap {
        let mut peers = self.received_peers.lock();
        std::mem::take(&mut *peers)
    }

    /// Returns raw signed overlay node
    pub fn sign_local_node(&self) -> proto::overlay::NodeOwned {
        let key = self.overlay_key();
        let version = now();

        let node_to_sign = proto::overlay::NodeToSign {
            id: key.id().as_slice(),
            overlay: self.id().as_slice(),
            version,
        };
        let signature = key.sign(&node_to_sign);

        proto::overlay::NodeOwned {
            id: key.full_id().as_tl().as_equivalent_owned(),
            overlay: *self.id().as_slice(),
            version,
            signature: signature.to_vec().into(),
        }
    }

    /// Exchanges random peers with the specified peer. Returns `Ok(None)` in case of timeout.
    /// Uses the default existing peers filter.
    pub async fn exchange_random_peers(
        &self,
        adnl: &adnl::Node,
        peer_id: &adnl::NodeIdShort,
        timeout: Option<u64>,
    ) -> Result<Option<Vec<adnl::NodeIdShort>>> {
        struct KnownPeers<'a>(&'a adnl::PeersSet);

        impl ExistingPeersFilter for KnownPeers<'_> {
            fn contains(&self, peer_id: &adnl::NodeIdShort) -> bool {
                self.0.contains(peer_id)
            }
        }

        self.exchange_random_peers_ext(adnl, peer_id, timeout, &KnownPeers(&self.known_peers))
            .await
    }

    /// Exchanges random peers with the specified peer. Returns `Ok(None)` in case of timeout.
    /// Uses the specified existing peers filter.
    pub async fn exchange_random_peers_ext(
        &self,
        adnl: &adnl::Node,
        peer_id: &adnl::NodeIdShort,
        timeout: Option<u64>,
        existing_peers: &dyn ExistingPeersFilter,
    ) -> Result<Option<Vec<adnl::NodeIdShort>>> {
        let query = proto::rpc::OverlayGetRandomPeersOwned {
            peers: self.prepare_random_peers(),
        };
        let answer = match self.adnl_query(adnl, peer_id, query, timeout).await? {
            Some(answer) => answer,
            None => {
                tracing::trace!(overlay_id = %self.id, %peer_id, "no random peers found");
                return Ok(None);
            }
        };

        let answer = tl_proto::deserialize_as_boxed(&answer)?;
        tracing::trace!(overlay_id = %self.id, %peer_id, "got random peers");
        let proto::overlay::Nodes { nodes } = self.filter_nodes(answer);

        let nodes = nodes
            .into_iter()
            .filter_map(|node| match adnl::NodeIdFull::try_from(node.id) {
                Ok(full_id) => {
                    let peer_id = full_id.compute_short_id();
                    if !existing_peers.contains(&peer_id) {
                        Some(peer_id)
                    } else {
                        None
                    }
                }
                Err(e) => {
                    tracing::warn!(overlay_id = %self.id, %peer_id, "failed to process peer: {e}");
                    None
                }
            })
            .collect();
        Ok(Some(nodes))
    }

    /// Process ordinary broadcast
    pub(super) async fn receive_broadcast(
        self: &Arc<Self>,
        adnl: &adnl::Node,
        local_id: &adnl::NodeIdShort,
        peer_id: &adnl::NodeIdShort,
        broadcast: proto::overlay::OverlayBroadcast<'_>,
        raw_data: &[u8],
    ) -> Result<()> {
        if self.is_broadcast_outdated(broadcast.date) {
            return Ok(());
        }

        let node_id = adnl::NodeIdFull::try_from(broadcast.src)?;
        let node_peer_id = node_id.compute_short_id();
        let source = match broadcast.flags {
            flags if flags & BROADCAST_FLAG_ANY_SENDER == 0 => Some(node_peer_id),
            _ => None,
        };

        let broadcast_data = match compression::decompress(broadcast.data) {
            Some(decompressed) => {
                let broadcast_to_sign =
                    make_broadcast_to_sign(&decompressed, broadcast.date, source.as_ref());
                match node_id.verify(&broadcast_to_sign, broadcast.signature) {
                    Ok(()) => {
                        let broadcast_id = broadcast_to_sign.compute_broadcast_id();
                        if !self.create_broadcast(broadcast_id) {
                            return Ok(());
                        }
                        Some((broadcast_id, decompressed))
                    }
                    Err(_) => None,
                }
            }
            None => None,
        };

        let (broadcast_id, data) = match broadcast_data {
            Some((id, data)) => (id, data),
            None => {
                let broadcast_to_sign =
                    make_broadcast_to_sign(broadcast.data, broadcast.date, source.as_ref());
                node_id.verify(&broadcast_to_sign, broadcast.signature)?;

                let broadcast_id = broadcast_to_sign.compute_broadcast_id();
                if !self.create_broadcast(broadcast_id) {
                    return Ok(());
                }
                (broadcast_id, broadcast.data.to_vec())
            }
        };

        self.received_broadcasts.push(IncomingBroadcastInfo {
            packets: 1,
            data,
            from: node_peer_id,
        });

        let neighbours = self
            .neighbours
            .get_random_peers(self.options.secondary_broadcast_target_count, Some(peer_id));
        self.distribute_broadcast(adnl, local_id, &neighbours, raw_data);
        self.spawn_broadcast_gc_task(broadcast_id);

        Ok(())
    }

    /// Process FEC broadcast
    pub(super) async fn receive_fec_broadcast(
        self: &Arc<Self>,
        adnl: &adnl::Node,
        local_id: &adnl::NodeIdShort,
        peer_id: &adnl::NodeIdShort,
        broadcast: proto::overlay::OverlayBroadcastFec<'_>,
        raw_data: &[u8],
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        if self.is_broadcast_outdated(broadcast.date) {
            return Ok(());
        }

        let broadcast_id = *broadcast.data_hash;
        let node_id = adnl::NodeIdFull::try_from(broadcast.src)?;
        let source = node_id.compute_short_id();

        let signature = match broadcast.signature.len() {
            64 => broadcast.signature.try_into().unwrap(),
            _ => return Err(OverlayError::UnsupportedSignature.into()),
        };

        let transfer = match self.owned_broadcasts.entry(broadcast_id) {
            // First packet of the broadcast
            Entry::Vacant(entry) => {
                self.spawn_fec_transfer_receiver(broadcast.fec, broadcast_id, source, entry)?
            }
            // Broadcast was already started
            Entry::Occupied(entry) => entry.get().clone(),
        };
        let transfer = match transfer.as_ref() {
            OwnedBroadcast::Incoming(transfer) => transfer,
            OwnedBroadcast::Other => return Ok(()),
        };

        transfer.updated_at.refresh();
        if transfer.source != source {
            tracing::trace!(
                overlay_id = %self.id,
                broadcast_id = %DisplayBroadcastId(&broadcast_id),
                "same broadcast but parts from different sources"
            );
            return Ok(());
        }

        // Ignore duplicate packets
        if !transfer.history.deliver_packet(broadcast.seqno as u64) {
            return Ok(());
        }

        // Send broadcast to the processing queue
        if !transfer.completed.load(Ordering::Acquire) {
            transfer.broadcast_tx.send(BroadcastFec {
                node_id,
                data_hash: broadcast_id,
                data_size: broadcast.data_size,
                flags: broadcast.flags,
                data: broadcast.data.to_vec(),
                seqno: broadcast.seqno,
                fec_type: broadcast.fec,
                date: broadcast.date,
                signature,
            })?;
        }

        // Redistribute broadcast
        let neighbours = self.neighbours.get_random_peers(
            self.options.secondary_fec_broadcast_target_count,
            Some(peer_id),
        );
        self.distribute_broadcast(adnl, local_id, &neighbours, raw_data);

        Ok(())
    }

    /// Process random peers request
    pub(super) fn process_get_random_peers(
        &self,
        query: proto::rpc::OverlayGetRandomPeers<'_>,
    ) -> proto::overlay::NodesOwned {
        use std::collections::hash_map::Entry;

        // Update received peers
        let peers = self.filter_nodes(query.peers).nodes;

        // Insert received peers
        let mut received_peers = self.received_peers.lock();
        for node in peers {
            match received_peers.entry(HashWrapper(node.id.as_equivalent_owned())) {
                Entry::Occupied(mut entry) => {
                    if entry.get().version < node.version {
                        entry.insert(node.as_equivalent_owned());
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(node.as_equivalent_owned());
                }
            }
        }

        // NOTE: reduce lock scope
        drop(received_peers);

        // Return random peers from our side
        self.prepare_random_peers()
    }

    /// Send ordinary broadcast
    fn send_broadcast(
        self: &Arc<Self>,
        adnl: &adnl::Node,
        local_id: &adnl::NodeIdShort,
        mut data: Vec<u8>,
        key: &Arc<adnl::Key>,
        target: BroadcastTarget,
    ) -> OutgoingBroadcastInfo {
        let date = now();
        let broadcast_to_sign = make_broadcast_to_sign(&data, date, None);
        let broadcast_id = broadcast_to_sign.compute_broadcast_id();
        if !self.create_broadcast(broadcast_id) {
            tracing::warn!(
                overlay_id = %self.id,
                broadcast_id = %DisplayBroadcastId(&broadcast_id),
                "trying to send duplicated broadcast"
            );
            return Default::default();
        }
        let signature = key.sign(broadcast_to_sign);

        if self.options.force_compression {
            if let Err(e) = compression::compress(&mut data) {
                tracing::warn!(
                    overlay_id = %self.id,
                    broadcast_id = %DisplayBroadcastId(&broadcast_id),
                    "failed to compress overlay broadcast: {e:?}"
                );
            }
        }

        let broadcast = proto::overlay::Broadcast::Broadcast(proto::overlay::OverlayBroadcast {
            src: key.full_id().as_tl(),
            certificate: proto::overlay::Certificate::EmptyCertificate,
            flags: BROADCAST_FLAG_ANY_SENDER,
            data: &data,
            date,
            signature: &signature,
        });

        let mut buffer = Vec::with_capacity(self.message_prefix.len() + broadcast.max_size_hint());
        buffer.extend_from_slice(&self.message_prefix);
        broadcast.write_to(&mut buffer);
        drop(data);

        let neighbours = match target {
            BroadcastTarget::RandomNeighbours => OwnedBroadcastTarget::Neighbours(
                self.neighbours
                    .get_random_peers(self.options.broadcast_target_count, None),
            ),
            BroadcastTarget::Explicit(neighbours) => OwnedBroadcastTarget::Explicit(neighbours),
        };

        self.distribute_broadcast(adnl, local_id, neighbours.as_ref(), &buffer);
        self.spawn_broadcast_gc_task(broadcast_id);

        OutgoingBroadcastInfo {
            packets: 1,
            recipient_count: neighbours.as_ref().len(),
        }
    }

    /// Send FEC broadcast
    fn send_fec_broadcast(
        self: &Arc<Self>,
        adnl: &Arc<adnl::Node>,
        local_id: &adnl::NodeIdShort,
        mut data: Vec<u8>,
        key: &Arc<adnl::Key>,
        target: BroadcastTarget,
    ) -> OutgoingBroadcastInfo {
        let broadcast_id = sha2::Sha256::digest(&data).into();
        if !self.create_broadcast(broadcast_id) {
            tracing::warn!(
                overlay_id = %self.id,
                broadcast_id = %DisplayBroadcastId(&broadcast_id),
                "trying to send duplicated broadcast",
            );
            return Default::default();
        }

        if self.options.force_compression {
            if let Err(e) = compression::compress(&mut data) {
                tracing::warn!(
                    overlay_id = %self.id,
                    broadcast_id = %DisplayBroadcastId(&broadcast_id),
                    "failed to compress overlay FEC broadcast: {e:?}"
                );
            }
        }

        let data_size = data.len() as u32;
        let mut outgoing_transfer = OutgoingFecTransfer {
            broadcast_id,
            encoder: RaptorQEncoder::with_data(&data),
            seqno: 0,
        };

        // NOTE: Data is already in encoder and not needed anymore
        drop(data);

        let neighbours = match target {
            BroadcastTarget::RandomNeighbours => OwnedBroadcastTarget::Neighbours(
                self.neighbours
                    .get_random_peers(self.options.broadcast_target_count, None),
            ),
            BroadcastTarget::Explicit(neighbours) => OwnedBroadcastTarget::Explicit(neighbours),
        };

        let info = OutgoingBroadcastInfo {
            packets: (data_size / outgoing_transfer.encoder.params().packet_len + 1) * 3 / 2,
            recipient_count: neighbours.as_ref().len(),
        };

        // Spawn sender
        let wave_len = self.options.fec_broadcast_wave_len;
        let waves_interval = Duration::from_millis(self.options.fec_broadcast_wave_interval_ms);
        let overlay = self.clone();
        let adnl = adnl.clone();
        let local_id = *local_id;
        let key = key.clone();
        tokio::spawn(async move {
            // Send broadcast in waves
            'outer: while outgoing_transfer.seqno <= info.packets {
                for _ in 0..wave_len {
                    let data = match overlay.prepare_fec_broadcast(&mut outgoing_transfer, &key) {
                        Ok(data) => data,
                        // Rare case, it is easier to just ignore it
                        Err(e) => {
                            tracing::warn!(
                                overlay_id = %overlay.id,
                                broadcast_id = %DisplayBroadcastId(&broadcast_id),
                                "failed to send overlay broadcast: {e}"
                            );
                            break 'outer;
                        }
                    };

                    overlay.distribute_broadcast(&adnl, &local_id, neighbours.as_ref(), &data);
                    if outgoing_transfer.seqno > info.packets {
                        break 'outer;
                    }
                }

                // Sleep between waves
                tokio::time::sleep(waves_interval).await;
            }
        });

        // Schedule broadcast cleanup
        self.spawn_broadcast_gc_task(broadcast_id);

        // Done
        info
    }

    /// Verifies and retains only valid remote peers
    fn filter_nodes<'a>(&self, mut nodes: proto::overlay::Nodes<'a>) -> proto::overlay::Nodes<'a> {
        nodes.nodes.retain(|node| {
            if !matches!(
                node.id,
                everscale_crypto::tl::PublicKey::Ed25519 { key }
                if key != self.node_key.full_id().public_key().as_bytes()
            ) {
                return false;
            }

            if let Err(e) = self.id.verify_overlay_node(node) {
                tracing::warn!(overlay_id = %self.id, "invalid overlay node: {e:?}");
                return false;
            }

            true
        });

        nodes
    }

    /// Creates nodes list
    fn prepare_random_peers(&self) -> proto::overlay::NodesOwned {
        const MAX_PEERS_IN_RESPONSE: u32 = 4;

        let mut nodes = SmallVec::with_capacity(MAX_PEERS_IN_RESPONSE as usize + 1);
        nodes.push(self.sign_local_node());

        let peers = adnl::PeersSet::with_capacity(MAX_PEERS_IN_RESPONSE);
        peers.randomly_fill_from(&self.neighbours, MAX_PEERS_IN_RESPONSE, None);
        for peer_id in &peers {
            if let Some(node) = self.nodes.get(peer_id) {
                nodes.push(node.clone());
            }
        }

        proto::overlay::NodesOwned { nodes }
    }

    /// Fills neighbours with a random subset from known peers
    fn update_neighbours(&self, amount: u32) {
        tracing::trace!(overlay_id = %self.id, amount, "updating neighbours");
        self.neighbours
            .randomly_fill_from(&self.known_peers, amount, Some(&self.ignored_peers));
    }

    /// Adds public peer info
    fn insert_public_peer(&self, peer_id: &adnl::NodeIdShort, node: proto::overlay::Node<'_>) {
        use dashmap::mapref::entry::Entry;

        self.ignored_peers.remove(peer_id);
        self.known_peers.insert(*peer_id);

        if !self.neighbours.is_full() {
            self.neighbours.insert(*peer_id);
        }

        match self.nodes.entry(*peer_id) {
            Entry::Occupied(mut entry) => {
                if entry.get().version < node.version {
                    entry.insert(node.as_equivalent_owned());
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(node.as_equivalent_owned());
            }
        }
    }

    /// Adds new broadcast id
    fn create_broadcast(&self, broadcast_id: BroadcastId) -> bool {
        use dashmap::mapref::entry::Entry;

        match self.owned_broadcasts.entry(broadcast_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(OwnedBroadcast::Other));
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Creates incoming FEC broadcast
    fn spawn_fec_transfer_receiver(
        self: &Arc<Self>,
        fec_type: proto::rldp::RaptorQFecType,
        broadcast_id: BroadcastId,
        peer_id: adnl::NodeIdShort,
        entry: VacantBroadcastEntry<'_>,
    ) -> Result<Arc<OwnedBroadcast>> {
        let (broadcast_tx, mut broadcast_rx) = mpsc::unbounded_channel();

        let entry = entry
            .insert(Arc::new(OwnedBroadcast::Incoming(IncomingFecTransfer {
                completed: AtomicBool::new(false),
                history: PacketsHistory::for_recv(),
                broadcast_tx,
                source: peer_id,
                updated_at: Default::default(),
            })))
            .clone();

        // Spawn packets receiver
        let overlay = self.clone();
        tokio::spawn(async move {
            let mut decoder = RaptorQDecoder::with_params(fec_type);

            // For each fec broadcast packet
            let mut packets = 0;
            while let Some(broadcast) = broadcast_rx.recv().await {
                packets += 1;

                // Add new data to the encoder
                match process_fec_broadcast(&mut decoder, broadcast) {
                    // Broadcast complete and successfully decoded
                    Ok(Some(data)) => {
                        let data = IncomingBroadcastInfo {
                            packets,
                            data,
                            from: peer_id,
                        };
                        overlay.received_broadcasts.push(data);
                        break;
                    }
                    // Broadcast is not complete yet
                    Ok(None) => continue,
                    // Error during decoding
                    Err(e) => {
                        tracing::warn!(
                            overlay_id = %overlay.id,
                            broadcast_id = %DisplayBroadcastId(&broadcast_id),
                            "error when receiving overlay broadcast: {e}"
                        );
                        break;
                    }
                }
            }

            // Mark broadcast as completed
            if let Some(broadcast) = overlay.owned_broadcasts.get(&broadcast_id) {
                match broadcast.value().as_ref() {
                    OwnedBroadcast::Incoming(transfer) => {
                        transfer.completed.store(true, Ordering::Release);
                    }
                    _ => {
                        tracing::error!(
                            overlay_id = %overlay.id,
                            broadcast_id = %DisplayBroadcastId(&broadcast_id),
                            "incoming fec broadcast mismatch"
                        );
                    }
                }
            }
        });

        // Spawn broadcast cleanup task
        let overlay = self.clone();
        let broadcast_timeout_sec = self.options.broadcast_timeout_sec;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(broadcast_timeout_sec * 100)).await;

                // Find incoming broadcast
                if let Some(broadcast) = overlay.owned_broadcasts.get(&broadcast_id) {
                    match broadcast.value().as_ref() {
                        // Keep waiting if broadcast is not expired or not complete
                        OwnedBroadcast::Incoming(transfer)
                            if !transfer.completed.load(Ordering::Acquire)
                                && !transfer.updated_at.is_expired(broadcast_timeout_sec) =>
                        {
                            continue
                        }
                        OwnedBroadcast::Incoming(_) => {}
                        _ => {
                            tracing::error!(
                                overlay_id = %overlay.id,
                                broadcast_id = %DisplayBroadcastId(&broadcast_id),
                                "incoming fec broadcast mismatch"
                            );
                        }
                    }
                }

                break;
            }

            overlay.spawn_broadcast_gc_task(broadcast_id);
        });

        Ok(entry)
    }

    /// Encodes next chunk of FEC broadcast
    fn prepare_fec_broadcast(
        &self,
        transfer: &mut OutgoingFecTransfer,
        key: &Arc<adnl::Key>,
    ) -> Result<Vec<u8>> {
        let chunk = transfer.encoder.encode(&mut transfer.seqno)?;
        let date = now();

        let broadcast_to_sign = &make_fec_part_to_sign(
            &transfer.broadcast_id,
            transfer.encoder.params().total_len,
            date,
            BROADCAST_FLAG_ANY_SENDER,
            transfer.encoder.params(),
            &chunk,
            transfer.seqno,
            None,
        );
        let signature = key.sign(broadcast_to_sign);

        let broadcast =
            proto::overlay::Broadcast::BroadcastFec(proto::overlay::OverlayBroadcastFec {
                src: key.full_id().as_tl(),
                certificate: proto::overlay::Certificate::EmptyCertificate,
                data_hash: &transfer.broadcast_id,
                data_size: transfer.encoder.params().total_len,
                flags: BROADCAST_FLAG_ANY_SENDER,
                data: &chunk,
                seqno: transfer.seqno,
                fec: *transfer.encoder.params(),
                date,
                signature: &signature,
            });

        transfer.seqno += 1;

        let mut buffer = Vec::with_capacity(self.message_prefix.len() + broadcast.max_size_hint());
        buffer.extend_from_slice(&self.message_prefix);
        broadcast.write_to(&mut buffer);

        Ok(buffer)
    }

    /// Sends ADNL messages to neighbours
    fn distribute_broadcast(
        &self,
        adnl: &adnl::Node,
        local_id: &adnl::NodeIdShort,
        neighbours: &[adnl::NodeIdShort],
        data: &[u8],
    ) {
        for peer_id in neighbours {
            if let Err(e) = adnl.send_custom_message(local_id, peer_id, data) {
                tracing::warn!(
                    overlay_id = %self.id,
                    %peer_id,
                    "failed to distribute broadcast: {e}"
                );
            }
        }
    }

    fn is_broadcast_outdated(&self, date: u32) -> bool {
        date + (self.options.broadcast_timeout_sec as u32) < now()
    }

    fn spawn_broadcast_gc_task(self: &Arc<Self>, broadcast_id: BroadcastId) {
        let overlay = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(overlay.options.broadcast_timeout_sec)).await;
            overlay
                .finished_broadcast_count
                .fetch_add(1, Ordering::Release);
            overlay.finished_broadcasts.push(broadcast_id);
        });
    }
}

/// Overlay broadcast target
#[derive(Debug, Clone)]
pub enum BroadcastTarget {
    /// Select N random peers from current neighbours
    RandomNeighbours,
    /// Explicit neighbour ids
    Explicit(Arc<Vec<adnl::NodeIdShort>>),
}

impl Default for BroadcastTarget {
    fn default() -> Self {
        Self::RandomNeighbours
    }
}

/// Filter for overlay peers exchange.
pub trait ExistingPeersFilter: Send + Sync {
    fn contains(&self, peer_id: &adnl::NodeIdShort) -> bool;
}

impl ExistingPeersFilter for () {
    fn contains(&self, _: &adnl::NodeIdShort) -> bool {
        false
    }
}

impl ExistingPeersFilter for bool {
    fn contains(&self, _: &adnl::NodeIdShort) -> bool {
        *self
    }
}

impl<S> ExistingPeersFilter for std::collections::HashSet<adnl::NodeIdShort, S>
where
    S: std::hash::BuildHasher + Send + Sync,
{
    fn contains(&self, peer_id: &adnl::NodeIdShort) -> bool {
        std::collections::HashSet::contains(self, peer_id)
    }
}

impl<S> ExistingPeersFilter for dashmap::DashSet<adnl::NodeIdShort, S>
where
    S: std::hash::BuildHasher + Send + Sync + Clone,
{
    fn contains(&self, peer_id: &adnl::NodeIdShort) -> bool {
        dashmap::DashSet::contains(self, peer_id)
    }
}

enum OwnedBroadcastTarget {
    Neighbours(Vec<adnl::NodeIdShort>),
    Explicit(Arc<Vec<adnl::NodeIdShort>>),
}

impl AsRef<[adnl::NodeIdShort]> for OwnedBroadcastTarget {
    fn as_ref(&self) -> &[adnl::NodeIdShort] {
        match self {
            OwnedBroadcastTarget::Neighbours(neighbours) => neighbours.as_ref(),
            OwnedBroadcastTarget::Explicit(neighbours) => neighbours.as_ref(),
        }
    }
}

/// Instant overlay metrics
#[derive(Debug, Copy, Clone)]
pub struct OverlayMetrics {
    pub owned_broadcasts_len: usize,
    pub finished_broadcasts_len: u32,
    pub node_count: usize,
    pub known_peers: usize,
    pub neighbours: usize,
    pub received_broadcasts_data_len: usize,
    pub received_broadcasts_barrier_count: usize,
}

fn process_fec_broadcast(
    decoder: &mut RaptorQDecoder,
    broadcast: BroadcastFec,
) -> Result<Option<Vec<u8>>> {
    let broadcast_id = &broadcast.data_hash;

    let broadcast_to_sign = &make_fec_part_to_sign(
        broadcast_id,
        broadcast.data_size,
        broadcast.date,
        broadcast.flags,
        &broadcast.fec_type,
        &broadcast.data,
        broadcast.seqno,
        if broadcast.flags & BROADCAST_FLAG_ANY_SENDER == 0 {
            Some(broadcast.node_id.compute_short_id())
        } else {
            None
        },
    );
    broadcast
        .node_id
        .verify(broadcast_to_sign, &broadcast.signature)?;

    match decoder.decode(broadcast.seqno, broadcast.data) {
        Some(result) if result.len() != broadcast.data_size as usize => {
            Err(OverlayError::DataSizeMismatch.into())
        }
        Some(result) => match compression::decompress(&result) {
            Some(decompressed)
                if sha2::Sha256::digest(&decompressed).as_slice() == broadcast_id =>
            {
                Ok(Some(decompressed))
            }
            _ => {
                let data_hash = sha2::Sha256::digest(&result);
                if data_hash.as_slice() == broadcast_id {
                    Ok(Some(result))
                } else {
                    Err(OverlayError::DataHashMismatch.into())
                }
            }
        },
        None => Ok(None),
    }
}

#[derive(TlWrite)]
#[tl(boxed, id = "overlay.broadcast.toSign", scheme = "scheme.tl")]
struct OverlayBroadcastToSign {
    hash: [u8; 32],
    date: u32,
}

impl OverlayBroadcastToSign {
    fn compute_broadcast_id(&self) -> BroadcastId {
        tl_proto::hash(self)
    }
}

fn make_broadcast_to_sign(
    data: &[u8],
    date: u32,
    source: Option<&adnl::NodeIdShort>,
) -> OverlayBroadcastToSign {
    const BROADCAST_ID: u32 = tl_proto::id!("overlay.broadcast.id", scheme = "scheme.tl");

    let mut broadcast_hash = sha2::Sha256::new();
    broadcast_hash.update(BROADCAST_ID.to_le_bytes());
    broadcast_hash.update(source.map(adnl::NodeIdShort::as_slice).unwrap_or(&[0; 32]));
    broadcast_hash.update(sha2::Sha256::digest(data).as_slice());
    broadcast_hash.update(BROADCAST_FLAG_ANY_SENDER.to_le_bytes());
    let broadcast_hash = broadcast_hash.finalize();

    OverlayBroadcastToSign {
        hash: broadcast_hash.into(),
        date,
    }
}

fn make_fec_part_to_sign(
    data_hash: &[u8; 32],
    data_size: u32,
    date: u32,
    flags: u32,
    params: &proto::rldp::RaptorQFecType,
    part: &[u8],
    seqno: u32,
    source: Option<adnl::NodeIdShort>,
) -> OverlayBroadcastToSign {
    const BROADCAST_FEC_ID: u32 = tl_proto::id!("overlay.broadcastFec.id", scheme = "scheme.tl");
    const BROADCAST_FEC_PART_ID: u32 =
        tl_proto::id!("overlay.broadcastFec.partId", scheme = "scheme.tl");

    let mut broadcast_hash = sha2::Sha256::new();
    broadcast_hash.update(BROADCAST_FEC_ID.to_le_bytes());
    broadcast_hash.update(
        source
            .as_ref()
            .map(adnl::NodeIdShort::as_slice)
            .unwrap_or(&[0; 32]),
    );
    broadcast_hash.update(tl_proto::hash(params));
    broadcast_hash.update(data_hash);
    broadcast_hash.update(data_size.to_le_bytes());
    broadcast_hash.update(flags.to_le_bytes());
    let broadcast_hash = broadcast_hash.finalize();

    let mut part_hash = sha2::Sha256::new();
    part_hash.update(BROADCAST_FEC_PART_ID.to_le_bytes());
    part_hash.update(broadcast_hash);
    part_hash.update(sha2::Sha256::digest(part).as_slice());
    part_hash.update(seqno.to_le_bytes());
    let part_hash = part_hash.finalize();

    OverlayBroadcastToSign {
        hash: part_hash.into(),
        date,
    }
}

/// Received overlay broadcast
pub struct IncomingBroadcastInfo {
    pub packets: u32,
    pub data: Vec<u8>,
    pub from: adnl::NodeIdShort,
}

/// Sent overlay broadcast info
#[derive(Default, Copy, Clone)]
pub struct OutgoingBroadcastInfo {
    pub packets: u32,
    pub recipient_count: usize,
}

struct IncomingFecTransfer {
    completed: AtomicBool,
    history: PacketsHistory,
    broadcast_tx: BroadcastFecTx,
    source: adnl::NodeIdShort,
    updated_at: UpdatedAt,
}

struct OutgoingFecTransfer {
    broadcast_id: BroadcastId,
    encoder: RaptorQEncoder,
    seqno: u32,
}

enum OwnedBroadcast {
    Other,
    Incoming(IncomingFecTransfer),
}

#[derive(Debug)]
struct BroadcastFec {
    node_id: adnl::NodeIdFull,
    data_hash: BroadcastId,
    data_size: u32,
    flags: u32,
    data: Vec<u8>,
    seqno: u32,
    fec_type: proto::rldp::RaptorQFecType,
    date: u32,
    signature: [u8; 64],
}

type VacantBroadcastEntry<'a> =
    dashmap::mapref::entry::VacantEntry<'a, BroadcastId, Arc<OwnedBroadcast>, FastHasherState>;

/// Type alias for received nodes
pub type ReceivedPeersMap =
    FastHashMap<HashWrapper<everscale_crypto::tl::PublicKeyOwned>, proto::overlay::NodeOwned>;

type BroadcastFecTx = mpsc::UnboundedSender<BroadcastFec>;

#[derive(Copy, Clone)]
pub struct DisplayBroadcastId<'a>(pub &'a BroadcastId);

impl std::fmt::Display for DisplayBroadcastId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(self.0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

type BroadcastId = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum OverlayError {
    #[error("Unsupported signature")]
    UnsupportedSignature,
    #[error("Data size mismatch")]
    DataSizeMismatch,
    #[error("Data hash mismatch")]
    DataHashMismatch,
}

const BROADCAST_FLAG_ANY_SENDER: u32 = 1; // Any sender
