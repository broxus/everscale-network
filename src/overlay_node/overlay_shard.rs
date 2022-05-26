use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use sha2::Digest;
use tl_proto::{HashWrapper, TlWrite};
use tokio::sync::mpsc;
use ton_api::{ton, IntoBoxed};

use super::{broadcast_receiver::*, MAX_OVERLAY_PEERS};
use crate::adnl_node::*;
use crate::rldp_node::*;
use crate::utils::*;

pub struct OverlayShard {
    adnl: Arc<AdnlNode>,
    overlay_id: OverlayIdShort,
    node_key: Arc<StoredAdnlNodeKey>,
    overlay_key: Option<Arc<StoredAdnlNodeKey>>,
    options: OverlayShardOptions,

    owned_broadcasts: FxDashMap<BroadcastId, Arc<OwnedBroadcast>>,
    finished_broadcasts: SegQueue<BroadcastId>,
    finished_broadcast_count: AtomicU32,

    received_peers: Arc<Mutex<ReceivedPeersMap>>,
    received_broadcasts: Arc<BroadcastReceiver<IncomingBroadcastInfo>>,
    received_catchain: Arc<BroadcastReceiver<CatchainUpdate>>,

    nodes: FxDashMap<AdnlNodeIdShort, ton::overlay::node::Node>,
    ignored_peers: FxDashSet<AdnlNodeIdShort>,
    known_peers: PeersCache,
    random_peers: PeersCache,
    neighbours: PeersCache,

    query_prefix: Vec<u8>,
    message_prefix: Vec<u8>,
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct OverlayShardOptions {
    /// Default: 20
    pub max_shard_peers: usize,
    /// Default: 5
    pub max_shard_neighbours: usize,
    /// Default: 1000
    pub max_broadcast_log: u32,
    /// Default: 1000
    pub broadcast_gc_timeout_ms: u64,
    /// Default: 60000
    pub overlay_peers_timeout_ms: u64,
    /// Default: 3
    pub broadcast_target_count: usize,
    /// Default: 3
    pub secondary_broadcast_target_count: usize,
    /// Default: 5
    pub secondary_fec_broadcast_target_count: usize,
    /// Default: 20
    pub max_broadcast_wave: usize,
    /// Default: 60
    pub broadcast_timeout_sec: u64,
    /// Default: false
    pub force_compression: bool,
}

impl Default for OverlayShardOptions {
    fn default() -> Self {
        Self {
            max_shard_peers: 20,
            max_shard_neighbours: 5,
            max_broadcast_log: 1000,
            broadcast_gc_timeout_ms: 1000,
            overlay_peers_timeout_ms: 60000,
            broadcast_target_count: 3,
            secondary_broadcast_target_count: 3,
            secondary_fec_broadcast_target_count: 5,
            max_broadcast_wave: 20,
            broadcast_timeout_sec: 60,
            force_compression: false,
        }
    }
}

impl OverlayShard {
    pub fn new(
        adnl: Arc<AdnlNode>,
        node_key: Arc<StoredAdnlNodeKey>,
        overlay_id: OverlayIdShort,
        overlay_key: Option<Arc<StoredAdnlNodeKey>>,
        options: OverlayShardOptions,
    ) -> Arc<Self> {
        let query_prefix = serialize(&ton::rpc::overlay::Query {
            overlay: ton::int256(overlay_id.into()),
        });

        let message_prefix = serialize_boxed(ton::overlay::message::Message {
            overlay: ton::int256(overlay_id.into()),
        });

        let overlay = Arc::new(Self {
            adnl,
            overlay_id,
            node_key,
            overlay_key,
            options,
            owned_broadcasts: FxDashMap::default(),
            finished_broadcasts: SegQueue::new(),
            finished_broadcast_count: AtomicU32::new(0),
            received_peers: Arc::new(Default::default()),
            received_broadcasts: Arc::new(BroadcastReceiver::default()),
            received_catchain: Arc::new(BroadcastReceiver::default()),
            nodes: FxDashMap::default(),
            ignored_peers: FxDashSet::default(),
            known_peers: PeersCache::with_capacity(MAX_OVERLAY_PEERS),
            random_peers: PeersCache::with_capacity(options.max_shard_peers),
            neighbours: PeersCache::with_capacity(options.max_shard_neighbours),
            query_prefix,
            message_prefix,
        });

        overlay.update_neighbours(options.max_shard_neighbours);

        tokio::spawn({
            let overlay = Arc::downgrade(&overlay);

            let gc_interval = Duration::from_millis(options.broadcast_gc_timeout_ms);

            async move {
                let mut peers_timeout = 0;
                while let Some(overlay) = overlay.upgrade() {
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

                    peers_timeout += options.broadcast_gc_timeout_ms;
                    if peers_timeout > options.overlay_peers_timeout_ms {
                        if overlay.is_private() {
                            overlay.update_neighbours(1);
                        } else {
                            overlay.update_random_peers(1);
                        }
                        peers_timeout = 0;
                    }

                    tokio::time::sleep(gc_interval).await;
                }
            }
        });

        overlay
    }

    #[inline(always)]
    pub fn options(&self) -> &OverlayShardOptions {
        &self.options
    }

    pub fn metrics(&self) -> OverlayShardMetrics {
        OverlayShardMetrics {
            owned_broadcasts_len: self.owned_broadcasts.len(),
            finished_broadcasts_len: self.finished_broadcast_count.load(Ordering::Acquire),
            node_count: self.nodes.len(),
            known_peers_len: self.known_peers.len(),
            random_peers_len: self.random_peers.len(),
            neighbours: self.neighbours.len(),
            received_broadcasts_data_len: self.received_broadcasts.data_len(),
            received_broadcasts_barrier_count: self.received_broadcasts.barriers_len(),
            received_catchain_data_len: self.received_catchain.data_len(),
            received_catchain_barrier_count: self.received_catchain.barriers_len(),
        }
    }

    pub fn adnl(&self) -> &Arc<AdnlNode> {
        &self.adnl
    }

    pub fn id(&self) -> &OverlayIdShort {
        &self.overlay_id
    }

    pub fn is_private(&self) -> bool {
        self.overlay_key.is_some()
    }

    pub fn overlay_key(&self) -> &Arc<StoredAdnlNodeKey> {
        match &self.overlay_key {
            Some(overlay_key) => overlay_key,
            None => &self.node_key,
        }
    }

    pub fn add_known_peers(&self, peers: &[AdnlNodeIdShort]) {
        match &self.overlay_key {
            Some(overlay_key) => self.known_peers.extend(
                peers
                    .iter()
                    .cloned()
                    .filter(|peer_id| peer_id != overlay_key.id()),
            ),
            None => self.known_peers.extend(peers.iter().cloned()),
        }

        self.update_neighbours(self.options.max_shard_neighbours);
    }

    pub fn add_public_peer(
        &self,
        ip_address: AdnlAddressUdp,
        node: ton::overlay::node::Node,
    ) -> Result<Option<AdnlNodeIdShort>> {
        if self.is_private() {
            return Err(OverlayShardError::PublicPeerToPrivateOverlay.into());
        }

        if let Err(e) = verify_node(&self.overlay_id, &node) {
            tracing::warn!("Error during overlay peer verification: {e:?}");
            return Ok(None);
        }

        let peer_id_full = AdnlNodeIdFull::try_from(&node.id)?;
        let peer_id = peer_id_full.compute_short_id();

        let is_new_peer = self.adnl.add_peer(
            PeerContext::PublicOverlay,
            self.node_key.id(),
            &peer_id,
            ip_address,
            peer_id_full,
        )?;
        if is_new_peer {
            self.insert_public_peer(&peer_id, node);
            Ok(Some(peer_id))
        } else {
            Ok(None)
        }
    }

    pub fn add_public_peers<I>(&self, nodes: I) -> Result<Vec<AdnlNodeIdShort>>
    where
        I: IntoIterator<Item = (AdnlAddressUdp, ton::overlay::node::Node)>,
    {
        if self.is_private() {
            return Err(OverlayShardError::PublicPeerToPrivateOverlay.into());
        }

        let mut result = Vec::new();
        for (ip_address, node) in nodes {
            if let Err(e) = verify_node(&self.overlay_id, &node) {
                tracing::debug!("Error during overlay peer verification: {e:?}");
                continue;
            }

            let peer_id_full = AdnlNodeIdFull::try_from(&node.id)?;
            let peer_id = peer_id_full.compute_short_id();

            let is_new_peer = self.adnl.add_peer(
                PeerContext::PublicOverlay,
                self.node_key.id(),
                &peer_id,
                ip_address,
                peer_id_full,
            )?;
            if is_new_peer {
                self.insert_public_peer(&peer_id, node);
                result.push(peer_id);
                tracing::trace!("Node id: {peer_id}, address: {ip_address}");
            }
        }

        Ok(result)
    }

    pub fn delete_public_peer(&self, peer_id: &AdnlNodeIdShort) -> bool {
        if !self.ignored_peers.insert(*peer_id) {
            return false;
        }
        if self.random_peers.contains(peer_id) {
            self.update_random_peers(self.options.max_shard_peers);
        }
        true
    }

    pub fn write_cached_peers(&self, amount: usize, dst: &PeersCache) {
        dst.randomly_fill_from(&self.known_peers, amount, Some(&self.ignored_peers));
    }

    pub fn query_prefix(&self) -> &Vec<u8> {
        &self.query_prefix
    }

    pub fn message_prefix(&self) -> &Vec<u8> {
        &self.message_prefix
    }

    pub fn send_message(&self, peer_id: &AdnlNodeIdShort, data: &[u8]) -> Result<()> {
        let local_id = self.overlay_key().id();

        let mut buffer = Vec::with_capacity(self.message_prefix().len() + data.len());
        buffer.extend_from_slice(self.message_prefix());
        buffer.extend_from_slice(data);
        self.adnl.send_custom_message(local_id, peer_id, &buffer)
    }

    pub fn broadcast(
        self: &Arc<Self>,
        data: Vec<u8>,
        source: Option<&Arc<StoredAdnlNodeKey>>,
    ) -> OutgoingBroadcastInfo {
        const ORDINARY_BROADCAST_MAX_SIZE: usize = 768;

        let local_id = self.overlay_key().id();

        let key = match source {
            Some(key) => key,
            None => &self.node_key,
        };

        if data.len() <= ORDINARY_BROADCAST_MAX_SIZE {
            self.send_broadcast(local_id, data, key)
        } else {
            self.send_fec_broadcast(local_id, data, key)
        }
    }

    pub async fn wait_for_broadcast(&self) -> IncomingBroadcastInfo {
        self.received_broadcasts.pop().await
    }

    pub fn take_new_peers(&self) -> ReceivedPeersMap {
        let mut peers = self.received_peers.lock();
        std::mem::take(&mut *peers)
    }

    pub fn push_peers(&self, peers: Vec<ton::overlay::node::Node>) {
        use std::collections::hash_map::Entry;

        let mut known_peers = self.received_peers.lock();
        for node in peers {
            match known_peers.entry(node.id.clone()) {
                Entry::Occupied(mut entry) => {
                    if entry.get().version < node.version {
                        entry.insert(node);
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(node);
                }
            }
        }
    }

    pub async fn wait_for_catchain(&self) -> CatchainUpdate {
        self.received_catchain.pop().await
    }

    #[allow(dead_code)]
    pub fn push_catchain(&self, update: CatchainUpdate) {
        self.received_catchain.push(update);
    }

    pub async fn receive_broadcast(
        self: &Arc<Self>,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        broadcast: OverlayBroadcastViewBroadcast<'_>,
        raw_data: &[u8],
    ) -> Result<()> {
        if self.is_broadcast_outdated(broadcast.date) {
            return Ok(());
        }

        let node_id = AdnlNodeIdFull::try_from(broadcast.src)?;
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
        self.distribute_broadcast(local_id, &neighbours, raw_data);
        self.spawn_broadcast_gc_task(broadcast_id);

        Ok(())
    }

    pub async fn receive_fec_broadcast(
        self: &Arc<Self>,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        broadcast: OverlayBroadcastViewBroadcastFec<'_>,
        raw_data: &[u8],
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        if self.is_broadcast_outdated(broadcast.date) {
            return Ok(());
        }

        let broadcast_id = *broadcast.data_hash;
        let node_id = AdnlNodeIdFull::try_from(broadcast.src)?;
        let source = node_id.compute_short_id();

        let signature = match broadcast.signature.len() {
            64 => broadcast.signature.try_into().unwrap(),
            _ => return Err(OverlayShardError::UnsupportedSignature.into()),
        };

        let transfer = match self.owned_broadcasts.entry(broadcast_id) {
            Entry::Vacant(entry) => {
                let incoming_transfer =
                    self.create_incoming_fec_transfer(broadcast.fec, broadcast_id, source)?;
                entry
                    .insert(Arc::new(OwnedBroadcast::Incoming(incoming_transfer)))
                    .clone()
            }
            Entry::Occupied(entry) => entry.get().clone(),
        };
        let transfer = match transfer.as_ref() {
            OwnedBroadcast::Incoming(transfer) => transfer,
            OwnedBroadcast::Other => return Ok(()),
        };

        transfer.updated_at.refresh();
        if transfer.source != source {
            tracing::trace!("Same broadcast but parts from different sources");
            return Ok(());
        }

        if !transfer.history.deliver_packet(broadcast.seqno as u64) {
            return Ok(());
        }

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

        let neighbours = self.neighbours.get_random_peers(
            self.options.secondary_fec_broadcast_target_count,
            Some(peer_id),
        );
        self.distribute_broadcast(local_id, &neighbours, raw_data);

        Ok(())
    }

    pub fn send_broadcast(
        self: &Arc<Self>,
        local_id: &AdnlNodeIdShort,
        mut data: Vec<u8>,
        key: &Arc<StoredAdnlNodeKey>,
    ) -> OutgoingBroadcastInfo {
        let date = now();
        let broadcast_to_sign = make_broadcast_to_sign(&data, date, None);
        let broadcast_id = broadcast_to_sign.compute_broadcast_id();
        if !self.create_broadcast(broadcast_id) {
            tracing::warn!("Trying to send duplicated broadcast");
            return Default::default();
        }
        let signature = key.sign(broadcast_to_sign);

        if self.options.force_compression {
            if let Err(e) = compression::compress(&mut data) {
                tracing::warn!("Failed to compress overlay broadcast: {e:?}");
            }
        }

        let broadcast = OverlayBroadcastView::Broadcast(OverlayBroadcastViewBroadcast {
            src: key.full_id().as_tl(),
            certificate: CertificateView::EmptyCertificate,
            flags: BROADCAST_FLAG_ANY_SENDER,
            data: &data,
            date,
            signature: &signature,
        });

        let mut buffer = self.message_prefix.clone();
        buffer.reserve(broadcast.max_size_hint());
        broadcast.write_to(&mut buffer);
        drop(data);

        let neighbours = self
            .neighbours
            .get_random_peers(self.options.broadcast_target_count, None);
        self.distribute_broadcast(local_id, &neighbours, &buffer);
        self.spawn_broadcast_gc_task(broadcast_id);

        OutgoingBroadcastInfo {
            packets: 1,
            recipient_count: neighbours.len(),
        }
    }

    pub fn send_fec_broadcast(
        self: &Arc<Self>,
        local_id: &AdnlNodeIdShort,
        mut data: Vec<u8>,
        key: &Arc<StoredAdnlNodeKey>,
    ) -> OutgoingBroadcastInfo {
        let broadcast_id = sha2::Sha256::digest(&data).into();
        if !self.create_broadcast(broadcast_id) {
            tracing::warn!("Trying to send duplicated broadcast");
            return Default::default();
        }

        if self.options.force_compression {
            if let Err(e) = compression::compress(&mut data) {
                tracing::warn!("Failed to compress overlay FEC broadcast: {e:?}");
            }
        }

        let data_size = data.len() as u32;
        let (data_tx, mut data_rx) = mpsc::unbounded_channel();

        let mut outgoing_transfer = OutgoingFecTransfer {
            broadcast_id,
            encoder: RaptorQEncoder::with_data(&data),
            seqno: 0,
        };

        // NOTE: Data is already in encoder and not needed anymore
        drop(data);

        let max_seqno = (data_size / outgoing_transfer.encoder.params().symbol_size + 1) * 3 / 2;

        // Spawn data producer
        tokio::spawn({
            let key = key.clone();
            let overlay_shard = self.clone();
            let max_broadcast_wave = self.options.max_broadcast_wave;

            async move {
                while outgoing_transfer.seqno <= max_seqno {
                    for _ in 0..max_broadcast_wave {
                        let result = overlay_shard
                            .prepare_fec_broadcast(&mut outgoing_transfer, &key)
                            .and_then(|data| {
                                data_tx.send(data)?;
                                Ok(())
                            });

                        if let Err(e) = result {
                            tracing::warn!("Failed to send overlay broadcast: {e}");
                            return;
                        }

                        if outgoing_transfer.seqno > max_seqno {
                            break;
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(TRANSFER_LOOP_INTERVAL)).await;
                }
            }
        });

        let neighbours = self
            .neighbours
            .get_random_peers(self.options.max_shard_neighbours, None);
        let info = OutgoingBroadcastInfo {
            packets: max_seqno,
            recipient_count: neighbours.len(),
        };

        // Spawn sender
        tokio::spawn({
            let overlay_shard = self.clone();
            let local_id = *local_id;

            async move {
                while let Some(data) = data_rx.recv().await {
                    overlay_shard.distribute_broadcast(&local_id, &neighbours, &data);
                }

                data_rx.close();
                while data_rx.recv().await.is_some() {}

                overlay_shard.spawn_broadcast_gc_task(broadcast_id);
            }
        });

        // Done
        info
    }

    pub async fn query(
        &self,
        peer_id: &AdnlNodeIdShort,
        query: &ton::TLObject,
        timeout: Option<u64>,
    ) -> Result<Option<ton::TLObject>> {
        let local_id = self.overlay_key().id();
        self.adnl
            .query_with_prefix(local_id, peer_id, Some(self.query_prefix()), query, timeout)
            .await
    }

    pub async fn query_via_rldp(
        &self,
        peer_id: &AdnlNodeIdShort,
        data: Vec<u8>,
        rldp: &Arc<RldpNode>,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let local_id = self.overlay_key().id();
        rldp.query(local_id, peer_id, data, roundtrip).await
    }

    pub async fn get_random_peers(
        &self,
        peer_id: &AdnlNodeIdShort,
        timeout: Option<u64>,
    ) -> Result<Option<Vec<ton::overlay::node::Node>>> {
        let query = ton::TLObject::new(ton::rpc::overlay::GetRandomPeers {
            peers: self.prepare_random_peers(),
        });
        match self.query(peer_id, &query, timeout).await? {
            Some(answer) => {
                let answer: ton::overlay::Nodes = parse_answer(answer)?;
                tracing::trace!("Got random peers from {peer_id}");
                Ok(Some(self.process_nodes(answer.only())))
            }
            None => {
                tracing::trace!("No random peers from {peer_id}");
                Ok(None)
            }
        }
    }

    pub fn process_get_random_peers(
        &self,
        query: ton::rpc::overlay::GetRandomPeers,
    ) -> ton::overlay::nodes::Nodes {
        let peers = self.process_nodes(query.peers);
        self.push_peers(peers);
        self.prepare_random_peers()
    }

    pub fn sign_local_node(&self) -> ton::overlay::node::Node {
        let key = self.overlay_key();
        let version = now();

        let node_to_sign = OverlayNodeToSign {
            id: key.id().as_slice(),
            overlay: self.id().as_slice(),
            version,
        };
        let signature = key.sign(&node_to_sign);

        ton::overlay::node::Node {
            id: key.full_id().as_old_tl().into_boxed(),
            overlay: ton::int256(self.id().into()),
            version: version as i32,
            signature: ton::bytes(signature.to_vec()),
        }
    }

    fn process_nodes(&self, nodes: ton::overlay::nodes::Nodes) -> Vec<ton::overlay::node::Node> {
        tracing::trace!("-------- Got random peers");

        let mut result = Vec::new();

        for node in nodes.nodes.0 {
            if !matches!(
                &node.id,
                ton::PublicKey::Pub_Ed25519(id)
                if &id.key.0 != self.node_key.full_id().public_key().as_bytes()
            ) {
                continue;
            }

            tracing::trace!("{node:?}");
            if let Err(e) = verify_node(&self.overlay_id, &node) {
                tracing::warn!("Error during overlay peer verification: {e:?}");
                continue;
            }

            result.push(node);
        }

        result
    }

    fn prepare_random_peers(&self) -> ton::overlay::nodes::Nodes {
        let mut result = vec![self.sign_local_node()];

        let amount = MAX_RANDOM_PEERS;

        let peers = PeersCache::with_capacity(amount);
        peers.randomly_fill_from(&self.random_peers, amount, None);
        for peer_id in &peers {
            if let Some(node) = self.nodes.get(peer_id) {
                result.push(node.clone());
            }
        }

        ton::overlay::nodes::Nodes {
            nodes: result.into(),
        }
    }

    fn update_random_peers(&self, amount: usize) {
        self.random_peers
            .randomly_fill_from(&self.known_peers, amount, Some(&self.ignored_peers));
    }

    fn update_neighbours(&self, amount: usize) {
        if self.is_private() {
            self.neighbours
                .randomly_fill_from(&self.known_peers, amount, None);
        } else {
            self.neighbours.randomly_fill_from(
                &self.random_peers,
                amount,
                Some(&self.ignored_peers),
            );
        }
    }

    fn insert_public_peer(&self, peer_id: &AdnlNodeIdShort, node: ton::overlay::node::Node) {
        use dashmap::mapref::entry::Entry;

        self.ignored_peers.remove(peer_id);
        self.known_peers.put(*peer_id);

        if self.random_peers.len() < self.options.max_shard_peers {
            self.random_peers.put(*peer_id);
        }

        if self.neighbours.len() < self.options.max_shard_neighbours {
            self.neighbours.put(*peer_id);
        }

        match self.nodes.entry(*peer_id) {
            Entry::Occupied(mut entry) => {
                if entry.get().version < node.version {
                    entry.insert(node);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(node);
            }
        }
    }

    fn is_broadcast_outdated(&self, date: u32) -> bool {
        date + (self.options.broadcast_timeout_sec as u32) < now()
    }

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

    fn create_incoming_fec_transfer(
        self: &Arc<Self>,
        fec_type: RaptorQFecType,
        broadcast_id: BroadcastId,
        peer_id: AdnlNodeIdShort,
    ) -> Result<IncomingFecTransfer> {
        let (broadcast_tx, mut broadcast_rx) = mpsc::unbounded_channel();
        let mut decoder = RaptorQDecoder::with_params(fec_type);

        tokio::spawn({
            let overlay_shard = self.clone();

            async move {
                let mut packets = 0;
                while let Some(broadcast) = broadcast_rx.recv().await {
                    packets += 1;
                    match process_fec_broadcast(&mut decoder, broadcast) {
                        Ok(Some(data)) => {
                            overlay_shard
                                .received_broadcasts
                                .push(IncomingBroadcastInfo {
                                    packets,
                                    data,
                                    from: peer_id,
                                });
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            tracing::warn!("Error when receiving overlay broadcast: {e}");
                        }
                    }
                    break;
                }

                if let Some(broadcast) = overlay_shard.owned_broadcasts.get(&broadcast_id) {
                    match broadcast.value().as_ref() {
                        OwnedBroadcast::Incoming(transfer) => {
                            transfer.completed.store(true, Ordering::Release);
                        }
                        _ => {
                            tracing::error!("Incoming fec broadcast mismatch");
                        }
                    }
                }

                broadcast_rx.close();
                while broadcast_rx.recv().await.is_some() {}
            }
        });

        tokio::spawn({
            let overlay_shard = self.clone();
            let broadcast_timeout_sec = self.options.broadcast_timeout_sec;

            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(broadcast_timeout_sec * 100)).await;

                    if let Some(broadcast) = overlay_shard.owned_broadcasts.get(&broadcast_id) {
                        match broadcast.value().as_ref() {
                            OwnedBroadcast::Incoming(transfer) => {
                                if !transfer.updated_at.is_expired(broadcast_timeout_sec) {
                                    continue;
                                }
                            }
                            _ => {
                                tracing::error!("Incoming fec broadcast mismatch");
                            }
                        }
                    }

                    break;
                }

                overlay_shard.spawn_broadcast_gc_task(broadcast_id);
            }
        });

        Ok(IncomingFecTransfer {
            completed: Default::default(),
            history: PacketsHistory::for_recv(),
            broadcast_tx,
            source: peer_id,
            updated_at: Default::default(),
        })
    }

    fn prepare_fec_broadcast(
        &self,
        transfer: &mut OutgoingFecTransfer,
        key: &Arc<StoredAdnlNodeKey>,
    ) -> Result<Vec<u8>> {
        let chunk = transfer.encoder.encode(&mut transfer.seqno)?;
        let date = now();

        let signature = make_fec_part_to_sign(
            &transfer.broadcast_id,
            transfer.encoder.params().data_size,
            date,
            BROADCAST_FLAG_ANY_SENDER,
            transfer.encoder.params(),
            &chunk,
            transfer.seqno,
            None,
        );
        let signature = key.sign(signature);

        let broadcast = OverlayBroadcastView::BroadcastFec(OverlayBroadcastViewBroadcastFec {
            src: key.full_id().as_tl(),
            certificate: CertificateView::EmptyCertificate,
            data_hash: &transfer.broadcast_id,
            data_size: transfer.encoder.params().data_size,
            flags: BROADCAST_FLAG_ANY_SENDER,
            data: &chunk,
            seqno: transfer.seqno,
            fec: *transfer.encoder.params(),
            date,
            signature: &signature,
        });

        transfer.seqno += 1;
        let mut buffer = self.message_prefix.clone();
        buffer.reserve(broadcast.max_size_hint());
        broadcast.write_to(&mut buffer);

        Ok(buffer)
    }

    fn distribute_broadcast(
        &self,
        local_id: &AdnlNodeIdShort,
        neighbours: &[AdnlNodeIdShort],
        data: &[u8],
    ) {
        for peer_id in neighbours {
            if let Err(e) = self.adnl.send_custom_message(local_id, peer_id, data) {
                tracing::warn!("Failed to distribute broadcast: {e}");
            }
        }
    }

    fn spawn_broadcast_gc_task(self: &Arc<Self>, broadcast_id: BroadcastId) {
        let overlay_shard = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(
                overlay_shard.options.broadcast_timeout_sec,
            ))
            .await;
            overlay_shard
                .finished_broadcast_count
                .fetch_add(1, Ordering::Release);
            overlay_shard.finished_broadcasts.push(broadcast_id);
        });
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OverlayShardMetrics {
    pub owned_broadcasts_len: usize,
    pub finished_broadcasts_len: u32,
    pub node_count: usize,
    pub known_peers_len: usize,
    pub random_peers_len: usize,
    pub neighbours: usize,
    pub received_broadcasts_data_len: usize,
    pub received_broadcasts_barrier_count: usize,
    pub received_catchain_data_len: usize,
    pub received_catchain_barrier_count: usize,
}

fn process_fec_broadcast(
    decoder: &mut RaptorQDecoder,
    broadcast: BroadcastFec,
) -> Result<Option<Vec<u8>>> {
    let broadcast_id = &broadcast.data_hash;

    let broadcast_to_sign = make_fec_part_to_sign(
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
        .verify(&broadcast_to_sign, &broadcast.signature)?;

    match decoder.decode(broadcast.seqno as u32, broadcast.data) {
        Some(result) if result.len() != broadcast.data_size as usize => {
            Err(OverlayShardError::DataSizeMismatch.into())
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
                    Err(OverlayShardError::DataHashMismatch.into())
                }
            }
        },
        None => Ok(None),
    }
}

#[derive(TlWrite)]
#[tl(boxed, id = 0xfa374e7c)]
struct OverlayBroadcastToSign {
    hash: [u8; 32],
    date: u32,
}

impl OverlayBroadcastToSign {
    fn compute_broadcast_id(&self) -> BroadcastId {
        let mut broadcast_id = sha2::Sha256::new();
        HashWrapper(self).update_hasher(&mut broadcast_id);
        broadcast_id.finalize().into()
    }
}

fn make_broadcast_to_sign(
    data: &[u8],
    date: u32,
    source: Option<&AdnlNodeIdShort>,
) -> OverlayBroadcastToSign {
    const BROADCAST_ID: u32 = 0x51fd789a;

    let mut broadcast_hash = sha2::Sha256::new();
    broadcast_hash.update(BROADCAST_ID.to_le_bytes());
    broadcast_hash.update(source.map(AdnlNodeIdShort::as_slice).unwrap_or(&[0; 32]));
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
    params: &RaptorQFecType,
    part: &[u8],
    seqno: u32,
    source: Option<AdnlNodeIdShort>,
) -> OverlayBroadcastToSign {
    const BROADCAST_FEC_ID: u32 = 0xfb3155a6;
    const BROADCAST_FEC_PART_ID: u32 = 0xa46962d0;

    let mut broadcast_hash = sha2::Sha256::new();
    broadcast_hash.update(BROADCAST_FEC_ID.to_le_bytes());
    broadcast_hash.update(
        source
            .as_ref()
            .map(AdnlNodeIdShort::as_slice)
            .unwrap_or(&[0; 32]),
    );
    broadcast_hash.update({
        let mut hash = sha2::Sha256::new();
        HashWrapper(params).update_hasher(&mut hash);
        hash.finalize().as_slice()
    });
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

pub struct IncomingBroadcastInfo {
    pub packets: u32,
    pub data: Vec<u8>,
    pub from: AdnlNodeIdShort,
}

#[derive(Default)]
pub struct OutgoingBroadcastInfo {
    pub packets: u32,
    pub recipient_count: usize,
}

pub struct CatchainUpdate {
    pub peer_id: AdnlNodeIdShort,
    pub catchain_update: ton::catchain::blockupdate::BlockUpdate,
    pub validator_session_update: ton::validator_session::blockupdate::BlockUpdate,
}

struct IncomingFecTransfer {
    completed: AtomicBool,
    history: PacketsHistory,
    broadcast_tx: BroadcastFecTx,
    source: AdnlNodeIdShort,
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
    node_id: AdnlNodeIdFull,
    data_hash: BroadcastId,
    data_size: u32,
    flags: u32,
    data: Vec<u8>,
    seqno: u32,
    fec_type: RaptorQFecType,
    date: u32,
    signature: [u8; 64],
}

pub type ReceivedPeersMap = FxHashMap<ton::PublicKey, ton::overlay::node::Node>;

type BroadcastFecTx = mpsc::UnboundedSender<BroadcastFec>;

type BroadcastId = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum OverlayShardError {
    #[error("Unsupported signature")]
    UnsupportedSignature,
    #[error("Data size mismatch")]
    DataSizeMismatch,
    #[error("Data hash mismatch")]
    DataHashMismatch,
    #[error("Cannot add public peer to private overlay")]
    PublicPeerToPrivateOverlay,
}

const MAX_RANDOM_PEERS: usize = 4;

const BROADCAST_FLAG_ANY_SENDER: u32 = 1; // Any sender

const TRANSFER_LOOP_INTERVAL: u64 = 10; // Milliseconds
