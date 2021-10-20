use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_queue::SegQueue;
use sha2::Digest;
use tokio::sync::mpsc;
use ton_api::{ton, IntoBoxed};

use super::{broadcast_receiver::*, MAX_OVERLAY_PEERS};
use crate::adnl_node::*;
use crate::rldp_node::*;
use crate::utils::*;

pub struct OverlayShard {
    adnl: Arc<AdnlNode>,
    overlay_id: OverlayIdShort,
    overlay_key: Option<Arc<StoredAdnlNodeKey>>,
    options: OverlayShardOptions,

    owned_broadcasts: FxDashMap<BroadcastId, Arc<OwnedBroadcast>>,
    finished_broadcasts: SegQueue<BroadcastId>,
    finished_broadcast_count: AtomicU32,

    received_peers: Arc<BroadcastReceiver<Vec<ton::overlay::node::Node>>>,
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
        }
    }
}

impl OverlayShard {
    pub fn new(
        adnl: Arc<AdnlNode>,
        overlay_id: OverlayIdShort,
        overlay_key: Option<Arc<StoredAdnlNodeKey>>,
        options: OverlayShardOptions,
    ) -> Result<Arc<Self>> {
        let query_prefix = serialize(&ton::rpc::overlay::Query {
            overlay: ton::int256(overlay_id.into()),
        })?;

        let message_prefix = serialize_boxed(ton::overlay::message::Message {
            overlay: ton::int256(overlay_id.into()),
        })?;

        let overlay = Arc::new(Self {
            adnl,
            overlay_id,
            overlay_key,
            options,
            owned_broadcasts: FxDashMap::default(),
            finished_broadcasts: SegQueue::new(),
            finished_broadcast_count: AtomicU32::new(0),
            received_peers: Arc::new(BroadcastReceiver::default()),
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

        Ok(overlay)
    }

    pub fn id(&self) -> &OverlayIdShort {
        &self.overlay_id
    }

    pub fn is_private(&self) -> bool {
        self.overlay_key.is_some()
    }

    pub fn overlay_key(&self) -> &Option<Arc<StoredAdnlNodeKey>> {
        &self.overlay_key
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

    pub fn add_public_peer(&self, peer_id: &AdnlNodeIdShort, node: ton::overlay::node::Node) {
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
            Entry::Occupied(entry) => {
                if entry.get().version < node.version {
                    entry.replace_entry(node);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(node);
            }
        }
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

    pub fn write_random_peers(&self, amount: usize, nodes: &mut Vec<ton::overlay::node::Node>) {
        let peers = PeersCache::with_capacity(amount);
        peers.randomly_fill_from(&self.random_peers, amount, None);
        for peer_id in &peers {
            if let Some(node) = self.nodes.get(peer_id) {
                nodes.push(node.clone());
            }
        }
    }

    pub fn query_prefix(&self) -> &Vec<u8> {
        &self.query_prefix
    }

    pub fn message_prefix(&self) -> &Vec<u8> {
        &self.message_prefix
    }

    pub async fn wait_for_broadcast(&self) -> IncomingBroadcastInfo {
        self.received_broadcasts.pop().await
    }

    pub async fn wait_for_peers(&self) -> Vec<ton::overlay::node::Node> {
        self.received_peers.pop().await
    }

    pub fn push_peers(&self, peers: Vec<ton::overlay::node::Node>) {
        self.received_peers.push(peers);
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
        let node_peer_id = node_id.compute_short_id()?;
        let source = match broadcast.flags {
            flags if flags & BROADCAST_FLAG_ANY_SENDER == 0 => Some(node_peer_id),
            _ => None,
        };

        let broadcast_to_sign =
            make_broadcast_to_sign(broadcast.data, broadcast.date, source.as_ref())?;
        let broadcast_id = match self.create_broadcast(&broadcast_to_sign) {
            Some(broadcast_id) => broadcast_id,
            None => return Ok(()),
        };

        node_id.verify(&broadcast_to_sign, broadcast.signature)?;

        self.received_broadcasts.push(IncomingBroadcastInfo {
            packets: 1,
            data: broadcast.data.to_vec(),
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
        let source = node_id.compute_short_id()?;

        let fec_type = match broadcast.fec {
            FecTypeView::RaptorQ {
                data_size,
                symbol_size,
                symbols_count,
            } => ton::fec::type_::RaptorQ {
                data_size,
                symbol_size,
                symbols_count,
            },
            _ => return Err(OverlayShardError::UnsupportedFecType.into()),
        };

        let signature = match broadcast.signature.len() {
            64 => broadcast.signature.try_into().unwrap(),
            _ => return Err(OverlayShardError::UnsupportedSignature.into()),
        };

        let transfer = match self.owned_broadcasts.entry(broadcast_id) {
            Entry::Vacant(entry) => {
                let incoming_transfer =
                    self.create_incoming_fec_transfer(fec_type.clone(), broadcast_id, source)?;
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
            log::trace!("Same broadcast but parts from different sources");
            return Ok(());
        }

        if !transfer.history.deliver_packet(broadcast.seqno as i64) {
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
                fec_type,
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
        data: &[u8],
        key: &Arc<StoredAdnlNodeKey>,
    ) -> Result<OutgoingBroadcastInfo> {
        let date = now();
        let signature = make_broadcast_to_sign(data, date, None)?;
        let broadcast_id = match self.create_broadcast(data) {
            Some(broadcast_id) => broadcast_id,
            None => {
                log::warn!("Trying to send duplicated broadcast");
                return Ok(Default::default());
            }
        };
        let signature = key.sign(&signature);

        let broadcast = ton::overlay::broadcast::Broadcast {
            src: key.full_id().as_tl().into_boxed(),
            certificate: ton::overlay::Certificate::Overlay_EmptyCertificate,
            flags: BROADCAST_FLAG_ANY_SENDER,
            data: ton::bytes(data.to_vec()),
            date,
            signature: ton::bytes(signature.as_ref().to_vec()),
        }
        .into_boxed();
        let mut buffer = self.message_prefix.clone();
        serialize_append(&mut buffer, &broadcast)?;

        let neighbours = self
            .neighbours
            .get_random_peers(self.options.broadcast_target_count, None);
        self.distribute_broadcast(local_id, &neighbours, &buffer);
        self.spawn_broadcast_gc_task(broadcast_id);

        Ok(OutgoingBroadcastInfo {
            packets: 1,
            recipient_count: neighbours.len(),
        })
    }

    pub fn send_fec_broadcast(
        self: &Arc<Self>,
        local_id: &AdnlNodeIdShort,
        data: &[u8],
        key: &Arc<StoredAdnlNodeKey>,
    ) -> Result<OutgoingBroadcastInfo> {
        let broadcast_id = match self.create_broadcast(data) {
            Some(id) => id,
            None => {
                log::warn!("Trying to send duplicated broadcast");
                return Ok(Default::default());
            }
        };

        let data_size = data.len() as u32;
        let (data_tx, mut data_rx) = mpsc::unbounded_channel();

        let mut outgoing_transfer = OutgoingFecTransfer {
            broadcast_id,
            encoder: RaptorQEncoder::with_data(data),
            seqno: 0,
        };
        let max_seqno =
            (data_size / outgoing_transfer.encoder.params().symbol_size as u32 + 1) * 3 / 2;

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
                            log::warn!("Failed to send overlay broadcast: {}", e);
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
        Ok(info)
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

    fn is_broadcast_outdated(&self, date: i32) -> bool {
        date + (self.options.broadcast_timeout_sec as i32) < now()
    }

    fn create_broadcast(&self, data: &[u8]) -> Option<BroadcastId> {
        use dashmap::mapref::entry::Entry;

        let broadcast_id = sha2::Sha256::digest(data).into();

        match self.owned_broadcasts.entry(broadcast_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(OwnedBroadcast::Other));
                Some(broadcast_id)
            }
            Entry::Occupied(_) => None,
        }
    }

    fn create_incoming_fec_transfer(
        self: &Arc<Self>,
        fec_type: ton::fec::type_::RaptorQ,
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
                            log::warn!("Error when receiving overlay broadcast: {}", e);
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
                            log::error!("Incoming fec broadcast mismatch");
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
                                log::error!("Incoming fec broadcast mismatch");
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
            transfer.seqno as i32,
            None,
        )?;
        let signature = key.sign(&signature);

        let broadcast = ton::overlay::broadcast::BroadcastFec {
            src: key.full_id().as_tl().into_boxed(),
            certificate: ton::overlay::Certificate::Overlay_EmptyCertificate,
            data_hash: ton::int256(transfer.broadcast_id),
            data_size: transfer.encoder.params().data_size,
            flags: BROADCAST_FLAG_ANY_SENDER,
            data: ton::bytes(chunk),
            seqno: transfer.seqno as i32,
            fec: transfer.encoder.params().clone().into_boxed(),
            date,
            signature: ton::bytes(signature.as_ref().to_vec()),
        }
        .into_boxed();

        transfer.seqno += 1;
        let mut buffer = self.message_prefix.clone();
        serialize_append(&mut buffer, &broadcast)?;

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
                log::warn!("Failed to distribute broadcast: {}", e);
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
            Some(broadcast.node_id.compute_short_id()?)
        } else {
            None
        },
    )?;
    broadcast
        .node_id
        .verify(&broadcast_to_sign, &broadcast.signature)?;

    match decoder.decode(broadcast.seqno as u32, broadcast.data) {
        Some(result) if result.len() != broadcast.data_size as usize => {
            Err(OverlayShardError::DataSizeMismatch.into())
        }
        Some(result) => {
            let data_hash = sha2::Sha256::digest(&result);
            if data_hash.as_slice() == broadcast_id {
                Ok(Some(result))
            } else {
                Err(OverlayShardError::DataHashMismatch.into())
            }
        }
        None => Ok(None),
    }
}

fn make_broadcast_to_sign(
    data: &[u8],
    date: i32,
    source: Option<&AdnlNodeIdShort>,
) -> Result<Vec<u8>> {
    let broadcast_id = ton::overlay::broadcast::id::Id {
        src: ton::int256(source.map(|id| *id.as_slice()).unwrap_or_default()),
        data_hash: ton::int256(sha2::Sha256::digest(data).into()),
        flags: BROADCAST_FLAG_ANY_SENDER,
    };
    let broadcast_hash = hash(broadcast_id)?;

    serialize_boxed(ton::overlay::broadcast::tosign::ToSign {
        hash: ton::int256(broadcast_hash),
        date,
    })
}

fn make_fec_part_to_sign(
    data_hash: &[u8; 32],
    data_size: i32,
    date: i32,
    flags: i32,
    params: &ton::fec::type_::RaptorQ,
    part: &[u8],
    seqno: i32,
    source: Option<AdnlNodeIdShort>,
) -> Result<Vec<u8>> {
    let broadcast_id = ton::overlay::broadcast_fec::id::Id {
        src: ton::int256(source.map(|id| id.into()).unwrap_or_default()),
        type_: ton::int256(hash(params.clone())?),
        data_hash: ton::int256(*data_hash),
        size: data_size,
        flags,
    };
    let broadcast_hash = hash(broadcast_id)?;

    let part_id = ton::overlay::broadcast_fec::partid::PartId {
        broadcast_hash: ton::int256(broadcast_hash),
        data_hash: ton::int256(sha2::Sha256::digest(part).into()),
        seqno,
    };
    let part_hash = hash(part_id)?;

    serialize_boxed(ton::overlay::broadcast::tosign::ToSign {
        hash: ton::int256(part_hash),
        date,
    })
}

const BROADCAST_FLAG_ANY_SENDER: i32 = 1; // Any sender

const TRANSFER_LOOP_INTERVAL: u64 = 10; // Milliseconds

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
    data_size: i32,
    flags: i32,
    data: Vec<u8>,
    seqno: i32,
    fec_type: ton::fec::type_::RaptorQ,
    date: i32,
    signature: [u8; 64],
}

type BroadcastFecTx = mpsc::UnboundedSender<BroadcastFec>;

type BroadcastId = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum OverlayShardError {
    #[error("Unsupported fec type")]
    UnsupportedFecType,
    #[error("Unsupported signature")]
    UnsupportedSignature,
    #[error("Data size mismatch")]
    DataSizeMismatch,
    #[error("Data hash mismatch")]
    DataHashMismatch,
}
