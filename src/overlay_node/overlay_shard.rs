use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_queue::SegQueue;
use dashmap::{DashMap, DashSet};
use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::Verifier;
use sha2::Digest;
use tokio::sync::mpsc;
use ton_api::{ton, IntoBoxed};

use super::broadcast_receiver::*;
use crate::adnl_node::*;
use crate::rldp_node::*;
use crate::utils::*;

pub struct OverlayShard {
    adnl: Arc<AdnlNode>,
    overlay_id: OverlayIdShort,
    overlay_key: Option<Arc<StoredAdnlNodeKey>>,

    owned_broadcasts: DashMap<BroadcastId, OwnedBroadcast>,
    finished_broadcasts: SegQueue<BroadcastId>,
    finished_broadcast_count: AtomicU32,

    received_peers: Arc<BroadcastReceiver<Vec<ton::overlay::node::Node>>>,
    received_broadcasts: Arc<BroadcastReceiver<IncomingBroadcastInfo>>,

    nodes: DashMap<AdnlNodeIdShort, ton::overlay::node::Node>,
    ignored_peers: DashSet<AdnlNodeIdShort>,
    known_peers: PeersCache,
    random_peers: PeersCache,
    neighbours: PeersCache,

    query_prefix: Vec<u8>,
    message_prefix: Vec<u8>,
}

impl OverlayShard {
    pub fn is_private(&self) -> bool {
        self.overlay_key.is_some()
    }

    pub fn add_public_peer(&self, peer_id: &AdnlNodeIdShort, node: &ton::overlay::node::Node) {
        use dashmap::mapref::entry::Entry;

        self.ignored_peers.remove(peer_id);
        self.known_peers.put(*peer_id);

        if self.random_peers.len() < MAX_SHARD_PEERS {
            self.random_peers.put(*peer_id);
        }

        if self.neighbours.len() < MAX_SHARD_NEIGHBOURS {
            self.neighbours.put(*peer_id);
        }

        match self.nodes.entry(*peer_id) {
            Entry::Occupied(entry) => {
                if entry.get().version < node.version {
                    entry.replace_entry(node.clone());
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(node.clone());
            }
        }
    }

    pub fn delete_public_peer(&self, peer_id: &AdnlNodeIdShort) -> bool {
        if !self.ignored_peers.insert(*peer_id) {
            return false;
        }
        if self.random_peers.contains(peer_id) {
            self.update_random_peers(MAX_SHARD_PEERS);
        }
        true
    }

    pub fn write_cached_peers(&self, amount: usize, dst: &PeersCache) {
        dst.randomly_fill_from(&self.known_peers, amount, Some(&self.ignored_peers));
    }

    pub fn query_prefix(&self) -> &Vec<u8> {
        &self.query_prefix
    }

    pub async fn wait_for_broadcast(&self) -> IncomingBroadcastInfo {
        self.received_broadcasts.pop().await
    }

    pub async fn wait_for_peers(&self) -> Vec<ton::overlay::node::Node> {
        self.received_peers.pop().await
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

    fn create_broadcast(&self, data: &[u8]) -> Option<BroadcastId> {
        use dashmap::mapref::entry::Entry;

        let broadcast_id = sha2::Sha256::digest(data).as_slice().try_into().unwrap();

        match self.owned_broadcasts.entry(broadcast_id) {
            Entry::Vacant(entry) => {
                entry.insert(OwnedBroadcast::Other);
                Some(broadcast_id)
            }
            Entry::Occupied(_) => None,
        }
    }

    fn create_incoming_fec_transfer(
        self: &Arc<Self>,
        broadcast: &ton::overlay::broadcast::BroadcastFec,
    ) -> Result<IncomingFecTransfer> {
        let fec_type = match &broadcast.fec {
            ton::fec::Type::Fec_RaptorQ(fec_type) => fec_type,
            _ => return Err(OverlayShardError::UnsupportedFecType.into()),
        };

        let (broadcast_tx, mut broadcast_rx) = mpsc::unbounded_channel();
        let mut decoder = RaptorQDecoder::with_params(fec_type.as_ref().clone());

        let broadcast_id = broadcast.data_hash.0;
        let node_id = AdnlNodeIdFull::try_from(&broadcast.src)?;
        let peer_id = node_id.compute_short_id()?;

        tokio::spawn({
            let overlay_shard = self.clone();

            async move {
                let mut packets = 0;
                while let Some(broadcast) = broadcast_rx.recv().await {
                    packets += 1;
                    match process_fec_broadcast(&mut decoder, &broadcast) {
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
                    match broadcast.value() {
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

            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(BROADCAST_TIMEOUT * 100)).await;

                    if let Some(broadcast) = overlay_shard.owned_broadcasts.get(&broadcast_id) {
                        match broadcast.value() {
                            OwnedBroadcast::Incoming(transfer) => {
                                if !transfer.updated_at.is_expired(BROADCAST_TIMEOUT) {
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
            history: Default::default(),
            broadcast_tx,
            source: peer_id,
            updated_at: Default::default(),
        })
    }

    fn create_outgoing_fec_transfer(
        self: &Arc<Self>,
        data: &[u8],
        source: &Arc<StoredAdnlNodeKey>,
        overlay_key: AdnlNodeIdShort,
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
            let source = source.clone();
            let overlay_shard = self.clone();

            async move {
                while outgoing_transfer.seqno <= max_seqno {
                    for _ in 0..MAX_BROADCAST_WAVE {
                        let result = overlay_shard
                            .prepare_fec_broadcast(&mut outgoing_transfer, &source)
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

        let neighbours = self.neighbours.get_random_peers(MAX_SHARD_NEIGHBOURS, None);
        let info = OutgoingBroadcastInfo {
            packets: max_seqno,
            recipient_count: neighbours.len(),
        };

        // Spawn sender
        tokio::spawn({
            let overlay_shard = self.clone();

            async move {
                while let Some(data) = data_rx.recv().await {
                    overlay_shard.distribute_broadcast(&overlay_key, &neighbours, &data);
                }

                data_rx.close();
                while data_rx.recv().await.is_some() {}

                overlay_shard.spawn_broadcast_gc_task(broadcast_id);
            }
        });

        // Done
        Ok(info)
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
        let signature = key.private_key().sign(&signature, key.id().public_key());

        let broadcast = ton::overlay::broadcast::BroadcastFec {
            src: key.id().as_tl().into_boxed(),
            certificate: ton::overlay::Certificate::Overlay_EmptyCertificate,
            data_hash: ton::int256(transfer.broadcast_id),
            data_size: transfer.encoder.params().data_size,
            flags: BROADCAST_FLAG_ANY_SENDER,
            data: ton::bytes(chunk),
            seqno: transfer.seqno as i32,
            fec: transfer.encoder.params().clone().into_boxed(),
            date,
            signature: ton::bytes(signature.to_bytes().to_vec()),
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
            tokio::time::sleep(Duration::from_secs(BROADCAST_TIMEOUT)).await;
            overlay_shard
                .finished_broadcast_count
                .fetch_add(1, Ordering::Release);
            overlay_shard.finished_broadcasts.push(broadcast_id);
        });
    }
}

fn process_fec_broadcast(
    decoder: &mut RaptorQDecoder,
    broadcast: &ton::overlay::broadcast::BroadcastFec,
) -> Result<Option<Vec<u8>>> {
    let fec_type = match &broadcast.fec {
        ton::fec::Type::Fec_RaptorQ(fec_type) => fec_type,
        _ => return Err(OverlayShardError::UnsupportedFecType.into()),
    };

    let broadcast_id = &broadcast.data_hash.0;
    let node_id = AdnlNodeIdFull::try_from(&broadcast.src)?;

    let signature = make_fec_part_to_sign(
        broadcast_id,
        broadcast.data_size,
        broadcast.date,
        broadcast.flags,
        fec_type,
        &broadcast.data,
        broadcast.seqno,
        if broadcast.flags & BROADCAST_FLAG_ANY_SENDER == 0 {
            Some(node_id.compute_short_id()?)
        } else {
            None
        },
    )?;

    let other_signature = ed25519_dalek::Signature::from_bytes(&broadcast.signature)?;
    node_id.public_key().verify(&signature, &other_signature)?;

    match decoder.decode(broadcast.seqno as u32, &broadcast.data) {
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
        data_hash: ton::int256(sha2::Sha256::digest(data).as_slice().try_into().unwrap()),
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
        data_hash: ton::int256(sha2::Sha256::digest(part).as_slice().try_into().unwrap()),
        seqno,
    };
    let part_hash = hash(part_id)?;

    serialize_boxed(ton::overlay::broadcast::tosign::ToSign {
        hash: ton::int256(part_hash),
        date,
    })
}

const MAX_BROADCAST_WAVE: u32 = 20;
const MAX_SHARD_NEIGHBOURS: usize = 5;
const MAX_SHARD_PEERS: usize = 20;

const BROADCAST_FLAG_ANY_SENDER: i32 = 1; // Any sender

const BROADCAST_TIMEOUT: u64 = 60; // Seconds
const TRANSFER_LOOP_INTERVAL: u64 = 10; // Milliseconds

pub struct IncomingBroadcastInfo {
    pub packets: u32,
    pub data: Vec<u8>,
    pub from: AdnlNodeIdShort,
}

#[derive(Default)]
struct OutgoingBroadcastInfo {
    pub packets: u32,
    pub recipient_count: usize,
}

struct IncomingFecTransfer {
    completed: AtomicBool,
    history: ReceivedMask,
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
    WillBeIncoming,
}

type BroadcastFecTx = mpsc::UnboundedSender<ton::overlay::broadcast::BroadcastFec>;

type BroadcastId = [u8; 32];

#[derive(thiserror::Error, Debug)]
enum OverlayShardError {
    #[error("Unsupported fec type")]
    UnsupportedFecType,
    #[error("Data size mismatch")]
    DataSizeMismatch,
    #[error("Data hash mismatch")]
    DataHashMismatch,
}
