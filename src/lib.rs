mod address_list;
mod channel;
mod config;
mod node_id;
mod peer;
mod queries_cache;
mod query;
mod received_mask;
mod subscriber;
mod transfer;
pub mod utils;

use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use aes::cipher::StreamCipher;
use anyhow::Result;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use ton_api::{ton, IntoBoxed};

pub use crate::address_list::*;
pub use crate::channel::*;
pub use crate::config::*;
pub use crate::node_id::*;
pub use crate::peer::*;
use crate::queries_cache::*;
use crate::query::*;
pub use crate::received_mask::*;
pub use crate::subscriber::*;
use crate::transfer::*;
use crate::utils::*;

pub struct AdnlNode {
    /// Ip address and keys for signing
    config: AdnlNodeConfig,

    /// Known peers for each local node id
    peers: DashMap<AdnlNodeIdShort, Arc<AdnlPeers>>,

    /// Channels table used to fast search on incoming packets
    channels_by_id: DashMap<AdnlChannelId, Arc<AdnlChannel>>,
    /// Channels table used to fast search when sending messages
    channels_by_peers: DashMap<AdnlNodeIdShort, Arc<AdnlChannel>>,
    /// Channels that were created on this node but waiting for confirmation
    channels_to_confirm: DashMap<AdnlNodeIdShort, Arc<AdnlChannel>>,

    /// Pending transfers of large messages that were split
    transfers: DashMap<TransferId, Arc<Transfer>>,

    /// Pending queries
    queries: QueriesCache,

    /// Outgoing packets queue
    sender_queue_tx: SenderQueueTx,
    /// Receiver end of the outgoing packets queue (NOTE: used only for initialization)
    sender_queue_rx: Mutex<Option<SenderQueueRx>>,

    /// Basic reinit date for all local peer states
    start_time: i32,
}

impl AdnlNode {
    pub fn new(config: AdnlNodeConfig) -> Self {
        let (sender_queue_tx, sender_queue_rx) = mpsc::unbounded_channel();

        Self {
            config,
            peers: Default::default(),
            channels_by_id: Default::default(),
            channels_by_peers: Default::default(),
            channels_to_confirm: Default::default(),
            transfers: Default::default(),
            queries: Default::default(),
            sender_queue_tx,
            sender_queue_rx: Mutex::new(Some(sender_queue_rx)),
            start_time: now(),
        }
    }

    pub async fn start(self: &Arc<Self>, mut subscribers: Vec<Arc<dyn Subscriber>>) -> Result<()> {
        // Consume receiver
        let sender_queue_rx = match self.sender_queue_rx.lock().take() {
            Some(rx) => rx,
            None => return Err(AdnlNodeError::AlreadyRunning.into()),
        };

        // Bind node socket
        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, self.config.ip_address().port())).await?,
        );

        let subscribers = Arc::new(subscribers);

        // Start background logic
        self.start_sender(socket.clone(), sender_queue_rx);
        self.start_receiver(socket, subscribers.clone());

        // Done
        Ok(())
    }

    /// Starts a process that forwards packets from the sender queue to the UDP socket
    fn start_sender(self: &Arc<Self>, socket: Arc<UdpSocket>, mut sender_queue_rx: SenderQueueRx) {
        let node = Arc::downgrade(self);

        tokio::spawn(async move {
            while let Some(packet) = sender_queue_rx.recv().await {
                // Check if node is still alive
                let _node = match node.upgrade() {
                    Some(node) => node,
                    None => return,
                };

                // Send packet
                let target: SocketAddrV4 = packet.destination.into();
                match socket.send_to(&packet.data, target).await {
                    Ok(len) if len != packet.data.len() => {
                        log::warn!("Incomplete send: {} of {}", len, packet.data.len());
                    }
                    Err(e) => {
                        log::warn!("Failed to send data: {}", e);
                    }
                    _ => {}
                };
            }
        });
    }

    /// Starts a process that listens for and processes packets from the UDP socket
    fn start_receiver(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    ) {
        const RECV_BUFFER_SIZE: usize = 2048;

        let node = Arc::downgrade(self);

        tokio::spawn(async move {
            let mut buffer = None;

            loop {
                // Check if node is still alive
                let node = match node.upgrade() {
                    Some(node) => node,
                    None => return,
                };

                // Receive packet
                let len = match socket
                    .recv_from(
                        buffer
                            .get_or_insert_with(|| vec![0u8; RECV_BUFFER_SIZE])
                            .as_mut_slice(),
                    )
                    .await
                {
                    Ok((len, _)) if len == 0 => continue,
                    Ok((len, _)) => len,
                    Err(e) => {
                        log::warn!("Failed to receive data: {}", e);
                        continue;
                    }
                };

                let mut buffer = match buffer.take() {
                    Some(buffer) => buffer,
                    None => continue,
                };
                buffer.truncate(len);

                // Process packet
                let subscribers = subscribers.clone();
                tokio::spawn(async move {
                    if let Err(e) = node
                        .handle_received_data(PacketView::from(buffer.as_mut_slice()), &subscribers)
                        .await
                    {
                        log::warn!("Failed to handle received data: {}", e);
                    }
                });
            }
        });
    }

    /// Decrypts and processes received data
    async fn handle_received_data(
        &self,
        mut data: PacketView<'_>,
        subscribers: &[Arc<dyn Subscriber>],
    ) -> Result<()> {
        // Decrypt packet and extract peers
        let (local_id, peer_id) =
            if let Some(local_id) = parse_handshake(self.config.keys(), &mut data, None)? {
                (local_id, None)
            } else if let Some(channel) = self.channels_by_id.get(&data[0..32]) {
                let channel = channel.value();
                channel.decrypt(&mut data)?;
                if let Some((key, removed)) = self.channels_to_confirm.remove(channel.peer_id()) {
                    self.channels_by_peers.insert(key, removed);
                }
                (*channel.local_id(), Some(*channel.peer_id()))
            } else {
                log::trace!(
                    "Received message to unknown key ID: {}",
                    hex::encode(&data[0..32])
                );
                return Ok(());
            };

        // Parse packet
        let packet = deserialize(data.as_slice())?
            .downcast::<ton::adnl::PacketContents>()
            .map_err(AdnlNodeError::UnknownPacket)?;

        // Validate packet
        let peer_id = self.check_packet(&packet, &local_id, peer_id)?;

        // Process message(s)
        if let Some(message) = packet.message() {
            self.process_message(&local_id, &peer_id, message, subscribers)
                .await?;
        } else if let Some(messages) = packet.messages() {
            for message in messages.iter() {
                self.process_message(&local_id, &peer_id, message, subscribers)
                    .await?;
            }
        }

        // Done
        Ok(())
    }

    async fn process_message(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        message: &ton::adnl::Message,
        subscribers: &[Arc<dyn Subscriber>],
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        const TRANSFER_TIMEOUT: u64 = 3; // Seconds

        // Handle split message case
        let alt_message = if let ton::adnl::Message::Adnl_Message_Part(part) = message {
            let transfer_id = part.hash.0;
            let transfer = match self.transfers.entry(transfer_id) {
                // Create new transfer state if it was a new incoming transfer
                Entry::Vacant(entry) => {
                    let entry = entry.insert(Arc::new(Transfer::new(part.total_size as usize)));
                    let transfer = entry.value().clone();

                    tokio::spawn({
                        let transfers = self.transfers.clone();
                        let transfer = transfer.clone();

                        async move {
                            loop {
                                tokio::time::sleep(Duration::from_secs(TRANSFER_TIMEOUT)).await;
                                if !transfer.timings().is_expired(TRANSFER_TIMEOUT) {
                                    continue;
                                }

                                if transfers.remove(&transfer_id).is_some() {
                                    log::debug!(
                                        "ADNL transfer {} timed out",
                                        hex::encode(&transfer_id)
                                    );
                                }
                                break;
                            }
                        }
                    });

                    transfer
                }
                // Update existing transfer state
                Entry::Occupied(entry) => entry.get().clone(),
            };

            // Refresh transfer timings on each incoming message
            transfer.timings().refresh();

            // Update transfer
            match transfer.add_part(part.offset as usize, part.data.to_vec(), &transfer_id) {
                Ok(Some(message)) => {
                    self.transfers.remove(&transfer_id);
                    Some(message)
                }
                Err(error) => {
                    self.transfers.remove(&transfer_id);
                    return Err(error);
                }
                _ => return Ok(()),
            }
        } else {
            None
        };

        let response: Option<ton::adnl::Message> = match alt_message.as_ref().unwrap_or(message) {
            ton::adnl::Message::Adnl_Message_Answer(answer) => {
                self.process_message_answer(answer).await?;
                None
            }
            ton::adnl::Message::Adnl_Message_ConfirmChannel(confirm) => {
                self.process_message_confirm_channel(local_id, peer_id, confirm)?;
                None
            }
            ton::adnl::Message::Adnl_Message_CreateChannel(create) => {
                let reply = self.process_message_create_channel(local_id, peer_id, create)?;
                Some(reply.into_boxed())
            }
            ton::adnl::Message::Adnl_Message_Custom(custom) => {
                if !process_message_custom(local_id, peer_id, subscribers, custom).await? {}
                None
            }
            ton::adnl::Message::Adnl_Message_Query(query) => {
                match process_message_adnl_query(local_id, peer_id, subscribers, query).await? {
                    QueryProcessingResult::Processed(answer) => answer,
                    QueryProcessingResult::Rejected => {
                        return Err(AdnlNodeError::NoSubscribersForQuery.into())
                    }
                }
            }
            _ => return Err(AdnlNodeError::UnknownMessage.into()),
        };

        // TODO
        Ok(())
    }

    async fn process_message_answer(
        &self,
        answer: &ton::adnl::message::message::Answer,
    ) -> Result<()> {
        let queries = &self.queries;
        let query_id = answer.query_id.0;

        if queries.update_query(query_id, Some(&answer.answer)).await? {
            Ok(())
        } else {
            Err(AdnlNodeError::UnknownQueryAnswer.into())
        }
    }

    fn process_message_confirm_channel(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        confirm: &ton::adnl::message::message::ConfirmChannel,
    ) -> Result<()> {
        // Create new channel
        let mut local_public_key = Some(confirm.peer_key.0);
        let peer_public_key = &confirm.key.0;

        let channel = self.create_channel(
            local_id,
            peer_id,
            &mut local_public_key,
            peer_public_key,
            "confirmation",
        )?;

        // Insert new channel
        self.channels_by_peers.insert(*peer_id, channel.clone());
        self.channels_by_id
            .insert(*channel.channel_in_id(), channel);

        // Done
        Ok(())
    }

    fn process_message_create_channel(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        create: &ton::adnl::message::message::CreateChannel,
    ) -> Result<ton::adnl::message::message::ConfirmChannel> {
        // Create new channel
        let mut local_public_key = None;
        let peer_public_key = &create.key.0;

        let channel = self.create_channel(
            local_id,
            peer_id,
            &mut local_public_key,
            peer_public_key,
            "creation",
        )?;

        // Prepare confirmation message
        let message = match local_public_key {
            Some(local_public_key) => ton::adnl::message::message::ConfirmChannel {
                key: ton::int256(local_public_key),
                peer_key: create.key,
                date: create.date,
            },
            None => return Err(AdnlNodeError::ChannelKeyMismatch.into()),
        };

        // Insert new channel into pending
        if self.channels_to_confirm.insert(*peer_id, channel).is_some() {
            // Make sure that removed channel will no longer exist anywhere
            self.channels_by_peers
                .remove(peer_id)
                .and_then(|(_, removed)| self.channels_by_id.remove(removed.channel_in_id()));
        }

        // Done
        Ok(message)
    }

    /// Validates incoming packet. Attempts to extract peer id
    fn check_packet(
        &self,
        packet: &ton::adnl::PacketContents,
        local_id: &AdnlNodeIdShort,
        peer_id: Option<AdnlNodeIdShort>,
    ) -> Result<AdnlNodeIdShort> {
        use std::cmp::Ordering;

        const CLOCK_TOLERANCE: i32 = 60;

        let explicit_peer_id = peer_id.is_some();

        // Extract peer id
        let peer_id = if let Some(peer_id) = peer_id {
            if packet.from().is_some() || packet.from_short().is_some() {
                return Err(AdnlPacketError::ExplicitSourceForChannel.into());
            }
            peer_id
        } else if let Some(public_key) = packet.from() {
            let full_id: AdnlNodeIdFull = public_key.try_into()?;
            let peer_id = full_id.compute_short_id()?;

            if matches!(packet.from_short(), Some(id) if peer_id != id.id.0) {
                return Err(AdnlPacketError::InvalidPeerId.into());
            }

            if let Some(list) = packet.address() {
                let ip_address = parse_address_list(list)?;
                self.add_peer(local_id, &peer_id, ip_address, full_id)?;
            }

            peer_id
        } else if let Some(peer_id) = packet.from_short() {
            AdnlNodeIdShort::new(peer_id.id.0)
        } else {
            return Err(AdnlPacketError::NoKeyDataInPacket.into());
        };

        // Check timings
        let dst_reinit_date = packet.dst_reinit_date();
        let reinit_date = packet.reinit_date();
        if dst_reinit_date.is_some() != reinit_date.is_some() {
            return Err(AdnlPacketError::ReinitDatesMismatch.into());
        }

        let peers = self.get_peers(&local_id)?;
        let peer = if explicit_peer_id {
            if let Some(channel) = self.channels_by_peers.get(&peer_id) {
                peers.get(channel.peer_id())
            } else {
                return Err(AdnlPacketError::UnknownChannel.into());
            }
        } else {
            peers.get(&peer_id)
        }
        .ok_or(AdnlPacketError::UnknownPeer)?;

        if let (Some(&dst_reinit_date), Some(&reinit_date)) = (dst_reinit_date, reinit_date) {
            if dst_reinit_date != 0 {
                match dst_reinit_date.cmp(&peer.receiver_state().reinit_date()) {
                    Ordering::Equal => {}
                    Ordering::Greater => return Err(AdnlPacketError::DstReinitDateTooNew.into()),
                    Ordering::Less => return Err(AdnlPacketError::DstReinitDateTooOld.into()),
                }
            }

            let sender_reinit_date = peer.sender_state().reinit_date();
            match reinit_date.cmp(&sender_reinit_date) {
                Ordering::Equal => {}
                Ordering::Greater => {
                    if reinit_date > now() + CLOCK_TOLERANCE {
                        return Err(AdnlPacketError::SrcReinitDateTooNew.into());
                    } else {
                        peer.sender_state().set_reinit_date(reinit_date);
                        if sender_reinit_date != 0 {
                            peer.sender_state().mask().reset();
                            peer.receiver_state().mask().reset();
                        }
                    }
                }
                Ordering::Less => return Err(AdnlPacketError::SrcReinitDateTooOld.into()),
            }
        }

        if let Some(&seqno) = packet.seqno() {
            peer.receiver_state().mask().deliver_packet(seqno)?;
        }

        if let Some(&confirm_seqno) = packet.confirm_seqno() {
            let sender_seqno = peer.sender_state().mask().seqno();
            if confirm_seqno > sender_seqno {
                return Err(AdnlPacketError::ConfirmationSeqnoTooNew.into());
            }
        }

        Ok(peer_id)
    }

    pub fn add_peer(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer_ip_address: AdnlAddressUdp,
        peer_full_id: AdnlNodeIdFull,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        if peer_id == local_id {
            return Ok(false);
        }

        match self.get_peers(local_id)?.entry(*peer_id) {
            Entry::Occupied(entry) => entry.get().set_ip_address(peer_ip_address),
            Entry::Vacant(entry) => {
                entry.insert(AdnlPeer::new(
                    self.start_time,
                    peer_ip_address,
                    peer_full_id,
                ));

                log::debug!(
                    "Added ADNL peer {}. PEER ID {} -> LOCAL ID {}",
                    peer_ip_address,
                    peer_id,
                    local_id
                );
            }
        };

        Ok(true)
    }

    pub fn delete_peer(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
    ) -> Result<bool> {
        let peers = self.get_peers(local_id)?;
        Ok(peers.remove(peer_id).is_some())
    }

    fn get_peers(&self, local_id: &AdnlNodeIdShort) -> Result<Arc<AdnlPeers>> {
        if let Some(peers) = self.peers.get(local_id) {
            Ok(peers.value().clone())
        } else {
            Err(AdnlNodeError::PeersNotFound.into())
        }
    }

    fn create_channel(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        local_public_key: &mut Option<[u8; 32]>,
        peer_public_key: &[u8; 32],
        context: &str,
    ) -> Result<Arc<AdnlChannel>> {
        let peers = self.get_peers(local_id)?;
        let peer = match peers.get(peer_id) {
            Some(peer) => peer,
            None => return Err(AdnlNodeError::UnknownPeerInChannel.into()),
        };
        let peer = peer.value();

        let channel_public_key = peer.id().public_key();

        if let Some(public_key) = local_public_key {
            if channel_public_key != public_key {
                return Err(AdnlNodeError::ChannelKeyMismatch.into());
            }
        } else {
            local_public_key.replace(*channel_public_key);
        }

        let local_key = self.config.key_by_id(local_id)?;

        let channel = AdnlChannel::new(
            *local_id,
            *peer_id,
            local_key.private_key(),
            peer_public_key,
        )?;
        log::debug!("Channel {}: {} -> {}", context, local_id, peer_id);

        Ok(Arc::new(channel))
    }
}

/// Attempts to decode the buffer as an ADNL handshake packet. On a successful nonempty result,
/// this buffer remains as decrypted packet data.
///
/// Expected packet structure:
///  - 0..=31 - short local node id
///  - 32..=63 - sender pubkey
///  - 64..=95 - checksum
///  - 96..... - encrypted data
///
/// **NOTE: even on failure can modify buffer**
fn parse_handshake(
    keys: &DashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>>,
    buffer: &mut PacketView<'_>,
    data_length: Option<usize>,
) -> Result<Option<AdnlNodeIdShort>> {
    use sha2::digest::Digest;

    if buffer.len() < 96 + data_length.unwrap_or_default() {
        return Err(AdnlNodeError::BadHandshakePacketLength.into());
    }

    let data_range = match data_length {
        Some(data_length) => 96..(96 + data_length),
        None => 96..buffer.len(),
    };

    // Since there are relatively few keys, linear search is optimal
    for key in keys.iter() {
        // Find suitable local node key
        if key.key() == &buffer[0..32] {
            // Decrypt data
            let mut shared_secret = compute_shared_secret(
                key.value().private_key().as_bytes(),
                buffer[32..64].try_into().unwrap(),
            )?;

            build_packet_cipher(&shared_secret, &buffer[64..96].try_into().unwrap())
                .apply_keystream(&mut buffer[data_range]);

            // Check checksum
            if !sha2::Sha256::digest(&buffer[96..])
                .as_slice()
                .eq(&buffer[64..96])
            {
                return Err(AdnlNodeError::BadHandshakePacketChecksum.into());
            }

            // Leave only data in buffer
            buffer.remove_prefix(96);
            return Ok(Some(*key.key()));
        }
    }

    // No local keys found
    Ok(None)
}

struct PacketToSend {
    destination: AdnlAddressUdp,
    data: Vec<u8>,
}

type SenderQueueTx = mpsc::UnboundedSender<PacketToSend>;
type SenderQueueRx = mpsc::UnboundedReceiver<PacketToSend>;

#[derive(thiserror::Error, Debug)]
enum AdnlNodeError {
    #[error("ADNL node is already running")]
    AlreadyRunning,
    #[error("Bad handshake packet length")]
    BadHandshakePacketLength,
    #[error("Bad handshake packet checksum")]
    BadHandshakePacketChecksum,
    #[error("Unknown ADNL packet format: {:?}", .0)]
    UnknownPacket(ton::TLObject),
    #[error("Local id peers not found")]
    PeersNotFound,
    #[error("Unknown message")]
    UnknownMessage,
    #[error("Received answer to unknown query")]
    UnknownQueryAnswer,
    #[error("Channel with unknown peer")]
    UnknownPeerInChannel,
    #[error("Channel key mismatch")]
    ChannelKeyMismatch,
    #[error("No subscribers for custom message")]
    NoSubscribersFroCustomMessage,
    #[error("No subscribers for query")]
    NoSubscribersForQuery,
}

#[derive(thiserror::Error, Debug)]
enum AdnlPacketError {
    #[error("Explicit source address inside channel packet")]
    ExplicitSourceForChannel,
    #[error("Mismatch between peer id and packet key")]
    InvalidPeerId,
    #[error("No key data in packet")]
    NoKeyDataInPacket,
    #[error("Destination and source reinit dates mismatch")]
    ReinitDatesMismatch,
    #[error("Unknown channel id")]
    UnknownChannel,
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Destination reinit date is too new")]
    DstReinitDateTooNew,
    #[error("Destination reinit date is too old")]
    DstReinitDateTooOld,
    #[error("Source reinit date is too new")]
    SrcReinitDateTooNew,
    #[error("Source reinit date is too old")]
    SrcReinitDateTooOld,
    #[error("Confirmation seqno is too new")]
    ConfirmationSeqnoTooNew,
}
