use std::convert::TryInto;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use ed25519_dalek::Verifier;
use parking_lot::Mutex;
use sha2::Digest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use ton_api::{ton, IntoBoxed};

use crate::subscriber::*;
use crate::utils::*;

pub use self::adnl_keystore::*;
use self::channel::*;
use self::peer::*;
use self::transfer::*;
use crate::utils::MessageView;

mod adnl_keystore;
mod channel;
mod peer;
mod transfer;

pub struct AdnlNode {
    ip_address: AdnlAddressUdp,
    keystore: AdnlKeystore,
    options: AdnlNodeOptions,
    node_filter: Option<Arc<dyn AdnlNodeFilter>>,

    /// Known peers for each local node id
    peers: FxDashMap<AdnlNodeIdShort, Arc<AdnlPeers>>,

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

    /// Basic reinit date for all local peer states
    start_time: i32,

    cancellation_token: CancellationToken,
}

enum ChannelReceiver {
    Ordinary(Arc<AdnlChannel>),
    Priority(Arc<AdnlChannel>),
}

impl Drop for AdnlNode {
    fn drop(&mut self) {
        self.shutdown()
    }
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AdnlNodeOptions {
    /// Default: 500
    pub query_min_timeout_ms: u64,
    /// Default: 5000
    pub query_max_timeout_ms: u64,
    /// Default: 3
    pub transfer_timeout_sec: u64,
    /// Default: 60
    pub clock_tolerance_sec: i32,
    /// Default: 1000
    pub address_list_timeout_sec: i32,
    /// Default: false
    pub packet_history_enabled: bool,
    /// Default: true
    pub packet_signature_required: bool,
    /// Default: true
    pub force_use_priority_channels: bool,
    /// Default: None
    pub version: Option<u16>,
}

impl Default for AdnlNodeOptions {
    fn default() -> Self {
        Self {
            query_min_timeout_ms: 500,
            query_max_timeout_ms: 5000,
            transfer_timeout_sec: 3,
            clock_tolerance_sec: 60,
            address_list_timeout_sec: 1000,
            packet_history_enabled: false,
            packet_signature_required: true,
            force_use_priority_channels: true,
            version: None,
        }
    }
}

pub trait AdnlNodeFilter: Send + Sync {
    fn check(&self, ctx: PeerContext, ip: AdnlAddressUdp, peer_id: &AdnlNodeIdShort) -> bool;
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum PeerContext {
    AdnlPacket,
    Dht,
    PublicOverlay,
    PrivateOverlay,
}

impl AdnlNode {
    pub fn new(
        ip_address: AdnlAddressUdp,
        keystore: AdnlKeystore,
        options: AdnlNodeOptions,
        node_filter: Option<Arc<dyn AdnlNodeFilter>>,
    ) -> Arc<Self> {
        let (sender_queue_tx, sender_queue_rx) = mpsc::unbounded_channel();
        let peers = FxDashMap::with_capacity_and_hasher(keystore.keys().len(), Default::default());
        for key in keystore.keys().keys() {
            peers.insert(*key, Default::default());
        }

        Arc::new(Self {
            ip_address,
            keystore,
            options,
            node_filter,
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

    #[inline(always)]
    pub fn options(&self) -> &AdnlNodeOptions {
        &self.options
    }

    pub fn metrics(&self) -> AdnlNodeMetrics {
        AdnlNodeMetrics {
            peer_count: self.peers.iter().map(|peers| peers.len()).sum(),
            channels_by_id_len: self.channels_by_id.len(),
            channels_by_peers_len: self.channels_by_peers.len(),
            incoming_transfers_len: self.incoming_transfers.len(),
            query_count: self.queries.len(),
        }
    }

    pub async fn start(self: &Arc<Self>, mut subscribers: Vec<Arc<dyn Subscriber>>) -> Result<()> {
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
        self.start_subscribers_polling(&subscribers);
        self.start_sender(socket.clone(), sender_queue_rx);
        self.start_receiver(socket, subscribers);

        // Done
        Ok(())
    }

    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
    }

    /// Starts a process that polls subscribers
    fn start_subscribers_polling(self: &Arc<Self>, subscribers: &[Arc<dyn Subscriber>]) {
        let start = Arc::new(Instant::now());

        for subscriber in subscribers {
            let node = Arc::downgrade(self);
            let subscriber = subscriber.clone();
            let start = start.clone();

            tokio::spawn(async move {
                while let Some(_node) = node.upgrade() {
                    // Poll
                    subscriber.poll(&start).await;
                }
            });
        }
    }

    /// Starts a process that forwards packets from the sender queue to the UDP socket
    fn start_sender(self: &Arc<Self>, socket: Arc<UdpSocket>, mut sender_queue_rx: SenderQueueRx) {
        use futures_util::future::{select, Either};

        let complete_signal = self.cancellation_token.clone();

        tokio::spawn(async move {
            tokio::pin!(let cancelled = complete_signal.cancelled(););

            while let Some(packet) = {
                tokio::pin!(let recv = sender_queue_rx.recv(););
                match select(recv, &mut cancelled).await {
                    Either::Left((packet, _)) => packet,
                    Either::Right(_) => return,
                }
            } {
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
        use futures_util::future::{select, Either};

        const RECV_BUFFER_SIZE: usize = 2048;

        let complete_signal = self.cancellation_token.clone();
        let node = self.clone();

        tokio::spawn(async move {
            let mut buffer = None;

            tokio::pin!(let cancelled = complete_signal.cancelled(););

            loop {
                // SAFETY: buffer capacity is always `RECV_BUFFER_SIZE` at the point of creating slice
                // NOTE: we don't need to initialize it before writing to it
                let raw_buffer = unsafe {
                    let buffer = buffer.get_or_insert_with(|| Vec::with_capacity(RECV_BUFFER_SIZE));
                    std::slice::from_raw_parts_mut(buffer.as_mut_ptr(), buffer.capacity())
                };

                // Receive packet
                tokio::pin!(let recv = socket.recv_from(raw_buffer););
                let result = match select(recv, &mut cancelled).await {
                    Either::Left((left, _)) => left,
                    Either::Right(_) => return,
                };

                let len = match result {
                    Ok((len, _)) if len == 0 => continue,
                    Ok((len, _)) => len,
                    Err(e) => {
                        log::warn!("Failed to receive data: {}", e);
                        continue;
                    }
                };

                let mut buffer = match buffer.take() {
                    Some(mut buffer) => {
                        // SAFETY: at this point we have initialized at least `len` bytes of partially
                        // initialized data of len `RECV_BUFFER_SIZE`
                        unsafe { buffer.set_len(len) };
                        buffer
                    }
                    None => continue,
                };

                // Process packet
                let node = node.clone();
                let subscribers = subscribers.clone();
                tokio::spawn(async move {
                    if let Err(e) = node
                        .handle_received_data(PacketView::from(buffer.as_mut_slice()), &subscribers)
                        .await
                    {
                        log::debug!("Failed to handle received data: {}", e);
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
        let (priority, local_id, peer_id, version) = if let Some((local_id, version)) =
            parse_handshake_packet(self.keystore.keys(), &mut data)?
        {
            (false, local_id, None, version)
        } else if let Some(channel) = self.channels_by_id.get(&data[0..32]) {
            let (channel, priority) = match channel.value() {
                ChannelReceiver::Priority(channel) => (channel, true),
                ChannelReceiver::Ordinary(channel) => (channel, false),
            };
            let version = channel.decrypt(&mut data, priority)?;
            channel.set_ready();
            channel.reset_drop_timeout();
            (
                priority,
                *channel.local_id(),
                Some(*channel.peer_id()),
                version,
            )
        } else {
            log::trace!(
                "Received message to unknown key ID: {}",
                hex::encode(&data[0..32])
            );
            return Ok(());
        };

        if let Some(version) = version {
            if version != ADNL_INITIAL_VERSION {
                return Err(AdnlNodeError::UnsupportedVersion.into());
            }
        }

        // Parse packet
        let (packet, signature) = PacketContentsView::read_from_packet(data.as_slice())
            .map_err(|_| AdnlNodeError::InvalidPacket)?;

        // Validate packet
        let peer_id =
            match self.check_packet(&data, &packet, signature, &local_id, peer_id, priority)? {
                // New packet
                Some(peer_id) => peer_id,
                // Repeated packet
                None => return Ok(()),
            };

        // Process message(s)
        if let Some(message) = packet.message {
            self.process_message(&local_id, &peer_id, message, subscribers, priority)
                .await?;
        } else if let Some(messages) = packet.messages {
            for message in messages {
                self.process_message(&local_id, &peer_id, message, subscribers, priority)
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
        message: MessageView<'_>,
        subscribers: &[Arc<dyn Subscriber>],
        priority: bool,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        // Handle split message case
        let alt_message = if let MessageView::Part {
            hash,
            total_size,
            offset,
            data,
        } = message
        {
            let transfer_id = *hash;
            let transfer = match self.incoming_transfers.entry(transfer_id) {
                // Create new transfer state if it was a new incoming transfer
                Entry::Vacant(entry) => {
                    let entry = entry.insert(Arc::new(Transfer::new(total_size as usize)));
                    let transfer = entry.value().clone();

                    tokio::spawn({
                        let incoming_transfers = self.incoming_transfers.clone();
                        let transfer = transfer.clone();
                        let transfer_timeout = self.options.transfer_timeout_sec;

                        async move {
                            loop {
                                tokio::time::sleep(Duration::from_secs(transfer_timeout)).await;
                                if !transfer.timings().is_expired(transfer_timeout) {
                                    continue;
                                }

                                if incoming_transfers.remove(&transfer_id).is_some() {
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
            match transfer.add_part(offset as usize, data.to_vec(), &transfer_id) {
                Ok(Some(message)) => {
                    self.incoming_transfers.remove(&transfer_id);
                    Some(message)
                }
                Err(error) => {
                    self.incoming_transfers.remove(&transfer_id);
                    return Err(error);
                }
                _ => return Ok(()),
            }
        } else {
            None
        };
        let alt_message = match &alt_message {
            Some(buffer) => Some(deserialize_view(buffer.as_slice())?),
            None => None,
        };

        // Process message
        match alt_message.unwrap_or(message) {
            MessageView::Answer { query_id, answer } => {
                self.process_message_answer(query_id, answer).await
            }
            MessageView::ConfirmChannel { key, date, .. } => {
                self.process_message_confirm_channel(local_id, peer_id, key, date)
            }
            MessageView::CreateChannel { key, date } => {
                self.process_message_create_channel(local_id, peer_id, key, date)
            }
            MessageView::Custom { data } => {
                if process_message_custom(local_id, peer_id, subscribers, data).await? {
                    Ok(())
                } else {
                    Err(AdnlNodeError::NoSubscribersForCustomMessage.into())
                }
            }
            MessageView::Nop => Ok(()),
            MessageView::Query { query_id, query } => {
                let result =
                    process_message_adnl_query(local_id, peer_id, subscribers, query_id, query)
                        .await?;

                match result {
                    QueryProcessingResult::Processed(Some(message)) => {
                        self.send_message(local_id, peer_id, message, priority)
                    }
                    QueryProcessingResult::Processed(None) => Ok(()),
                    QueryProcessingResult::Rejected => {
                        Err(AdnlNodeError::NoSubscribersForQuery.into())
                    }
                }
            }
            _ => Err(AdnlNodeError::UnknownMessage.into()),
        }
    }

    async fn process_message_answer(&self, query_id: &QueryId, answer: &[u8]) -> Result<()> {
        if self.queries.update_query(*query_id, Some(answer)).await? {
            Ok(())
        } else {
            Err(AdnlNodeError::UnknownQueryAnswer.into())
        }
    }

    fn process_message_confirm_channel(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer_channel_public_key: &[u8; 32],
        peer_channel_date: i32,
    ) -> Result<()> {
        self.create_channel(
            local_id,
            peer_id,
            peer_channel_public_key,
            peer_channel_date,
            ChannelCreationContext::ConfirmChannel,
        )
    }

    fn process_message_create_channel(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer_channel_public_key: &[u8; 32],
        peer_channel_date: i32,
    ) -> Result<()> {
        self.create_channel(
            local_id,
            peer_id,
            peer_channel_public_key,
            peer_channel_date,
            ChannelCreationContext::CreateChannel,
        )
    }

    /// Validates incoming packet. Attempts to extract peer id
    fn check_packet(
        &self,
        raw_packet: &PacketView<'_>,
        packet: &PacketContentsView<'_>,
        mut signature: Option<PacketContentsSignature>,
        local_id: &AdnlNodeIdShort,
        peer_id: Option<AdnlNodeIdShort>,
        priority: bool,
    ) -> Result<Option<AdnlNodeIdShort>> {
        use std::cmp::Ordering;

        fn verify(
            raw_packet: &PacketView<'_>,
            signature: &mut Option<PacketContentsSignature>,
            public_key: &ed25519_dalek::PublicKey,
            mandatory: bool,
        ) -> Result<()> {
            if let Some(signature) = signature.take() {
                // SAFETY: called only once on same packet
                let (message, signature) = unsafe { signature.extract(raw_packet)? };
                let signature = ed25519_dalek::Signature::from_bytes(&signature)?;
                public_key.verify(message, &signature)?;
            } else if mandatory {
                return Err(AdnlPacketError::SignatureNotFound.into());
            }
            Ok(())
        }

        let from_channel = peer_id.is_some();

        // Extract peer id
        let (peer_id, check_signature) = if let Some(peer_id) = peer_id {
            if packet.from.is_some() || packet.from_short.is_some() {
                return Err(AdnlPacketError::ExplicitSourceForChannel.into());
            }
            (peer_id, true)
        } else if let Some(public_key) = packet.from {
            let full_id: AdnlNodeIdFull = public_key.try_into()?;
            let peer_id = full_id.compute_short_id()?;

            if matches!(packet.from_short, Some(id) if peer_id.as_slice() != id) {
                return Err(AdnlPacketError::InvalidPeerId.into());
            }

            verify(
                raw_packet,
                &mut signature,
                full_id.public_key(),
                self.options.packet_signature_required,
            )?;

            if let Some(list) = &packet.address {
                let ip_address = parse_address_list_view(list, self.options.clock_tolerance_sec)?;
                self.add_peer(
                    PeerContext::AdnlPacket,
                    local_id,
                    &peer_id,
                    ip_address,
                    full_id,
                )?;
            }

            (peer_id, false)
        } else if let Some(peer_id) = packet.from_short {
            (AdnlNodeIdShort::new(*peer_id), true)
        } else {
            return Err(AdnlPacketError::NoKeyDataInPacket.into());
        };

        // Check timings
        let dst_reinit_date = packet.dst_reinit_date;
        let reinit_date = packet.reinit_date;
        if dst_reinit_date.is_some() != reinit_date.is_some() {
            return Err(AdnlPacketError::ReinitDatesMismatch.into());
        }

        let peers = self.get_peers(local_id)?;
        let peer = if from_channel {
            if self.channels_by_peers.contains_key(&peer_id) {
                peers.get(&peer_id)
            } else {
                return Err(AdnlPacketError::UnknownChannel.into());
            }
        } else {
            peers.get(&peer_id)
        }
        .ok_or(AdnlPacketError::UnknownPeer)?;

        if check_signature {
            verify(raw_packet, &mut signature, peer.id().public_key(), false)?;
        }

        if let (Some(dst_reinit_date), Some(reinit_date)) = (dst_reinit_date, reinit_date) {
            let local_reinit_date = peer.receiver_state().reinit_date();
            let dst_reinit_date_cmp = dst_reinit_date.cmp(&local_reinit_date);

            if dst_reinit_date_cmp == Ordering::Greater {
                return Err(AdnlPacketError::DstReinitDateTooNew.into());
            }

            if reinit_date > now() + self.options.clock_tolerance_sec {
                return Err(AdnlPacketError::SrcReinitDateTooNew.into());
            }

            if !peer.try_reinit(reinit_date) {
                return Err(AdnlPacketError::SrcReinitDateTooOld.into());
            }

            if dst_reinit_date != 0 && dst_reinit_date_cmp == Ordering::Less {
                drop(peer);

                self.send_message(
                    local_id,
                    &peer_id,
                    ton::adnl::Message::Adnl_Message_Nop,
                    false,
                )?;
                return Err(AdnlPacketError::DstReinitDateTooOld.into());
            }
        }

        if self.options.packet_history_enabled {
            if let Some(seqno) = packet.seqno {
                if !peer
                    .receiver_state()
                    .history(priority)
                    .deliver_packet(seqno)
                {
                    return Ok(None);
                }
            }
        }

        if let Some(confirm_seqno) = packet.confirm_seqno {
            let sender_seqno = peer.sender_state().history(priority).seqno();
            if confirm_seqno > sender_seqno {
                return Err(AdnlPacketError::ConfirmationSeqnoTooNew.into());
            }
        }

        Ok(Some(peer_id))
    }

    fn send_message(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        message: ton::adnl::Message,
        priority: bool,
    ) -> Result<()> {
        const MAX_ADNL_MESSAGE_SIZE: usize = 1024;

        const MSG_ANSWER_SIZE: usize = 44;
        const MSG_CONFIRM_CHANNEL_SIZE: usize = 72;
        const MSG_CREATE_CHANNEL_SIZE: usize = 40;
        const MSG_CUSTOM_SIZE: usize = 12;
        const MSG_NOP_SIZE: usize = 4;
        const MSG_QUERY_SIZE: usize = 44;

        let peers = self.get_peers(local_id)?;
        let peer = match peers.get(peer_id) {
            Some(peer) => peer,
            None => return Err(AdnlNodeError::UnknownPeer.into()),
        };
        let peer = peer.value();

        let local_key = self.keystore.key_by_id(local_id)?;
        let mut channel = self.channels_by_peers.get(peer_id);
        let (mut size, additional_message) = match &channel {
            Some(channel) if channel.ready() => (0, None),
            Some(channel_data) => {
                log::debug!("Confirm channel {} -> {}", local_id, peer_id);

                let message = ton::adnl::message::message::ConfirmChannel {
                    key: ton::int256(peer.channel_key().public_key().to_bytes()),
                    peer_key: ton::int256(*channel_data.peer_channel_public_key()),
                    date: channel_data.peer_channel_date(),
                }
                .into_boxed();

                channel = None;
                (MSG_CONFIRM_CHANNEL_SIZE, Some(message))
            }
            None => {
                log::debug!("Create channel {} -> {}", local_id, peer_id);

                let message = ton::adnl::message::message::CreateChannel {
                    key: ton::int256(peer.channel_key().public_key().to_bytes()),
                    date: now(),
                }
                .into_boxed();

                (MSG_CREATE_CHANNEL_SIZE, Some(message))
            }
        };

        size += match &message {
            ton::adnl::Message::Adnl_Message_Answer(msg) => msg.answer.len() + MSG_ANSWER_SIZE,
            ton::adnl::Message::Adnl_Message_ConfirmChannel(_) => MSG_CONFIRM_CHANNEL_SIZE,
            ton::adnl::Message::Adnl_Message_Custom(msg) => msg.data.len() + MSG_CUSTOM_SIZE,
            ton::adnl::Message::Adnl_Message_Nop => MSG_NOP_SIZE,
            ton::adnl::Message::Adnl_Message_Query(msg) => msg.query.len() + MSG_QUERY_SIZE,
            _ => return Err(AdnlNodeError::UnexpectedMessageToSend.into()),
        };

        let signer = match channel.as_ref() {
            Some(channel) => MessageSigner::Channel {
                channel: channel.value(),
                priority,
            },
            None => MessageSigner::Random(&local_key),
        };

        if size <= MAX_ADNL_MESSAGE_SIZE {
            let message = match additional_message {
                Some(additional_message) => {
                    MessageToSend::Multiple(vec![additional_message, message])
                }
                None => MessageToSend::Single(message),
            };

            self.send_packet(peer_id, peer, signer, message)
        } else {
            fn build_part_message(
                data: &[u8],
                hash: &[u8; 32],
                max_size: usize,
                offset: &mut usize,
            ) -> ton::adnl::Message {
                let len = std::cmp::min(data.len(), *offset + max_size);

                let result = ton::adnl::message::message::Part {
                    hash: ton::int256(*hash),
                    total_size: data.len() as i32,
                    offset: *offset as i32,
                    data: ton::bytes(data[*offset..len].to_vec()),
                }
                .into_boxed();

                *offset += len;
                result
            }

            let data = serialize(&message)?;
            let hash: [u8; 32] = sha2::Sha256::digest(&data).into();
            let mut offset = 0;

            if let Some(additional_message) = additional_message {
                let message = build_part_message(
                    &data,
                    &hash,
                    MAX_ADNL_MESSAGE_SIZE - MSG_CREATE_CHANNEL_SIZE,
                    &mut offset,
                );

                self.send_packet(
                    peer_id,
                    peer,
                    signer,
                    MessageToSend::Multiple(vec![additional_message, message]),
                )?;
            }

            while offset < data.len() {
                let message = MessageToSend::Single(build_part_message(
                    &data,
                    &hash,
                    MAX_ADNL_MESSAGE_SIZE,
                    &mut offset,
                ));

                self.send_packet(peer_id, peer, signer, message)?;
            }

            Ok(())
        }
    }

    fn send_packet(
        &self,
        peer_id: &AdnlNodeIdShort,
        peer: &AdnlPeer,
        mut signer: MessageSigner,
        message: MessageToSend,
    ) -> Result<()> {
        const MAX_PRIORITY_ATTEMPTS: i64 = 10;

        let priority = if let MessageSigner::Channel { priority, .. } = &mut signer {
            if peer.receiver_state().history(*priority).seqno() == 0
                && peer.sender_state().history(true).seqno() > MAX_PRIORITY_ATTEMPTS
            {
                *priority = false;
            }
            *priority
        } else {
            false
        };

        let (message, messages) = match message {
            MessageToSend::Single(message) => (Some(message), None),
            MessageToSend::Multiple(messages) => (None, Some(messages.into())),
        };

        let mut packet = ton::adnl::packetcontents::PacketContents {
            rand1: ton::bytes(gen_packet_offset()),
            from: match signer {
                MessageSigner::Channel { .. } => None,
                MessageSigner::Random(local_key) => Some(local_key.full_id().as_tl().into_boxed()),
            },
            from_short: match signer {
                MessageSigner::Channel { .. } => None,
                MessageSigner::Random(local_key) => Some(local_key.id().as_tl()),
            },
            message,
            messages,
            address: Some(
                self.build_address_list(Some(now() + self.options.address_list_timeout_sec)),
            ),
            priority_address: None,
            seqno: Some(peer.sender_state().history(priority).bump_seqno()),
            confirm_seqno: Some(peer.receiver_state().history(priority).seqno()),
            recv_addr_list_version: None,
            recv_priority_addr_list_version: None,
            reinit_date: match signer {
                MessageSigner::Channel { .. } => None,
                MessageSigner::Random(_) => Some(peer.receiver_state().reinit_date()),
            },
            dst_reinit_date: match signer {
                MessageSigner::Channel { .. } => None,
                MessageSigner::Random(_) => Some(peer.sender_state().reinit_date()),
            },
            signature: None,
            rand2: ton::bytes(gen_packet_offset()),
        };

        if let MessageSigner::Random(signer) = signer {
            let signature = signer.sign(&serialize_boxed(packet.clone())?);
            packet.signature = Some(ton::bytes(signature.to_bytes().to_vec()));
        }

        let mut data = serialize_boxed(packet)?;

        match signer {
            MessageSigner::Channel { channel, priority } => {
                channel.encrypt(&mut data, priority, self.options.version)?
            }
            MessageSigner::Random(_) => {
                build_handshake_packet(peer_id, peer.id(), &mut data, self.options.version)?
            }
        }

        self.sender_queue_tx
            .send(PacketToSend {
                destination: peer.ip_address(),
                data,
            })
            .map_err(|_| AdnlNodeError::FailedToSendPacket)?;

        Ok(())
    }

    pub fn compute_query_timeout(&self, roundtrip: Option<u64>) -> u64 {
        let timeout = roundtrip.unwrap_or(self.options.query_max_timeout_ms);
        if timeout < self.options.query_min_timeout_ms {
            self.options.query_min_timeout_ms
        } else {
            timeout
        }
    }

    pub fn ip_address(&self) -> AdnlAddressUdp {
        self.ip_address
    }

    pub fn start_time(&self) -> i32 {
        self.start_time
    }

    pub fn build_address_list(
        &self,
        expire_at: Option<i32>,
    ) -> ton::adnl::addresslist::AddressList {
        let now = now();
        ton::adnl::addresslist::AddressList {
            addrs: vec![self.ip_address.as_tl()].into(),
            version: now,
            reinit_date: self.start_time,
            priority: 0,
            expire_at: expire_at.unwrap_or_default(),
        }
    }

    pub fn add_key(
        &mut self,
        key: ed25519_dalek::SecretKey,
        tag: usize,
    ) -> Result<AdnlNodeIdShort> {
        use dashmap::mapref::entry::Entry;

        let result = self.keystore.add_key(key, tag)?;
        if let Entry::Vacant(entry) = self.peers.entry(result) {
            entry.insert(Arc::new(Default::default()));
        };

        Ok(result)
    }

    pub fn delete_key(&mut self, key: &AdnlNodeIdShort, tag: usize) -> Result<bool> {
        self.peers.remove(key);
        self.keystore.delete_key(key, tag)
    }

    pub fn key_by_id(&self, id: &AdnlNodeIdShort) -> Result<Arc<StoredAdnlNodeKey>> {
        self.keystore.key_by_id(id)
    }

    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<StoredAdnlNodeKey>> {
        self.keystore.key_by_tag(tag)
    }

    pub fn add_peer(
        &self,
        ctx: PeerContext,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer_ip_address: AdnlAddressUdp,
        peer_full_id: AdnlNodeIdFull,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        if peer_id == local_id && peer_ip_address == self.ip_address {
            return Ok(false);
        }

        if let Some(filter) = &self.node_filter {
            if !filter.check(ctx, peer_ip_address, peer_id) {
                return Ok(false);
            }
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

    pub fn get_peer_ip(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
    ) -> Option<AdnlAddressUdp> {
        let peers = self.get_peers(local_id).ok()?;
        let peer = peers.get(peer_id)?;
        Some(peer.ip_address())
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
            ton::adnl::message::message::Custom {
                data: ton::bytes(data.to_vec()),
            }
            .into_boxed(),
            self.options.force_use_priority_channels,
        )
    }

    pub async fn query(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        query: &ton::TLObject,
        timeout: Option<u64>,
    ) -> Result<Option<ton::TLObject>> {
        self.query_with_prefix(local_id, peer_id, None, query, timeout)
            .await
    }

    pub async fn query_with_prefix(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        prefix: Option<&[u8]>,
        query: &ton::TLObject,
        timeout: Option<u64>,
    ) -> Result<Option<ton::TLObject>> {
        let (query_id, message) = build_query(prefix, query)?;

        let pending_query = self.queries.add_query(query_id);

        self.send_message(local_id, peer_id, message, true)?;
        let channel = self
            .channels_by_peers
            .get(peer_id)
            .map(|entry| entry.value().clone());

        tokio::spawn({
            let queries = self.queries.clone();
            let timeout = timeout.unwrap_or(self.options.query_max_timeout_ms);

            async move {
                tokio::time::sleep(Duration::from_millis(timeout)).await;

                match queries.update_query(query_id, None).await {
                    Ok(true) => { /* dropped query */ }
                    Err(e) => {
                        log::warn!("Failed to drop query {} ({})", ShortQueryId(&query_id), e)
                    }
                    _ => { /* do nothing */ }
                }
            }
        });

        let query = pending_query.wait().await;

        match query {
            Ok(Some(answer)) => Ok(Some(deserialize(&answer)?)),
            Ok(None) => {
                if let Some(channel) = channel {
                    let now = now();
                    let was = channel.update_drop_timeout(now);
                    if (was > 0) && (was < now) {
                        self.reset_peer(local_id, peer_id)?;
                    }
                }
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn get_peers(&self, local_id: &AdnlNodeIdShort) -> Result<Arc<AdnlPeers>> {
        if let Some(peers) = self.peers.get(local_id) {
            Ok(peers.value().clone())
        } else {
            Err(AdnlNodeError::PeersNotFound.into())
        }
    }

    fn reset_peer(&self, local_id: &AdnlNodeIdShort, peer_id: &AdnlNodeIdShort) -> Result<()> {
        let peers = self.get_peers(local_id)?;
        let mut peer = peers.get_mut(peer_id).ok_or(AdnlNodeError::UnknownPeer)?;

        log::debug!("Resetting peer pair {} -> {}", local_id, peer_id);

        self.channels_by_peers
            .remove(peer_id)
            .and_then(|(_, removed)| {
                self.channels_by_id.remove(removed.ordinary_channel_in_id());
                self.channels_by_id.remove(removed.priority_channel_in_id())
            });

        peer.reset();

        Ok(())
    }

    fn create_channel(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer_channel_public_key: &[u8; 32],
        peer_channel_date: i32,
        context: ChannelCreationContext,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        let peers = self.get_peers(local_id)?;
        let peer = match peers.get(peer_id) {
            Some(peer) => peer,
            None => return Err(AdnlNodeError::UnknownPeerInChannel.into()),
        };
        let peer = peer.value();

        match self.channels_by_peers.entry(*peer_id) {
            Entry::Occupied(mut entry) => {
                let channel = entry.get();

                if channel.is_still_valid(peer_channel_public_key, peer_channel_date) {
                    if context == ChannelCreationContext::ConfirmChannel {
                        channel.set_ready();
                    }
                    return Ok(());
                }

                let new_channel = Arc::new(AdnlChannel::new(
                    *local_id,
                    *peer_id,
                    peer.channel_key().private_key_part(),
                    peer_channel_public_key,
                    peer_channel_date,
                    context,
                )?);

                let old_channel = entry.insert(new_channel.clone());
                self.channels_by_id
                    .remove(old_channel.ordinary_channel_in_id());
                self.channels_by_id
                    .remove(old_channel.priority_channel_in_id());

                self.channels_by_id.insert(
                    *new_channel.ordinary_channel_in_id(),
                    ChannelReceiver::Ordinary(new_channel.clone()),
                );
                self.channels_by_id.insert(
                    *new_channel.priority_channel_in_id(),
                    ChannelReceiver::Priority(new_channel),
                );
            }
            Entry::Vacant(entry) => {
                let new_channel = entry
                    .insert(Arc::new(AdnlChannel::new(
                        *local_id,
                        *peer_id,
                        peer.channel_key().private_key_part(),
                        peer_channel_public_key,
                        peer_channel_date,
                        context,
                    )?))
                    .clone();
                self.channels_by_id.insert(
                    *new_channel.ordinary_channel_in_id(),
                    ChannelReceiver::Ordinary(new_channel.clone()),
                );
                self.channels_by_id.insert(
                    *new_channel.priority_channel_in_id(),
                    ChannelReceiver::Priority(new_channel),
                );
            }
        }

        log::debug!("Channel {}: {} -> {}", context, local_id, peer_id);

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AdnlNodeMetrics {
    pub peer_count: usize,
    pub channels_by_id_len: usize,
    pub channels_by_peers_len: usize,
    pub incoming_transfers_len: usize,
    pub query_count: usize,
}

struct PacketToSend {
    destination: AdnlAddressUdp,
    data: Vec<u8>,
}

#[derive(Copy, Clone)]
enum MessageSigner<'a> {
    Channel {
        channel: &'a Arc<AdnlChannel>,
        priority: bool,
    },
    Random(&'a Arc<StoredAdnlNodeKey>),
}

enum MessageToSend {
    Single(ton::adnl::Message),
    Multiple(Vec<ton::adnl::Message>),
}

type SenderQueueTx = mpsc::UnboundedSender<PacketToSend>;
type SenderQueueRx = mpsc::UnboundedReceiver<PacketToSend>;

#[derive(thiserror::Error, Debug)]
enum AdnlNodeError {
    #[error("ADNL node is already running")]
    AlreadyRunning,
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Local id peers not found")]
    PeersNotFound,
    #[error("Unknown message")]
    UnknownMessage,
    #[error("Received answer to unknown query")]
    UnknownQueryAnswer,
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Channel with unknown peer")]
    UnknownPeerInChannel,
    #[error("No subscribers for custom message")]
    NoSubscribersForCustomMessage,
    #[error("No subscribers for query")]
    NoSubscribersForQuery,
    #[error("Unexpected message to send")]
    UnexpectedMessageToSend,
    #[error("Failed to send ADNL packet")]
    FailedToSendPacket,
    #[error("Unsupported version")]
    UnsupportedVersion,
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
    #[error("Signature not found")]
    SignatureNotFound,
}

const ADNL_INITIAL_VERSION: u16 = 0;
