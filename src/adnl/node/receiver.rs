use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use everscale_crypto::ed25519;
use tl_proto::TlRead;
use tokio::net::UdpSocket;

use crate::adnl::channel::*;
use crate::adnl::handshake::*;
use crate::adnl::node_id::{NodeIdFull, NodeIdShort};
use crate::adnl::packet_view::*;
use crate::adnl::peer::*;
use crate::adnl::queries_cache::*;
use crate::adnl::transfer::*;
use crate::adnl::Node;
use crate::proto;
use crate::subscriber::*;
use crate::util::*;

impl Node {
    /// Starts a process that listens for and processes packets from the UDP socket
    pub(super) fn start_receiver(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
        message_subscribers: Vec<Arc<dyn MessageSubscriber>>,
        query_subscribers: Vec<Arc<dyn QuerySubscriber>>,
    ) {
        use futures_util::future::{select, Either};

        struct ReceiverContext {
            node: Arc<Node>,
            message_subscribers: Vec<Arc<dyn MessageSubscriber>>,
            query_subscribers: Vec<Arc<dyn QuerySubscriber>>,
        }

        const RECV_BUFFER_SIZE: usize = 2048;

        let complete_signal = self.cancellation_token.clone();
        let ctx = Arc::new(ReceiverContext {
            node: self.clone(),
            message_subscribers,
            query_subscribers,
        });

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
                    Either::Right(_) => break,
                };

                let len = match result {
                    Ok((len, _)) if len == 0 => continue,
                    Ok((len, _)) => len,
                    Err(e) => {
                        tracing::warn!("failed to receive data: {e}");
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
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(error) = ctx
                        .node
                        .handle_received_data(
                            PacketView::from(buffer.as_mut_slice()),
                            &ctx.message_subscribers,
                            &ctx.query_subscribers,
                        )
                        .await
                    {
                        tracing::trace!(?error, "failed to handle received data");
                    }
                });
            }

            tracing::debug!("receiver loop finished");
        });
    }

    /// Decrypts and processes received data
    async fn handle_received_data(
        self: &Arc<Self>,
        mut data: PacketView<'_>,
        message_subscribers: &[Arc<dyn MessageSubscriber>],
        query_subscribers: &[Arc<dyn QuerySubscriber>],
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
            tracing::trace!(
                key_id = hex::encode(&data[0..32]),
                "received message to unknown key ID",
            );
            return Ok(());
        };

        if let Some(version) = version {
            if version != ADNL_INITIAL_VERSION {
                return Err(AdnlReceiverError::UnsupportedVersion.into());
            }
        }

        // Parse packet
        let mut packet =
            tl_proto::deserialize::<proto::adnl::IncomingPacketContents>(data.as_slice())
                .map_err(|_| AdnlReceiverError::InvalidPacket)?;

        // Validate packet
        let peer_id = match self.check_packet(&data, &mut packet, &local_id, peer_id, priority)? {
            // New packet
            Some(peer_id) => peer_id,
            // Repeated packet
            None => return Ok(()),
        };

        // Process message(s)
        for message in packet.messages {
            self.process_message(
                &local_id,
                &peer_id,
                message,
                message_subscribers,
                query_subscribers,
                priority,
            )
            .await?;
        }

        // Done
        Ok(())
    }

    async fn process_message(
        self: &Arc<Self>,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        message: proto::adnl::Message<'_>,
        message_subscribers: &[Arc<dyn MessageSubscriber>],
        query_subscribers: &[Arc<dyn QuerySubscriber>],
        priority: bool,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        // Handle split message case
        let alt_message = if let proto::adnl::Message::Part {
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
                    tracing::debug!(
                        %local_id,
                        %peer_id,
                        total = total_size,
                        transfer_id = %DisplayTransferId(&transfer_id),
                        "started ADNL transfer"
                    );

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
                                    tracing::debug!(
                                        transfer_id = %DisplayTransferId(&transfer_id),
                                        "ADNL transfer timed out"
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
                    return Err(error.into());
                }
                _ => return Ok(()),
            }
        } else {
            None
        };
        let alt_message = match &alt_message {
            Some(buffer) => Some(tl_proto::deserialize(buffer)?),
            None => None,
        };

        // Process message
        match alt_message.unwrap_or(message) {
            proto::adnl::Message::Answer { query_id, answer } => {
                self.process_message_answer(query_id, answer);
                Ok(())
            }
            proto::adnl::Message::ConfirmChannel { key, date, .. } => self
                .process_message_confirm_channel(
                    local_id,
                    peer_id,
                    ed25519::PublicKey::from_bytes(*key).ok_or(AdnlReceiverError::InvalidPacket)?,
                    date,
                ),
            proto::adnl::Message::CreateChannel { key, date } => self
                .process_message_create_channel(
                    local_id,
                    peer_id,
                    ed25519::PublicKey::from_bytes(*key).ok_or(AdnlReceiverError::InvalidPacket)?,
                    date,
                ),
            proto::adnl::Message::Custom { data } => {
                let ctx = SubscriberContext {
                    adnl: self,
                    local_id,
                    peer_id,
                };
                if process_message_custom(ctx, message_subscribers, data).await? {
                    Ok(())
                } else {
                    Err(AdnlReceiverError::NoSubscribersForCustomMessage.into())
                }
            }
            proto::adnl::Message::Nop => Ok(()),
            proto::adnl::Message::Query { query_id, query } => {
                let ctx = SubscriberContext {
                    adnl: self,
                    local_id,
                    peer_id,
                };
                match process_query(ctx, query_subscribers, Cow::Borrowed(query)).await? {
                    QueryProcessingResult::Processed(Some(answer)) => self.send_message(
                        local_id,
                        peer_id,
                        proto::adnl::Message::Answer {
                            query_id,
                            answer: &answer,
                        },
                        priority,
                    ),
                    QueryProcessingResult::Processed(None) => Ok(()),
                    QueryProcessingResult::Rejected => {
                        Err(AdnlReceiverError::NoSubscribersForQuery.into())
                    }
                }
            }
            _ => Err(AdnlReceiverError::UnknownMessage.into()),
        }
    }

    fn process_message_answer(&self, query_id: &QueryId, answer: &[u8]) {
        self.queries.update_query(query_id, answer);
    }

    fn process_message_confirm_channel(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        peer_channel_public_key: ed25519::PublicKey,
        peer_channel_date: u32,
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
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        peer_channel_public_key: ed25519::PublicKey,
        peer_channel_date: u32,
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
        packet: &mut proto::adnl::IncomingPacketContents<'_>,
        local_id: &NodeIdShort,
        peer_id: Option<NodeIdShort>,
        priority: bool,
    ) -> Result<Option<NodeIdShort>> {
        use std::cmp::Ordering;

        fn verify(
            raw_packet: &PacketView<'_>,
            signature: &mut Option<proto::adnl::PacketContentsSignature>,
            public_key: &ed25519::PublicKey,
            mandatory: bool,
        ) -> Result<(), AdnlPacketError> {
            if let Some(signature) = signature.take() {
                // SAFETY: called only once on same packet
                let (message, signature) = unsafe {
                    let origin = raw_packet.as_slice().as_ptr() as *mut u8;
                    let packet = std::slice::from_raw_parts_mut(origin, raw_packet.len());
                    signature
                        .extract(packet)
                        .ok_or(AdnlPacketError::SignatureNotFound)?
                };

                if !public_key.verify_raw(message, &signature) {
                    return Err(AdnlPacketError::InvalidSignature);
                }
            } else if mandatory {
                return Err(AdnlPacketError::SignatureNotFound);
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
            let full_id: NodeIdFull = public_key.try_into()?;
            let peer_id = full_id.compute_short_id();

            if matches!(packet.from_short, Some(id) if peer_id.as_slice() != id) {
                return Err(AdnlPacketError::InvalidPeerId.into());
            }

            verify(
                raw_packet,
                &mut packet.signature,
                full_id.public_key(),
                self.options.packet_signature_required,
            )?;

            if let Some(list) = &packet.address {
                let addr = parse_address_list(list, self.options.clock_tolerance_sec)?;
                self.add_peer(
                    NewPeerContext::AdnlPacket,
                    local_id,
                    &peer_id,
                    addr,
                    full_id,
                )?;
            }

            (peer_id, false)
        } else if let Some(peer_id) = packet.from_short {
            (NodeIdShort::new(*peer_id), true)
        } else {
            return Err(AdnlPacketError::NoKeyDataInPacket.into());
        };

        // Check timings

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
            verify(
                raw_packet,
                &mut packet.signature,
                peer.id().public_key(),
                false,
            )?;
        }

        if let Some(proto::adnl::ReinitDates {
            local: peer_reinit_date,
            target: local_reinit_date,
        }) = packet.reinit_dates
        {
            let expected_local_reinit_date = local_reinit_date.cmp(&self.start_time);
            if expected_local_reinit_date == Ordering::Greater {
                return Err(AdnlPacketError::DstReinitDateTooNew.into());
            }

            if peer_reinit_date > now() + self.options.clock_tolerance_sec {
                return Err(AdnlPacketError::SrcReinitDateTooNew.into());
            }

            if !peer.try_reinit_sender(peer_reinit_date) {
                return Err(AdnlPacketError::SrcReinitDateTooOld.into());
            }

            if local_reinit_date != 0 && expected_local_reinit_date == Ordering::Less {
                drop(peer);

                self.send_message(local_id, &peer_id, proto::adnl::Message::Nop, false)?;
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

    fn create_channel(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        peer_channel_public_key: ed25519::PublicKey,
        peer_channel_date: u32,
        context: ChannelCreationContext,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        let peers = self.get_peers(local_id)?;
        let peer = match peers.get(peer_id) {
            Some(peer) => peer,
            None => return Err(AdnlReceiverError::UnknownPeerInChannel.into()),
        };
        let peer = peer.value();

        match self.channels_by_peers.entry(*peer_id) {
            Entry::Occupied(mut entry) => {
                let channel = entry.get();

                if channel.is_still_valid(&peer_channel_public_key, peer_channel_date) {
                    if context == ChannelCreationContext::ConfirmChannel {
                        channel.set_ready();
                    }
                    return Ok(());
                }

                let new_channel = Arc::new(Channel::new(
                    *local_id,
                    *peer_id,
                    peer.channel_key(),
                    peer_channel_public_key,
                    peer_channel_date,
                    context,
                ));

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
                    .insert(Arc::new(Channel::new(
                        *local_id,
                        *peer_id,
                        peer.channel_key(),
                        peer_channel_public_key,
                        peer_channel_date,
                        context,
                    )))
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

        tracing::trace!(%local_id, %peer_id, "{context} channel");

        Ok(())
    }
}

/// Duplicated channel
pub enum ChannelReceiver {
    Ordinary(Arc<Channel>),
    Priority(Arc<Channel>),
}

async fn process_message_custom<'a>(
    ctx: SubscriberContext<'a>,
    subscribers: &[Arc<dyn MessageSubscriber>],
    data: &[u8],
) -> Result<bool> {
    let constructor = u32::read_from(data, &mut 0)?;
    for subscriber in subscribers {
        if subscriber
            .try_consume_custom(ctx, constructor, data)
            .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

const ADNL_INITIAL_VERSION: u16 = 0;

#[derive(thiserror::Error, Debug)]
enum AdnlReceiverError {
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Unknown message")]
    UnknownMessage,
    #[error("Channel with unknown peer")]
    UnknownPeerInChannel,
    #[error("No subscribers for custom message")]
    NoSubscribersForCustomMessage,
    #[error("No subscribers for query")]
    NoSubscribersForQuery,
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
    #[error("Invalid signature")]
    InvalidSignature,
}
