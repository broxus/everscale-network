use std::net::SocketAddrV4;
use std::sync::Arc;

use anyhow::Result;
use sha2::Digest;
use tl_proto::TlWrite;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::adnl::channel::*;
use crate::adnl::handshake::*;
use crate::adnl::keystore::Key;
use crate::adnl::node_id::NodeIdShort;
use crate::adnl::peer::*;
use crate::adnl::Node;

use crate::proto;
use crate::utils::*;

impl Node {
    /// Starts a process that forwards packets from the sender queue to the UDP socket
    pub(super) fn start_sender(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
        mut sender_queue_rx: SenderQueueRx,
    ) {
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
                socket.send_to(&packet.data, target).await.ok();
            }
        });
    }

    pub(super) fn send_message(
        &self,
        local_id: &NodeIdShort,
        peer_id: &NodeIdShort,
        message: proto::adnl::Message,
        priority: bool,
    ) -> Result<()> {
        const MAX_ADNL_MESSAGE_SIZE: usize = 1024;

        const MSG_ANSWER_SIZE: usize = 44;
        const MSG_CONFIRM_CHANNEL_SIZE: usize = 72;
        const MSG_CREATE_CHANNEL_SIZE: usize = 40;
        const MSG_CUSTOM_SIZE: usize = 12;
        const MSG_NOP_SIZE: usize = 4;
        const MSG_QUERY_SIZE: usize = 44;
        const MSG_PART_PREFIX_SIZE: usize = 40;

        // Find peer by id
        let peers = self.get_peers(local_id)?;
        let peer = match peers.get(peer_id) {
            Some(peer) => peer,
            None => return Err(AdnlSenderError::UnknownPeer.into()),
        };
        let peer = peer.value();

        // Get local key
        let local_key = self.keystore.key_by_id(local_id)?;
        let channel = self.channels_by_peers.get(peer_id);
        let mut force_handshake = false;
        let (additional_size, additional_message) = match &channel {
            Some(channel) if channel.ready() => (0, None),
            Some(channel_data) => {
                tracing::trace!("Confirm channel {local_id} -> {peer_id}");

                force_handshake = true;
                (
                    MSG_CONFIRM_CHANNEL_SIZE,
                    Some(proto::adnl::Message::ConfirmChannel {
                        key: peer.channel_key().public_key.as_bytes(),
                        peer_key: channel_data.peer_channel_public_key().as_bytes(),
                        date: channel_data.peer_channel_date(),
                    }),
                )
            }
            None => {
                tracing::trace!("Create channel {local_id} -> {peer_id}");

                (
                    MSG_CREATE_CHANNEL_SIZE,
                    Some(proto::adnl::Message::CreateChannel {
                        key: peer.channel_key().public_key.as_bytes(),
                        date: now(),
                    }),
                )
            }
        };

        let mut size = additional_size;
        size += match message {
            proto::adnl::Message::Answer { answer, .. } => answer.len() + MSG_ANSWER_SIZE,
            proto::adnl::Message::ConfirmChannel { .. } => MSG_CONFIRM_CHANNEL_SIZE,
            proto::adnl::Message::Custom { data } => data.len() + MSG_CUSTOM_SIZE,
            proto::adnl::Message::Nop => MSG_NOP_SIZE,
            proto::adnl::Message::Query { query, .. } => query.len() + MSG_QUERY_SIZE,
            _ => return Err(AdnlSenderError::UnexpectedMessageToSend.into()),
        };

        let signer = match channel.as_ref() {
            Some(channel) if !force_handshake => MessageSigner::Channel {
                channel: channel.value(),
                priority,
            },
            _ => MessageSigner::Random(local_key),
        };

        if size <= MAX_ADNL_MESSAGE_SIZE {
            let mut buffer = Vec::with_capacity(size);
            let messages = match additional_message {
                Some(additional_message) => {
                    additional_message.write_to(&mut buffer);
                    message.write_to(&mut buffer);
                    proto::adnl::OutgoingMessages::Pair(&buffer)
                }
                None => {
                    message.write_to(&mut buffer);
                    proto::adnl::OutgoingMessages::Single(&buffer)
                }
            };

            self.send_packet(peer_id, peer, signer, messages)
        } else {
            pub fn build_part_message<'a>(
                data: &'a [u8],
                hash: &'a [u8; 32],
                max_size: usize,
                offset: &mut usize,
            ) -> proto::adnl::Message<'a> {
                let len = std::cmp::min(data.len(), *offset + max_size);

                let result = proto::adnl::Message::Part {
                    hash,
                    total_size: data.len() as u32,
                    offset: *offset as u32,
                    data: if *offset < len {
                        &data[*offset..len]
                    } else {
                        &data[..0]
                    },
                };

                *offset += len;
                result
            }

            let data = tl_proto::serialize(message);
            let hash: [u8; 32] = sha2::Sha256::digest(&data).into();
            let mut offset = 0;

            let mut buffer = Vec::with_capacity(MAX_ADNL_MESSAGE_SIZE);
            if let Some(additional_message) = additional_message {
                additional_message.write_to(&mut buffer);

                let message = build_part_message(
                    &data,
                    &hash,
                    MAX_ADNL_MESSAGE_SIZE - MSG_PART_PREFIX_SIZE - additional_size,
                    &mut offset,
                );
                message.write_to(&mut buffer);

                ok!(self.send_packet(
                    peer_id,
                    peer,
                    signer,
                    proto::adnl::OutgoingMessages::Pair(&buffer),
                ));
            }

            while offset < data.len() {
                buffer.clear();
                let message = build_part_message(&data, &hash, MAX_ADNL_MESSAGE_SIZE, &mut offset);
                message.write_to(&mut buffer);

                ok!(self.send_packet(
                    peer_id,
                    peer,
                    signer,
                    proto::adnl::OutgoingMessages::Single(&buffer),
                ));
            }

            Ok(())
        }
    }

    /// Encodes and sends packet to the peer
    fn send_packet(
        &self,
        peer_id: &NodeIdShort,
        peer: &Peer,
        mut signer: MessageSigner,
        messages: proto::adnl::OutgoingMessages,
    ) -> Result<()> {
        use rand::Rng;

        const MAX_PRIORITY_ATTEMPTS: u64 = 10;

        // Determine whether priority channels are supported by remote peer
        let priority = if let MessageSigner::Channel { priority, .. } = &mut signer {
            if peer.receiver_state().history(*priority).seqno() == 0
                && peer.sender_state().history(true).seqno() > MAX_PRIORITY_ATTEMPTS
            {
                *priority = false;
            }
            *priority
        } else {
            // All handshake packets are sent as ordinary
            false
        };

        // Generate on-stack random data
        let rand_bytes: [u8; 10] = rand::thread_rng().gen();

        let now = now();
        let address = proto::adnl::AddressList {
            address: Some(self.socket_addr.as_tl()),
            version: now,
            reinit_date: self.start_time,
            expire_at: now + self.options.address_list_timeout_sec,
        };

        let mut packet = proto::adnl::OutgoingPacketContents {
            rand1: &rand_bytes[..3],
            from: match signer {
                MessageSigner::Channel { .. } => None,
                MessageSigner::Random(local_key) => Some(local_key.full_id().as_tl()),
            },
            messages,
            address,
            seqno: peer.sender_state().history(priority).bump_seqno(),
            confirm_seqno: peer.receiver_state().history(priority).seqno(),
            reinit_dates: match signer {
                MessageSigner::Channel { .. } => None,
                MessageSigner::Random(_) => Some(proto::adnl::ReinitDates {
                    local: self.start_time,
                    target: peer.sender_state().reinit_date(),
                }),
            },
            signature: None,
            rand2: &rand_bytes[3..],
        };

        let signature = match signer {
            // Always sign handshake packets
            MessageSigner::Random(signer) => Some(signer.sign(&packet)),
            MessageSigner::Channel { .. } => None,
        };
        packet.signature = signature.as_ref().map(<[u8; 64]>::as_slice);

        // Serialize packet
        let mut data = tl_proto::serialize(packet);
        match signer {
            MessageSigner::Channel { channel, priority } => {
                channel.encrypt(&mut data, priority, self.options.version)
            }
            MessageSigner::Random(_) => {
                build_handshake_packet(peer_id, peer.id(), &mut data, self.options.version)
            }
        }

        if self
            .sender_queue_tx
            .send(PacketToSend {
                destination: peer.ip_address(),
                data,
            })
            .is_err()
        {
            return Err(AdnlSenderError::FailedToSendPacket.into());
        }

        Ok(())
    }
}

#[derive(Copy, Clone)]
enum MessageSigner<'a> {
    Channel {
        channel: &'a Arc<Channel>,
        priority: bool,
    },
    Random(&'a Arc<Key>),
}

pub struct PacketToSend {
    destination: PackedSocketAddr,
    data: Vec<u8>,
}

pub type SenderQueueTx = mpsc::UnboundedSender<PacketToSend>;
pub type SenderQueueRx = mpsc::UnboundedReceiver<PacketToSend>;

#[derive(thiserror::Error, Debug)]
enum AdnlSenderError {
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Unexpected message to send")]
    UnexpectedMessageToSend,
    #[error("Failed to send ADNL packet")]
    FailedToSendPacket,
}
