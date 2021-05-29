mod address_list;
mod channel;
mod config;
mod node_id;
mod peer;
mod received_mask;
pub mod utils;

use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use aes::cipher::StreamCipher;
use anyhow::Result;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use ton_api::ton;

pub use crate::address_list::*;
pub use crate::channel::*;
pub use crate::config::*;
pub use crate::node_id::*;
pub use crate::received_mask::*;
use crate::utils::*;

const ADNL_MTU: usize = 1024;
const HUGE_PACKET_SIZE: usize = ADNL_MTU * 8;

#[async_trait::async_trait]
pub trait Subscriber: Send + Sync {
    fn receive_message(&self, src: AdnlNodeIdShort, dst: AdnlNodeIdShort, data: Vec<u8>);

    async fn receive_query(
        &self,
        src: AdnlNodeIdShort,
        dst: AdnlNodeIdShort,
        data: Vec<u8>,
    ) -> Result<Vec<u8>>;
}

pub struct AdnlNode {
    /// Ip address and keys for signing
    config: AdnlNodeConfig,

    /// Channels table used to fast search on incoming packets
    channels_by_id: DashMap<AdnlChannelId, Arc<AdnlChannel>>,
    /// Channels table used to fast search when sending messages
    channels_by_peers: DashMap<AdnlNodeIdShort, Arc<AdnlChannel>>,
    /// Channels that were created on this node but waiting for confirmation
    channels_to_confirm: DashMap<AdnlNodeIdShort, Arc<AdnlChannel>>,

    /// Outgoing packets queue
    sender_queue_tx: SenderQueueTx,
    /// Receiver end of the outgoing packets queue (NOTE: used only for initialization)
    sender_queue_rx: Mutex<Option<SenderQueueRx>>,
}

impl AdnlNode {
    pub fn new(config: AdnlNodeConfig) -> Self {
        let (sender_queue_tx, sender_queue_rx) = mpsc::unbounded_channel();

        Self {
            config,
            channels_by_id: Default::default(),
            channels_by_peers: Default::default(),
            channels_to_confirm: Default::default(),
            sender_queue_tx,
            sender_queue_rx: Mutex::new(Some(sender_queue_rx)),
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

    async fn handle_received_data(
        &self,
        mut data: PacketView<'_>,
        subscribers: &[Arc<dyn Subscriber>],
    ) -> Result<()> {
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

        let packet = deserialize(data.as_slice())?
            .downcast::<ton::adnl::PacketContents>()
            .map_err(AdnlNodeError::UnknownPacket)?;

        // todo
        Ok(())
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
}
