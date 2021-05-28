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
    ip_address: AdnlAddressUdp,
    sender_queue_tx: SenderQueueTx,
    sender_queue_rx: Mutex<Option<SenderQueueRx>>,
}

impl AdnlNode {
    pub async fn start(self: &Arc<Self>, mut subscribers: Vec<Arc<dyn Subscriber>>) -> Result<()> {
        let sender_queue_rx = match self.sender_queue_rx.lock().take() {
            Some(rx) => rx,
            None => return Err(AdnlNodeError::AlreadyRunning.into()),
        };

        let socket =
            Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, self.ip_address.port())).await?);

        let subscribers = Arc::new(subscribers);

        self.start_sender(socket.clone(), sender_queue_rx);
        self.start_receiver(socket, subscribers.clone());

        Ok(())
    }

    fn start_sender(self: &Arc<Self>, socket: Arc<UdpSocket>, mut sender_queue_rx: SenderQueueRx) {
        let node = Arc::downgrade(self);

        tokio::spawn(async move {
            while let Some(packet) = sender_queue_rx.recv().await {
                let _node = match node.upgrade() {
                    Some(node) => node,
                    None => return,
                };

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
                let node = match node.upgrade() {
                    Some(node) => node,
                    None => return,
                };

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
        data: PacketView<'_>,
        subscribers: &[Arc<dyn Subscriber>],
    ) -> Result<()> {
        // todo
        Ok(())
    }
}

fn parse_handshake(
    keys: &DashMap<AdnlNodeIdShort, StoredAdnlNodeKey>,
    buffer: &mut PacketView<'_>,
    length: Option<usize>,
) -> Result<Option<AdnlNodeIdShort>> {
    use sha2::digest::Digest;

    if buffer.len() < 96 + length.unwrap_or_default() {
        return Err(AdnlNodeError::BadHandshakePacketLength.into());
    }

    let data_range = match length {
        Some(length) => 96..(96 + length),
        None => 96..buffer.len(),
    };

    for key in keys.iter() {
        if key.key() == &buffer[0..32] {
            let mut shared_secret = compute_shared_secret(
                key.value().private_key().as_bytes(),
                buffer[32..64].try_into().unwrap(),
            )?;

            build_packet_cipher(&shared_secret, &buffer[64..96].try_into().unwrap())
                .apply_keystream(&mut buffer[data_range]);

            if !sha2::Sha256::digest(&buffer[96..])
                .as_slice()
                .eq(&buffer[64..96])
            {
                return Err(AdnlNodeError::BadHandshakePacketChecksum.into());
            }

            buffer.remove_prefix(96);
            return Ok(Some(*key.key()));
        }
    }

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
}
