use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::Result;
use rand::Rng;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use ton_api::ton::{self, TLObject};
use ton_api::IntoBoxed;

use self::ping_cache::*;
use crate::utils::*;

mod ping_cache;

pub struct AdnlTcpClient {
    ping_cache: Arc<PingCache>,
    queries_cache: Arc<QueriesCache>,
    sender: mpsc::UnboundedSender<PacketToSend>,
    pub has_broken: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct AdnlTcpClientConfig {
    pub server_address: SocketAddrV4,
    pub server_key: ed25519_dalek::PublicKey,
    pub socket_read_timeout: Duration,
    pub socket_send_timeout: Duration,
}

impl AdnlTcpClient {
    pub async fn ping(&self, timeout: Duration) -> Result<()> {
        if self.has_broken.load(Ordering::Acquire) {
            return Err(AdnlTcpClientError::SocketClosed.into());
        }

        let (seqno, pending_ping) = self.ping_cache.add_query();
        let message = serialize(&TLObject::new(pending_ping.as_tl()));
        let _ = self.sender.send(PacketToSend {
            data: message,
            should_encrypt: true,
        });

        tokio::spawn({
            let ping_cache = self.ping_cache.clone();

            async move {
                tokio::time::sleep(timeout).await;

                match ping_cache.update_query(seqno, false).await {
                    Ok(true) => tracing::info!("Dropped ping query"),
                    Err(_) => tracing::info!("Failed to drop ping query"),
                    _ => {}
                }
            }
        });

        pending_ping.wait().await?;

        Ok(())
    }

    pub async fn query(&self, query: &TLObject) -> Result<TLObject> {
        if self.has_broken.load(Ordering::Acquire) {
            return Err(AdnlTcpClientError::SocketClosed.into());
        }

        let (query_id, message) = build_query(query);
        let message = serialize(&message);

        let pending_query = self.queries_cache.add_query(query_id);
        let _ = self.sender.send(PacketToSend {
            data: message,
            should_encrypt: true,
        });

        tokio::spawn({
            let queries_cache = self.queries_cache.clone();

            async move {
                let timeout = Duration::from_secs(10);
                tokio::time::sleep(timeout).await;

                match queries_cache.update_query(query_id, None).await {
                    Ok(true) => tracing::info!("Dropped query"),
                    Err(_) => tracing::info!("Failed to drop query"),
                    _ => {}
                }
            }
        });

        match pending_query.wait().await? {
            Some(query) => Ok(deserialize(&query)?),
            None => Err(AdnlTcpClientError::QueryTimeout.into()),
        }
    }

    pub async fn connect(config: AdnlTcpClientConfig) -> Result<Arc<Self>> {
        let (peer_id_full, peer_id) = config.server_key.compute_node_ids();

        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        let socket = tokio::net::TcpStream::connect(config.server_address).await?;
        socket.set_linger(Some(Duration::from_secs(0)))?;
        let (socket_rx, socket_tx) = socket.into_split();
        let mut socket_rx = tokio_io_timeout::TimeoutReader::new(socket_rx);
        socket_rx.set_timeout(Some(config.socket_read_timeout));
        let mut socket_tx = tokio_io_timeout::TimeoutWriter::new(socket_tx);
        socket_tx.set_timeout(Some(config.socket_send_timeout));

        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rng = rand::thread_rng();
        let mut initial_buffer: Vec<u8> = (0..160).map(|_| rng.gen()).collect();

        let mut cipher_receive = Aes256Ctr::new(
            generic_array::GenericArray::from_slice(&initial_buffer[0..32]),
            generic_array::GenericArray::from_slice(&initial_buffer[64..80]),
        );
        let mut cipher_send = Aes256Ctr::new(
            generic_array::GenericArray::from_slice(&initial_buffer[32..64]),
            generic_array::GenericArray::from_slice(&initial_buffer[80..96]),
        );

        let client = Arc::new(AdnlTcpClient {
            ping_cache: Arc::new(Default::default()),
            queries_cache: Arc::new(Default::default()),
            sender: tx,
            has_broken: Arc::new(AtomicBool::new(false)),
        });

        let has_broken = client.has_broken.clone();
        tokio::spawn(async move {
            let has_broken = has_broken.clone();
            while let Some(mut packet) = rx.recv().await {
                if packet.should_encrypt {
                    let packet = &mut packet.data;

                    let len = packet.len();

                    packet.reserve(len + 68);
                    packet.resize(len + 36, 0);
                    packet[..].copy_within(..len, 36);
                    packet[..4].copy_from_slice(&((len + 64) as u32).to_le_bytes());

                    let nonce: [u8; 32] = rand::thread_rng().gen();
                    packet[4..36].copy_from_slice(&nonce);

                    packet.extend_from_slice(sha2::Sha256::digest(&packet[4..]).as_slice());
                    cipher_send.apply_keystream(packet);
                }

                if let Err(e) = socket_tx.get_mut().write_all(&packet.data).await {
                    tracing::error!("Failed to send packet: {e}");
                    has_broken.store(true, Ordering::Release);
                    return;
                }
            }
        });

        tokio::spawn({
            let client = Arc::downgrade(&client);
            async move {
                loop {
                    let client = match client.upgrade() {
                        Some(client) => client,
                        None => return,
                    };
                    if client.has_broken.load(Ordering::Acquire) {
                        return;
                    }

                    let mut length = [0; 4];
                    if let Err(e) = socket_rx.get_mut().read_exact(&mut length).await {
                        tracing::error!("Failed to read packet length: {e}");
                        client.has_broken.store(true, Ordering::Release);
                        return;
                    }
                    cipher_receive.apply_keystream(&mut length);

                    let length = u32::from_le_bytes(length) as usize;
                    if length < 64 {
                        tracing::warn!("Too small size for ADNL packet: {length}");
                        continue;
                    }

                    let mut buffer = vec![0; length];
                    if let Err(e) = socket_rx.get_mut().read_exact(&mut buffer).await {
                        tracing::error!("Failed to read buffer of length {length}: {e}");
                        client.has_broken.store(true, Ordering::Release);
                        return;
                    }
                    cipher_receive.apply_keystream(&mut buffer);

                    if !sha2::Sha256::digest(&buffer[..length - 32])
                        .as_slice()
                        .eq(&buffer[length - 32..length])
                    {
                        tracing::error!("Invalid ADNL packet checksum");
                        continue;
                    }

                    buffer.truncate(length - 32);
                    buffer.drain(..32);

                    if buffer.is_empty() {
                        continue;
                    }

                    let data = match deserialize(&buffer) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!("Got invalid ADNL packet: {e}");
                            continue;
                        }
                    };

                    match data.downcast::<ton::adnl::Message>() {
                        Ok(ton::adnl::Message::Adnl_Message_Answer(message)) => {
                            match client
                                .queries_cache
                                .update_query(message.query_id.0, Some(&message.answer))
                                .await
                            {
                                Ok(true) => {}
                                _ => tracing::error!("Failed to resolve query"),
                            }
                        }
                        Ok(_) => tracing::error!("Got unknown ADNL message"),
                        Err(message) => match message.downcast::<ton::tcp::Pong>() {
                            Ok(pong) => {
                                let _ = client
                                    .ping_cache
                                    .update_query(*pong.random_id(), true)
                                    .await;
                            }
                            _ => tracing::error!("Got unknown TL response object"),
                        },
                    }
                }
            }
        });

        tracing::info!("Created connection. Sending init packet...");

        build_handshake_packet(&peer_id, &peer_id_full, &mut initial_buffer, None)?;
        let _ = client.sender.send(PacketToSend {
            data: initial_buffer,
            should_encrypt: false,
        });

        Ok(client)
    }
}

fn build_query(query: &TLObject) -> (QueryId, ton::adnl::Message) {
    let query_id: QueryId = rand::thread_rng().gen();
    let query = serialize(query);

    (
        query_id,
        ton::adnl::message::message::Query {
            query_id: ton::int256(query_id),
            query: ton::bytes(query),
        }
        .into_boxed(),
    )
}

struct PacketToSend {
    data: Vec<u8>,
    should_encrypt: bool,
}

#[derive(thiserror::Error, Debug)]
enum AdnlTcpClientError {
    #[error("Query timeout")]
    QueryTimeout,
    #[error("Socket is closed")]
    SocketClosed,
}
