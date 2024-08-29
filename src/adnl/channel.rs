use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aes::cipher::{StreamCipher, StreamCipherSeek};
use everscale_crypto::ed25519;

use super::encryption::*;
use super::node_id::NodeIdShort;
use super::packet_view::*;

/// ADNL channel state
pub struct Channel {
    /// Whether channel was confirmed by both sides
    ready: AtomicBool,
    /// Id and secret, used to encrypt outgoing messages
    channel_out: ChannelSide,
    /// Id and secret, used to decrypt incoming messages
    channel_in: ChannelSide,
    /// Short id of the local peer for which this channel is established
    local_id: NodeIdShort,
    /// Short id of the remote peer for which this channel is established
    peer_id: NodeIdShort,
    /// Public key of the keypair from the peer's side
    peer_channel_public_key: ed25519::PublicKey,
    /// Channel creation time
    peer_channel_date: u32,
    /// Channel drop timestamp
    drop: AtomicU32,
}

impl Channel {
    /// Creates new channel state between `local_id` and `peer_id`
    pub fn new(
        local_id: NodeIdShort,
        peer_id: NodeIdShort,
        channel_key: &ed25519::KeyPair,
        peer_channel_public_key: ed25519::PublicKey,
        peer_channel_date: u32,
        context: ChannelCreationContext,
    ) -> Self {
        let shared_secret = channel_key.compute_shared_secret(&peer_channel_public_key);
        let mut reversed_secret = shared_secret;
        reversed_secret.reverse();

        let (in_secret, out_secret) = match local_id.cmp(&peer_id) {
            std::cmp::Ordering::Less => (shared_secret, reversed_secret),
            std::cmp::Ordering::Equal => (shared_secret, shared_secret),
            std::cmp::Ordering::Greater => (reversed_secret, shared_secret),
        };

        Self {
            // Confirmed channel instantly becomes ready because other side already has it
            ready: AtomicBool::new(context == ChannelCreationContext::ConfirmChannel),
            channel_out: ChannelSide::from_secret(out_secret),
            channel_in: ChannelSide::from_secret(in_secret),
            local_id,
            peer_id,
            peer_channel_public_key,
            peer_channel_date,
            drop: Default::default(),
        }
    }

    /// Checks whether channel it initialized by the given key and date
    pub fn is_still_valid(
        &self,
        peer_channel_public_key: &ed25519::PublicKey,
        peer_channel_date: u32,
    ) -> bool {
        &self.peer_channel_public_key == peer_channel_public_key
            || self.peer_channel_date >= peer_channel_date
    }

    /// Whether channel can be used for sending messages
    #[inline(always)]
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Sets channel ready
    #[inline(always)]
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release)
    }

    /// Public key of the keypair from the peer's side
    #[inline(always)]
    pub fn peer_channel_public_key(&self) -> &ed25519::PublicKey {
        &self.peer_channel_public_key
    }

    /// Channel creation time
    #[inline(always)]
    pub fn peer_channel_date(&self) -> u32 {
        self.peer_channel_date
    }

    /// Local channel id (priority)
    #[inline(always)]
    pub fn priority_channel_in_id(&self) -> &AdnlChannelId {
        &self.channel_in.priority.id
    }

    /// Local channel id (ordinary)
    #[inline(always)]
    pub fn ordinary_channel_in_id(&self) -> &AdnlChannelId {
        &self.channel_in.ordinary.id
    }

    /// Short id of the local peer for which this channel is established
    #[inline(always)]
    pub fn local_id(&self) -> &NodeIdShort {
        &self.local_id
    }

    /// Short id of the remote peer for which this channel is established
    #[inline(always)]
    pub fn peer_id(&self) -> &NodeIdShort {
        &self.peer_id
    }

    /// Sets channel drop timestamp if it wasn't set before.
    /// Returns whether channel should be dropped
    pub fn update_drop_timeout(&self, now: u32, timeout: u32) -> bool {
        let drop_timestamp = self
            .drop
            .compare_exchange(0, now + timeout, Ordering::Acquire, Ordering::Relaxed)
            .unwrap_or_else(std::convert::identity);

        drop_timestamp > 0 && drop_timestamp < now
    }

    /// Resets channel drop timestamp
    #[inline(always)]
    pub fn reset_drop_timeout(&self) {
        self.drop.store(0, Ordering::Release);
    }

    /// Decrypts data from the channel. Returns the version of the ADNL
    pub fn decrypt(
        &self,
        buffer: &mut PacketView,
        priority: bool,
    ) -> Result<Option<u16>, AdnlChannelError> {
        // Ordinary data ranges
        const DATA_START: usize = 64;
        const CHECKSUM_RANGE: std::ops::Range<usize> = 32..DATA_START;
        const DATA_RANGE: std::ops::RangeFrom<usize> = DATA_START..;

        // Data ranges for packets with ADNL version
        const EXT_DATA_START: usize = 68;
        const EXT_CHECKSUM_RANGE: std::ops::Range<usize> = 36..EXT_DATA_START;
        const EXT_DATA_RANGE: std::ops::RangeFrom<usize> = EXT_DATA_START..;

        if buffer.len() < DATA_START {
            return Err(AdnlChannelError::ChannelMessageIsTooShort(buffer.len()));
        }

        let shared_secret = if priority {
            &self.channel_in.priority.secret
        } else {
            &self.channel_in.ordinary.secret
        };

        if buffer.len() > EXT_DATA_START {
            if let Some(version) =
                decode_version::<EXT_DATA_START>((&buffer[..EXT_DATA_START]).try_into().unwrap())
            {
                // Build cipher
                let mut cipher = build_packet_cipher(
                    shared_secret,
                    &buffer[EXT_CHECKSUM_RANGE].try_into().unwrap(),
                );

                // Decode data
                cipher.apply_keystream(&mut buffer[EXT_DATA_RANGE]);

                // If hash is ok
                if compute_packet_data_hash(Some(version), &buffer[EXT_DATA_RANGE]).as_slice()
                    == &buffer[EXT_CHECKSUM_RANGE]
                {
                    // Leave only data in the buffer and return version
                    buffer.remove_prefix(EXT_DATA_START);
                    return Ok(Some(version));
                }

                // Otherwise restore data
                cipher.seek(0);
                cipher.apply_keystream(&mut buffer[EXT_DATA_RANGE]);
            }
        }

        // Decode data
        build_packet_cipher(shared_secret, &buffer[CHECKSUM_RANGE].try_into().unwrap())
            .apply_keystream(&mut buffer[DATA_RANGE]);

        // Check checksum
        if compute_packet_data_hash(None, &buffer[DATA_RANGE]).as_slice() != &buffer[CHECKSUM_RANGE]
        {
            return Err(AdnlChannelError::InvalidChannelMessageChecksum);
        }

        // Leave only data in the buffer
        buffer.remove_prefix(DATA_START);

        Ok(None)
    }

    /// Modifies `buffer` in-place to contain the channel packet
    pub fn encrypt(&self, buffer: &mut Vec<u8>, priority: bool, version: Option<u16>) {
        let checksum: [u8; 32] = compute_packet_data_hash(version, buffer.as_slice());
        let channel_out = if priority {
            &self.channel_out.priority
        } else {
            &self.channel_out.ordinary
        };

        let prefix_len = Self::compute_prefix_len(version);
        let buffer_len = buffer.len();
        buffer.resize(prefix_len + buffer_len, 0);
        buffer.copy_within(..buffer_len, prefix_len);

        buffer[..32].copy_from_slice(&channel_out.id);

        match version {
            Some(version) => {
                let mut xor = [
                    (version >> 8) as u8,
                    version as u8,
                    (version >> 8) as u8,
                    version as u8,
                ];
                for (i, byte) in buffer[..32].iter().enumerate() {
                    xor[i % 4] ^= *byte;
                }
                for (i, byte) in checksum.iter().enumerate() {
                    xor[i % 4] ^= *byte;
                }
                buffer[32..36].copy_from_slice(&xor);
                buffer[36..68].copy_from_slice(&checksum);
                build_packet_cipher(&channel_out.secret, &checksum)
                    .apply_keystream(&mut buffer[68..]);
            }
            None => {
                buffer[32..64].copy_from_slice(&checksum);
                build_packet_cipher(&channel_out.secret, &checksum)
                    .apply_keystream(&mut buffer[64..]);
            }
        }
    }

    #[inline(always)]
    pub fn compute_prefix_len(version: Option<u16>) -> usize {
        64 + if version.is_some() { 4 } else { 0 }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ChannelCreationContext {
    CreateChannel,
    ConfirmChannel,
}

impl std::fmt::Display for ChannelCreationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateChannel => f.write_str("created"),
            Self::ConfirmChannel => f.write_str("confirmed"),
        }
    }
}

struct ChannelSide {
    ordinary: SubChannelSide,
    priority: SubChannelSide,
}

impl ChannelSide {
    fn from_secret(secret: [u8; 32]) -> Self {
        let priority_secret = build_priority_secret(secret);
        Self {
            ordinary: SubChannelSide {
                id: compute_channel_id(&secret),
                secret,
            },
            priority: SubChannelSide {
                id: compute_channel_id(&priority_secret),
                secret: priority_secret,
            },
        }
    }
}

struct SubChannelSide {
    id: AdnlChannelId,
    secret: [u8; 32],
}

fn build_priority_secret(ordinary_secret: [u8; 32]) -> [u8; 32] {
    [
        ordinary_secret[1],
        ordinary_secret[0],
        ordinary_secret[3],
        ordinary_secret[2],
        ordinary_secret[5],
        ordinary_secret[4],
        ordinary_secret[7],
        ordinary_secret[6],
        ordinary_secret[9],
        ordinary_secret[8],
        ordinary_secret[11],
        ordinary_secret[10],
        ordinary_secret[13],
        ordinary_secret[12],
        ordinary_secret[15],
        ordinary_secret[14],
        ordinary_secret[17],
        ordinary_secret[16],
        ordinary_secret[19],
        ordinary_secret[18],
        ordinary_secret[21],
        ordinary_secret[20],
        ordinary_secret[23],
        ordinary_secret[22],
        ordinary_secret[25],
        ordinary_secret[24],
        ordinary_secret[27],
        ordinary_secret[26],
        ordinary_secret[29],
        ordinary_secret[28],
        ordinary_secret[31],
        ordinary_secret[30],
    ]
}

pub type AdnlChannelId = [u8; 32];

#[inline(always)]
fn compute_channel_id(key: &[u8; 32]) -> AdnlChannelId {
    tl_proto::hash(everscale_crypto::tl::PublicKey::Aes { key })
}

#[derive(thiserror::Error, Debug)]
pub enum AdnlChannelError {
    #[error("Channel message is too short: {}", .0)]
    ChannelMessageIsTooShort(usize),
    #[error("Invalid channel message checksum")]
    InvalidChannelMessageChecksum,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::adnl::ComputeNodeIds;
    use crate::util::now;

    #[test]
    fn test_encrypt_decrypt() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));

        let peer1_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
        let (_, peer1_id) = peer1_key.compute_node_ids();
        let peer1_channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());

        let peer2_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
        let (_, peer2_id) = peer2_key.compute_node_ids();
        let peer2_channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());

        let channel12 = Channel::new(
            peer1_id,
            peer2_id,
            &peer1_channel_key,
            peer2_channel_key.public_key,
            now(),
            ChannelCreationContext::CreateChannel,
        );

        let channel21 = Channel::new(
            peer2_id,
            peer1_id,
            &peer2_channel_key,
            peer1_channel_key.public_key,
            now(),
            ChannelCreationContext::CreateChannel,
        );

        let message = b"Hello world!";

        for version in [None, Some(0)] {
            // Send 1 to 2
            {
                let mut packet = message.to_vec();
                channel12.encrypt(&mut packet, false, version);

                let mut received_packet = PacketView::new(addr, packet.as_mut_slice());
                let parsed_version = channel21.decrypt(&mut received_packet, false).unwrap();
                assert_eq!(parsed_version, version);

                assert_eq!(received_packet.as_slice(), message);
            }

            // Send 2 to 1
            {
                let mut packet = message.to_vec();
                channel21.encrypt(&mut packet, true, version);

                let mut received_packet = PacketView::new(addr, packet.as_mut_slice());
                let parsed_version = channel12.decrypt(&mut received_packet, true).unwrap();
                assert_eq!(parsed_version, version);

                assert_eq!(received_packet.as_slice(), message);
            }
        }
    }
}
