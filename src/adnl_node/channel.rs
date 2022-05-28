use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aes::cipher::StreamCipher;
use anyhow::Result;
use everscale_crypto::ed25519;

use crate::utils::*;

const CHANNEL_RESET_TIMEOUT: u32 = 30; // Seconds

pub struct AdnlChannel {
    ready: AtomicBool,
    channel_out: ChannelSide,
    channel_in: ChannelSide,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    /// Public key of the keypair from the peer side
    peer_channel_public_key: ed25519::PublicKey,
    peer_channel_date: u32,
    drop: AtomicU32,
}

impl AdnlChannel {
    pub fn new(
        local_id: AdnlNodeIdShort,
        peer_id: AdnlNodeIdShort,
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

    pub fn is_still_valid(
        &self,
        peer_channel_public_key: &ed25519::PublicKey,
        peer_channel_date: u32,
    ) -> bool {
        &self.peer_channel_public_key == peer_channel_public_key
            || self.peer_channel_date >= peer_channel_date
    }

    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release)
    }

    #[inline(always)]
    pub fn peer_channel_public_key(&self) -> &ed25519::PublicKey {
        &self.peer_channel_public_key
    }

    #[inline(always)]
    pub fn peer_channel_date(&self) -> u32 {
        self.peer_channel_date
    }

    #[inline(always)]
    pub fn priority_channel_in_id(&self) -> &AdnlChannelId {
        &self.channel_in.priority.id
    }

    #[inline(always)]
    pub fn ordinary_channel_in_id(&self) -> &AdnlChannelId {
        &self.channel_in.ordinary.id
    }

    #[inline(always)]
    pub fn local_id(&self) -> &AdnlNodeIdShort {
        &self.local_id
    }

    #[inline(always)]
    pub fn peer_id(&self) -> &AdnlNodeIdShort {
        &self.peer_id
    }

    pub fn update_drop_timeout(&self, now: u32) -> u32 {
        self.drop
            .compare_exchange(
                0,
                now + CHANNEL_RESET_TIMEOUT,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .unwrap_or_else(|was| was)
    }

    pub fn reset_drop_timeout(&self) {
        self.drop.store(0, Ordering::Release);
    }

    /// Decrypts data from the channel. Returns the version of the ADNL version
    pub fn decrypt(&self, buffer: &mut PacketView, priority: bool) -> Result<Option<u16>> {
        if buffer.len() < 64 {
            return Err(AdnlChannelError::ChannelMessageIsTooShort(buffer.len()).into());
        }

        let shared_secret = if priority {
            &self.channel_in.priority.secret
        } else {
            &self.channel_in.ordinary.secret
        };

        // NOTE: macros is used here to avoid useless bound checks, saving the `.len()` context
        macro_rules! process {
            ($buffer:ident, $shared_secret:ident, $version:expr, $start:literal .. $end:literal) => {
                build_packet_cipher($shared_secret, &$buffer[$start..$end].try_into().unwrap())
                    .apply_keystream(&mut $buffer[$end..]);

                // Check checksum
                if compute_packet_data_hash($version, &$buffer[$end..]).as_slice()
                    != &$buffer[$start..$end]
                {
                    return Err(AdnlChannelError::InvalidChannelMessageChecksum.into());
                }

                // Leave only data in the buffer
                $buffer.remove_prefix($end);
            };
        }

        if buffer.len() > 68 {
            if let Some(version) = decode_version((&buffer[..68]).try_into().unwrap()) {
                process!(buffer, shared_secret, Some(version), 36..68);
                return Ok(Some(version));
            }
        }

        process!(buffer, shared_secret, None, 32..64);
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

        let prefix_len = 64 + if version.is_some() { 4 } else { 0 };
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
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ChannelCreationContext {
    CreateChannel,
    ConfirmChannel,
}

impl std::fmt::Display for ChannelCreationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateChannel => f.write_str("creation"),
            Self::ConfirmChannel => f.write_str("confirmation"),
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
    let key = everscale_crypto::tl::PublicKey::Aes { key };
    tl_proto::hash(key)
}

fn decode_version(prefix: &[u8; 68]) -> Option<u16> {
    let mut xor: [u8; 4] = prefix[32..36].try_into().unwrap();
    for (i, byte) in prefix[..32].iter().enumerate() {
        xor[i % 4] ^= *byte;
    }
    for (i, byte) in prefix[36..].iter().enumerate() {
        xor[i % 4] ^= *byte;
    }
    if xor[0] == xor[2] && xor[1] == xor[3] {
        Some(u16::from_be_bytes(xor[..2].try_into().unwrap()))
    } else {
        None
    }
}

#[derive(thiserror::Error, Debug)]
enum AdnlChannelError {
    #[error("Channel message is too short: {}", .0)]
    ChannelMessageIsTooShort(usize),
    #[error("Invalid channel message checksum")]
    InvalidChannelMessageChecksum,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let peer1_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
        let (_, peer1_id) = peer1_key.compute_node_ids();
        let peer1_channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());

        let peer2_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
        let (_, peer2_id) = peer2_key.compute_node_ids();
        let peer2_channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());

        let channel12 = AdnlChannel::new(
            peer1_id,
            peer2_id,
            &peer1_channel_key,
            peer2_channel_key.public_key,
            now(),
            ChannelCreationContext::CreateChannel,
        );

        let channel21 = AdnlChannel::new(
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

                let mut received_packet = PacketView::from(packet.as_mut_slice());
                let parsed_version = channel21.decrypt(&mut received_packet, false).unwrap();
                assert_eq!(parsed_version, version);

                assert_eq!(received_packet.as_slice(), message);
            }

            // Send 2 to 1
            {
                let mut packet = message.to_vec();
                channel21.encrypt(&mut packet, true, version);

                let mut received_packet = PacketView::from(packet.as_mut_slice());
                let parsed_version = channel12.decrypt(&mut received_packet, true).unwrap();
                assert_eq!(parsed_version, version);

                assert_eq!(received_packet.as_slice(), message);
            }
        }
    }
}
