use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use aes::cipher::StreamCipher;
use anyhow::Result;
use sha2::Digest;
use ton_api::ton;

use crate::utils::*;

const CHANNEL_RESET_TIMEOUT: i32 = 30; // Seconds

pub struct AdnlChannel {
    ready: AtomicBool,
    channel_out: ChannelSide,
    channel_in: ChannelSide,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    peer_channel_public_key: [u8; 32],
    peer_channel_date: i32,
    drop: AtomicI32,
}

impl AdnlChannel {
    pub fn new(
        local_id: AdnlNodeIdShort,
        peer_id: AdnlNodeIdShort,
        channel_private_key_part: &[u8; 32],
        channel_public_key: &[u8; 32],
        peer_channel_date: i32,
        context: ChannelCreationContext,
    ) -> Result<Self> {
        let shared_secret = compute_shared_secret(channel_private_key_part, channel_public_key)?;
        let mut reversed_secret = shared_secret;
        reversed_secret.reverse();

        let (in_secret, out_secret) = match local_id.cmp(&peer_id) {
            std::cmp::Ordering::Less => (shared_secret, reversed_secret),
            std::cmp::Ordering::Equal => (shared_secret, shared_secret),
            std::cmp::Ordering::Greater => (reversed_secret, shared_secret),
        };

        Ok(Self {
            ready: AtomicBool::new(context == ChannelCreationContext::ConfirmChannel),
            channel_out: ChannelSide::from_secret(out_secret)?,
            channel_in: ChannelSide::from_secret(in_secret)?,
            local_id,
            peer_id,
            peer_channel_public_key: *channel_public_key,
            peer_channel_date,
            drop: Default::default(),
        })
    }

    pub fn is_still_valid(
        &self,
        peer_channel_public_key: &[u8; 32],
        peer_channel_date: i32,
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
    pub fn peer_channel_public_key(&self) -> &[u8; 32] {
        &self.peer_channel_public_key
    }

    #[inline(always)]
    pub fn peer_channel_date(&self) -> i32 {
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

    pub fn update_drop_timeout(&self, now: i32) -> i32 {
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

    pub fn decrypt(&self, buffer: &mut PacketView, priority: bool) -> Result<()> {
        if buffer.len() < 64 {
            return Err(AdnlChannelError::ChannelMessageIsTooShort(buffer.len()).into());
        }

        process_channel_data(
            buffer.as_mut_slice(),
            if priority {
                &self.channel_in.priority.secret
            } else {
                &self.channel_in.ordinary.secret
            },
        );

        if sha2::Sha256::digest(&buffer[64..]).as_slice() != &buffer[32..64] {
            return Err(AdnlChannelError::InvalidChannelMessageChecksum.into());
        }

        buffer.remove_prefix(64);
        Ok(())
    }

    pub fn encrypt(&self, buffer: &mut Vec<u8>, priority: bool) -> Result<()> {
        let checksum: [u8; 32] = sha2::Sha256::digest(buffer.as_slice()).into();

        let channel_out = if priority {
            &self.channel_out.priority
        } else {
            &self.channel_out.ordinary
        };

        let len = buffer.len();
        buffer.resize(len + 64, 0);
        buffer.copy_within(..len, 64);
        buffer[..32].copy_from_slice(&channel_out.id);
        buffer[32..64].copy_from_slice(&checksum);

        process_channel_data(buffer, &channel_out.secret);
        Ok(())
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
    fn from_secret(secret: [u8; 32]) -> Result<Self> {
        let priority_secret = build_priority_secret(secret);
        Ok(Self {
            ordinary: SubChannelSide {
                id: compute_channel_id(secret)?,
                secret,
            },
            priority: SubChannelSide {
                id: compute_channel_id(priority_secret)?,
                secret: priority_secret,
            },
        })
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

pub struct ChannelKey {
    public_key: ed25519_dalek::PublicKey,
    private_key_part: [u8; 32],
}

impl ChannelKey {
    pub fn generate() -> Self {
        let private_key = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng());
        let public_key = ed25519_dalek::PublicKey::from(&private_key);
        let private_key = ed25519_dalek::ExpandedSecretKey::from(&private_key);
        let private_key_part = private_key.to_bytes()[0..32].try_into().unwrap();

        Self {
            public_key,
            private_key_part,
        }
    }

    pub fn public_key(&self) -> &ed25519_dalek::PublicKey {
        &self.public_key
    }

    pub fn private_key_part(&self) -> &[u8; 32] {
        &self.private_key_part
    }
}

pub type AdnlChannelId = [u8; 32];

fn compute_channel_id(secret: [u8; 32]) -> Result<AdnlChannelId> {
    hash(ton::pub_::publickey::Aes {
        key: ton::int256(secret),
    })
}

fn process_channel_data(buffer: &mut [u8], secret: &[u8; 32]) {
    build_packet_cipher(secret, buffer[32..64].try_into().unwrap())
        .apply_keystream(&mut buffer[64..])
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
        let peer1_key = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng());
        let peer1_id = peer1_key.compute_node_ids().unwrap().1;
        let peer1_channel_key = ChannelKey::generate();

        let peer2_key = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng());
        let peer2_id = peer2_key.compute_node_ids().unwrap().1;
        let peer2_channel_key = ChannelKey::generate();

        let channel12 = AdnlChannel::new(
            peer1_id,
            peer2_id,
            peer1_channel_key.private_key_part(),
            peer2_channel_key.public_key().as_bytes(),
            now(),
            ChannelCreationContext::CreateChannel,
        )
        .unwrap();

        let channel21 = AdnlChannel::new(
            peer2_id,
            peer1_id,
            peer2_channel_key.private_key_part(),
            peer1_channel_key.public_key().as_bytes(),
            now(),
            ChannelCreationContext::CreateChannel,
        )
        .unwrap();

        let message = b"Hello world!";

        // Send 1 to 2
        {
            let mut packet = message.to_vec();
            channel12.encrypt(&mut packet, false).unwrap();

            let mut received_packet = PacketView::from(packet.as_mut_slice());
            channel21.decrypt(&mut received_packet, false).unwrap();

            assert_eq!(received_packet.as_slice(), message);
        }

        // Send 2 to 1
        {
            let mut packet = message.to_vec();
            channel21.encrypt(&mut packet, true).unwrap();

            let mut received_packet = PacketView::from(packet.as_mut_slice());
            channel12.decrypt(&mut received_packet, true).unwrap();

            assert_eq!(received_packet.as_slice(), message);
        }
    }
}
