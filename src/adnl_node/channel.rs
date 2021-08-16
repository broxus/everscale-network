use std::convert::TryInto;
use std::sync::atomic::{AtomicI32, Ordering};

use aes::cipher::StreamCipher;
use anyhow::Result;
use sha2::Digest;

use crate::proto::*;
use crate::utils::*;

const CHANNEL_RESET_TIMEOUT: i32 = 30; // Seconds

pub struct AdnlChannel {
    channel_out: ChannelSide,
    channel_in: ChannelSide,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    drop: AtomicI32,
}

impl AdnlChannel {
    pub fn new(
        local_id: AdnlNodeIdShort,
        peer_id: AdnlNodeIdShort,
        channel_private_key_part: &[u8; 32],
        channel_public_key: &[u8; 32],
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
            channel_out: ChannelSide::from_secret(out_secret)?,
            channel_in: ChannelSide::from_secret(in_secret)?,
            local_id,
            peer_id,
            drop: Default::default(),
        })
    }

    pub fn channel_in_id(&self) -> &AdnlChannelId {
        &self.channel_in.id
    }

    #[allow(dead_code)]
    pub fn channel_out_id(&self) -> &AdnlChannelId {
        &self.channel_out.id
    }

    pub fn local_id(&self) -> &AdnlNodeIdShort {
        &self.local_id
    }

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

    pub fn decrypt(&self, buffer: &mut PacketView) -> Result<()> {
        if buffer.len() < 64 {
            return Err(AdnlChannelError::ChannelMessageIsTooShort(buffer.len()).into());
        }

        process_channel_data(buffer.as_mut_slice(), &self.channel_in.secret);

        if sha2::Sha256::digest(&buffer[64..]).as_slice() != &buffer[32..64] {
            return Err(AdnlChannelError::InvalidChannelMessageChecksum.into());
        }

        buffer.remove_prefix(64);
        Ok(())
    }

    pub fn encrypt<T>(&self, data: T) -> Result<Vec<u8>>
    where
        T: WriteToPacket,
    {
        // Create buffer
        let len = data.max_size_hint();
        let mut result = Vec::with_capacity(64 + len);

        // Fill packet header and data
        result.extend_from_slice(&self.channel_out.id);
        result.resize(64, 0); // empty checksum
        data.write_to(&mut result)?;

        // Fill packet checksum
        let checksum: [u8; 32] = sha2::Sha256::digest(&result[64..]).into();
        result[32..64].copy_from_slice(&checksum);

        // Encrypt packet data
        process_channel_data(&mut result, &self.channel_out.secret);

        // Done
        Ok(result)
    }
}

struct ChannelSide {
    id: AdnlChannelId,
    secret: [u8; 32],
}

impl ChannelSide {
    fn from_secret(secret: [u8; 32]) -> Result<Self> {
        Ok(Self {
            id: compute_channel_id(&secret)?,
            secret,
        })
    }
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

fn compute_channel_id(secret: &[u8; 32]) -> Result<AdnlChannelId> {
    hash(PublicKeyView::Aes { key: secret })
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
