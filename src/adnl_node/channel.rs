use std::convert::TryInto;
use std::sync::atomic::{AtomicI32, Ordering};

use aes::cipher::StreamCipher;
use anyhow::Result;
use sha2::Digest;
use ton_api::ton;

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

    pub fn encrypt(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let checksum: [u8; 32] = sha2::Sha256::digest(buffer.as_slice()).into();

        let len = buffer.len();
        buffer.resize(len + 64, 0);
        buffer.copy_within(..len, 64);
        buffer[..32].copy_from_slice(&self.channel_out.id);
        buffer[32..64].copy_from_slice(&checksum);

        process_channel_data(buffer, &self.channel_out.secret);
        Ok(())
    }
}

struct ChannelSide {
    id: AdnlChannelId,
    secret: [u8; 32],
}

impl ChannelSide {
    fn from_secret(secret: [u8; 32]) -> Result<Self> {
        Ok(Self {
            id: compute_channel_id(secret)?,
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
        )
        .unwrap();

        let channel21 = AdnlChannel::new(
            peer2_id,
            peer1_id,
            peer2_channel_key.private_key_part(),
            peer1_channel_key.public_key().as_bytes(),
        )
        .unwrap();

        let message = "Hello world!";

        // Send 1 to 2
        {
            let mut packet = message.as_bytes().to_vec();
            channel12.encrypt(&mut packet).unwrap();

            let mut received_packet = PacketView::from(packet.as_mut_slice());
            channel21.decrypt(&mut received_packet).unwrap();

            let received_message = String::from_utf8(received_packet.as_slice().to_vec()).unwrap();
            assert_eq!(received_message, message);
        }

        // Send 2 to 1
        {
            let mut packet = message.as_bytes().to_vec();
            channel21.encrypt(&mut packet).unwrap();

            let mut received_packet = PacketView::from(packet.as_mut_slice());
            channel12.decrypt(&mut received_packet).unwrap();

            let received_message = String::from_utf8(received_packet.as_slice().to_vec()).unwrap();
            assert_eq!(received_message, message);
        }
    }
}
