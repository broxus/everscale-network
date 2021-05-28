use anyhow::Result;
use ton_api::ton;

use crate::node_id::*;
use crate::utils::*;

pub struct AdnlChannel {
    channel_out: ChannelSide,
    channel_in: ChannelSide,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
}

impl AdnlChannel {
    pub fn new(
        private_key: &ed25519_dalek::SecretKey,
        local_id: AdnlNodeIdShort,
        peer_id: AdnlNodeIdShort,
    ) -> Result<Self> {
        let public_key = ed25519_dalek::PublicKey::from(private_key);
        let shared_secret = compute_shared_secret(private_key.as_bytes(), public_key.as_bytes())?;
        let mut reversed_secret = shared_secret;
        reversed_secret.reverse();

        let (in_secret, out_secret) = match local_id.cmp(&peer_id) {
            std::cmp::Ordering::Less => (shared_secret, reversed_secret),
            std::cmp::Ordering::Equal => (shared_secret, shared_secret),
            std::cmp::Ordering::Greater => (reversed_secret, shared_secret),
        };

        Ok(Self {
            channel_out: ChannelSide::from_secret(in_secret)?,
            channel_in: ChannelSide::from_secret(out_secret)?,
            local_id,
            peer_id,
        })
    }

    pub fn channel_in_id(&self) -> &ChannelId {
        &self.channel_in.id
    }

    pub fn channel_out_id(&self) -> &ChannelId {
        &self.channel_out.id
    }
}

struct ChannelSide {
    id: ChannelId,
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

type ChannelId = [u8; 32];

fn compute_channel_id(secret: [u8; 32]) -> Result<ChannelId> {
    hash(ton::pub_::publickey::Aes {
        key: ton::int256(secret),
    })
}
