use std::convert::TryInto;
use std::sync::Arc;

use aes::cipher::StreamCipher;
use anyhow::Result;
use dashmap::DashMap;
use sha2::Digest;

use super::node_id::*;
use super::packet_view::*;
use super::{build_packet_cipher, compute_shared_secret};

pub fn build_handshake_packet(
    peer_id: &AdnlNodeIdShort,
    peer_id_full: &AdnlNodeIdFull,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    // Create temp local key
    let temp_private_key = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng());
    let temp_public_key = ed25519_dalek::PublicKey::from(&temp_private_key);

    // Prepare packet
    let hash = sha2::Sha256::digest(buffer.as_slice());
    let checksum: &[u8; 32] = hash.as_slice().try_into().unwrap();

    let length = buffer.len();
    buffer.resize(length + 96, 0);
    buffer.copy_within(..length, 96);

    buffer[..32].copy_from_slice(peer_id.as_slice());
    buffer[32..64].copy_from_slice(temp_public_key.as_bytes());
    buffer[64..96].copy_from_slice(checksum);

    // Encrypt packet data
    let temp_private_key_part = ed25519_dalek::ExpandedSecretKey::from(&temp_private_key)
        .to_bytes()[0..32]
        .try_into()
        .unwrap();

    let shared_secret =
        compute_shared_secret(&temp_private_key_part, peer_id_full.public_key().as_bytes())?;
    build_packet_cipher(&shared_secret, checksum).apply_keystream(&mut buffer[96..]);

    // Done
    Ok(())
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
pub fn parse_handshake_packet(
    keys: &DashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>>,
    buffer: &mut PacketView<'_>,
    data_length: Option<usize>,
) -> Result<Option<AdnlNodeIdShort>> {
    if buffer.len() < 96 + data_length.unwrap_or_default() {
        return Err(HandshakeError::BadHandshakePacketLength.into());
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
            let shared_secret = compute_shared_secret(
                key.value().private_key_part(),
                buffer[32..64].try_into().unwrap(),
            )?;

            build_packet_cipher(&shared_secret, &buffer[64..96].try_into().unwrap())
                .apply_keystream(&mut buffer[data_range]);

            // Check checksum
            if !sha2::Sha256::digest(&buffer[96..])
                .as_slice()
                .eq(&buffer[64..96])
            {
                return Err(HandshakeError::BadHandshakePacketChecksum.into());
            }

            // Leave only data in buffer
            buffer.remove_prefix(96);
            return Ok(Some(*key.key()));
        }
    }

    // No local keys found
    Ok(None)
}

#[derive(thiserror::Error, Debug)]
enum HandshakeError {
    #[error("Bad handshake packet length")]
    BadHandshakePacketLength,
    #[error("Bad handshake packet checksum")]
    BadHandshakePacketChecksum,
}
