use std::convert::TryInto;
use std::sync::Arc;

use aes::cipher::{StreamCipher, StreamCipherSeek};
use everscale_crypto::ed25519;

use super::encryption::*;
use super::keystore::Key;
use super::node_id::{NodeIdFull, NodeIdShort};
use super::packet_view::*;
use crate::utils::*;

/// Modifies `buffer` in-place to contain the handshake packet
pub fn build_handshake_packet(
    peer_id: &NodeIdShort,
    peer_id_full: &NodeIdFull,
    buffer: &mut Vec<u8>,
    version: Option<u16>,
) {
    // Create temp local key
    let temp_private_key = ed25519::SecretKey::generate(&mut rand::thread_rng());
    let temp_private_key = ed25519::ExpandedSecretKey::from(&temp_private_key);
    let temp_public_key = ed25519::PublicKey::from(&temp_private_key);

    let shared_secret = temp_private_key.compute_shared_secret(peer_id_full.public_key());

    // Prepare packet
    let checksum: [u8; 32] = compute_packet_data_hash(version, buffer.as_slice());

    let header_len = 96 + if version.is_some() { 4 } else { 0 };
    let buffer_len = buffer.len();
    buffer.resize(header_len + buffer_len, 0);
    buffer.copy_within(..buffer_len, header_len);

    buffer[..32].copy_from_slice(peer_id.as_slice());
    buffer[32..64].copy_from_slice(temp_public_key.as_bytes());

    match version {
        Some(version) => {
            let mut xor = [
                (version >> 8) as u8,
                version as u8,
                (version >> 8) as u8,
                version as u8,
            ];
            for (i, byte) in buffer[..64].iter().enumerate() {
                xor[i % 4] ^= *byte;
            }
            for (i, byte) in checksum.iter().enumerate() {
                xor[i % 4] ^= *byte;
            }
            buffer[64..68].copy_from_slice(&xor);
            buffer[68..100].copy_from_slice(&checksum);
            build_packet_cipher(&shared_secret, &checksum).apply_keystream(&mut buffer[100..]);
        }
        None => {
            buffer[64..96].copy_from_slice(&checksum);
            build_packet_cipher(&shared_secret, &checksum).apply_keystream(&mut buffer[96..]);
        }
    }
}

/// Attempts to decode the buffer as an ADNL handshake packet. On a successful nonempty result,
/// this buffer remains as decrypted packet data.
///
/// Expected packet structure (without version):
///  - 0..=31 - short local node id
///  - 32..=63 - sender pubkey
///  - 64..=95 - checksum
///  - 96..... - encrypted data
///
/// Expected packet structure (with version):
///  - 0..=31 - short local node id
///  - 32..=63 - sender pubkey
///  - 64..=68 - XOR'ed ADNL version
///  - 68..=100 - checksum
///  - 100..... - encrypted data
///
/// **NOTE: even on failure buffer can be modified**
pub fn parse_handshake_packet(
    keys: &FxHashMap<NodeIdShort, Arc<Key>>,
    buffer: &mut PacketView<'_>,
) -> Result<Option<(NodeIdShort, Option<u16>)>, HandshakeError> {
    const PUBLIC_KEY_RANGE: std::ops::Range<usize> = 32..64;

    // Ordinary data ranges
    const DATA_START: usize = 96;
    const CHECKSUM_RANGE: std::ops::Range<usize> = 64..DATA_START;
    const DATA_RANGE: std::ops::RangeFrom<usize> = DATA_START..;

    // Data ranges for packets with ADNL version
    const EXT_DATA_START: usize = 100;
    const EXT_CHECKSUM_RANGE: std::ops::Range<usize> = 68..EXT_DATA_START;
    const EXT_DATA_RANGE: std::ops::RangeFrom<usize> = EXT_DATA_START..;

    if buffer.len() < DATA_START {
        return Err(HandshakeError::BadHandshakePacketLength);
    }

    // SAFETY: NodeIdShort is 32 (<= 96) bytes and has the same layout as `[u8; 32]`
    // due to `#[repr(transparent)]`
    let local_id = unsafe { &*(buffer.as_ptr() as *const NodeIdShort) };

    // Get local id
    let local_key = match keys.get(local_id) {
        Some(key) => key,
        // No local keys found
        None => return Ok(None),
    };

    // Compute shared secret
    let shared_secret = local_key.secret_key().compute_shared_secret(
        &ed25519::PublicKey::from_bytes(buffer[PUBLIC_KEY_RANGE].try_into().unwrap())
            .ok_or(HandshakeError::InvalidPublicKey)?,
    );

    if buffer.len() > EXT_DATA_START {
        if let Some(version) =
            decode_version::<EXT_DATA_START>((&buffer[..EXT_DATA_START]).try_into().unwrap())
        {
            // Build cipher
            let mut cipher = build_packet_cipher(
                &shared_secret,
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
                return Ok(Some((*local_id, Some(version))));
            }

            // Otherwise restore data
            cipher.seek(0);
            cipher.apply_keystream(&mut buffer[EXT_DATA_RANGE]);
        }
    }

    // Decode data
    build_packet_cipher(&shared_secret, &buffer[CHECKSUM_RANGE].try_into().unwrap())
        .apply_keystream(&mut buffer[DATA_RANGE]);

    // Check checksum
    if compute_packet_data_hash(None, &buffer[DATA_RANGE]).as_slice() != &buffer[CHECKSUM_RANGE] {
        return Err(HandshakeError::BadHandshakePacketChecksum);
    }

    // Leave only data in the buffer
    buffer.remove_prefix(DATA_START);

    Ok(Some((*local_id, None)))
}

#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("Bad handshake packet length")]
    BadHandshakePacketLength,
    #[error("Bad handshake packet checksum")]
    BadHandshakePacketChecksum,
    #[error("Invalid public key")]
    InvalidPublicKey,
}
