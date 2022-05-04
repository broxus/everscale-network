use std::convert::TryInto;
use std::sync::Arc;

use aes::cipher::StreamCipher;
use anyhow::Result;
use everscale_crypto::ed25519;
use sha2::Digest;

use super::build_packet_cipher;
use super::node_id::*;
use super::packet_view::*;
use super::FxHashMap;

/// Modifies `buffer` in-place to contain the handshake packet
pub fn build_handshake_packet(
    peer_id: &AdnlNodeIdShort,
    peer_id_full: &AdnlNodeIdFull,
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
    keys: &FxHashMap<AdnlNodeIdShort, Arc<StoredAdnlNodeKey>>,
    buffer: &mut PacketView<'_>,
) -> Result<Option<(AdnlNodeIdShort, Option<u16>)>> {
    if buffer.len() < 96 {
        return Err(HandshakeError::BadHandshakePacketLength.into());
    }

    // SAFETY: AdnlNodeIdShort is 32 (<= 96) bytes and has the same layout as `[u8; 32]`
    // due to `#[repr(transparent)]`
    let local_id = unsafe { &*(buffer.as_ptr() as *const AdnlNodeIdShort) };

    // Get local id
    let value = match keys.get(local_id) {
        Some(value) => value,
        // No local keys found
        None => return Ok(None),
    };

    // Compute shared secret
    let shared_secret = value.private_key().compute_shared_secret(
        &ed25519::PublicKey::from_bytes(buffer[32..64].try_into().unwrap())
            .ok_or(HandshakeError::InvalidPublicKey)?,
    );

    // NOTE: macros is used here to avoid useless bound checks, saving the `.len()` context
    macro_rules! process {
        ($buffer:ident, $shared_secret:ident, $version:expr, $start:literal .. $end:literal) => {
            build_packet_cipher(&$shared_secret, &$buffer[$start..$end].try_into().unwrap())
                .apply_keystream(&mut $buffer[$end..]);

            // Check checksum
            if compute_packet_data_hash($version, &$buffer[$end..]).as_slice()
                != &$buffer[$start..$end]
            {
                return Err(HandshakeError::BadHandshakePacketChecksum.into());
            }

            // Leave only data in the buffer
            $buffer.remove_prefix($end);
        };
    }

    if buffer.len() > 100 {
        if let Some(version) = decode_version((&buffer[..100]).try_into().unwrap()) {
            process!(buffer, shared_secret, Some(version), 68..100);
            return Ok(Some((*local_id, Some(version))));
        }
    }

    process!(buffer, shared_secret, None, 64..96);
    Ok(Some((*local_id, None)))
}

pub fn compute_packet_data_hash(version: Option<u16>, data: &[u8]) -> [u8; 32] {
    match version {
        Some(version) => {
            let mut hash = sha2::Sha256::new();
            hash.update(&version.to_be_bytes());
            hash.update(data);
            hash.finalize()
        }
        None => sha2::Sha256::digest(data),
    }
    .into()
}

fn decode_version(prefix: &[u8; 100]) -> Option<u16> {
    let mut xor: [u8; 4] = prefix[64..68].try_into().unwrap();
    for (i, byte) in prefix[..64].iter().enumerate() {
        xor[i % 4] ^= *byte;
    }
    for (i, byte) in prefix[68..].iter().enumerate() {
        xor[i % 4] ^= *byte;
    }
    if xor[0] == xor[2] && xor[1] == xor[3] {
        Some(u16::from_be_bytes(xor[..2].try_into().unwrap()))
    } else {
        None
    }
}

#[derive(thiserror::Error, Debug)]
enum HandshakeError {
    #[error("Bad handshake packet length")]
    BadHandshakePacketLength,
    #[error("Bad handshake packet checksum")]
    BadHandshakePacketChecksum,
    #[error("Invalid public key")]
    InvalidPublicKey,
}
