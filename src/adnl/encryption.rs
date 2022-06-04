use sha2::Digest;

pub fn build_packet_cipher(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> Aes256Ctr {
    use aes::cipher::KeyIvInit;

    let mut aes_key_bytes: [u8; 32] = *shared_secret;
    aes_key_bytes[16..32].copy_from_slice(&checksum[16..32]);
    let mut aes_ctr_bytes: [u8; 16] = checksum[0..16].try_into().unwrap();
    aes_ctr_bytes[4..16].copy_from_slice(&shared_secret[20..32]);

    Aes256Ctr::new(
        &generic_array::GenericArray::from(aes_key_bytes),
        &generic_array::GenericArray::from(aes_ctr_bytes),
    )
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

pub fn decode_version<const LEN: usize>(prefix: &[u8; LEN]) -> Option<u16> {
    let end: usize = LEN - 32;
    let start: usize = end - 4;

    let mut xor: [u8; 4] = prefix[start..end].try_into().unwrap();
    for (i, byte) in prefix[..start].iter().enumerate() {
        xor[i % 4] ^= *byte;
    }
    for (i, byte) in prefix[end..].iter().enumerate() {
        xor[i % 4] ^= *byte;
    }
    if xor[0] == xor[2] && xor[1] == xor[3] {
        Some(u16::from_be_bytes(xor[..2].try_into().unwrap()))
    } else {
        None
    }
}

pub type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

#[cfg(test)]
mod tests {
    use aes::cipher::{StreamCipher, StreamCipherSeek};
    use rand::Rng;

    use super::*;

    #[test]
    fn double_encode() {
        let data: [u8; 32] = rand::thread_rng().gen();

        let mut cipher = build_packet_cipher(&rand::thread_rng().gen(), &rand::thread_rng().gen());

        let mut encoded_data = data;
        cipher.apply_keystream(&mut encoded_data);
        assert_ne!(encoded_data, data);

        cipher.seek(0);
        cipher.apply_keystream(&mut encoded_data);
        assert_eq!(encoded_data, data);
    }
}
