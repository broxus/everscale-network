use std::convert::TryInto;
use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
pub use rustc_hash::{FxHashMap, FxHashSet};

pub use self::address_list::*;
pub use self::dht::*;
pub use self::keystore::*;
pub use self::node_id::*;
pub use self::overlay::*;
pub use self::packet_view::*;
pub use self::packets_history::*;
pub use self::peers_cache::*;
pub use self::queries_cache::*;
pub use self::query::*;
pub use self::response_collector::*;
pub use self::socket::*;
pub use self::updated_at::*;

mod address_list;
pub mod compression;
mod dht;
mod keystore;
mod node_id;
mod overlay;
mod packet_view;
mod packets_history;
mod peers_cache;
mod queries_cache;
mod query;
mod response_collector;
mod socket;
mod updated_at;

pub type FxDashSet<K> = dashmap::DashSet<K, BuildHasherDefault<FxHasher>>;
pub type FxDashMap<K, V> = dashmap::DashMap<K, V, BuildHasherDefault<FxHasher>>;

pub type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

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

#[derive(thiserror::Error, Debug)]
#[error("Bad public key data")]
struct BadPublicKeyData;

pub fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

pub fn ordered_boundaries<T>(min: T, max: T) -> (T, T)
where
    T: Ord,
{
    if min > max {
        (max, min)
    } else {
        (min, max)
    }
}

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
