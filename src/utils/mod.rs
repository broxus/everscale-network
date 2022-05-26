use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::hash::BuildHasherDefault;

use anyhow::Result;
pub use rustc_hash::FxHasher;
use sha2::Digest;
use ton_api::ton::TLObject;
use ton_api::{BoxedSerialize, Deserializer, IntoBoxed, Serializer};

pub use self::address_list::*;
pub use self::dht::*;
pub use self::handshake::*;
pub use self::node_id::*;
pub use self::operations_pool::*;
pub use self::overlay::*;
pub use self::packet_view::*;
pub use self::packets_history::*;
pub use self::peers_cache::*;
pub use self::queries_cache::*;
pub use self::query::*;
pub use self::response_collector::*;
pub use self::socket::*;
pub use self::tl_view::*;
pub use self::updated_at::*;

mod address_list;
pub mod compression;
mod dht;
mod handshake;
mod node_id;
mod operations_pool;
mod overlay;
mod packet_view;
mod packets_history;
mod peers_cache;
mod queries_cache;
mod query;
mod response_collector;
mod socket;
mod tl_view;
mod updated_at;

pub type FxDashSet<K> = dashmap::DashSet<K, BuildHasherDefault<FxHasher>>;
pub type FxDashMap<K, V> = dashmap::DashMap<K, V, BuildHasherDefault<FxHasher>>;

pub type FxHashSet<K> = HashSet<K, BuildHasherDefault<FxHasher>>;
pub type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

pub type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

pub fn gen_packet_offset() -> Vec<u8> {
    use rand::Rng;

    const RAND_SIZE: usize = 16; // TODO: randomly choose between 7 and 15

    let mut result = vec![0; RAND_SIZE];
    rand::thread_rng().fill(result.as_mut_slice());
    result
}

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

pub fn hash<T: IntoBoxed>(object: T) -> [u8; 32] {
    hash_boxed(&object.into_boxed())
}

/// Calculates hash of TL object
pub fn hash_boxed<T: BoxedSerialize>(object: &T) -> [u8; 32] {
    sha2::Sha256::digest(&serialize(object)).into()
}

pub fn serialize<T: BoxedSerialize>(object: &T) -> Vec<u8> {
    let mut ret = Vec::new();
    Serializer::new(&mut ret).write_boxed(object);
    ret
}

pub fn serialize_boxed<T: IntoBoxed>(object: T) -> Vec<u8> {
    let object = object.into_boxed();
    serialize(&object)
}

#[allow(clippy::ptr_arg)] // https://github.com/rust-lang/rust-clippy/issues/8482
pub fn serialize_append<T>(buffer: &mut Vec<u8>, object: &T)
where
    T: BoxedSerialize,
{
    Serializer::new(buffer).write_boxed(object)
}

pub fn serialize_inplace<T>(buffer: &mut Vec<u8>, object: &T)
where
    T: BoxedSerialize,
{
    buffer.truncate(0);
    serialize_append(buffer, object)
}

/// Deserializes TL object from bytes
pub fn deserialize(bytes: &[u8]) -> Result<TLObject> {
    let mut reader = bytes;
    Deserializer::new(&mut reader).read_boxed::<TLObject>()
}

/// Deserializes a bundle of TL objects from bytes
pub fn deserialize_bundle(mut bytes: &[u8]) -> Result<Vec<TLObject>> {
    let mut deserializer = Deserializer::new(&mut bytes);
    let mut result = Vec::new();
    loop {
        match deserializer.read_boxed::<TLObject>() {
            Ok(object) => result.push(object),
            Err(error) => {
                if result.is_empty() {
                    return Err(error);
                } else {
                    break;
                }
            }
        }
    }
    Ok(result)
}

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
