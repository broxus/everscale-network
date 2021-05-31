use std::convert::TryInto;
use std::mem::MaybeUninit;
use std::ops::{Index, IndexMut, Range, RangeFrom};

use anyhow::Result;
use sha2::Digest;
use ton_api::ton::TLObject;
use ton_api::{BoxedSerialize, Deserializer, IntoBoxed, Serializer};

pub struct PacketView<'a> {
    bytes: &'a mut [u8],
}

impl<'a> PacketView<'a> {
    pub const fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn remove_prefix(&mut self, prefix_len: usize) {
        let len = self.bytes.len();
        let ptr = self.bytes.as_mut_ptr();
        // SAFETY: `bytes` is already a reference bounded by a lifetime
        self.bytes =
            unsafe { std::slice::from_raw_parts_mut(ptr.add(prefix_len), len - prefix_len) };
    }
}

impl Index<Range<usize>> for PacketView<'_> {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        self.bytes.index(index)
    }
}

impl IndexMut<Range<usize>> for PacketView<'_> {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        self.bytes.index_mut(index)
    }
}

impl Index<RangeFrom<usize>> for PacketView<'_> {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        self.bytes.index(index)
    }
}

impl IndexMut<RangeFrom<usize>> for PacketView<'_> {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output {
        self.bytes.index_mut(index)
    }
}

impl<'a> From<&'a mut [u8]> for PacketView<'a> {
    fn from(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

pub fn hash<T: IntoBoxed>(object: T) -> Result<[u8; 32]> {
    hash_boxed(&object.into_boxed())
}

pub fn gen_packet_offset() -> Vec<u8> {
    use rand::Rng;

    const RAND_SIZE: usize = 16; // TODO: randomly choose between 7 and 15

    let mut result = vec![0; RAND_SIZE];
    rand::thread_rng().fill(result.as_mut_slice());
    result
}

pub fn build_packet_cipher(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> aes::Aes256Ctr {
    use aes::cipher::NewCipher;

    let mut aes_key_bytes: [u8; 32] = *shared_secret;
    aes_key_bytes[16..32].copy_from_slice(&checksum[16..32]);
    let mut aes_ctr_bytes: [u8; 16] = checksum[0..16].try_into().unwrap();
    aes_ctr_bytes[4..16].copy_from_slice(&shared_secret[20..32]);

    aes::Aes256Ctr::new(
        generic_array::GenericArray::from_slice(&aes_key_bytes),
        generic_array::GenericArray::from_slice(&aes_ctr_bytes),
    )
}

pub fn compute_shared_secret(
    private_key_part: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<[u8; 32]> {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(*public_key)
        .decompress()
        .ok_or(BadPublicKeyData)?
        .to_montgomery()
        .to_bytes();
    Ok(x25519_dalek::x25519(*private_key_part, point))
}

#[derive(thiserror::Error, Debug)]
#[error("Bad public key data")]
struct BadPublicKeyData;

/// Calculates hash of TL object
pub fn hash_boxed<T: BoxedSerialize>(object: &T) -> Result<[u8; 32]> {
    let buf = sha2::Sha256::digest(&serialize(object)?);
    Ok(buf.as_slice().try_into().unwrap())
}

pub fn serialize<T: BoxedSerialize>(object: &T) -> Result<Vec<u8>> {
    let mut ret = Vec::new();
    Serializer::new(&mut ret).write_boxed(object).convert()?;
    Ok(ret)
}

/// Deserializes TL object from bytes
pub fn deserialize(bytes: &[u8]) -> Result<TLObject> {
    let mut reader = bytes;
    Deserializer::new(&mut reader)
        .read_boxed::<TLObject>()
        .convert()
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
                    return Err(error).convert();
                } else {
                    break;
                }
            }
        }
    }
    Ok(result)
}

pub fn now() -> i32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i32
}

pub trait NoFailure {
    type Output;

    fn convert(self) -> anyhow::Result<Self::Output>;
}

impl<T> NoFailure for ton_types::Result<T> {
    type Output = T;

    fn convert(self) -> anyhow::Result<Self::Output> {
        self.map_err(|e| anyhow::Error::msg(e.to_string()))
    }
}
