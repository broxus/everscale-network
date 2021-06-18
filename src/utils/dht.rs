use std::convert::TryFrom;

use anyhow::Result;
use ton_api::ton::{self, TLObject};

use super::address_list::*;
use super::node_id::*;

pub fn make_dht_key(peer_id: &AdnlNodeIdShort, name: &str) -> ton::dht::key::Key {
    ton::dht::key::Key {
        id: ton::int256(*peer_id.as_slice()),
        name: ton::bytes(name.as_bytes().to_vec()),
        idx: 0,
    }
}

pub fn parse_dht_value_address(
    key: ton::dht::keydescription::KeyDescription,
    value: TLObject,
) -> Result<(AdnlAddressUdp, AdnlNodeIdFull)> {
    let address_list = match value.downcast::<ton::adnl::AddressList>() {
        Ok(address_list) => address_list,
        Err(_) => return Err(DhtError::ValueTypeMismatch.into()),
    };

    let ip_address = parse_address_list(&address_list.only())?;
    let full_id = AdnlNodeIdFull::try_from(&key.id)?;

    Ok((ip_address, full_id))
}

pub fn get_affinity(key1: &AdnlNodeIdShort, key2: &AdnlNodeIdShort) -> u8 {
    let key1 = key1.as_slice();
    let key2 = key2.as_slice();

    let mut result = 0;
    for i in 0..32 {
        match key1[i] ^ key2[i] {
            0 => result += 8,
            x => {
                if x & 0xf0 == 0 {
                    result += BITS[(x & 0x0f) as usize] + 4;
                } else {
                    result += BITS[(x >> 4) as usize]
                }
                break;
            }
        }
    }
    result
}

/// XOR  | BITS
/// 0000 | 4
/// 0001 | 3
/// 001x | 2
/// 01xx | 1
/// 1xxx | 0
const BITS: [u8; 16] = [4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(thiserror::Error, Debug)]
enum DhtError {
    #[error("DHT value type mismatch")]
    ValueTypeMismatch,
}
