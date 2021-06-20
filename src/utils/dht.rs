use std::convert::TryFrom;

use anyhow::Result;
use ton_api::ton::{self, TLObject};

use super::address_list::*;
use super::node_id::*;

pub fn make_dht_key<T>(id: &T, name: &str) -> ton::dht::key::Key
where
    T: AsRef<[u8; 32]>,
{
    ton::dht::key::Key {
        id: ton::int256(*id.as_ref()),
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

#[derive(thiserror::Error, Debug)]
enum DhtError {
    #[error("DHT value type mismatch")]
    ValueTypeMismatch,
}
