use std::convert::TryFrom;

use anyhow::Result;
use ton_api::ton::{self, TLObject};
use ton_api::IntoBoxed;

use super::address_list::*;
use super::node_id::*;
use super::now;

pub fn sign_dht_value(
    key: &StoredAdnlNodeKey,
    name: &str,
    value: &[u8],
    timeout: u32,
) -> Result<ton::dht::value::Value> {
    let value = ton::dht::value::Value {
        key: sign_dht_key_description(key, name)?,
        value: ton::bytes(value.to_vec()),
        ttl: now() + timeout as i32,
        signature: Default::default(),
    };
    key.sign_boxed(value, |value, signature| {
        let mut value = value.only();
        value.signature = signature;
        value
    })
}

pub fn sign_dht_key_description(
    key: &StoredAdnlNodeKey,
    name: &str,
) -> Result<ton::dht::keydescription::KeyDescription> {
    let key_description = ton::dht::keydescription::KeyDescription {
        key: make_dht_key(key.id(), name),
        id: key.full_id().as_tl().into_boxed(),
        update_rule: ton::dht::UpdateRule::Dht_UpdateRule_Signature,
        signature: Default::default(),
    };
    key.sign_boxed(key_description, |key, signature| {
        let mut key = key.only();
        key.signature = signature;
        key
    })
}

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
