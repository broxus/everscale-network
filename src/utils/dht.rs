use std::convert::TryFrom;

use anyhow::Result;
use ton_api::ton::{self, TLObject};

use super::address_list::*;
use super::node_id::*;
use super::now;
use crate::proto::*;

pub const DHT_VALUE_TIMEOUT: i32 = 3600; // Seconds

pub fn sign_dht_value<'a, V>(
    key: &'a StoredAdnlNodeKey,
    name: &'a str,
    value: V,
) -> Result<DhtValueView<'a, V, OwnedSignature>>
where
    V: WriteToPacket + Boxed + 'a,
{
    let mut value = DhtValueView {
        key: sign_dht_key_description(key, name)?,
        value: IntermediateBytes(value),
        ttl: now() + DHT_VALUE_TIMEOUT,
        signature: Default::default(),
    };
    value.signature = key.sign(value.wrap())?.into();
    Ok(value)
}

pub fn sign_dht_key_description<'a>(
    key: &'a StoredAdnlNodeKey,
    name: &'a str,
) -> Result<DhtKeyDescriptionView<'a, OwnedSignature>> {
    let mut key_description = DhtKeyDescriptionView {
        key: make_dht_key(key.id(), name),
        id: key.full_id().as_tl(),
        update_rule: DhtUpdateRuleView::Signature,
        signature: Default::default(),
    };
    key_description.signature = key.sign(key_description.wrap())?.into();
    Ok(key_description)
}

pub fn make_dht_key<'a, T>(id: &'a T, name: &'a str) -> DhtKeyView<'a>
where
    T: AsRef<[u8; 32]>,
{
    DhtKeyView {
        id: id.as_ref(),
        name: name.as_bytes(),
        idx: 0,
    }
}

pub fn parse_dht_value_address<S>(
    key: DhtKeyDescriptionView<'_, S>,
    value: TLObject,
) -> Result<(AdnlAddressUdp, AdnlNodeIdFull)>
where
    S: DataSignature,
{
    let address_list = match value.downcast::<ton::adnl::AddressList>() {
        Ok(address_list) => address_list,
        Err(_) => return Err(DhtError::ValueTypeMismatch.into()),
    };

    let ip_address = parse_address_list(&address_list.only())?;
    let full_id = AdnlNodeIdFull::try_from(key.id)?;

    Ok((ip_address, full_id))
}

#[derive(thiserror::Error, Debug)]
enum DhtError {
    #[error("DHT value type mismatch")]
    ValueTypeMismatch,
}
