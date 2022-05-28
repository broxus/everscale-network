use std::convert::TryFrom;

use anyhow::Result;
use tl_proto::BoxedReader;

use super::address_list::*;
use super::node_id::*;
use crate::proto;

pub fn make_dht_key<'a, T>(id: &'a T, name: &'a str) -> proto::dht::Key<'a>
where
    T: AsRef<[u8; 32]>,
{
    proto::dht::Key {
        id: id.as_ref(),
        name: name.as_bytes(),
        idx: 0,
    }
}

pub fn parse_dht_value_address(
    key: proto::dht::KeyDescription,
    value: &[u8],
    clock_tolerance_sec: u32,
) -> Result<(AdnlAddressUdp, AdnlNodeIdFull)> {
    let BoxedReader(address_list) = tl_proto::deserialize(value)?;

    let ip_address = parse_address_list(&address_list, clock_tolerance_sec)?;
    let full_id = AdnlNodeIdFull::try_from(key.id)?;

    Ok((ip_address, full_id))
}
