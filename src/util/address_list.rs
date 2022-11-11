use std::net::{Ipv4Addr, SocketAddrV4};

use super::now;
use crate::proto;

/// Validates address list and extracts socket address from it
pub fn parse_address_list(
    list: &proto::adnl::AddressList,
    clock_tolerance: u32,
) -> Result<SocketAddrV4, AdnlAddressListError> {
    let address = list.address.ok_or(AdnlAddressListError::ListIsEmpty)?;

    let version = now();
    if list.reinit_date > version + clock_tolerance {
        return Err(AdnlAddressListError::TooNewVersion);
    }

    if list.expire_at != 0 && list.expire_at < version {
        return Err(AdnlAddressListError::Expired);
    }

    Ok(SocketAddrV4::new(
        Ipv4Addr::from(address.ip),
        address.port as u16,
    ))
}

#[derive(thiserror::Error, Debug)]
pub enum AdnlAddressListError {
    #[error("Address list is empty")]
    ListIsEmpty,
    #[error("Address list version is too new")]
    TooNewVersion,
    #[error("Address list is expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    #[test]
    fn correct_port_update() {
        let mut ip = SocketAddrV4::new(0x12345678.into(), 123);
        assert_eq!(ip.port(), 123);

        ip.set_port(4560);
        assert_eq!(ip.port(), 4560);
    }
}
