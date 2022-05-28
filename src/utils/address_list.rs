use std::hash::Hash;
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::Result;

use super::now;
use crate::proto;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct AdnlAddressUdp(u64);

impl AdnlAddressUdp {
    pub fn localhost(port: u16) -> Self {
        Self::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    pub fn new(addr: SocketAddrV4) -> Self {
        let ip = u32::from_be_bytes(addr.ip().octets());
        Self((ip as u64) << 16 | addr.port() as u64)
    }

    pub fn from_ip_and_port(ip: u32, port: u16) -> Self {
        Self((ip as u64) << 16 | port as u64)
    }

    pub fn port(&self) -> u16 {
        self.0 as u16
    }

    pub fn as_tl(&self) -> proto::adnl::Address {
        proto::adnl::Address::Udp {
            ip: (self.0 >> 16) as u32,
            port: self.0 as u16 as u32,
        }
    }
}

impl From<u64> for AdnlAddressUdp {
    fn from(encoded: u64) -> Self {
        Self(encoded)
    }
}

impl From<SocketAddrV4> for AdnlAddressUdp {
    fn from(addr: SocketAddrV4) -> Self {
        Self::new(addr)
    }
}

impl From<AdnlAddressUdp> for SocketAddrV4 {
    fn from(address: AdnlAddressUdp) -> Self {
        let addr = Ipv4Addr::from(((address.0 >> 16) as u32).to_be_bytes());
        SocketAddrV4::new(addr, address.0 as u16)
    }
}

impl From<AdnlAddressUdp> for u64 {
    fn from(address: AdnlAddressUdp) -> Self {
        address.0
    }
}

impl std::fmt::Display for AdnlAddressUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}.{}.{}.{}:{}",
            (self.0 >> 40) as u8,
            (self.0 >> 32) as u8,
            (self.0 >> 24) as u8,
            (self.0 >> 16) as u8,
            self.0 as u16
        ))
    }
}

pub fn parse_address_list(
    list: &proto::adnl::AddressList,
    clock_tolerance: u32,
) -> Result<AdnlAddressUdp> {
    let address = list.address.ok_or(AdnlAddressListError::ListIsEmpty)?;

    let version = now();
    if list.reinit_date > version + clock_tolerance {
        return Err(AdnlAddressListError::TooNewVersion.into());
    }

    if list.expire_at != 0 && list.expire_at < version {
        return Err(AdnlAddressListError::Expired.into());
    }

    match address {
        proto::adnl::Address::Udp { ip, port } => {
            Ok(AdnlAddressUdp::from_ip_and_port(ip, port as u16))
        } // _ => Err(AdnlAddressListError::UnsupportedAddress.into()),
    }
}

#[derive(thiserror::Error, Debug)]
enum AdnlAddressListError {
    #[error("Address list is empty")]
    ListIsEmpty,
    #[error("Address list version is too new")]
    TooNewVersion,
    #[error("Address list is expired")]
    Expired,
}
