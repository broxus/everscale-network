use std::hash::Hash;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicI32, Ordering};

use dashmap::DashSet;
use ton_api::ton::adnl::Address;
use ton_api::{ton, IntoBoxed};

pub trait AdnlAddress: Sized {
    fn is_public(&self) -> bool;
    fn serialized_size(&self) -> usize;
    fn as_tl(&self) -> ton::adnl::Address;
}

pub struct AdnlAddressList<T> {
    version: AtomicI32,
    reinit_date: AtomicI32,
    expire_at: AtomicI32,
    priority: AtomicI32,
    addresses: DashSet<T>,
}

impl<T> AdnlAddressList<T>
where
    T: AdnlAddress + Hash + Eq,
{
    const MAX_SERIALIZED_SIZE: usize = 128;

    pub fn version(&self) -> i32 {
        self.version.load(Ordering::Acquire)
    }

    pub fn set_version(&self, version: i32) {
        self.version.store(version, Ordering::Release);
    }

    pub fn reinit_date(&self) -> i32 {
        self.reinit_date.load(Ordering::Acquire)
    }

    pub fn set_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, Ordering::Release);
    }

    pub fn expire_at(&self) -> i32 {
        self.expire_at.load(Ordering::Acquire)
    }

    pub fn set_expire_at(&self, date: i32) {
        self.expire_at.store(date, Ordering::Release);
    }

    pub fn priority(&self) -> i32 {
        self.priority.load(Ordering::Acquire)
    }

    pub fn public_only(&self) -> bool {
        self.addresses.iter().all(|addr| addr.is_public())
    }

    pub fn iter(&self) -> impl Iterator<Item = dashmap::setref::multiple::RefMulti<T>> {
        self.addresses.iter()
    }

    pub fn push(&self, address: T) {
        self.addresses.insert(address);
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn as_tl(&self) -> ton::adnl::addresslist::AddressList {
        ton::adnl::addresslist::AddressList {
            addrs: self
                .addresses
                .iter()
                .map(|item| item.key().as_tl())
                .collect::<Vec<_>>()
                .into(),
            version: self.version(),
            reinit_date: self.reinit_date(),
            priority: self.priority(),
            expire_at: self.expire_at(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct AdnlAddressUdp(u64);

impl AdnlAddressUdp {
    pub fn new(addr: SocketAddrV4) -> Self {
        let ip = u32::from_be_bytes(addr.ip().octets());
        Self((ip as u64) << 16 | addr.port() as u64)
    }

    pub fn port(&self) -> u16 {
        self.0 as u16
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

impl AdnlAddress for AdnlAddressUdp {
    fn is_public(&self) -> bool {
        true
    }

    fn serialized_size(&self) -> usize {
        12
    }

    fn as_tl(&self) -> Address {
        ton::adnl::address::address::Udp {
            ip: (self.0 >> 16) as i32,
            port: self.0 as u16 as i32,
        }
        .into_boxed()
    }
}
