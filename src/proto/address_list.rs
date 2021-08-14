use std::io::Write;

use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Copy, Clone)]
pub struct AddressListView<'a> {
    /// Single address instead of list, because only one is always passed
    pub address: Option<AddressView<'a>>,
    pub version: i32,
    pub reinit_date: i32,
    pub priority: i32,
    pub expire_at: i32,
}

impl BoxedConstructor for AddressListView<'_> {
    const ID: u32 = ID_ADDRESS_LIST;
}

impl<'a> ReadFromPacket<'a> for AddressListView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let address_count = i32::read_from(packet, offset)?;
        let mut address = None;
        for _ in 0..address_count {
            let item = AddressView::read_from(packet, offset)?;
            if address.is_none() {
                address = Some(item);
            }
        }

        let version = i32::read_from(packet, offset)?;
        let reinit_date = i32::read_from(packet, offset)?;
        let priority = i32::read_from(packet, offset)?;
        let expire_at = i32::read_from(packet, offset)?;

        Ok(Self {
            address,
            version,
            reinit_date,
            priority,
            expire_at,
        })
    }
}

impl WriteToPacket for AddressListView<'_> {
    fn max_size_hint(&self) -> usize {
        // 4 bytes address count, optional address, 4 bytes for version, reinit_date, priority and expire_at
        4 + self.address.max_size_hint() + 4 + 4 + 4 + 4
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        if let Some(address) = &self.address {
            1i32.write_to(packet)?;
            address.write_to(packet)?;
        } else {
            0i32.write_to(packet)?;
        }

        self.version.write_to(packet)?;
        self.reinit_date.write_to(packet)?;
        self.priority.write_to(packet)?;
        self.expire_at.write_to(packet)?;

        Ok(())
    }
}

const ID_ADDRESS_LIST: u32 = 0x2227e658;

#[derive(Debug, Copy, Clone)]
pub enum AddressView<'a> {
    Udp {
        ip: i32,
        port: i32,
    },
    Udp6 {
        ip: &'a [u8; 16],
        port: i32,
    },
    Tunnel {
        to: HashRef<'a>,
        pubkey: PublicKeyView<'a>,
    },
}

impl<'a> ReadFromPacket<'a> for AddressView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_ADDRESS_UDP => Ok(Self::Udp {
                ip: i32::read_from(packet, offset)?,
                port: i32::read_from(packet, offset)?,
            }),
            ID_ADDRESS_UDP6 => Ok(Self::Udp6 {
                ip: read_fixed_bytes(packet, offset)?,
                port: i32::read_from(packet, offset)?,
            }),
            ID_ADDRESS_TUNNEL => Ok(Self::Tunnel {
                to: read_fixed_bytes(packet, offset)?,
                pubkey: PublicKeyView::read_from(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for AddressView<'_> {
    #[inline]
    fn max_size_hint(&self) -> usize {
        4 + match self {
            Self::Tunnel { to, pubkey } => to.max_size_hint() + pubkey.max_size_hint(),
            Self::Udp { ip, port } => ip.max_size_hint() + port.max_size_hint(),
            Self::Udp6 { ip, port } => ip.max_size_hint() + port.max_size_hint(),
        }
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Udp { ip, port } => {
                ID_ADDRESS_UDP.write_to(packet)?;
                ip.write_to(packet)?;
                port.write_to(packet)
            }
            Self::Udp6 { ip, port } => {
                ID_ADDRESS_UDP6.write_to(packet)?;
                ip.write_to(packet)?;
                port.write_to(packet)
            }
            Self::Tunnel { to, pubkey } => {
                ID_ADDRESS_TUNNEL.write_to(packet)?;
                to.write_to(packet)?;
                pubkey.write_to(packet)
            }
        }
    }
}

const ID_ADDRESS_UDP: u32 = 0x670da6e7;
const ID_ADDRESS_UDP6: u32 = 0xe31d63fa;
const ID_ADDRESS_TUNNEL: u32 = 0x092b02eb;
