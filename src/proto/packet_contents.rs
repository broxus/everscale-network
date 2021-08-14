use smallvec::SmallVec;

use super::address_list::*;
use super::message::*;
use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Clone)]
pub struct PacketContentsView<'a> {
    pub from: Option<PublicKeyView<'a>>,
    pub from_short: Option<HashRef<'a>>,
    pub message: Option<MessageView<'a>>,
    pub messages: Option<SmallVec<[MessageView<'a>; 4]>>,
    pub address: Option<AddressListView<'a>>,
    pub seqno: Option<i64>,
    pub confirm_seqno: Option<i64>,
    pub recv_addr_list_version: Option<i32>,
    pub recv_priority_addr_list_version: Option<i32>,
    pub reinit_date: Option<i32>,
    pub dst_reinit_date: Option<i32>,
    pub signature: Option<&'a [u8]>,
}

impl<'a> ReadFromPacket<'a> for PacketContentsView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let constructor = u32::read_from(packet, offset)?;
        if constructor != 0xd142cd89 {
            return Err(PacketContentsError::UnknownConstructor);
        }

        read_bytes(packet, offset)?; // skip rand1

        let flags = u32::read_from(packet, offset)?;

        let from = read_optional(packet, offset, flags & 0x0001 != 0)?;
        let from_short = read_optional(packet, offset, flags & 0x0002 != 0)?;

        let message = read_optional(packet, offset, flags & 0x0004 != 0)?;
        let messages = read_optional(packet, offset, flags & 0x0008 != 0)?;

        let address = read_optional(packet, offset, flags & 0x0010 != 0)?;
        read_optional::<AddressListView>(packet, offset, flags & 0x0020 != 0)?; // skip `priority_address`

        let seqno = read_optional(packet, offset, flags & 0x0040 != 0)?;
        let confirm_seqno = read_optional(packet, offset, flags & 0x0080 != 0)?;

        let recv_addr_list_version = read_optional(packet, offset, flags & 0x0100 != 0)?;
        let recv_priority_addr_list_version = read_optional(packet, offset, flags & 0x0200 != 0)?;

        let reinit_date = read_optional(packet, offset, flags & 0x0400 != 0)?;
        let dst_reinit_date = read_optional(packet, offset, flags & 0x0400 != 0)?;

        let signature = read_optional(packet, offset, flags & 0x0800 != 0)?;

        read_bytes(packet, offset)?; // skip rand2

        Ok(Self {
            from,
            from_short,
            message,
            messages,
            address,
            seqno,
            confirm_seqno,
            recv_addr_list_version,
            recv_priority_addr_list_version,
            reinit_date,
            dst_reinit_date,
            signature,
        })
    }
}
