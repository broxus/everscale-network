use std::io::Write;

use bitflags::bitflags;
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

bitflags! {
struct Flags:u32
    {
        const FROM = 0x0001;
        const FROM_SHORT = 0x0002;
        const MESSAGE = 0x0004;
        const MESSAGES = 0x0008;
        const ADDRESS = 0x0010;
        const PRIORITY_ADDRESS = 0x0020;
        const SEQNO = 0x0040;
        const CONFIRM_SEQNO = 0x0080;
        const RECV_ADDR_LIST_VERSION = 0x0100;
        const RECV_PRIORITY_ADDR_LIST_VERSION = 0x0200;
        const REINIT_DATE = 0x0400;
        const SIGNATURE = 0x0800;
    }
}

const CONSTRUCTOR: u32 = 0xd142cd89;

impl<'a> ReadFromPacket<'a> for PacketContentsView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let constructor = u32::read_from(packet, offset)?;
        if constructor != CONSTRUCTOR {
            return Err(PacketContentsError::UnknownConstructor);
        }

        read_bytes(packet, offset)?; // skip rand1

        let flags = u32::read_from(packet, offset)?;
        let flags = match Flags::from_bits(flags) {
            Some(a) => a,
            None => return Err(PacketContentsError::UnexpectedEof),
        };
        let from = read_optional(packet, offset, flags.contains(Flags::FROM))?;
        let from_short = read_optional(packet, offset, flags.contains(Flags::FROM_SHORT))?;

        let message = read_optional(packet, offset, flags.contains(Flags::MESSAGE))?;
        let messages = read_optional(packet, offset, flags.contains(Flags::MESSAGES))?;

        let address = read_optional(packet, offset, flags.contains(Flags::ADDRESS))?;
        read_optional::<AddressListView>(packet, offset, flags.contains(Flags::PRIORITY_ADDRESS))?; // skip `priority_address`

        let seqno = read_optional(packet, offset, flags.contains(Flags::SEQNO))?;
        let confirm_seqno = read_optional(packet, offset, flags.contains(Flags::CONFIRM_SEQNO))?;

        let recv_addr_list_version = read_optional(
            packet,
            offset,
            flags.contains(Flags::RECV_ADDR_LIST_VERSION),
        )?;
        let recv_priority_addr_list_version = read_optional(
            packet,
            offset,
            flags.contains(Flags::RECV_PRIORITY_ADDR_LIST_VERSION),
        )?;

        let reinit_date = read_optional(packet, offset, flags.contains(Flags::REINIT_DATE))?;
        let dst_reinit_date = read_optional(packet, offset, flags.contains(Flags::REINIT_DATE))?;

        let signature = read_optional(packet, offset, flags.contains(Flags::SIGNATURE))?;

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

impl<'a> WriteToPacket for PacketContentsView<'a> {
    fn max_size_hint(&self) -> usize {
        todo!()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        packet.write(&CONSTRUCTOR.to_le_bytes())?;
        let mut flag = Flags::empty();
        if self.from.is_some() {
            flag.toggle(Flags::FROM);
        }
        if self.from_short.is_some() {
            flag.toggle(Flags::FROM_SHORT);
        }
        if self.message.is_some() {
            flag.toggle(Flags::MESSAGE)
        }
        if self.messages.is_some() {
            flag.toggle(Flags::MESSAGES)
        }
        if self.address.is_some() {
            flag.toggle(Flags::ADDRESS)
        }
        if self.seqno.is_some() {
            flag.toggle(Flags::SEQNO)
        }
        if self.confirm_seqno.is_some() {
            flag.toggle(Flags::CONFIRM_SEQNO)
        }
        if self.recv_addr_list_version.is_some() {
            flag.toggle(Flags::RECV_ADDR_LIST_VERSION)
        }
        if self.reinit_date.is_some() {
            flag.toggle(Flags::REINIT_DATE)
        }
        if self.signature.is_some() {
            flag.toggle(Flags::SIGNATURE)
        }

        flag.bits.write_to(packet);

        if let Some(a) = self.from {
            a.write_to(packet)?
        }
        if let Some(a) = self.from_short {
            a.write_to(packet)?
        }
        if let Some(a) = self.message {
            a.write_to(packet)?
        }
        if let Some(a) = &self.messages {
            a.write_to(packet)?
        }
        if let Some(a) = self.address {
            a.write_to(packet)?
        }
        if let Some(a) = self.seqno {
            a.write_to(packet)?
        }
        if let Some(a) = self.confirm_seqno {
            a.write_to(packet)?
        }
        if let Some(a) = self.recv_addr_list_version {
            a.write_to(packet)?
        }
        if let Some(a) = self.reinit_date {
            a.write_to(packet)?
        }
        if let Some(a) = self.dst_reinit_date {
            a.write_to(packet)?
        }
        if let Some(a) = self.signature {
            a.write_to(packet)?
        }
        Ok(())
    }
}
