use std::io::Write;

use bitflags::bitflags;
use rand::RngCore;
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

impl Flags {
    #[inline]
    fn set_name<T>(&mut self, flag: Flags, to_set: &Option<T>) {
        if to_set.is_some() {
            self.toggle(flag)
        }
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

        flag.set_name(Flags::FROM, &self.from);
        flag.set_name(Flags::FROM_SHORT, &self.from_short);
        flag.set_name(Flags::MESSAGE, &self.message);
        flag.set_name(Flags::MESSAGES, &self.messages);
        flag.set_name(Flags::ADDRESS, &self.address);
        flag.set_name(Flags::SEQNO, &self.seqno);
        flag.set_name(Flags::CONFIRM_SEQNO, &self.confirm_seqno);
        flag.set_name(Flags::RECV_ADDR_LIST_VERSION, &self.recv_addr_list_version);
        flag.set_name(
            Flags::RECV_PRIORITY_ADDR_LIST_VERSION,
            &self.recv_priority_addr_list_version,
        );
        flag.set_name(Flags::REINIT_DATE, &self.reinit_date);
        flag.set_name(Flags::SIGNATURE, &self.signature);

        flag.bits.write_to(packet);
        self.from.write_to(packet)?;
        self.from_short.write_to(packet)?;
        self.message.write_to(packet)?;

        if let Some(a) = &self.messages {
            a.write_to(packet)?
        }
        self.address.write_to(packet)?;
        self.seqno.write_to(packet)?;
        self.confirm_seqno.write_to(packet)?;
        self.recv_addr_list_version.write_to(packet)?;
        self.reinit_date.write_to(packet)?;
        self.dst_reinit_date.write_to(packet)?;
        self.signature.write_to(packet)?;
        let mut bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes.write_to(packet)?;
        Ok(())
    }
}
