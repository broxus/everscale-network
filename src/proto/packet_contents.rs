use std::io::Write;

use rand::RngCore;
use smallvec::SmallVec;

use super::address_list::*;
use super::message::*;
use super::prelude::*;
use super::public_key::*;

#[derive(Debug, Clone)]
pub struct PacketContentsView<'a, T> {
    pub from: Option<PublicKeyView<'a>>,
    pub from_short: Option<HashRef<'a>>,
    pub message: Option<MessageView<'a, T>>,
    pub messages: Option<SmallVec<[MessageView<'a, T>; 4]>>,
    pub address: Option<AddressListView<'a>>,
    pub seqno: Option<i64>,
    pub confirm_seqno: Option<i64>,
    pub recv_addr_list_version: Option<i32>,
    pub reinit_date: Option<i32>,
    pub dst_reinit_date: Option<i32>,
    pub signature: Option<&'a [u8]>,
}

impl<T> Boxed for PacketContentsView<'_, T> {}

impl<'a> ReadFromPacket<'a> for PacketContentsView<'a, RawBytes<'a>> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let constructor = u32::read_from(packet, offset)?;
        if constructor != ID_PACKET_CONTENTS {
            return Err(PacketContentsError::UnknownConstructor);
        }

        read_bytes(packet, offset)?; // skip rand1

        let flags = Flags(u32::read_from(packet, offset)?);

        let from = read_optional(packet, offset, flags.contains(HAS_FROM))?;
        let from_short = read_optional(packet, offset, flags.contains(HAS_FROM_SHORT))?;

        let message = read_optional(packet, offset, flags.contains(HAS_MESSAGE))?;
        let messages = read_optional(packet, offset, flags.contains(HAS_MESSAGES))?;

        let address = read_optional(packet, offset, flags.contains(HAS_ADDRESS))?;
        read_optional::<AddressListView>(packet, offset, flags.contains(HAS_PRIORITY_ADDRESS))?; // skip `priority_address`

        let seqno = read_optional(packet, offset, flags.contains(HAS_SEQNO))?;
        let confirm_seqno = read_optional(packet, offset, flags.contains(HAS_CONFIRM_SEQNO))?;

        let recv_addr_list_version =
            read_optional(packet, offset, flags.contains(HAS_RECV_ADDR_LIST_VERSION))?;
        read_optional::<i32>(
            packet,
            offset,
            flags.contains(HAS_RECV_PRIORITY_ADDR_LIST_VERSION),
        )?; // skip `recv_priority_addr_list_version`

        let reinit_date = read_optional(packet, offset, flags.contains(HAS_REINIT_DATE))?;
        let dst_reinit_date = read_optional(packet, offset, flags.contains(HAS_REINIT_DATE))?;

        let signature = read_optional(packet, offset, flags.contains(HAS_SIGNATURE))?;

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
            reinit_date,
            dst_reinit_date,
            signature,
        })
    }
}

impl<'a, T> WriteToPacket for PacketContentsView<'a, T>
where
    T: WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        4 + RAND_LEN
            + 4 // flags
            + self.from.max_size_hint()
            + self.from_short.max_size_hint()
            + self.message.max_size_hint()
            + self.messages.max_size_hint()
            + self.address.max_size_hint()
            + self.seqno.max_size_hint()
            + self.confirm_seqno.max_size_hint()
            + self.recv_addr_list_version.max_size_hint()
            + self.reinit_date.max_size_hint()
            + self.dst_reinit_date.max_size_hint()
            + self.signature.max_size_hint()
            + RAND_LEN
    }

    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        // prepare rand buffer
        let mut rng = rand::thread_rng();
        let mut rand_bytes = [0; 16];

        // prepare flags
        let mut flags = Flags::default();
        flags.update(HAS_FROM, &self.from);
        flags.update(HAS_FROM_SHORT, &self.from_short);
        flags.update(HAS_MESSAGE, &self.message);
        flags.update(HAS_MESSAGES, &self.messages);
        flags.update(HAS_ADDRESS, &self.address);
        flags.update(HAS_SEQNO, &self.seqno);
        flags.update(HAS_CONFIRM_SEQNO, &self.confirm_seqno);
        flags.update(HAS_RECV_ADDR_LIST_VERSION, &self.recv_addr_list_version);
        flags.update(HAS_REINIT_DATE, &self.reinit_date);
        flags.update(HAS_SIGNATURE, &self.signature);

        // write data
        ID_PACKET_CONTENTS.write_to(packet)?;

        rng.fill_bytes(&mut rand_bytes);
        write_bytes(&rand_bytes, packet)?; // rand1

        flags.0.write_to(packet)?;

        self.from.write_to(packet)?;
        self.from_short.write_to(packet)?;
        self.message.write_to(packet)?;
        self.messages.write_to(packet)?;
        self.address.write_to(packet)?;
        self.seqno.write_to(packet)?;
        self.confirm_seqno.write_to(packet)?;
        self.recv_addr_list_version.write_to(packet)?;
        self.reinit_date.write_to(packet)?;
        self.dst_reinit_date.write_to(packet)?;
        self.signature.write_to(packet)?;

        rng.fill_bytes(&mut rand_bytes);
        write_bytes(&rand_bytes, packet)?; // rand2

        Ok(())
    }
}

#[derive(Default)]
struct Flags(u32);

impl Flags {
    #[inline]
    fn contains(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    #[inline]
    fn update<T>(&mut self, flag: u32, option: &Option<T>) {
        if option.is_some() {
            self.0 |= flag;
        }
    }
}

const RAND_LEN: usize = 16;

const HAS_FROM: u32 = 0x0001;
const HAS_FROM_SHORT: u32 = 0x0002;
const HAS_MESSAGE: u32 = 0x0004;
const HAS_MESSAGES: u32 = 0x0008;
const HAS_ADDRESS: u32 = 0x0010;
const HAS_PRIORITY_ADDRESS: u32 = 0x0020;
const HAS_SEQNO: u32 = 0x0040;
const HAS_CONFIRM_SEQNO: u32 = 0x0080;
const HAS_RECV_ADDR_LIST_VERSION: u32 = 0x0100;
const HAS_RECV_PRIORITY_ADDR_LIST_VERSION: u32 = 0x0200;
const HAS_REINIT_DATE: u32 = 0x0400;
const HAS_SIGNATURE: u32 = 0x0800;

const ID_PACKET_CONTENTS: u32 = 0xd142cd89;
