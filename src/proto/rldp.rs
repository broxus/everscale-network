use tl_proto::{TlRead, TlWrite};

use super::HashRef;

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum Message<'tl> {
    #[tl(id = 0x7d1bcd1e)]
    Message {
        #[tl(size_hint = 32)]
        id: HashRef<'tl>,
        data: &'tl [u8],
    },
    #[tl(id = 0xa3fc5c03)]
    Answer {
        #[tl(size_hint = 32)]
        query_id: HashRef<'tl>,
        data: &'tl [u8],
    },
    #[tl(id = 0x8a794d69)]
    Query {
        #[tl(size_hint = 32)]
        query_id: HashRef<'tl>,
        max_answer_size: u64,
        timeout: u32,
        data: &'tl [u8],
    },
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum MessagePart<'tl> {
    #[tl(id = 0x185c22cc)]
    MessagePart {
        #[tl(size_hint = 32)]
        transfer_id: HashRef<'tl>,
        fec_type: RaptorQFecType,
        part: u32,
        total_size: u64,
        seqno: u32,
        data: &'tl [u8],
    },
    #[tl(id = 0xf582dc58, size_hint = 40)]
    Confirm {
        transfer_id: HashRef<'tl>,
        part: u32,
        seqno: u32,
    },
    #[tl(id = 0xbc0cb2bf, size_hint = 36)]
    Complete {
        transfer_id: HashRef<'tl>,
        part: u32,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TlRead, TlWrite)]
#[tl(boxed, id = 0x8b93a7e0, size_hint = 12)]
pub struct RaptorQFecType {
    pub data_size: u32,
    pub symbol_size: u32,
    pub symbols_count: u32,
}
