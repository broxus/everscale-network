use tl_proto::{TlRead, TlWrite};

use super::HashRef;

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum Message<'tl> {
    #[tl(id = "rldp.message")]
    Message {
        #[tl(size_hint = 32)]
        id: HashRef<'tl>,
        data: &'tl [u8],
    },
    #[tl(id = "rldp.answer")]
    Answer {
        #[tl(size_hint = 32)]
        query_id: HashRef<'tl>,
        data: &'tl [u8],
    },
    #[tl(id = "rldp.query")]
    Query {
        #[tl(size_hint = 32)]
        query_id: HashRef<'tl>,
        max_answer_size: u64,
        timeout: u32,
        data: &'tl [u8],
    },
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed, scheme = "scheme.tl")]
pub enum MessagePart<'tl> {
    #[tl(id = "rldp.messagePart")]
    MessagePart {
        #[tl(size_hint = 32)]
        transfer_id: HashRef<'tl>,
        fec_type: RaptorQFecType,
        part: u32,
        total_size: u64,
        seqno: u32,
        data: &'tl [u8],
    },
    #[tl(id = "rldp.confirm", size_hint = 40)]
    Confirm {
        transfer_id: HashRef<'tl>,
        part: u32,
        seqno: u32,
    },
    #[tl(id = "rldp.complete", size_hint = 36)]
    Complete {
        transfer_id: HashRef<'tl>,
        part: u32,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TlRead, TlWrite)]
#[tl(boxed, id = "fec.raptorQ", size_hint = 12, scheme = "scheme.tl")]
pub struct RaptorQFecType {
    pub total_len: u32,
    pub packet_len: u32,
    pub packet_count: u32,
}
