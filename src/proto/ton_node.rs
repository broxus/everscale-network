use tl_proto::{TlRead, TlWrite};

#[derive(Debug, Copy, Clone, Eq, PartialEq, TlWrite, TlRead)]
#[tl(boxed, id = 0xf5bf60c0)]
pub struct Capabilities {
    pub version: u32,
    pub capabilities: u64,
}
