#![allow(clippy::enum_variant_names)]

pub mod adnl;
pub mod dht;
pub mod overlay;
pub mod rldp;
pub mod rpc;
pub mod ton_node;

pub type HashRef<'a> = &'a [u8; 32];
