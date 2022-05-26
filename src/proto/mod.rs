#![allow(clippy::enum_variant_names)]

pub mod adnl;
pub mod overlay;
pub mod rldp;

pub type HashRef<'a> = &'a [u8; 32];
