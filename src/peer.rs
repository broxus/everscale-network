use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use parking_lot::RwLock;
use ton_api::ton;
use ton_api::ton::adnl::message::message as adnlmessage;
use ton_api::ton::adnl::packetcontents::PacketContents;

use crate::node_id::*;
use crate::received_mask::*;
use crate::{ADNL_MTU, HUGE_PACKET_SIZE};

pub struct AdnlPeer {
    peer_id_short: AdnlNodeIdShort,
    peer_id: RwLock<AdnlNodeIdFull>,
    peer_pairs: DashMap<AdnlNodeIdShort, Arc<AdnlPeerPair>>,
}

impl AdnlPeer {
    fn receive_packet(
        &self,
        dst: AdnlNodeIdShort,
        dst_mode: u32,
        packet: PacketContents,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        if let Some(from) = packet.from {
            self.update_id(from.try_into()?)?;
        }

        match self.peer_pairs.entry(dst) {
            Entry::Vacant(entry) => {}
            _ => {}
        }

        todo!()
    }

    fn send_query(
        &self,
        src: AdnlNodeIdShort,
        src_mode: u32,
        timeout: Duration,
        data: Vec<u8>,
        flags: u32,
    ) {
        todo!()
    }

    fn update_id(&self, id: AdnlNodeIdFull) -> Result<()> {
        {
            let mut peer_id = self.peer_id.write();

            if !peer_id.is_empty() {
                return Ok(());
            }

            if id.compute_short_id()? != self.peer_id_short {
                return Err(PeerError::InvalidNewPeerId.into());
            }

            *peer_id = id;
        }

        for pair in self.peer_pairs.iter() {
            pair.value().update_peer_id(id);
        }

        Ok(())
    }
}

pub struct AdnlPeerPair {
    in_seqno_mask: AdnlReceivedMask,
}

impl AdnlPeerPair {
    const PACKET_HEADER_MAX_SIZE: usize = 272;
    const CHANNEL_PACKET_HEADER_MAX_SIZE: usize = 128;
    const ADDR_LIST_MAX_SIZE: usize = 128;

    const MTU: usize = ADNL_MTU + 128;
    const HUGE_PACKET_MAX_SIZE: usize = HUGE_PACKET_SIZE + 128;

    fn update_peer_id(&self, id: AdnlNodeIdFull) {
        todo!()
    }

    fn process_message_create_channel(&self, message: adnlmessage::CreateChannel) {
        todo!()
    }

    fn process_message_confirm_channel(&self, message: adnlmessage::ConfirmChannel) {
        todo!()
    }

    fn process_message_custom(&self, message: adnlmessage::Custom) {
        todo!()
    }

    fn process_message_nop(&self, message: adnlmessage::Reinit) {
        todo!()
    }

    fn process_message_query(&self, message: adnlmessage::Query) {
        todo!()
    }

    fn process_message_answer(&self, message: adnlmessage::Answer) {
        todo!()
    }

    fn process_message_part(&self, message: adnlmessage::Part) {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
enum PeerError {
    #[error("Invalid new peer id")]
    InvalidNewPeerId,
}
