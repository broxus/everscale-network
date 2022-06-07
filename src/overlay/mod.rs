//! ## Overlay - virtual subnetwork
//!
//! An overlay (sub)network is simply a (virtual) network implemented inside some larger network.
//! Only some nodes of the larger network participate in the overlay subnetwork,
//! and only some "links" between these nodes, physical or virtual, are part of the overlay
//! sub-network.
//!
//! TODO

use std::sync::Arc;

use anyhow::Result;
use frunk_core::hlist::{HCons, HList, IntoTuple2, Selector};
use frunk_core::indices::{Here, There};

pub use node::OverlayNode;
pub use overlay_shard::{
    IncomingBroadcastInfo, OutgoingBroadcastInfo, OverlayShard, OverlayShardMetrics,
    OverlayShardOptions, ReceivedPeersMap,
};

use crate::adnl::AdnlNode;
use crate::rldp::DeferredRldpNode;
use crate::utils::{DeferredInitialization, NetworkBuilder};

mod broadcast_receiver;
mod node;
mod overlay_shard;

pub(crate) type DeferredOverlayNode = Result<Arc<OverlayNode>>;

impl DeferredInitialization for DeferredOverlayNode {
    type Initialized = Arc<OverlayNode>;

    fn initialize(self) -> Result<Self::Initialized> {
        self
    }
}

impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<DeferredRldpNode, Here> + Selector<Arc<AdnlNode>, I>,
    HCons<DeferredOverlayNode, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_overlay(
        mut self,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> NetworkBuilder<HCons<DeferredOverlayNode, L>, There<I>> {
        let adnl: &Arc<AdnlNode> = self.0.get();
        let overlay = OverlayNode::new(adnl.clone(), zero_state_file_hash, key_tag);
        if let Ok(overlay) = &overlay {
            let rldp: &mut DeferredRldpNode = self.0.get_mut();
            rldp.1.push(overlay.query_subscriber());
        }

        NetworkBuilder(self.0.prepend(overlay), Default::default())
    }
}

/// Max allowed known peer count
pub const MAX_OVERLAY_PEERS: usize = 65536;
