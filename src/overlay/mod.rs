//! ## Overlay - virtual subnetwork
//!
//! An overlay (sub)network is simply a (virtual) network implemented inside some larger network.
//! Only some nodes of the larger network participate in the overlay subnetwork,
//! and only some "links" between these nodes, physical or virtual, are part of the overlay
//! sub-network.
//!
//! TODO

pub use overlay_id::{IdFull, IdShort};

mod overlay_id;

#[cfg(feature = "overlay")]
mod broadcast_receiver;
#[cfg(feature = "overlay")]
mod node;
#[cfg(feature = "overlay")]
#[allow(clippy::module_inception)]
mod overlay;

#[cfg(feature = "overlay")]
mod node_impl {
    use std::sync::Arc;

    use anyhow::Result;
    use frunk_core::hlist::{HCons, HList, IntoTuple2, Selector};
    use frunk_core::indices::{Here, There};

    pub use super::node::Node;
    pub use super::overlay::{
        BroadcastTarget, IncomingBroadcastInfo, OutgoingBroadcastInfo, Overlay, OverlayMetrics,
        OverlayOptions, ReceivedPeersMap,
    };

    use crate::adnl;
    use crate::rldp;
    use crate::utils::{DeferredInitialization, NetworkBuilder};

    pub(crate) type Deferred = Result<Arc<Node>>;

    impl DeferredInitialization for Deferred {
        type Initialized = Arc<Node>;

        fn initialize(self) -> Result<Self::Initialized> {
            self
        }
    }

    impl<L, I> NetworkBuilder<L, I>
    where
        L: HList + Selector<rldp::Deferred, Here> + Selector<Arc<adnl::Node>, I>,
        HCons<Deferred, L>: IntoTuple2,
    {
        #[allow(clippy::type_complexity)]
        pub fn with_overlay(
            mut self,
            key_tag: usize,
        ) -> NetworkBuilder<HCons<Deferred, L>, There<I>> {
            let adnl: &Arc<adnl::Node> = self.0.get();
            let overlay = Node::new(adnl.clone(), key_tag);
            if let Ok(overlay) = &overlay {
                let rldp: &mut rldp::Deferred = self.0.get_mut();
                rldp.1.push(overlay.query_subscriber());
            }

            NetworkBuilder(self.0.prepend(overlay), Default::default())
        }
    }

    /// Max allowed known peer count
    pub const MAX_OVERLAY_PEERS: usize = 65536;
}

#[cfg(feature = "overlay")]
pub use node_impl::*;
