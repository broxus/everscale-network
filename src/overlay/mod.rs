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
    use frunk_core::indices::There;

    pub use super::node::Node;
    pub use super::overlay::{
        BroadcastTarget, IncomingBroadcastInfo, OutgoingBroadcastInfo, Overlay, OverlayMetrics,
        OverlayOptions, ReceivedPeersMap,
    };

    use crate::rldp;
    use crate::util::{DeferredInitialization, NetworkBuilder};

    pub(crate) type Deferred = Result<Arc<Node>>;

    impl DeferredInitialization for Deferred {
        type Initialized = Arc<Node>;

        fn initialize(self) -> Result<Self::Initialized> {
            self
        }
    }

    impl<L, A, R> NetworkBuilder<L, (A, R)>
    where
        L: HList + Selector<rldp::Deferred, R>,
        HCons<Deferred, L>: IntoTuple2,
    {
        /// Creates overlay network layer.
        ///
        /// NOTE: RLDP network layer must be present before calling this method.
        ///
        /// # Examples
        ///
        /// ```
        /// # use anyhow::Result;
        /// # use everscale_network::{adnl, rldp, NetworkBuilder};
        /// #[tokio::main]
        /// async fn main() -> Result<()> {
        ///     const OVERLAY_KEY_TAG: usize = 0;
        ///
        ///     let keystore = adnl::Keystore::builder()
        ///         .with_tagged_key([0; 32], OVERLAY_KEY_TAG)?
        ///         .build();
        ///
        ///     let adnl_options = adnl::NodeOptions::default();
        ///     let rldp_options = rldp::NodeOptions::default();
        ///
        ///     let (adnl, rldp, overlay) =
        ///         NetworkBuilder::with_adnl("127.0.0.1:10000", keystore, adnl_options)
        ///             .with_rldp(rldp_options)
        ///             .with_overlay(OVERLAY_KEY_TAG)
        ///             .build()?;
        ///     Ok(())
        /// }
        /// ```
        #[allow(clippy::type_complexity)]
        pub fn with_overlay(
            mut self,
            key_tag: usize,
        ) -> NetworkBuilder<HCons<Deferred, L>, (There<A>, There<R>)> {
            let deferred = match self.0.get_mut() {
                Ok((adnl, subscribers, _)) => {
                    let overlay = Node::new(adnl.clone(), key_tag);
                    if let Ok(overlay) = &overlay {
                        subscribers.push(overlay.query_subscriber());
                    }
                    overlay
                }
                Err(_) => Err(anyhow::anyhow!("ADNL was not initialized")),
            };

            NetworkBuilder(self.0.prepend(deferred), Default::default())
        }
    }

    /// Max allowed known peer count
    pub const MAX_OVERLAY_PEERS: u32 = 65536;
}

#[cfg(feature = "overlay")]
pub use node_impl::*;
