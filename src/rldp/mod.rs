//! ## RLDP - Reliable Large Datagram Protocol
//!
//! A reliable arbitrary-size datagram protocol built upon the ADNL, called RLDP, is used instead
//! of a TCP-like protocol. This reliable datagram protocol can be employed, for instance,
//! to send RPC queries to remote hosts and receive answers from them.
//!
//! TODO

use std::sync::Arc;

use anyhow::Result;
use frunk_core::hlist::{HCons, HList, IntoTuple2, Selector};
use frunk_core::indices::There;

pub use node::{RldpNode, RldpNodeMetrics, RldpNodeOptions};

use crate::adnl::AdnlNode;
use crate::subscriber::QuerySubscriber;
use crate::utils::{DeferredInitialization, NetworkBuilder};

pub(crate) mod decoder;
pub(crate) mod encoder;
mod incoming_transfer;
mod node;
mod outgoing_transfer;
mod transfers_cache;

pub(crate) type DeferredRldpNode = (
    Arc<AdnlNode>,
    Vec<Arc<dyn QuerySubscriber>>,
    RldpNodeOptions,
);

impl DeferredInitialization for DeferredRldpNode {
    type Initialized = Arc<RldpNode>;

    fn initialize(self) -> Result<Self::Initialized> {
        RldpNode::new(self.0, self.1, self.2)
    }
}

impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<Arc<AdnlNode>, I>,
    HCons<DeferredRldpNode, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_rldp(
        self,
        options: RldpNodeOptions,
    ) -> NetworkBuilder<HCons<DeferredRldpNode, L>, There<I>> {
        let rldp = (self.0.get().clone(), Vec::new(), options);
        NetworkBuilder(self.0.prepend(rldp), Default::default())
    }
}
