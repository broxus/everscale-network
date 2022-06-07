//! ## DHT - Kademlia-like Distributed Hash Table
//!
//! TODO

use std::sync::Arc;

use anyhow::Result;
use frunk_core::hlist::{HCons, HList, IntoTuple2, Selector};
use frunk_core::indices::There;

pub use entry::DhtEntry;
pub use node::{DhtNode, DhtNodeMetrics, DhtNodeOptions};

use crate::adnl::AdnlNode;
use crate::utils::{DeferredInitialization, NetworkBuilder};

mod buckets;
mod entry;
pub mod futures;
mod node;
mod peers_iter;
mod storage;
pub mod streams;

pub(crate) type DeferredDhtNode = (Arc<AdnlNode>, usize, DhtNodeOptions);

impl DeferredInitialization for DeferredDhtNode {
    type Initialized = Arc<DhtNode>;

    fn initialize(self) -> Result<Self::Initialized> {
        DhtNode::new(self.0, self.1, self.2)
    }
}

impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<Arc<AdnlNode>, I>,
    HCons<DeferredDhtNode, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_dht(
        self,
        key_tag: usize,
        options: DhtNodeOptions,
    ) -> NetworkBuilder<HCons<DeferredDhtNode, L>, There<I>> {
        let deferred_dht = (self.0.get().clone(), key_tag, options);
        NetworkBuilder(self.0.prepend(deferred_dht), Default::default())
    }
}

const DHT_KEY_ADDRESS: &str = "address";
const DHT_KEY_NODES: &str = "nodes";

pub const MAX_DHT_PEERS: usize = 65536;
