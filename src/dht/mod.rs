//! ## DHT - Kademlia-like Distributed Hash Table
//!
//! TODO

use std::sync::Arc;

use anyhow::Result;
use frunk_core::hlist::{HCons, HList, IntoTuple2, Selector};
use frunk_core::indices::There;

pub use entry::Entry;
pub use node::{Node, NodeMetrics, NodeOptions};

use crate::adnl;
use crate::utils::{DeferredInitialization, NetworkBuilder};

mod buckets;
mod entry;
pub mod futures;
mod node;
mod peers_iter;
mod storage;
pub mod streams;

pub(crate) type Deferred = (Arc<adnl::Node>, usize, NodeOptions);

impl DeferredInitialization for Deferred {
    type Initialized = Arc<Node>;

    fn initialize(self) -> Result<Self::Initialized> {
        Node::new(self.0, self.1, self.2)
    }
}

impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<Arc<adnl::Node>, I>,
    HCons<Deferred, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_dht(
        self,
        key_tag: usize,
        options: NodeOptions,
    ) -> NetworkBuilder<HCons<Deferred, L>, There<I>> {
        let deferred_dht = (self.0.get().clone(), key_tag, options);
        NetworkBuilder(self.0.prepend(deferred_dht), Default::default())
    }
}

pub const KEY_ADDRESS: &str = "address";
pub const KEY_NODES: &str = "nodes";

pub const MAX_DHT_PEERS: usize = 65536;
