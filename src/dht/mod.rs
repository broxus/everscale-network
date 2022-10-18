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

pub(crate) type Deferred = Result<(Arc<adnl::Node>, usize, NodeOptions)>;

impl DeferredInitialization for Deferred {
    type Initialized = Arc<Node>;

    fn initialize(self) -> Result<Self::Initialized> {
        let (adnl, key_tag, options) = self?;
        Node::new(adnl, key_tag, options)
    }
}

impl<L, A, R> NetworkBuilder<L, (A, R)>
where
    L: HList + Selector<adnl::Deferred, A>,
    HCons<Deferred, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_dht(
        self,
        key_tag: usize,
        options: NodeOptions,
    ) -> NetworkBuilder<HCons<Deferred, L>, (There<A>, There<R>)> {
        let deferred = match self.0.get() {
            Ok(adnl) => Ok((adnl.clone(), key_tag, options)),
            Err(_) => Err(anyhow::anyhow!("ADNL was not initialized")),
        };
        NetworkBuilder(self.0.prepend(deferred), Default::default())
    }
}

pub const KEY_ADDRESS: &str = "address";
pub const KEY_NODES: &str = "nodes";

pub const MAX_DHT_PEERS: usize = 65536;
