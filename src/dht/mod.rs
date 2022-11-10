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
use crate::util::{DeferredInitialization, NetworkBuilder};

mod buckets;
mod entry;
mod node;
mod peers_iter;
mod storage;

/// DHT helper futures
pub mod futures;
/// DHT helper streams
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
    /// Creates DHT network layer
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    ///
    /// use everscale_network::{adnl, dht, NetworkBuilder};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn Error>> {
    ///     const DHT_KEY_TAG: usize = 0;
    ///
    ///     let keystore = adnl::Keystore::builder()
    ///         .with_tagged_key([0; 32], DHT_KEY_TAG)?
    ///         .build();
    ///
    ///     let adnl_options = adnl::NodeOptions::default();
    ///     let dht_options = dht::NodeOptions::default();
    ///
    ///     let (adnl, dht) = NetworkBuilder::with_adnl("127.0.0.1:10000", keystore, adnl_options)
    ///         .with_dht(DHT_KEY_TAG, dht_options)
    ///         .build()?;
    ///     Ok(())
    /// }
    /// ```
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

/// DHT key name used for storing nodes socket address
pub const KEY_ADDRESS: &str = "address";

/// DHT key name used for storing overlay nodes
pub const KEY_NODES: &str = "nodes";

/// Max allowed DHT peers in the network
pub const MAX_DHT_PEERS: u32 = 65536;
