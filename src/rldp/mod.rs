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
use frunk_core::indices::{Here, There};

pub(crate) use decoder::RaptorQDecoder;
pub(crate) use encoder::RaptorQEncoder;
pub use node::{Node, NodeMetrics, NodeOptions};

use crate::adnl;
use crate::subscriber::QuerySubscriber;
use crate::utils::{DeferredInitialization, NetworkBuilder};

pub(crate) mod compression;
mod decoder;
mod encoder;
mod incoming_transfer;
mod node;
mod outgoing_transfer;
mod transfers_cache;

pub(crate) type Deferred = Result<(Arc<adnl::Node>, Vec<Arc<dyn QuerySubscriber>>, NodeOptions)>;

impl DeferredInitialization for Deferred {
    type Initialized = Arc<Node>;

    fn initialize(self) -> Result<Self::Initialized> {
        let (adnl, subscripts, options) = self?;
        Node::new(adnl, subscripts, options)
    }
}

impl<L, A, R> NetworkBuilder<L, (A, R)>
where
    L: HList + Selector<adnl::Deferred, A>,
    HCons<Deferred, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_rldp(
        self,
        options: NodeOptions,
    ) -> NetworkBuilder<HCons<Deferred, L>, (There<A>, Here)> {
        self.with_rldp_ext(options, Vec::new())
    }

    #[allow(clippy::type_complexity)]
    pub fn with_rldp_ext(
        self,
        options: NodeOptions,
        subscribers: Vec<Arc<dyn QuerySubscriber>>,
    ) -> NetworkBuilder<HCons<Deferred, L>, (There<A>, Here)> {
        let deferred = match self.0.get() {
            Ok(adnl) => Ok((adnl.clone(), subscribers, options)),
            Err(_) => Err(anyhow::anyhow!("ADNL was not initialized")),
        };
        NetworkBuilder(self.0.prepend(deferred), Default::default())
    }
}
