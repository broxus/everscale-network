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
use crate::util::{DeferredInitialization, NetworkBuilder};

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
        let (adnl, subscribers, options) = self?;
        Node::new(adnl, subscribers, options)
    }
}

impl<L, A, R> NetworkBuilder<L, (A, R)>
where
    L: HList + Selector<adnl::Deferred, A>,
    HCons<Deferred, L>: IntoTuple2,
{
    /// Creates RLDP network layer
    ///
    /// See [`with_rldp_ext`] if you need an RLDP node with additional subscribers
    ///
    /// [`with_rldp_ext`]: fn@crate::util::NetworkBuilder::with_rldp_ext
    ///
    /// # Examples
    ///
    /// ```
    /// # use anyhow::Result;
    /// # use everscale_network::{adnl, rldp, NetworkBuilder};
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let keystore = adnl::Keystore::builder()
    ///         .with_tagged_key([0; 32], 0)?
    ///         .build();
    ///
    ///     let adnl_options = adnl::NodeOptions::default();
    ///     let rldp_options = rldp::NodeOptions::default();
    ///
    ///     let (adnl, rldp) = NetworkBuilder::with_adnl("127.0.0.1:10000", keystore, adnl_options)
    ///         .with_rldp(rldp_options)
    ///         .build()?;
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn with_rldp(
        self,
        options: NodeOptions,
    ) -> NetworkBuilder<HCons<Deferred, L>, (There<A>, Here)> {
        self.with_rldp_ext(options, Vec::new())
    }

    /// Creates RLDP network layer with additional RLDP query subscribers
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use std::sync::Arc;
    /// # use anyhow::Result;
    /// # use everscale_network::{
    /// #     adnl, rldp, NetworkBuilder, QueryConsumingResult, QuerySubscriber, SubscriberContext,
    /// # };
    /// struct LoggerSubscriber;
    ///
    /// #[async_trait::async_trait]
    /// impl QuerySubscriber for LoggerSubscriber {
    ///     async fn try_consume_query<'a>(
    ///         &self,
    ///         ctx: SubscriberContext<'a>,
    ///         constructor: u32,
    ///         query: Cow<'a, [u8]>,
    ///     ) -> Result<QueryConsumingResult<'a>> {
    ///         println!("received {constructor}");
    ///         Ok(QueryConsumingResult::Rejected(query))
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let keystore = adnl::Keystore::builder()
    ///         .with_tagged_key([0; 32], 0)?
    ///         .build();
    ///
    ///     let adnl_options = adnl::NodeOptions::default();
    ///     let rldp_options = rldp::NodeOptions::default();
    ///
    ///     let subscriber = Arc::new(LoggerSubscriber);
    ///
    ///     let (adnl, rldp) = NetworkBuilder::with_adnl("127.0.0.1:10000", keystore, adnl_options)
    ///         .with_rldp_ext(rldp_options, vec![subscriber])
    ///         .build()?;
    ///     Ok(())
    /// }
    /// ```
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
