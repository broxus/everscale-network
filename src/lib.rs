#![allow(clippy::too_many_arguments)]

use std::sync::Arc;

use anyhow::Result;
use frunk_core::hlist::{HCons, HList, HNil, IntoTuple2, Selector};
use frunk_core::indices::{Here, There};

pub use self::adnl::{AdnlNode, AdnlNodeMetrics, AdnlNodeOptions, Keystore, NewPeerContext};
#[cfg(feature = "dht")]
pub use self::dht::{DhtNode, DhtNodeMetrics, DhtNodeOptions};
#[cfg(feature = "overlay")]
pub use self::overlay::{OverlayNode, OverlayShard, OverlayShardMetrics, OverlayShardOptions};
#[cfg(feature = "rldp")]
pub use self::rldp::{RldpNode, RldpNodeMetrics, RldpNodeOptions};
pub use self::subscriber::{MessageSubscriber, QueryConsumingResult, QuerySubscriber};

pub mod adnl;
#[cfg(feature = "dht")]
pub mod dht;
#[cfg(feature = "full")]
pub mod network;
#[cfg(feature = "overlay")]
pub mod overlay;
pub mod proto;
#[cfg(feature = "rldp")]
pub mod rldp;
mod subscriber;
pub mod utils;

pub struct NetworkBuilder<T, I>(T, std::marker::PhantomData<I>);

impl<I> NetworkBuilder<HCons<Arc<AdnlNode>, HNil>, I> {
    pub fn build(self) -> Arc<AdnlNode> {
        self.0.head
    }
}

impl<T, I> NetworkBuilder<T, I>
where
    T: utils::untuple::HConsUntuple,
{
    pub fn build(self) -> T::Output {
        self.0.untuple()
    }
}

impl NetworkBuilder<HNil, Here> {
    pub fn with_adnl<T>(
        socket_addr: T,
        keystore: Keystore,
        options: AdnlNodeOptions,
    ) -> NetworkBuilder<HCons<Arc<AdnlNode>, HNil>, Here>
    where
        T: Into<utils::PackedSocketAddr>,
    {
        NetworkBuilder(
            HCons {
                head: AdnlNode::new(socket_addr, keystore, options, None),
                tail: HNil,
            },
            Default::default(),
        )
    }
}

#[cfg(feature = "dht")]
impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<Arc<AdnlNode>, I>,
    HCons<Arc<DhtNode>, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_dht(
        self,
        key_tag: usize,
        options: DhtNodeOptions,
    ) -> Result<NetworkBuilder<HCons<Arc<DhtNode>, L>, There<I>>> {
        let adnl = self.0.get();
        let dht = DhtNode::new(adnl.clone(), key_tag, options)?;
        Ok(NetworkBuilder(self.0.prepend(dht), Default::default()))
    }
}

#[cfg(feature = "rldp")]
impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<Arc<AdnlNode>, I>,
    HCons<Arc<RldpNode>, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_rldp(
        self,
        options: RldpNodeOptions,
    ) -> Result<NetworkBuilder<HCons<Arc<RldpNode>, L>, There<I>>> {
        let adnl = self.0.get();
        let rldp = RldpNode::new(adnl.clone(), Default::default(), options);
        Ok(NetworkBuilder(self.0.prepend(rldp), Default::default()))
    }
}

#[cfg(feature = "overlay")]
impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<Arc<RldpNode>, Here> + Selector<Arc<AdnlNode>, I>,
    HCons<Arc<RldpNode>, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_overlay(
        self,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> Result<NetworkBuilder<HCons<Arc<OverlayNode>, L>, There<I>>> {
        let adnl: &Arc<AdnlNode> = self.0.get();
        let overlay = OverlayNode::new(adnl.clone(), zero_state_file_hash, key_tag)?;
        Ok(NetworkBuilder(self.0.prepend(overlay), Default::default()))
    }
}

// fn example() -> Result<()> {
//     let (adnl, rldp, dht) = NetworkBuilder::with_adnl(
//         utils::PackedSocketAddr::localhost(1),
//         Default::default(),
//         Default::default(),
//     )
//     .with_rldp(Default::default())?
//     .with_dht(0, Default::default())?
//     .build();
//
//     Ok(())
// }
