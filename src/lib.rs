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
pub use self::subscriber::{
    MessageSubscriber, QueryConsumingResult, QuerySubscriber, SubscriberContext,
};

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
    T: NetworkBuilderParts,
{
    pub fn build(self) -> Result<T::Output> {
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

pub trait DeferredInitialization {
    type Initialized;
    fn initialize(self) -> Result<Self::Initialized>;
}

type DeferredDhtNode = (Arc<AdnlNode>, usize, DhtNodeOptions);

impl DeferredInitialization for DeferredDhtNode {
    type Initialized = Arc<DhtNode>;

    fn initialize(self) -> Result<Self::Initialized> {
        DhtNode::new(self.0, self.1, self.2)
    }
}

#[cfg(feature = "dht")]
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

type DeferredRldpNode = (
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

#[cfg(feature = "rldp")]
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

type DeferredOverlayNode = Result<Arc<OverlayNode>>;

#[cfg(feature = "overlay")]
impl<L, I> NetworkBuilder<L, I>
where
    L: HList + Selector<DeferredRldpNode, Here> + Selector<Arc<AdnlNode>, I>,
    HCons<DeferredOverlayNode, L>: IntoTuple2,
{
    #[allow(clippy::type_complexity)]
    pub fn with_overlay(
        mut self,
        zero_state_file_hash: [u8; 32],
        key_tag: usize,
    ) -> NetworkBuilder<HCons<DeferredOverlayNode, L>, There<I>> {
        let adnl: &Arc<AdnlNode> = self.0.get();
        let overlay = OverlayNode::new(adnl.clone(), zero_state_file_hash, key_tag);
        if let Ok(overlay) = &overlay {
            let rldp: &mut DeferredRldpNode = self.0.get_mut();
            rldp.1.push(overlay.query_subscriber());
        }

        NetworkBuilder(self.0.prepend(overlay), Default::default())
    }
}

pub trait NetworkBuilderParts {
    type Output;
    fn untuple(self) -> Result<Self::Output>;
}

type BaseLayer = HCons<Arc<AdnlNode>, HNil>;

impl<T1> NetworkBuilderParts for HCons<T1, BaseLayer>
where
    T1: DeferredInitialization,
{
    type Output = (Arc<AdnlNode>, T1::Initialized);

    fn untuple(self) -> Result<Self::Output> {
        let t1 = self.head.initialize()?;
        Ok((self.tail.head, t1))
    }
}

impl<T1, T2> NetworkBuilderParts for HCons<T2, HCons<T1, BaseLayer>>
where
    T1: DeferredInitialization,
    T2: DeferredInitialization,
{
    type Output = (Arc<AdnlNode>, T1::Initialized, T2::Initialized);

    fn untuple(self) -> Result<Self::Output> {
        let t2 = self.head.initialize()?;
        let t1 = self.tail.head.initialize()?;
        Ok((self.tail.tail.head, t1, t2))
    }
}

impl<T1, T2, T3> NetworkBuilderParts for HCons<T3, HCons<T2, HCons<T1, BaseLayer>>>
where
    T1: DeferredInitialization,
    T2: DeferredInitialization,
    T3: DeferredInitialization,
{
    type Output = (
        Arc<AdnlNode>,
        T1::Initialized,
        T2::Initialized,
        T3::Initialized,
    );

    fn untuple(self) -> Result<Self::Output> {
        let t3 = self.head.initialize()?;
        let t2 = self.tail.head.initialize()?;
        let t1 = self.tail.tail.head.initialize()?;
        Ok((self.tail.tail.tail.head, t1, t2, t3))
    }
}

impl<T1, T2, T3, T4> NetworkBuilderParts for HCons<T4, HCons<T3, HCons<T2, HCons<T1, BaseLayer>>>>
where
    T1: DeferredInitialization,
    T2: DeferredInitialization,
    T3: DeferredInitialization,
    T4: DeferredInitialization,
{
    type Output = (
        Arc<AdnlNode>,
        T1::Initialized,
        T2::Initialized,
        T3::Initialized,
        T4::Initialized,
    );

    fn untuple(self) -> Result<Self::Output> {
        let t4 = self.head.initialize()?;
        let t3 = self.tail.head.initialize()?;
        let t2 = self.tail.tail.head.initialize()?;
        let t1 = self.tail.tail.tail.head.initialize()?;
        Ok((self.tail.tail.tail.tail.head, t1, t2, t3, t4))
    }
}

// fn example() -> Result<()> {
//     let (adnl, rldp, dht) = NetworkBuilder::with_adnl(
//         utils::PackedSocketAddr::localhost(1),
//         Default::default(),
//         Default::default(),
//     )
//     .with_rldp(Default::default())
//     .with_dht(0, Default::default())
//     .build()?;
//
//     Ok(())
// }
