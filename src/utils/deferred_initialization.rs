use anyhow::Result;
use frunk_core::hlist::{HCons, HNil};

pub trait DeferredInitialization {
    type Initialized;

    fn initialize(self) -> Result<Self::Initialized>;
}

pub trait DeferredInitializationList {
    type Output;

    fn initialize(self) -> Result<Self::Output>;
}

type BaseLayer<T> = HCons<T, HNil>;

impl<T, T1> DeferredInitializationList for HCons<T1, BaseLayer<T>>
where
    T1: DeferredInitialization,
{
    type Output = (T, T1::Initialized);

    fn initialize(self) -> Result<Self::Output> {
        let t1 = self.head.initialize()?;
        Ok((self.tail.head, t1))
    }
}

impl<T, T1, T2> DeferredInitializationList for HCons<T2, HCons<T1, BaseLayer<T>>>
where
    T1: DeferredInitialization,
    T2: DeferredInitialization,
{
    type Output = (T, T1::Initialized, T2::Initialized);

    fn initialize(self) -> Result<Self::Output> {
        let t2 = self.head.initialize()?;
        let t1 = self.tail.head.initialize()?;
        Ok((self.tail.tail.head, t1, t2))
    }
}

impl<T, T1, T2, T3> DeferredInitializationList for HCons<T3, HCons<T2, HCons<T1, BaseLayer<T>>>>
where
    T1: DeferredInitialization,
    T2: DeferredInitialization,
    T3: DeferredInitialization,
{
    type Output = (T, T1::Initialized, T2::Initialized, T3::Initialized);

    fn initialize(self) -> Result<Self::Output> {
        let t3 = self.head.initialize()?;
        let t2 = self.tail.head.initialize()?;
        let t1 = self.tail.tail.head.initialize()?;
        Ok((self.tail.tail.tail.head, t1, t2, t3))
    }
}

impl<T, T1, T2, T3, T4> DeferredInitializationList
    for HCons<T4, HCons<T3, HCons<T2, HCons<T1, BaseLayer<T>>>>>
where
    T1: DeferredInitialization,
    T2: DeferredInitialization,
    T3: DeferredInitialization,
    T4: DeferredInitialization,
{
    type Output = (
        T,
        T1::Initialized,
        T2::Initialized,
        T3::Initialized,
        T4::Initialized,
    );

    fn initialize(self) -> Result<Self::Output> {
        let t4 = self.head.initialize()?;
        let t3 = self.tail.head.initialize()?;
        let t2 = self.tail.tail.head.initialize()?;
        let t1 = self.tail.tail.tail.head.initialize()?;
        Ok((self.tail.tail.tail.tail.head, t1, t2, t3, t4))
    }
}
