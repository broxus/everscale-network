use anyhow::Result;

use super::DeferredInitializationList;

/// Convenient network layer builder
pub struct NetworkBuilder<T, I>(pub(crate) T, pub(crate) std::marker::PhantomData<I>);

impl<T, I> NetworkBuilder<T, I>
where
    T: DeferredInitializationList,
{
    pub fn build(self) -> Result<T::Output> {
        self.0.initialize()
    }
}
