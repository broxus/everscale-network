use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, StreamExt};
use tl_proto::TlRead;

use super::streams::DhtValuesStream;
use super::DhtNode;
use crate::proto;

/// Future for the `DhtNode::store_value` method.
#[must_use = "futures do nothing unless polled"]
pub struct DhtStoreValue {
    dht: Arc<DhtNode>,
    key: proto::dht::KeyOwned,
    query: Bytes,
    futures: FuturesUnordered<StoreFuture>,
    started: bool,
}

impl DhtStoreValue {
    pub(super) fn new(dht: Arc<DhtNode>, value: proto::dht::Value<'_>) -> Result<Self> {
        dht.storage.insert(value)?;

        let key = value.key.key.as_equivalent_owned();
        let query = tl_proto::serialize(proto::rpc::DhtStore { value }).into();

        Ok(Self {
            dht,
            key,
            query,
            futures: Default::default(),
            started: false,
        })
    }

    /// Wraps `DhtStoreValue` into future which verifies that value is stored in the DHT
    /// and passes the predicate test
    pub fn then_check<T, FV>(self, check_value: FV) -> DhtStoreValueWithCheck<T, FV> {
        DhtStoreValueWithCheck {
            store_value: self,
            find_value: None,
            check_value,
            check_all: false,
            _marker: Default::default(),
        }
    }

    /// Drops the future, causing the value to be stored only locally
    pub fn only_locally(self) {}
}

impl Future for DhtStoreValue {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            for &peer_id in self.dht.known_peers.iter() {
                let dht = self.dht.clone();
                let query = self.query.clone();
                self.futures.push(Box::pin(async move {
                    dht.query_raw(&peer_id, query).await.ok();
                }));
            }
            self.started = true;
        }

        loop {
            match self.futures.poll_next_unpin(cx) {
                Poll::Ready(Some(_)) => continue,
                Poll::Ready(None) => break Poll::Ready(()),
                Poll::Pending => break Poll::Pending,
            }
        }
    }
}

/// Future for the `DhtStoreValue::ensure_stored` method.
#[must_use = "futures do nothing unless polled"]
pub struct DhtStoreValueWithCheck<T, FV> {
    store_value: DhtStoreValue,
    find_value: Option<DhtValuesStream<T>>,
    check_value: FV,
    check_all: bool,
    _marker: std::marker::PhantomData<T>,
}

impl<T, FV> DhtStoreValueWithCheck<T, FV> {
    /// Forces the future to check all stored values
    pub fn check_all(mut self) -> Self {
        self.check_all = true;
        self
    }
}

impl<T, FV> Unpin for DhtStoreValueWithCheck<T, FV> {}

impl<T, FV> Future for DhtStoreValueWithCheck<T, FV>
where
    FV: FnMut(proto::dht::KeyDescriptionOwned, T) -> Result<bool>,
    for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
{
    type Output = Result<bool>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.find_value {
                None => {
                    futures_util::ready!(self.store_value.poll_unpin(cx));
                    self.find_value = Some(
                        DhtValuesStream::new(
                            self.store_value.dht.clone(),
                            self.store_value.key.as_equivalent_ref(),
                        )
                        .use_new_peers(true),
                    );
                }
                Some(find_value) => match find_value.poll_next_unpin(cx) {
                    Poll::Ready(Some((key, value))) => match (self.check_value)(key, value) {
                        Ok(true) => break Poll::Ready(Ok(true)),
                        Ok(false) => continue,
                        Err(e) => break Poll::Ready(Err(e)),
                    },
                    Poll::Ready(None) => break Poll::Ready(Ok(false)),
                    Poll::Pending => break Poll::Pending,
                },
            }
        }
    }
}

type StoreFuture = BoxFuture<'static, ()>;
