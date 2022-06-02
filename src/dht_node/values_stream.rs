use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};
use pin_project_lite::pin_project;
use tl_proto::TlRead;

use super::{DhtNode, PeersIter, ReceivedValue};
use crate::proto;

pin_project! {
    pub struct DhtValuesStream<T> {
        dht: Arc<DhtNode>,
        key: proto::dht::KeyOwned,
        batch_len: Option<usize>,
        known_peers_version: u64,
        peers_iter: PeersIter,
        #[pin]
        futures: FuturesUnordered<ValueFuture<T>>,
        future_count: usize,
        _marker: std::marker::PhantomData<T>,
    }
}

impl<T> DhtValuesStream<T>
where
    for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
{
    pub(super) fn new(dht: Arc<DhtNode>, key: proto::dht::Key<'_>) -> Self {
        let key_id = tl_proto::hash_as_boxed(key);
        let mut peers_iter = PeersIter::with_key_id(key_id);

        let known_peers_version = dht.known_peers.version();

        Self {
            dht,
            key: key.as_equivalent_owned(),
            batch_len: None,
            known_peers_version,
            peers_iter,
            futures: Default::default(),
            future_count: Default::default(),
            _marker: Default::default(),
        }
    }

    pub fn with_batch_len(mut self, batch_len: usize) -> Self {
        self.batch_len = Some(batch_len);
        self
    }
}

impl<T> Stream for DhtValuesStream<T>
where
    for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
{
    type Item = ReceivedValue<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            if *this.future_count == 0 {
                this.peers_iter.reset(this.dht, *this.batch_len);
                refill_futures(
                    this.dht,
                    this.peers_iter,
                    this.key,
                    &this.futures,
                    this.future_count,
                );
            }

            match this.futures.poll_next_unpin(cx) {
                Poll::Ready(Some(value)) => {
                    match this.dht.known_peers.version() {
                        version if version != *this.known_peers_version => {
                            this.peers_iter.reset(this.dht, *this.batch_len);
                            *this.known_peers_version = version;
                        }
                        _ => {}
                    }

                    *this.future_count -= 1;
                    refill_futures(
                        this.dht,
                        this.peers_iter,
                        this.key,
                        &this.futures,
                        this.future_count,
                    );

                    if let Some(value) = value {
                        break Poll::Ready(Some(value));
                    }
                }
                Poll::Ready(None) => break Poll::Ready(None),
                Poll::Pending => break Poll::Pending,
            }
        }
    }
}

fn refill_futures<T>(
    dht: &Arc<DhtNode>,
    peers_iter: &mut PeersIter,
    key: &proto::dht::KeyOwned,
    futures: &FuturesUnordered<ValueFuture<T>>,
    future_count: &mut usize,
) where
    for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
{
    // Spawn at most `max_tasks` queries
    while let Some(peer_id) = peers_iter.next() {
        let dht = dht.clone();
        let key = key.clone();

        futures.push(Box::pin(async move {
            let key = key.as_equivalent_ref();
            match dht.query_value::<T>(&peer_id, key).await {
                Ok(value) => value,
                Err(e) => {
                    tracing::warn!("Failed to query value: {e}");
                    None
                }
            }
        }));

        *future_count += 1;
        if *future_count > MAX_PARALLEL_FUTURES {
            break;
        }
    }
}

type ValueFuture<T> = BoxFuture<'static, Option<ReceivedValue<T>>>;

const MAX_PARALLEL_FUTURES: usize = 10;
