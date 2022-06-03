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
        use_new_peers: bool,
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
        let peers_iter = PeersIter::with_key_id(key_id);

        let batch_len = Some(dht.options.query_value_batch_len);
        let known_peers_version = dht.known_peers.version();

        Self {
            dht,
            key: key.as_equivalent_owned(),
            batch_len,
            known_peers_version,
            use_new_peers: false,
            peers_iter,
            futures: Default::default(),
            future_count: usize::MAX,
            _marker: Default::default(),
        }
    }

    /// Use all DHT nodes in peers iterator
    pub fn use_full_batch(mut self) -> Self {
        self.batch_len = None;
        self
    }

    /// Whether stream should fill peers iterator when new nodes are found
    pub fn use_new_peers(mut self, enable: bool) -> Self {
        self.use_new_peers = enable;
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

        // Fill iterator during the first poll
        if *this.future_count == usize::MAX {
            this.peers_iter.fill(this.dht, *this.batch_len);
            *this.future_count = 0;
        }

        loop {
            // Keep starting new futures when we can
            if *this.future_count < MAX_PARALLEL_FUTURES {
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
                    // Refill peers iterator when version has changed and `use_new_peers` is set
                    match this.dht.known_peers.version() {
                        version if *this.use_new_peers && version != *this.known_peers_version => {
                            this.peers_iter.fill(this.dht, *this.batch_len);
                            *this.known_peers_version = version;
                        }
                        _ => {}
                    }

                    // Decrease the number of parallel futures on each new item from `futures`
                    *this.future_count -= 1;

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

const MAX_PARALLEL_FUTURES: usize = 5;
