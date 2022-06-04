use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};
use tl_proto::TlRead;

use super::node::DhtNode;
use super::peers_iter::PeersIter;
use crate::proto;

/// Stream for the `DhtNode::values` method.
#[must_use = "streams do nothing unless polled"]
pub struct DhtValuesStream<T> {
    dht: Arc<DhtNode>,
    key: proto::dht::KeyOwned,
    batch_len: Option<usize>,
    known_peers_version: u64,
    use_new_peers: bool,
    peers_iter: PeersIter,
    futures: FuturesUnordered<ValueFuture<T>>,
    future_count: usize,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Unpin for DhtValuesStream<T> {}

impl<T> DhtValuesStream<T>
where
    for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
{
    pub(super) fn new(dht: Arc<DhtNode>, key: proto::dht::Key<'_>) -> Self {
        let key_id = tl_proto::hash_as_boxed(key);
        let peers_iter = PeersIter::with_key_id(key_id);

        let batch_len = Some(dht.options.default_value_batch_len);
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

    fn refill_futures(&mut self) {
        // Spawn at most `max_tasks` queries
        while let Some(peer_id) = self.peers_iter.next() {
            let dht = self.dht.clone();
            let key = self.key.clone();

            self.futures.push(Box::pin(async move {
                let key = key.as_equivalent_ref();
                match dht.query_value::<T>(&peer_id, key).await {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::warn!("Failed to query value: {e}");
                        None
                    }
                }
            }));

            self.future_count += 1;
            if self.future_count > MAX_PARALLEL_FUTURES {
                break;
            }
        }
    }
}

impl<T> Stream for DhtValuesStream<T>
where
    for<'a> T: TlRead<'a, Repr = tl_proto::Boxed> + Send + 'static,
{
    type Item = ReceivedValue<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Fill iterator during the first poll
        if this.future_count == usize::MAX {
            this.peers_iter.fill(&this.dht, this.batch_len);
            this.future_count = 0;
        }

        loop {
            // Keep starting new futures when we can
            if this.future_count < MAX_PARALLEL_FUTURES {
                this.refill_futures();
            }

            match this.futures.poll_next_unpin(cx) {
                Poll::Ready(Some(value)) => {
                    // Refill peers iterator when version has changed and `use_new_peers` is set
                    match this.dht.known_peers.version() {
                        version if this.use_new_peers && version != this.known_peers_version => {
                            this.peers_iter.fill(&this.dht, this.batch_len);
                            this.known_peers_version = version;
                        }
                        _ => {}
                    }

                    // Decrease the number of parallel futures on each new item from `futures`
                    this.future_count -= 1;

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

type ValueFuture<T> = BoxFuture<'static, Option<ReceivedValue<T>>>;
type ReceivedValue<T> = (proto::dht::KeyDescriptionOwned, T);

const MAX_PARALLEL_FUTURES: usize = 5;
