use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use tokio::sync::Barrier;

pub struct RldpPeer {
    max_queries: u32,
    queries: AtomicU32,
    queue: SegQueue<Arc<Barrier>>,
}

impl RldpPeer {
    pub fn new(max_queries: u32) -> Self {
        Self {
            max_queries,
            queries: Default::default(),
            queue: Default::default(),
        }
    }

    pub async fn begin_query(self: &Arc<Self>) -> RldpQueryGuard {
        let state = Arc::new(RldpQueryGuardState {
            complete: AtomicBool::new(false),
            waker: Mutex::new(None),
        });
        let guard = RldpQueryGuard {
            state: state.clone(),
        };

        tokio::spawn({
            let peer = self.clone();
            async move {
                RldpQueryFinisher { state }.await;
                peer.end_query().await
            }
        });

        if self.queries.fetch_add(1, Ordering::AcqRel) < self.max_queries {
            return guard;
        }

        let barrier = Arc::new(Barrier::new(2));
        self.queue.push(barrier.clone());
        barrier.wait().await;

        guard
    }

    async fn end_query(&self) {
        if self.queries.fetch_sub(1, Ordering::AcqRel) <= self.max_queries {
            return;
        }

        loop {
            if let Some(barrier) = self.queue.pop() {
                barrier.wait().await;
                return;
            }

            tokio::task::yield_now().await;
        }
    }
}

pub struct RldpQueryGuard {
    state: Arc<RldpQueryGuardState>,
}

impl Drop for RldpQueryGuard {
    fn drop(&mut self) {
        if self.state.complete.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Some(waker) = std::mem::take(&mut *self.state.waker.lock()) {
            waker.wake();
        }
    }
}

struct RldpQueryFinisher {
    state: Arc<RldpQueryGuardState>,
}

impl Future for RldpQueryFinisher {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.state.complete.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        let mut waker = self.state.waker.lock();
        return if self.state.complete.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            *waker = Some(cx.waker().clone());
            Poll::Pending
        };
    }
}

struct RldpQueryGuardState {
    complete: AtomicBool,
    waker: Mutex<Option<Waker>>,
}
