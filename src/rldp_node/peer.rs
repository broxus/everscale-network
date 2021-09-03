use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crossbeam_queue::SegQueue;
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

    pub async fn begin_query(&self) {
        if self.queries.fetch_add(1, Ordering::AcqRel) < self.max_queries {
            return;
        }

        let barrier = Arc::new(Barrier::new(2));
        self.queue.push(barrier.clone());
        barrier.wait().await;
    }

    pub async fn end_query(&self) {
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
