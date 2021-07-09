use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crossbeam_queue::SegQueue;
use tokio::sync::Barrier;

#[derive(Default)]
pub struct RldpPeer {
    queries: AtomicU32,
    queue: SegQueue<Arc<Barrier>>,
}

impl RldpPeer {
    pub async fn begin_query(&self) {
        if self.queries.fetch_add(1, Ordering::AcqRel) < MAX_QUERIES {
            return;
        }

        let barrier = Arc::new(Barrier::new(2));
        self.queue.push(barrier.clone());
        barrier.wait().await;
    }

    pub async fn end_query(&self) {
        if self.queries.fetch_sub(1, Ordering::AcqRel) < MAX_QUERIES {
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

const MAX_QUERIES: u32 = 3;
