use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Barrier;

#[derive(Default)]
pub struct RldpPeer {
    queries: AtomicU32,
    queue: Mutex<VecDeque<Arc<Barrier>>>,
}

impl RldpPeer {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn begin_query(&self) {
        if self.queries.fetch_add(1, Ordering::Acquire) < MAX_QUERIES {
            return;
        }

        let barrier = Arc::new(Barrier::new(2));
        self.queue.lock().push_back(barrier.clone());
        barrier.wait().await;
    }

    pub async fn end_query(&self) {
        if self.queries.fetch_sub(1, Ordering::Acquire) < MAX_QUERIES {
            return;
        }

        loop {
            if let Some(barrier) = self.queue.lock().pop_front() {
                barrier.wait().await;
                return;
            }

            tokio::task::yield_now().await;
        }
    }
}

const MAX_QUERIES: u32 = 3;
