use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use tokio::sync::Barrier;

pub struct BroadcastReceiver<T> {
    data: SegQueue<T>,
    barriers: SegQueue<Arc<Barrier>>,
    sync_lock: AtomicU32,
}

impl<T: Send + 'static> BroadcastReceiver<T> {
    pub fn push(self: &Arc<Self>, data: T) {
        let receiver = self.clone();
        tokio::spawn(async move {
            receiver.data.push(data);
            while receiver.sync_lock.load(Ordering::Acquire) > 0 {
                if let Some(barrier) = receiver.barriers.pop() {
                    barrier.wait().await;
                    break;
                } else {
                    tokio::task::yield_now().await;
                }
            }
        });
    }

    pub async fn pop(&self) -> Result<T> {
        self.sync_lock.fetch_add(1, Ordering::Release);
        loop {
            match self.data.pop() {
                Some(data) => {
                    self.sync_lock.fetch_sub(1, Ordering::Release);
                    return Ok(data);
                }
                None => {
                    let barrier = Arc::new(Barrier::new(2));
                    self.barriers.push(barrier.clone());
                    barrier.wait().await;
                }
            }
        }
    }
}
