use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crossbeam_queue::SegQueue;
use tokio::sync::Barrier;

pub struct BroadcastReceiver<T> {
    data: SegQueue<T>,
    barriers: SegQueue<Arc<Barrier>>,
    sync_lock: AtomicU32,
}

impl<T: Send + 'static> BroadcastReceiver<T> {
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    pub fn barriers_len(&self) -> usize {
        self.barriers.len()
    }

    pub fn push(self: &Arc<Self>, data: T) {
        self.data.push(data);
        let receiver = self.clone();
        tokio::spawn(async move {
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

    pub async fn pop(&self) -> T {
        self.sync_lock.fetch_add(1, Ordering::Release);
        loop {
            match self.data.pop() {
                Some(data) => {
                    self.sync_lock.fetch_sub(1, Ordering::Release);
                    return data;
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

impl<T> Default for BroadcastReceiver<T> {
    fn default() -> Self {
        Self {
            data: Default::default(),
            barriers: Default::default(),
            sync_lock: Default::default(),
        }
    }
}
