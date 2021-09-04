use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use parking_lot::Mutex;

use super::FxHashMap;

pub fn trigger() -> (Trigger, TriggerReceiver) {
    let state = Arc::new(State {
        complete: AtomicBool::new(false),
        wakers: Mutex::new(FxHashMap::default()),
        next_id: AtomicUsize::new(1),
    });
    (
        Trigger {
            state: state.clone(),
        },
        TriggerReceiver { id: 0, state },
    )
}

#[derive(Clone)]
pub struct Trigger {
    state: Arc<State>,
}

impl Trigger {
    pub fn trigger(&self) {
        if self.state.complete.swap(true, Ordering::AcqRel) {
            return;
        }

        let wakers = std::mem::take(&mut *self.state.wakers.lock());
        for waker in wakers.into_values() {
            waker.wake();
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.state.complete.load(Ordering::Acquire)
    }
}

pub struct TriggerReceiver {
    id: usize,
    state: Arc<State>,
}

impl Drop for TriggerReceiver {
    fn drop(&mut self) {
        if !self.state.complete.load(Ordering::Acquire) {
            self.state.wakers.lock().remove(&self.id);
        }
    }
}

impl Clone for TriggerReceiver {
    fn clone(&self) -> Self {
        Self {
            id: self.state.next_id.fetch_add(1, Ordering::AcqRel),
            state: self.state.clone(),
        }
    }
}

impl Future for TriggerReceiver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.state.complete.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        let mut wakers = self.state.wakers.lock();
        if self.state.complete.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            wakers.insert(self.id, cx.waker().clone());
            Poll::Pending
        }
    }
}

struct State {
    complete: AtomicBool,
    wakers: Mutex<FxHashMap<usize, Waker>>,
    next_id: AtomicUsize,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_trigger() {
        let (trigger, signal) = trigger();

        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    panic!("Trigger was not called");
                }
                _ = signal => {}
            };
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.trigger();

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
