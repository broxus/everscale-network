use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct UpdatedAt {
    started_at: Instant,
    updated_at: AtomicU64,
}

impl UpdatedAt {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            updated_at: Default::default(),
        }
    }

    pub fn refresh(&self) {
        self.updated_at
            .store(self.started_at.elapsed().as_secs(), Ordering::Release)
    }

    pub fn is_expired(&self, timeout: u64) -> bool {
        self.started_at.elapsed().as_secs() - self.updated_at.load(Ordering::Acquire) >= timeout
    }
}

impl Default for UpdatedAt {
    fn default() -> Self {
        Self::new()
    }
}
