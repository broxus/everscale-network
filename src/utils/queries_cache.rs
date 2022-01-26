use std::sync::{Arc, Weak};

use anyhow::Result;
use tokio::sync::Barrier;

use super::query::*;
use super::FxDashMap;

#[derive(Default)]
pub struct QueriesCache {
    queries: FxDashMap<QueryId, QueryState>,
}

impl QueriesCache {
    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn add_query(self: &Arc<Self>, query_id: QueryId) -> PendingAdnlQuery {
        let barrier = Arc::new(Barrier::new(2));
        let query = QueryState::Sent(barrier.clone());

        self.queries.insert(query_id, query);

        PendingAdnlQuery {
            query_id,
            barrier,
            cache: Arc::downgrade(self),
            finished: false,
        }
    }

    pub async fn update_query(&self, query_id: QueryId, answer: Option<&[u8]>) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        let old = match self.queries.entry(query_id) {
            Entry::Vacant(_) => None,
            Entry::Occupied(entry) => match entry.get() {
                QueryState::Sent(_) => {
                    let (_, old) = entry.replace_entry(match answer {
                        Some(bytes) => QueryState::Received(bytes.to_vec()),
                        None => QueryState::Timeout,
                    });
                    Some(old)
                }
                _ => None,
            },
        };

        match old {
            Some(QueryState::Sent(barrier)) => {
                barrier.wait().await;
                Ok(true)
            }
            Some(_) => Err(QueriesCacheError::UnexpectedState.into()),
            None => Ok(false),
        }
    }
}

pub struct PendingAdnlQuery {
    query_id: QueryId,
    barrier: Arc<Barrier>,
    cache: Weak<QueriesCache>,
    finished: bool,
}

impl PendingAdnlQuery {
    pub async fn wait(mut self) -> Result<Option<Vec<u8>>> {
        self.barrier.wait().await;
        self.finished = true;

        let cache = match self.cache.upgrade() {
            Some(cache) => cache,
            None => return Err(QueriesCacheError::CacheDropped.into()),
        };

        match cache.queries.remove(&self.query_id) {
            Some((_, QueryState::Received(answer))) => Ok(Some(answer)),
            Some((_, QueryState::Timeout)) => Ok(None),
            Some(_) => Err(QueriesCacheError::InvalidQueryState.into()),
            None => Err(QueriesCacheError::UnknownId.into()),
        }
    }
}

impl Drop for PendingAdnlQuery {
    fn drop(&mut self) {
        if self.finished {
            return;
        }

        if let Some(cache) = self.cache.upgrade() {
            cache.queries.remove(&self.query_id);
        }
    }
}

enum QueryState {
    /// Initial state. Barrier is used to block receiver part until answer is received
    Sent(Arc<Barrier>),
    /// Query was resolved with some data
    Received(Vec<u8>),
    /// Query was timed out
    Timeout,
}

#[derive(thiserror::Error, Debug)]
enum QueriesCacheError {
    #[error("Queries cache was dropped")]
    CacheDropped,
    #[error("Invalid query state")]
    InvalidQueryState,
    #[error("Unknown query id")]
    UnknownId,
    #[error("Unexpected query state")]
    UnexpectedState,
}
