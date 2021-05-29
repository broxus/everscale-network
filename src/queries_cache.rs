use std::sync::{Arc, Weak};

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::Barrier;
use ton_api::ton;

#[derive(Default)]
pub struct QueriesCache {
    queries: DashMap<QueryId, QueryState>,
}

impl QueriesCache {
    pub fn add_query(self: &Arc<Self>, query_id: QueryId) -> PendingAdnlQuery {
        let barrier = Arc::new(Barrier::new(2));
        let query = QueryState::Sent(barrier.clone());

        self.queries.insert(query_id, query);

        PendingAdnlQuery {
            query_id,
            barrier,
            cache: Arc::downgrade(self),
        }
    }

    pub async fn update_query(
        &self,
        query_id: QueryId,
        answer: Option<&ton::bytes>,
    ) -> Result<bool> {
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
            None => return Ok(false),
        }
    }
}

pub struct PendingAdnlQuery {
    query_id: QueryId,
    barrier: Arc<Barrier>,
    cache: Weak<QueriesCache>,
}

impl PendingAdnlQuery {
    pub async fn wait(self) -> Result<Option<Vec<u8>>> {
        self.barrier.wait().await;
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

enum QueryState {
    /// Initial state. Barrier is used to block receiver part until answer is received
    Sent(Arc<Barrier>),
    /// Query was resolved with some data
    Received(Vec<u8>),
    /// Query was timed out
    Timeout,
}

/// Query id wrapper used for printing
pub struct ShortQueryId<'a>(&'a QueryId);

impl std::fmt::Display for ShortQueryId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        ))
    }
}

pub type QueryId = [u8; 32];

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
