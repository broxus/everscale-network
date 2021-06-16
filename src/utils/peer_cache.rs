use std::sync::atomic::{AtomicU32, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;

use super::node_id::*;

pub struct PeerCache {
    state: RwLock<PeerCacheState>,
}

impl PeerCache {
    pub fn with_limit(limit: u32) -> Self {
        Self {
            state: RwLock::new(PeerCacheState {
                cache: Default::default(),
                index: Default::default(),
                limit,
                upper: 0,
            }),
        }
    }

    pub fn contains(&self, peer: &AdnlNodeIdShort) -> bool {
        self.state.read().cache.contains_key(peer)
    }

    pub fn count(&self) -> u32 {
        let state = self.state.read();
        std::cmp::min(state.upper, state.limit)
    }

    pub fn get_random_peers(
        &self,
        except: Option<&AdnlNodeIdShort>,
        count: u32,
    ) -> Vec<AdnlNodeIdShort> {
        let state = self.state.read();

        let mut result = Vec::new();
        todo!()
    }

    pub fn put(&self, peer_id: AdnlNodeIdShort) -> bool {
        use dashmap::mapref::entry::Entry;

        let mut state = self.state.write();

        let index = match state.cache.entry(peer_id) {
            Entry::Vacant(entry) => {
                let mut index = state.upper;
                state.upper += 1;

                if index >= state.limit {
                    if index >= state.limit * 2 {
                        state.upper -= state.limit;
                    }
                    index %= state.limit;
                }

                entry.insert(index);
                index
            }
            Entry::Occupied(_) => return false,
        };

        if let Some(peer_id) = state.index.insert(index, peer_id) {
            if let Entry::Occupied(entry) = state.cache.entry(peer_id) {
                if entry.get() == &index {
                    entry.remove();
                }
            }
        }

        true
    }
}

struct PeerCacheState {
    cache: DashMap<AdnlNodeIdShort, u32>,
    index: DashMap<u32, AdnlNodeIdShort>,
    limit: u32,
    upper: u32,
}
