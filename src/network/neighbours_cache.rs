use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use parking_lot::RwLock;

use super::neighbour::Neighbour;
use super::MAX_NEIGHBOURS;
use crate::utils::*;

pub struct NeighboursCache {
    state: RwLock<NeighboursCacheState>,
}

impl NeighboursCache {
    pub fn new(initial_peers: &[AdnlNodeIdShort]) -> Self {
        let result = Self {
            state: RwLock::new(NeighboursCacheState::new()),
        };

        let mut state = result.state.write();
        for peer_id in initial_peers.iter().take(MAX_NEIGHBOURS) {
            state.insert(*peer_id).unwrap();
        }
        std::mem::drop(state);

        result
    }

    pub fn len(&self) -> usize {
        self.state.read().indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.read().indices.is_empty()
    }

    pub fn contains(&self, peer_id: &AdnlNodeIdShort) -> bool {
        self.state.read().values.contains_key(peer_id)
    }

    pub fn insert(&self, peer_id: AdnlNodeIdShort) -> Result<bool> {
        self.state.write().insert(peer_id)
    }

    pub fn replace(
        &self,
        old_peer_id: &AdnlNodeIdShort,
        new_peer_id: AdnlNodeIdShort,
    ) -> Result<bool> {
        self.state.write().replace(old_peer_id, new_peer_id)
    }

    pub fn get(&self, peer_id: &AdnlNodeIdShort) -> Option<Arc<Neighbour>> {
        self.state.read().values.get(peer_id).cloned()
    }

    pub fn get_next_for_ping(&self, start: &Instant) -> Option<Arc<Neighbour>> {
        let mut state = self.state.write();
        if state.indices.is_empty() {
            return None;
        }

        let start = start.elapsed().as_millis() as u64;

        let mut next = state.next;
        let started_from = state.next;

        let mut result: Option<Arc<Neighbour>> = None;
        loop {
            let peer_id = &state.indices[next];
            next = (next + 1) % state.indices.len();

            if let Some(neighbour) = state.values.get(peer_id) {
                if start.saturating_sub(neighbour.last_ping()) < 1000 {
                    if next == started_from {
                        break;
                    } else if let Some(result) = &result {
                        if neighbour.last_ping() >= result.last_ping() {
                            continue;
                        }
                    }
                }

                result.replace(neighbour.clone());
                break;
            }
        }

        state.next = next;

        result
    }
}

struct NeighboursCacheState {
    next: usize,
    values: HashMap<AdnlNodeIdShort, Arc<Neighbour>>,
    indices: Vec<AdnlNodeIdShort>,
}

impl NeighboursCacheState {
    fn new() -> Self {
        Self {
            next: 0,
            values: Default::default(),
            indices: Vec::with_capacity(MAX_NEIGHBOURS),
        }
    }

    fn insert(&mut self, peer_id: AdnlNodeIdShort) -> Result<bool> {
        use std::collections::hash_map::Entry;

        if self.indices.len() >= MAX_NEIGHBOURS {
            return Err(NeighboursCacheError::Overflow.into());
        }

        Ok(match self.values.entry(peer_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(Neighbour::new(peer_id)));
                self.indices.push(peer_id);
                true
            }
            Entry::Occupied(_) => false,
        })
    }

    fn replace(
        &mut self,
        old_peer_id: &AdnlNodeIdShort,
        new_peer_id: AdnlNodeIdShort,
    ) -> Result<bool> {
        use std::collections::hash_map::Entry;

        let index = match self.indices.iter().position(|item| item == old_peer_id) {
            Some(index) => index,
            None => return Err(NeighboursCacheError::NeighbourNotFound.into()),
        };

        Ok(match self.values.entry(new_peer_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(Neighbour::new(new_peer_id)));
                self.values.remove(old_peer_id);
                self.indices[index] = new_peer_id;
                true
            }
            Entry::Occupied(_) => false,
        })
    }
}

#[derive(thiserror::Error, Debug)]
enum NeighboursCacheError {
    #[error("Neighbours cache overflow")]
    Overflow,
    #[error("Replaced neighbour not found")]
    NeighbourNotFound,
}
