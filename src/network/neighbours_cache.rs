use std::sync::Arc;
use std::time::Instant;

use parking_lot::{RwLock, RwLockWriteGuard};
use rand::Rng;

use super::neighbour::Neighbour;
use crate::utils::*;

pub struct NeighboursCache {
    state: RwLock<NeighboursCacheState>,
}

impl NeighboursCache {
    pub fn new(initial_peers: &[AdnlNodeIdShort], max_len: usize) -> Self {
        let result = Self {
            state: RwLock::new(NeighboursCacheState::new(max_len)),
        };

        let mut state = result.state.write();
        for peer_id in initial_peers.iter().take(max_len) {
            state.insert(*peer_id);
        }
        drop(state);

        result
    }

    pub fn len(&self) -> usize {
        self.state.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.read().is_empty()
    }

    pub fn contains(&self, peer_id: &AdnlNodeIdShort) -> bool {
        self.state.read().contains(peer_id)
    }

    pub fn choose_neighbour(
        &self,
        rng: &mut impl Rng,
        average_failures: f64,
    ) -> Option<Arc<Neighbour>> {
        self.state.read().choose_neighbour(rng, average_failures)
    }

    pub fn insert(&self, peer_id: AdnlNodeIdShort) -> bool {
        self.state.write().insert(peer_id)
    }

    pub fn get(&self, peer_id: &AdnlNodeIdShort) -> Option<Arc<Neighbour>> {
        self.state.read().get(peer_id)
    }

    pub fn get_next_for_ping(&self, start: &Instant) -> Option<Arc<Neighbour>> {
        self.state.write().get_next_for_ping(start)
    }

    pub fn write(&self) -> RwLockWriteGuard<NeighboursCacheState> {
        self.state.write()
    }
}

pub struct NeighboursCacheState {
    max_len: usize,
    next: usize,
    values: FxHashMap<AdnlNodeIdShort, Arc<Neighbour>>,
    indices: Vec<AdnlNodeIdShort>,
}

impl NeighboursCacheState {
    fn new(max_len: usize) -> Self {
        Self {
            max_len,
            next: 0,
            values: Default::default(),
            indices: Vec::with_capacity(max_len),
        }
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    pub fn contains(&self, peer_id: &AdnlNodeIdShort) -> bool {
        self.values.contains_key(peer_id)
    }

    pub fn choose_neighbour(
        &self,
        rng: &mut impl Rng,
        average_failures: f64,
    ) -> Option<Arc<Neighbour>> {
        if self.indices.len() == 1 {
            let first = self.indices.first();
            return first.and_then(|peer_id| self.values.get(peer_id)).cloned();
        }

        let mut best_neighbour = None;
        let mut total_weight = 0;
        for neighbour in &self.indices {
            let neighbour = match self.values.get(neighbour) {
                Some(neighbour) => neighbour,
                None => continue,
            };

            if neighbour.try_select(rng, &mut total_weight, average_failures) {
                best_neighbour = Some(neighbour);
            }
        }

        best_neighbour.cloned()
    }

    pub fn get(&self, peer_id: &AdnlNodeIdShort) -> Option<Arc<Neighbour>> {
        self.values.get(peer_id).cloned()
    }

    pub fn get_next_for_ping(&mut self, start: &Instant) -> Option<Arc<Neighbour>> {
        if self.indices.is_empty() {
            return None;
        }

        let start = start.elapsed().as_millis() as u64;

        let mut next = self.next;
        let started_from = self.next;

        let mut result: Option<Arc<Neighbour>> = None;
        loop {
            let peer_id = &self.indices[next];
            next = (next + 1) % self.indices.len();

            if let Some(neighbour) = self.values.get(peer_id) {
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

        self.next = next;

        result
    }

    pub fn insert(&mut self, peer_id: AdnlNodeIdShort) -> bool {
        use std::collections::hash_map::Entry;

        if self.indices.len() >= self.max_len {
            return false;
        }

        match self.values.entry(peer_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(Neighbour::new(peer_id)));
                self.indices.push(peer_id);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub fn insert_or_replace_unreliable<R: Rng>(
        &mut self,
        rng: &mut R,
        peer_id: AdnlNodeIdShort,
    ) -> (NeighboursCacheHint, Option<AdnlNodeIdShort>) {
        use std::collections::hash_map::Entry;

        const MAX_UNRELIABILITY: u32 = 5;

        if self.indices.len() < self.max_len {
            return match self.values.entry(peer_id) {
                Entry::Vacant(entry) => {
                    entry.insert(Arc::new(Neighbour::new(peer_id)));
                    self.indices.push(peer_id);
                    if self.indices.len() == self.max_len {
                        (NeighboursCacheHint::MaybeHasUnreliable, None)
                    } else {
                        (NeighboursCacheHint::HasSpace, None)
                    }
                }
                Entry::Occupied(_) => (NeighboursCacheHint::HasSpace, None),
            };
        }

        let mut unreliable_peer: Option<(u32, usize)> = None;

        for (i, existing_peer_id) in self.indices.iter().enumerate() {
            let neighbour = match self.values.get(existing_peer_id) {
                Some(neighbour) => neighbour,
                None => continue,
            };

            let unreliability = neighbour.unreliability();
            let max_unreliability = unreliable_peer.map(|(u, _)| u).unwrap_or_default();

            if unreliability > max_unreliability {
                unreliable_peer = Some((unreliability, i));
            }
        }

        let (hint, replaced_index, unreliable_peer) = match unreliable_peer {
            Some((unreliability, i)) if unreliability > MAX_UNRELIABILITY => (
                NeighboursCacheHint::MaybeHasUnreliable,
                i,
                Some(self.indices[i]),
            ),
            _ => (
                NeighboursCacheHint::DefinitelyFull,
                rng.gen_range(0..self.indices.len()),
                None,
            ),
        };

        match self.values.entry(peer_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(Neighbour::new(peer_id)));
                self.values.remove(&self.indices[replaced_index]);
                self.indices[replaced_index] = peer_id;
                (hint, unreliable_peer)
            }
            Entry::Occupied(_) => (hint, None),
        }
    }
}

#[derive(Default)]
pub struct ExternalNeighboursCacheIter(usize);

impl ExternalNeighboursCacheIter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, cache: &NeighboursCache) -> Option<AdnlNodeIdShort> {
        cache.state.read().indices.get(self.0).cloned()
    }

    pub fn bump(&mut self) {
        self.0 += 1;
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum NeighboursCacheHint {
    HasSpace,
    MaybeHasUnreliable,
    DefinitelyFull,
}
