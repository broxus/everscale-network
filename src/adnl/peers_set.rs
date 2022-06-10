use parking_lot::{RwLock, RwLockReadGuard};
use rand::seq::SliceRandom;

use super::node_id::NodeIdShort;
use crate::utils::{FxDashSet, FxHashMap};

/// A set of unique short node ids
pub struct PeersSet {
    state: RwLock<PeersSetState>,
}

impl PeersSet {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: RwLock::new(PeersSetState {
                version: 0,
                cache: Default::default(),
                index: Default::default(),
                capacity: capacity as u32,
                upper: 0,
            }),
        }
    }

    pub fn version(&self) -> u64 {
        self.state.read().version
    }

    pub fn contains(&self, peer: &NodeIdShort) -> bool {
        self.state.read().cache.contains_key(peer)
    }

    pub fn get(&self, index: usize) -> Option<NodeIdShort> {
        self.state.read().index.get(index).cloned()
    }

    pub fn len(&self) -> usize {
        self.state.read().index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.read().index.is_empty()
    }

    pub fn iter(&self) -> PeersCacheIter {
        PeersCacheIter::new(self.state.read())
    }

    pub fn get_random_peers(
        &self,
        amount: usize,
        except: Option<&NodeIdShort>,
    ) -> Vec<NodeIdShort> {
        let state = self.state.read();

        let items = state
            .index
            .choose_multiple(
                &mut rand::thread_rng(),
                if except.is_some() { amount + 1 } else { amount },
            )
            .cloned();

        match except {
            Some(except) => items.filter(|item| item != except).take(amount).collect(),
            None => items.collect(),
        }
    }

    pub fn randomly_fill_from(
        &self,
        other: &PeersSet,
        amount: usize,
        except: Option<&FxDashSet<NodeIdShort>>,
    ) {
        // NOTE: early return, otherwise it will deadlock if `other` is the same as self
        if std::ptr::eq(self, other) {
            return;
        }

        let selected_amount = match except {
            Some(peers) => amount + peers.len(),
            None => amount,
        };

        let other_state = other.state.read();
        let new_peers = other_state
            .index
            .choose_multiple(&mut rand::thread_rng(), selected_amount)
            .cloned();

        let mut state = self.state.write();
        match except {
            Some(except) => {
                new_peers
                    .filter(|peer_id| !except.contains(peer_id))
                    .take(amount)
                    .for_each(|peer_id| {
                        state.insert(peer_id);
                    });
            }
            None => new_peers.for_each(|peer_id| {
                state.insert(peer_id);
            }),
        }
    }

    /// Adds a value to the set.
    ///
    /// If the set did not have this value present, `true` is returned.
    pub fn insert(&self, peer_id: NodeIdShort) -> bool {
        self.state.write().insert(peer_id)
    }

    pub fn extend<I>(&self, peers: I)
    where
        I: IntoIterator<Item = NodeIdShort>,
    {
        let mut state = self.state.write();
        for peer_id in peers.into_iter() {
            state.insert(peer_id);
        }
    }
}

pub struct PeersCacheIter<'a> {
    _state: RwLockReadGuard<'a, PeersSetState>,
    iter: std::slice::Iter<'a, NodeIdShort>,
}

impl<'a> PeersCacheIter<'a> {
    fn new(state: RwLockReadGuard<'a, PeersSetState>) -> Self {
        // SAFETY: index array lifetime is bounded to the lifetime of the `RwLockReadGuard`
        let iter = unsafe {
            std::slice::from_raw_parts::<'a>(state.index.as_ptr(), state.index.len()).iter()
        };
        Self {
            _state: state,
            iter,
        }
    }
}

impl<'a> Iterator for PeersCacheIter<'a> {
    type Item = &'a NodeIdShort;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl IntoIterator for PeersSet {
    type Item = NodeIdShort;
    type IntoIter = std::vec::IntoIter<NodeIdShort>;

    fn into_iter(self) -> Self::IntoIter {
        self.state.into_inner().index.into_iter()
    }
}

impl<'a> IntoIterator for &'a PeersSet {
    type Item = &'a NodeIdShort;
    type IntoIter = PeersCacheIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

struct PeersSetState {
    version: u64,
    cache: FxHashMap<NodeIdShort, u32>,
    index: Vec<NodeIdShort>,
    capacity: u32,
    upper: u32,
}

impl PeersSetState {
    fn insert(&mut self, peer_id: NodeIdShort) -> bool {
        use std::collections::hash_map::Entry;

        // Insert new peer into cache
        let (index, upper) = match self.cache.entry(peer_id) {
            Entry::Vacant(entry) => {
                // Calculate index in range [0..limit)

                let mut index = self.upper;
                let mut upper = self.upper + 1;

                if index >= self.capacity {
                    if index >= self.capacity * 2 {
                        upper -= self.capacity;
                    }
                    index %= self.capacity;
                }

                self.version += 1;
                entry.insert(index);

                (index as usize, upper)
            }
            Entry::Occupied(_) => return false,
        };

        self.upper = upper;

        // Update index
        if index < self.index.len() {
            let old_peer = std::mem::replace(&mut self.index[index], peer_id);

            // Remove old peer
            if let Entry::Occupied(entry) = self.cache.entry(old_peer) {
                if entry.get() == &(index as u32) {
                    entry.remove();
                }
            }
        } else {
            self.index.push(peer_id);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_insertion() {
        let cache = PeersSet::with_capacity(10);

        let peer_id = NodeIdShort::random();
        assert!(cache.insert(peer_id));
        assert!(!cache.insert(peer_id));
    }

    #[test]
    fn test_entries_replacing() {
        let cache = PeersSet::with_capacity(3);

        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(4)
            .collect::<Vec<_>>();

        for peer_id in peers.iter().take(3) {
            assert!(cache.insert(*peer_id));
        }

        assert!(cache.contains(&peers[0]));

        cache.insert(peers[3]);
        assert!(cache.contains(&peers[3]));

        assert!(!cache.contains(&peers[0]));
    }

    #[test]
    fn test_full_entries_replacing() {
        let cache = PeersSet::with_capacity(3);

        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(3)
            .collect::<Vec<_>>();

        for peer_id in peers.iter() {
            assert!(cache.insert(*peer_id));
        }

        for peer_id in peers.iter() {
            assert!(cache.contains(peer_id));
        }

        std::iter::repeat_with(NodeIdShort::random)
            .take(6)
            .for_each(|peer_id| {
                cache.insert(peer_id);
            });

        for peer_id in peers.iter() {
            assert!(!cache.contains(peer_id));
        }
    }

    #[test]
    fn test_iterator() {
        let cache = PeersSet::with_capacity(10);

        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(3)
            .collect::<Vec<_>>();

        for peer_id in peers.iter() {
            assert!(cache.insert(*peer_id));
        }

        assert_eq!(peers.len(), cache.iter().count());
        for (cache_peer_id, peer_id) in cache.iter().zip(peers.iter()) {
            assert_eq!(cache_peer_id, peer_id);
        }
    }

    #[test]
    fn test_overlapping_insertion() {
        let cache = PeersSet::with_capacity(10);

        for i in 1..1000 {
            assert!(cache.insert(NodeIdShort::random()));
            assert_eq!(cache.len(), std::cmp::min(i, 10));
        }
    }

    #[test]
    fn test_random_peers() {
        let cache = PeersSet::with_capacity(10);
        std::iter::repeat_with(NodeIdShort::random)
            .take(10)
            .for_each(|peer_id| {
                cache.insert(peer_id);
            });

        let peers = cache.get_random_peers(5, None);
        assert_eq!(peers.len(), 5);
        assert_eq!(peers.into_iter().collect::<HashSet<_>>().len(), 5);

        for i in 0..cache.len() {
            let except = cache.get(i).unwrap();

            let peers = cache.get_random_peers(5, Some(&except));
            assert_eq!(peers.len(), 5);

            let unique_peers = peers.into_iter().collect::<HashSet<_>>();
            assert!(!unique_peers.contains(&except));
            assert_eq!(unique_peers.len(), 5);
        }
    }
}
