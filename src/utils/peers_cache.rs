use std::sync::atomic::{AtomicU32, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;

use super::node_id::*;

pub struct PeersCache {
    state: RwLock<PeerCacheState>,
}

impl PeersCache {
    pub fn with_capacity(capacity: u32) -> Self {
        Self {
            state: RwLock::new(PeerCacheState {
                cache: Default::default(),
                index: Default::default(),
                capacity,
                upper: 0,
            }),
        }
    }

    pub fn contains(&self, peer: &AdnlNodeIdShort) -> bool {
        self.state.read().cache.contains_key(peer)
    }

    pub fn get<I>(&self, index: I) -> Option<AdnlNodeIdShort>
    where
        I: std::slice::SliceIndex<[AdnlNodeIdShort], Output = AdnlNodeIdShort>,
    {
        self.state.read().index.get(index).cloned()
    }

    pub fn len(&self) -> usize {
        self.state.read().index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.read().index.is_empty()
    }

    pub fn get_random_peers(
        &self,
        count: u32,
        except: Option<&AdnlNodeIdShort>,
    ) -> Vec<AdnlNodeIdShort> {
        use rand::seq::SliceRandom;

        let state = self.state.read();

        let items = state
            .index
            .choose_multiple(
                &mut rand::thread_rng(),
                if except.is_some() { count + 1 } else { count } as usize,
            )
            .cloned();

        match except {
            Some(except) => items
                .filter(|item| item != except)
                .take(count as usize)
                .collect(),
            None => items.collect(),
        }
    }

    pub fn put(&self, peer_id: AdnlNodeIdShort) -> bool {
        use dashmap::mapref::entry::Entry;

        let mut state = self.state.write();

        // Insert new peer into cache
        let (index, upper) = match state.cache.entry(peer_id) {
            Entry::Vacant(entry) => {
                // Calculate index in range [0..limit)

                let mut index = state.upper;
                let mut upper = state.upper + 1;

                if index >= state.capacity {
                    if index >= state.capacity * 2 {
                        upper -= state.capacity;
                    }
                    index %= state.capacity;
                }

                entry.insert(index);

                (index as usize, upper)
            }
            Entry::Occupied(_) => return false,
        };

        state.upper = upper;

        // Update index
        if index < state.index.len() {
            let old_peer = std::mem::replace(&mut state.index[index], peer_id);

            // Remove old peer
            if let Entry::Occupied(entry) = state.cache.entry(old_peer) {
                if entry.get() == &(index as u32) {
                    entry.remove();
                }
            }
        } else {
            state.index.push(peer_id);
        }

        true
    }
}

struct PeerCacheState {
    cache: DashMap<AdnlNodeIdShort, u32>,
    index: Vec<AdnlNodeIdShort>,
    capacity: u32,
    upper: u32,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_insertion() {
        let cache = PeersCache::with_capacity(10);

        let peer_id = AdnlNodeIdShort::random();
        assert!(cache.put(peer_id));
        assert!(!cache.put(peer_id));
    }

    #[test]
    fn test_entries_replacing() {
        let cache = PeersCache::with_capacity(3);

        let peers = std::iter::repeat_with(AdnlNodeIdShort::random)
            .take(4)
            .collect::<Vec<_>>();

        for peer_id in peers.iter().take(3) {
            assert!(cache.put(*peer_id));
        }

        assert!(cache.contains(&peers[0]));

        cache.put(peers[3]);
        assert!(cache.contains(&peers[3]));

        assert!(!cache.contains(&peers[0]));
    }

    #[test]
    fn test_full_entries_replacing() {
        let cache = PeersCache::with_capacity(3);

        let peers = std::iter::repeat_with(AdnlNodeIdShort::random)
            .take(3)
            .collect::<Vec<_>>();

        for peer_id in peers.iter() {
            assert!(cache.put(*peer_id));
        }

        for peer_id in peers.iter() {
            assert!(cache.contains(peer_id));
        }

        std::iter::repeat_with(AdnlNodeIdShort::random)
            .take(6)
            .for_each(|peer_id| {
                cache.put(peer_id);
            });

        for peer_id in peers.iter() {
            assert!(!cache.contains(peer_id));
        }
    }

    #[test]
    fn test_overlapping_insertion() {
        let cache = PeersCache::with_capacity(10);

        for i in 1..1000 {
            assert!(cache.put(AdnlNodeIdShort::random()));
            assert_eq!(cache.len(), std::cmp::min(i, 10));
        }
    }

    #[test]
    fn test_random_peers() {
        let cache = PeersCache::with_capacity(10);
        std::iter::repeat_with(AdnlNodeIdShort::random)
            .take(10)
            .for_each(|peer_id| {
                cache.put(peer_id);
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
