use std::borrow::Borrow;
use std::num::NonZeroU32;
use std::rc::Rc;

use parking_lot::{RwLock, RwLockReadGuard};
use rand::seq::SliceRandom;
use rustc_hash::FxHashMap;

use super::node_id::NodeIdShort;
use crate::util::{fast_thread_rng, FxDashSet};

/// A set of unique short node ids
pub struct PeersSet {
    state: RwLock<PeersSetState>,
}

impl PeersSet {
    /// Constructs new peers set with the specified fixed capacity
    pub fn with_capacity(capacity: u32) -> Self {
        Self {
            state: RwLock::new(PeersSetState::with_capacity(make_capacity(capacity))),
        }
    }

    /// Constructs new peers set with some initial peers
    ///
    /// NOTE: Only first `capacity` peers will be added
    pub fn with_peers_and_capacity(peers: &[NodeIdShort], capacity: u32) -> Self {
        Self {
            state: RwLock::new(PeersSetState::with_peers_and_capacity(
                peers,
                make_capacity(capacity),
            )),
        }
    }

    pub fn version(&self) -> u64 {
        self.state.read().version
    }

    pub fn contains(&self, peer: &NodeIdShort) -> bool {
        self.state.read().cache.contains_key(Wrapper::wrap(peer))
    }

    pub fn get(&self, index: usize) -> Option<NodeIdShort> {
        let state = self.state.read();

        let item = state.index.get(index)?;
        Some(*item.0.borrow())
    }

    pub fn len(&self) -> usize {
        self.state.read().index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.read().index.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.state.read().is_full()
    }

    pub fn iter(&self) -> Iter {
        Iter::new(self.state.read())
    }

    pub fn get_random_peers(&self, amount: u32, except: Option<&NodeIdShort>) -> Vec<NodeIdShort> {
        let state = self.state.read();

        let items = state.index.choose_multiple(
            &mut fast_thread_rng(),
            if except.is_some() { amount + 1 } else { amount } as usize,
        );

        match except {
            Some(except) => items
                .filter(|item| &*item.0 != except)
                .take(amount as usize)
                .map(RefId::copy_inner)
                .collect(),
            None => items.map(RefId::copy_inner).collect(),
        }
    }

    pub fn randomly_fill_from(
        &self,
        other: &PeersSet,
        amount: u32,
        except: Option<&FxDashSet<NodeIdShort>>,
    ) {
        // NOTE: early return, otherwise it will deadlock if `other` is the same as self
        if std::ptr::eq(self, other) {
            return;
        }

        let selected_amount = match except {
            Some(peers) => amount as usize + peers.len(),
            None => amount as usize,
        };

        let other_state = other.state.read();
        let new_peers = other_state
            .index
            .choose_multiple(&mut rand::thread_rng(), selected_amount);

        let mut state = self.state.write();

        let insert = |peer_id: &RefId| {
            state.insert(peer_id.copy_inner());
        };

        match except {
            Some(except) => {
                new_peers
                    .filter(|peer_id| !except.contains(&*peer_id.0))
                    .take(amount as usize)
                    .for_each(insert);
            }
            None => new_peers.for_each(insert),
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

    /// Clones internal node ids storage
    pub fn clone_inner(&self) -> Vec<NodeIdShort> {
        let state = self.state.read();
        state.index.iter().map(Ref::copy_inner).collect()
    }
}

impl IntoIterator for PeersSet {
    type Item = NodeIdShort;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.state.into_inner().index.into_iter(),
        }
    }
}

pub struct IntoIter {
    inner: std::vec::IntoIter<Ref<NodeIdShort>>,
}

impl Iterator for IntoIter {
    type Item = NodeIdShort;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let next = self.inner.next()?;
            if let Ok(id) = Rc::try_unwrap(next.0) {
                break Some(id);
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct Iter<'a> {
    _state: RwLockReadGuard<'a, PeersSetState>,
    iter: std::slice::Iter<'a, Ref<NodeIdShort>>,
}

impl<'a> Iter<'a> {
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

impl<'a> Iterator for Iter<'a> {
    type Item = &'a NodeIdShort;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.iter.next()?;
        Some(item.0.as_ref())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> IntoIterator for &'a PeersSet {
    type Item = &'a NodeIdShort;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

struct PeersSetState {
    version: u64,
    cache: FxHashMap<RefId, u32>,
    index: Vec<RefId>,
    capacity: NonZeroU32,
    upper: u32,
}

impl PeersSetState {
    fn with_capacity(capacity: NonZeroU32) -> Self {
        Self {
            version: 0,
            cache: FxHashMap::with_capacity_and_hasher(capacity.get() as usize, Default::default()),
            index: Vec::with_capacity(capacity.get() as usize),
            capacity,
            upper: 0,
        }
    }

    fn with_peers_and_capacity(peers: &[NodeIdShort], capacity: NonZeroU32) -> Self {
        use std::collections::hash_map::Entry;

        let mut res = Self::with_capacity(capacity);
        let capacity = res.capacity.get();

        for peer in peers {
            if res.upper >= capacity {
                break;
            }

            let peer = Ref(Rc::new(*peer));

            match res.cache.entry(peer.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(res.upper);
                    res.index.push(peer);
                    res.upper += 1;
                }
                Entry::Occupied(_) => continue,
            }
        }

        res.upper %= capacity;
        res
    }

    fn is_full(&self) -> bool {
        self.index.len() >= self.capacity.get() as usize
    }

    fn insert(&mut self, peer_id: NodeIdShort) -> bool {
        use std::collections::hash_map::Entry;

        let peer_id = Ref(Rc::new(peer_id));

        // Insert new peer into cache
        match self.cache.entry(peer_id.clone()) {
            Entry::Vacant(entry) => {
                self.version += 1;
                entry.insert(self.upper);
            }
            Entry::Occupied(_) => return false,
        };

        let upper = (self.upper + 1) % self.capacity;
        let index = std::mem::replace(&mut self.upper, upper) as usize;

        match self.index.get_mut(index) {
            Some(slot) => {
                let old_peer = std::mem::replace(slot, peer_id);

                // Remove old peer
                if let Entry::Occupied(entry) = self.cache.entry(old_peer) {
                    if entry.get() == &(index as u32) {
                        entry.remove();
                    }
                }
            }
            None => self.index.push(peer_id),
        }

        true
    }
}

// SAFETY: internal Rcs are not exposed by the api and the reference
// counts only change in methods with `&mut self`
unsafe impl Send for PeersSetState {}
unsafe impl Sync for PeersSetState {}

type RefId = Ref<NodeIdShort>;

#[derive(Hash, Eq, PartialEq)]
struct Ref<T>(Rc<T>);

impl<T: Copy> Ref<T> {
    #[inline]
    fn copy_inner(&self) -> T {
        *self.0
    }
}

impl<T> Clone for Ref<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Hash, Eq, PartialEq)]
#[repr(transparent)]
struct Wrapper<T: ?Sized>(T);

impl<T: ?Sized> Wrapper<T> {
    #[inline(always)]
    fn wrap(value: &T) -> &Self {
        // SAFETY: Wrapper<T> is #[repr(transparent)]
        unsafe { &*(value as *const T as *const Self) }
    }
}

impl<K, Q> Borrow<Wrapper<Q>> for Ref<K>
where
    K: Borrow<Q>,
    Q: ?Sized,
{
    fn borrow(&self) -> &Wrapper<Q> {
        let k: &K = self.0.borrow();
        let q: &Q = k.borrow();
        Wrapper::wrap(q)
    }
}

fn make_capacity(capacity: u32) -> NonZeroU32 {
    let capacity = std::cmp::max(1, capacity);
    // SAFETY: capacity is guaranteed to be at least 1
    unsafe { NonZeroU32::new_unchecked(capacity) }
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
        assert!(!cache.is_full());
    }

    #[test]
    fn test_entries_replacing() {
        let cache = PeersSet::with_capacity(3);

        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(4)
            .collect::<Vec<_>>();

        for peer_id in peers.iter().take(3) {
            assert!(!cache.is_full());
            assert!(cache.insert(*peer_id));
        }

        assert!(cache.is_full());
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
            assert!(!cache.is_full());
            assert!(cache.insert(*peer_id));
        }

        for peer_id in peers.iter() {
            assert!(cache.contains(peer_id));
        }

        std::iter::repeat_with(NodeIdShort::random)
            .take(6)
            .for_each(|peer_id| {
                assert!(cache.is_full());
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

    #[test]
    fn with_peers_same_size_as_capacity() {
        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(10)
            .collect::<Vec<_>>();
        let cache = PeersSet::with_peers_and_capacity(&peers, peers.len() as u32);

        {
            let state = cache.state.write();
            assert_eq!(state.version, 0);
            assert_eq!(state.cache.len(), peers.len());
            assert_eq!(state.index.len(), peers.len());
            assert_eq!(state.upper, 0);
            assert!(state.is_full());
        }
    }

    #[test]
    fn with_peers_less_than_capacity() {
        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(5)
            .collect::<Vec<_>>();
        let cache = PeersSet::with_peers_and_capacity(&peers, 10);

        {
            let state = cache.state.write();
            assert_eq!(state.cache.len(), peers.len());
            assert_eq!(state.index.len(), peers.len());
            assert_eq!(state.upper, peers.len() as u32);
            assert!(!state.is_full());
        }
    }

    #[test]
    fn with_peers_greater_than_capacity() {
        let peers = std::iter::repeat_with(NodeIdShort::random)
            .take(16)
            .collect::<Vec<_>>();
        let cache = PeersSet::with_peers_and_capacity(&peers, 10);

        {
            let state = cache.state.write();
            assert_eq!(state.cache.len(), 10);
            assert_eq!(state.index.len(), 10);
            assert_eq!(state.upper, 0);
            assert!(state.is_full());
        }
    }
}
