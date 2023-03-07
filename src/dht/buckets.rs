use std::borrow::Borrow;

use crate::adnl;
use crate::proto;
use crate::util::*;

/// DHT nodes, distributed by max equal bits
pub struct Buckets {
    local_id: [u8; 32],
    buckets: Box<[FastDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>; 256]>,
}

impl Buckets {
    pub fn new(local_id: &adnl::NodeIdShort) -> Self {
        Self {
            local_id: *local_id.as_slice(),
            buckets: Box::new([(); 256].map(|_| Default::default())),
        }
    }

    /// Returns iterator over all buckets, starting from the most distant
    pub fn iter(&self) -> std::slice::Iter<FastDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>> {
        self.buckets.iter()
    }

    /// Inserts DHT node into the bucket based on its distance
    pub fn insert(&self, peer_id: &adnl::NodeIdShort, peer: proto::dht::NodeOwned) {
        use dashmap::mapref::entry::Entry;

        let affinity = get_affinity(&self.local_id, peer_id.borrow());
        match self.buckets[affinity as usize].entry(*peer_id) {
            Entry::Occupied(mut entry) => {
                if entry.get().version < peer.version {
                    entry.insert(peer);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(peer);
            }
        }
    }

    /// Finds `k` closest DHT nodes for the given `peer_id`
    pub fn find<T>(&self, peer_id: T, k: u32) -> proto::dht::NodesOwned
    where
        T: Borrow<[u8; 32]>,
    {
        let key1 = &self.local_id;
        let key2: &[u8; 32] = peer_id.borrow();

        let mut nodes = Vec::new();

        // Iterate over buckets
        'outer: for i in 0..32 {
            let mut distance = i as u8 * 8;

            // Compare bytes
            let mut diff = key1[i] ^ key2[i];

            // If they are not equal (otherwise we will just add 8 bits
            // to the distance and continue to the next byte)
            while diff != 0 {
                // Get equal bit count
                let equal_bits = diff.leading_zeros() as u8; // 0..=7
                distance += equal_bits;

                // Add all nodes from this distance to the result
                let bucket = &self.buckets[distance as usize];
                for item in bucket.iter() {
                    nodes.push(item.value().clone());
                    if nodes.len() >= k as usize {
                        break 'outer;
                    }
                }

                // Skip one different bit:
                if equal_bits < 7 {
                    diff <<= equal_bits + 1;
                    distance = distance.saturating_add(1);
                } else {
                    continue 'outer;
                }
            }
        }

        // Done
        proto::dht::NodesOwned { nodes }
    }
}

impl<'a> IntoIterator for &'a Buckets {
    type Item = &'a FastDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>;
    type IntoIter = std::slice::Iter<'a, FastDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Returns the length of the longest common prefix of two keys
pub fn get_affinity(key1: &[u8; 32], key2: &[u8; 32]) -> u8 {
    for i in 0..32 {
        let diff = key1[i] ^ key2[i];
        if diff != 0 {
            return (i * 8 + diff.leading_zeros() as usize) as u8;
        }
    }
    255
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_affinity() {
        assert_eq!(get_affinity(&[0xaa; 32], &[0xaa; 32]), 255);
    }
}
