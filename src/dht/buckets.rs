use std::borrow::Borrow;

use crate::adnl;
use crate::proto;
use crate::util::*;

/// DHT nodes, distributed by max equal bits
pub struct Buckets {
    local_id: [u8; 32],
    buckets: Box<[FxDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>; 256]>,
}

impl Buckets {
    pub fn new(local_id: &adnl::NodeIdShort) -> Self {
        Self {
            local_id: *local_id.as_slice(),
            buckets: Box::new([(); 256].map(|_| Default::default())),
        }
    }

    /// Returns iterator over all buckets, starting from the most distant
    pub fn iter(&self) -> std::slice::Iter<FxDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>> {
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
        let key2 = peer_id.borrow();

        let mut distance = 0u8;
        let mut nodes = Vec::new();

        // Iterate over buckets
        'outer: for i in 0..32 {
            let mut subdistance = distance;

            // Compare bytes
            let mut xor = key1[i] ^ key2[i];

            // If they are not equal (otherwise we will just add 8 bits
            // to the distance and continue to the next byte)
            while xor != 0 {
                if xor & 0xf0 == 0 {
                    // If high 4 bits of the comparison result are equal then shift comparison
                    // result to the left, so that low 4 bits will become the high 4 bits
                    subdistance = subdistance.saturating_add(4);
                    xor <<= 4;
                } else {
                    // Get equal bit count
                    let shift = BITS[(xor >> 4) as usize];
                    subdistance = subdistance.saturating_add(shift);

                    // Add all nodes from this distance to the result
                    let bucket = &self.buckets[subdistance as usize];
                    for item in bucket.iter() {
                        nodes.push(item.value().clone());
                        if nodes.len() >= k as usize {
                            break 'outer;
                        }
                    }

                    // Skip one different bit:
                    // xor = 0000____ | shift + 1 = 5, xor = ________
                    // xor = 0001____ | shift + 1 = 4, xor = ________
                    // xor = 001x____ | shift + 1 = 3, xor = x_______
                    // xor = 01xx____ | shift + 1 = 2, xor = xx______
                    // xor = 1xxx____ | shift + 1 = 1, xor = xxx_____
                    xor <<= shift + 1;
                    subdistance = subdistance.saturating_add(1);
                }
            }

            // Increase distance
            distance = distance.saturating_add(8);
        }

        // Done
        proto::dht::NodesOwned { nodes }
    }
}

impl<'a> IntoIterator for &'a Buckets {
    type Item = &'a FxDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>;
    type IntoIter = std::slice::Iter<'a, FxDashMap<adnl::NodeIdShort, proto::dht::NodeOwned>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Returns the length of the longest common prefix of two keys
pub fn get_affinity(key1: &[u8; 32], key2: &[u8; 32]) -> u8 {
    let mut result = 0;
    for i in 0..32 {
        match key1[i] ^ key2[i] {
            0 => result += 8,
            x => {
                if x & 0xf0 == 0 {
                    result += BITS[(x & 0x0f) as usize] + 4;
                } else {
                    result += BITS[(x >> 4) as usize]
                }
                break;
            }
        }
    }
    result
}

/// XOR  | BITS
/// 0000 | 4
/// 0001 | 3
/// 001x | 2
/// 01xx | 1
/// 1xxx | 0
const BITS: [u8; 16] = [4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
