use ton_api::ton;

use crate::utils::*;

pub struct Buckets {
    buckets: Vec<FxDashMap<AdnlNodeIdShort, ton::dht::node::Node>>,
}

impl Buckets {
    pub fn iter(&self) -> std::slice::Iter<FxDashMap<AdnlNodeIdShort, ton::dht::node::Node>> {
        self.buckets.iter()
    }

    pub fn insert(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        peer: &ton::dht::node::Node,
    ) {
        use dashmap::mapref::entry::Entry;

        let affinity = get_affinity(local_id.as_slice(), peer_id.as_slice());
        match self.buckets[affinity as usize].entry(*peer_id) {
            Entry::Occupied(entry) => {
                if entry.get().version < peer.version {
                    entry.replace_entry(peer.clone());
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(peer.clone());
            }
        }
    }

    pub fn find(
        &self,
        local_id: &AdnlNodeIdShort,
        key: &[u8; 32],
        k: i32,
    ) -> ton::dht::nodes::Nodes {
        let key1 = local_id.as_slice();
        let key2 = key;

        let mut distance = 0u8;
        let mut result = Vec::new();

        // Iterate over keys bytes
        'outer: for i in 0..32 {
            let mut subdistance = distance;

            // Compare bytes
            let mut xor = key1[i] ^ key2[i];

            // While they are not equal
            while xor != 0 {
                if xor & 0xf0 == 0 {
                    // If high 4 bits of the comparison result are equal then shift xor
                    subdistance = subdistance.saturating_add(4);
                    xor <<= 4;
                } else {
                    // Get equal bit count
                    let shift = BITS[(xor >> 4) as usize];
                    subdistance = subdistance.saturating_add(shift);

                    // Add all nodes from this distance to the result
                    let bucket = &self.buckets[subdistance as usize];
                    for item in bucket.iter() {
                        result.push(item.value().clone());
                        if result.len() == k as usize {
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
        ton::dht::nodes::Nodes {
            nodes: result.into(),
        }
    }
}

impl<'a> IntoIterator for &'a Buckets {
    type Item = &'a FxDashMap<AdnlNodeIdShort, ton::dht::node::Node>;
    type IntoIter = std::slice::Iter<'a, FxDashMap<AdnlNodeIdShort, ton::dht::node::Node>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Default for Buckets {
    fn default() -> Self {
        Self {
            buckets: std::iter::repeat_with(Default::default).take(256).collect(),
        }
    }
}

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
