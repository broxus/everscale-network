use super::buckets::get_affinity;
use super::node::Node;
use super::storage::StorageKeyId;
use crate::adnl;

pub struct PeersIter {
    key_id: StorageKeyId,
    peer_ids: Vec<(u8, adnl::NodeIdShort)>,
    index: usize,
}

impl PeersIter {
    pub fn with_key_id(key_id: StorageKeyId) -> Self {
        Self {
            key_id,
            peer_ids: Default::default(),
            index: 0,
        }
    }

    pub fn next(&mut self) -> Option<adnl::NodeIdShort> {
        self.peer_ids.pop().map(|(_, peer_id)| peer_id)
    }

    pub fn fill(&mut self, dht: &Node, batch_len: Option<usize>) {
        // Get next peer (skipping bad peers) and update the index
        while let Some(peer_id) = self.next_known_peer(dht) {
            let affinity = get_affinity(&self.key_id, peer_id.as_slice());

            // Keep adding peer ids until max tasks is reached
            // or there are values with higher affinity
            let add = match (self.peer_ids.last(), batch_len) {
                (None, _) | (_, None) => true,
                (Some((top_affinity, _)), Some(batch_len)) => {
                    *top_affinity <= affinity || self.peer_ids.len() < batch_len
                }
            };

            if add {
                self.peer_ids.push((affinity, peer_id))
            }
        }

        // Sort peer ids by ascending affinity
        self.peer_ids
            .sort_unstable_by_key(|(affinity, _)| std::cmp::Reverse(*affinity));

        if let Some(batch_len) = batch_len {
            if let Some(top_affinity) = self.peer_ids.first().map(|(affinity, _)| *affinity) {
                let mut offset = 0;
                tracing::trace!(top_affinity, batch_len, "clearing peer ids");
                self.peer_ids.retain(|(affinity, _)| {
                    if offset < batch_len || *affinity >= top_affinity {
                        offset += 1;
                        true
                    } else {
                        offset += 1;
                        false
                    }
                });
            }
        }
    }

    fn next_known_peer(&mut self, dht: &Node) -> Option<adnl::NodeIdShort> {
        loop {
            let peer_id = dht.known_peers().get(self.index);
            self.index += 1;

            if let Some(peer) = &peer_id {
                if dht.is_bad_peer(peer) {
                    continue;
                }
            }

            break peer_id;
        }
    }
}
