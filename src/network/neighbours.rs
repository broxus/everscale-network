use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use ton_api::ton::{self, TLObject};

use super::neighbour::*;
use super::neighbours_cache::*;
use crate::dht_node::*;
use crate::overlay_node::*;
use crate::utils::*;

pub struct Neighbours {
    dht: Arc<DhtNode>,
    overlay_shard: Arc<OverlayShard>,
    options: NeighboursOptions,

    cache: Arc<NeighboursCache>,
    overlay_peers: FxDashSet<AdnlNodeIdShort>,

    failed_attempts: AtomicU64,
    all_attempts: AtomicU64,

    start: Instant,

    peer_search_task_count: Arc<AtomicUsize>,
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NeighboursOptions {
    /// Default: 16
    pub max_neighbours: usize,
    /// Default: 10
    pub reloading_min_interval_sec: u32,
    /// Default: 30
    pub reloading_max_interval_sec: u32,
    /// Default: 500
    pub ping_interval_ms: u64,
    /// Default: 1000
    pub search_interval_ms: u64,
    /// Default: 10
    pub ping_min_timeout_ms: u64,
    /// Default: 1000
    pub ping_max_timeout_ms: u64,
    /// Default: 2000
    pub default_rldp_roundtrip_ms: u64,
    /// Default: 6
    pub max_ping_tasks: usize,
}

impl Default for NeighboursOptions {
    fn default() -> Self {
        Self {
            max_neighbours: 16,
            reloading_min_interval_sec: 10,
            reloading_max_interval_sec: 30,
            ping_interval_ms: 500,
            search_interval_ms: 1000,
            ping_min_timeout_ms: 10,
            ping_max_timeout_ms: 1000,
            default_rldp_roundtrip_ms: 2000,
            max_ping_tasks: 6,
        }
    }
}

impl Neighbours {
    pub fn new(
        dht: &Arc<DhtNode>,
        overlay_shard: &Arc<OverlayShard>,
        initial_peers: &[AdnlNodeIdShort],
        options: NeighboursOptions,
    ) -> Arc<Self> {
        let cache = Arc::new(NeighboursCache::new(
            initial_peers,
            options.max_neighbours,
            NeighbourOptions {
                default_rldp_roundtrip_ms: options.default_rldp_roundtrip_ms,
            },
        ));

        Arc::new(Self {
            dht: dht.clone(),
            overlay_shard: overlay_shard.clone(),
            options,
            cache,
            overlay_peers: Default::default(),
            failed_attempts: Default::default(),
            all_attempts: Default::default(),
            start: Instant::now(),
            peer_search_task_count: Arc::new(Default::default()),
        })
    }

    pub fn options(&self) -> &NeighboursOptions {
        &self.options
    }

    pub fn overlay_shard(&self) -> &Arc<OverlayShard> {
        &self.overlay_shard
    }

    pub fn start_reloading_neighbours(self: &Arc<Self>) {
        use rand::distributions::Distribution;

        let neighbours = Arc::downgrade(self);

        let (min_ms, max_ms) = ordered_boundaries(
            self.options.reloading_min_interval_sec,
            self.options.reloading_max_interval_sec,
        );
        let distribution = rand::distributions::Uniform::new(min_ms, max_ms);

        tokio::spawn(async move {
            loop {
                let sleep_duration = distribution.sample(&mut rand::thread_rng()) as u64;
                tokio::time::sleep(Duration::from_secs(sleep_duration)).await;

                let neighbours = match neighbours.upgrade() {
                    Some(neighbours) => neighbours,
                    None => return,
                };

                if let Err(e) = neighbours.reload_neighbours() {
                    log::warn!("Failed to reload neighbours: {}", e);
                }
            }
        });
    }

    pub fn start_pinging_neighbours(self: &Arc<Self>) {
        let interval = Duration::from_millis(self.options.ping_interval_ms);

        let neighbours = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let neighbours = match neighbours.upgrade() {
                    Some(neighbours) => neighbours,
                    None => return,
                };

                if let Err(e) = neighbours.ping_neighbours().await {
                    log::warn!("Failed to ping neighbours: {}", e);
                    tokio::time::sleep(interval).await;
                }
            }
        });
    }

    pub fn start_searching_peers(self: &Arc<Self>) {
        let interval = Duration::from_millis(self.options.search_interval_ms);

        let neighbours = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(interval).await;

            let neighbours = match neighbours.upgrade() {
                Some(neighbours) => neighbours,
                None => return,
            };

            let mut external_iter = ExternalNeighboursCacheIter::new();
            while let Some(peer_id) = external_iter.get(&neighbours.cache) {
                external_iter.bump();

                match neighbours
                    .overlay_shard
                    .get_random_peers(&peer_id, None)
                    .await
                {
                    Ok(Some(peers)) => {
                        let mut new_peers = Vec::new();

                        for peer in peers.into_iter() {
                            match AdnlNodeIdFull::try_from(&peer.id)
                                .and_then(|full_id| full_id.compute_short_id())
                            {
                                Ok(peer_id) => {
                                    if !neighbours.contains_overlay_peer(&peer_id) {
                                        new_peers.push(peer_id);
                                    }
                                }
                                Err(e) => log::warn!("Failed to process peer: {}", e),
                            }
                        }

                        if !new_peers.is_empty() {
                            neighbours.add_new_peers(new_peers);
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to get random peers: {}", e);
                    }
                    _ => {}
                }
            }
        });
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn metrics(&self) -> NeighboursMetrics {
        NeighboursMetrics {
            peer_search_task_count: self.peer_search_task_count.load(Ordering::Acquire),
        }
    }

    pub fn contains(&self, peer_id: &AdnlNodeIdShort) -> bool {
        self.cache.contains(peer_id)
    }

    pub fn add(&self, peer_id: AdnlNodeIdShort) -> bool {
        self.cache.insert(peer_id)
    }

    pub fn contains_overlay_peer(&self, peer_id: &AdnlNodeIdShort) -> bool {
        self.overlay_peers.contains(peer_id)
    }

    pub fn add_overlay_peer(&self, peer_id: AdnlNodeIdShort) {
        self.overlay_peers.insert(peer_id);
    }

    pub fn remove_overlay_peer(&self, peer_id: &AdnlNodeIdShort) {
        self.overlay_peers.remove(peer_id);
    }

    pub fn get(&self, peer_id: &AdnlNodeIdShort) -> Option<Arc<Neighbour>> {
        self.cache.get(peer_id)
    }

    pub fn choose_neighbour(&self) -> Option<Arc<Neighbour>> {
        self.cache
            .choose_neighbour(&mut rand::thread_rng(), self.average_failures())
    }

    pub fn choose_neighbours(&self, count: usize) -> MultipleNeighbours {
        self.cache
            .choose_neighbours(&mut rand::thread_rng(), self.average_failures(), count)
    }

    pub fn average_failures(&self) -> f64 {
        self.failed_attempts.load(Ordering::Acquire) as f64
            / std::cmp::max(self.all_attempts.load(Ordering::Acquire), 1) as f64
    }

    pub fn reload_neighbours(&self) -> Result<()> {
        log::trace!(
            "Start reload_neighbours (overlay: {})",
            self.overlay_shard.id()
        );

        let peers = PeersCache::with_capacity(self.options.max_neighbours * 2 + 1);
        self.overlay_shard
            .write_cached_peers(self.options.max_neighbours * 2, &peers);
        self.process_neighbours(peers)?;

        log::trace!(
            "Finish reload_neighbours (overlay: {})",
            self.overlay_shard.id()
        );
        Ok(())
    }

    pub async fn ping_neighbours(self: &Arc<Self>) -> Result<()> {
        let neighbour_count = self.cache.len();
        if neighbour_count == 0 {
            return Err(NeighboursError::NoPeersInOverlay(*self.overlay_shard.id()).into());
        } else {
            log::trace!(
                "Pinging neighbours in overlay {} (count: {})",
                *self.overlay_shard.id(),
                neighbour_count,
            )
        }

        let max_tasks = std::cmp::min(neighbour_count, self.options.max_ping_tasks);
        let mut response_collector = LimitedResponseCollector::new(max_tasks);
        loop {
            let neighbour = match self.cache.get_next_for_ping(&self.start) {
                Some(neighbour) => neighbour,
                None => {
                    log::trace!("No neighbours to ping");
                    tokio::time::sleep(Duration::from_millis(self.options.ping_min_timeout_ms))
                        .await;
                    continue;
                }
            };

            let ms_since_last_ping = self.elapsed().saturating_sub(neighbour.last_ping());
            let additional_sleep = if ms_since_last_ping < self.options.ping_max_timeout_ms {
                self.options
                    .ping_max_timeout_ms
                    .saturating_sub(ms_since_last_ping)
            } else {
                self.options.ping_min_timeout_ms
            };
            tokio::time::sleep(Duration::from_millis(additional_sleep)).await;

            if let Some(response_tx) = response_collector.make_request() {
                let neighbours = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = neighbours.update_capabilities(neighbour).await {
                        log::debug!("Failed to ping peer: {}", e);
                    }
                    response_tx.send(Some(()));
                });
            } else {
                while response_collector.count_pending() > 0 {
                    response_collector.wait(false).await;
                }
            }
        }
    }

    pub fn add_new_peers(self: &Arc<Self>, peers: Vec<AdnlNodeIdShort>) {
        let neighbours = self.clone();

        self.peer_search_task_count.fetch_add(1, Ordering::Release);
        let peer_search_task_count = self.peer_search_task_count.clone();

        tokio::spawn(async move {
            for peer_id in peers.into_iter() {
                log::trace!(
                    "add_new_peers: start searching address for peer {}",
                    peer_id
                );
                match neighbours.dht.find_address(&peer_id).await {
                    Ok((ip, _)) => {
                        log::info!("add_new_peers: found overlay peer address: {}", ip);
                        neighbours.add_overlay_peer(peer_id);
                    }
                    Err(e) => {
                        log::warn!("add_new_peers: failed to find overlay peer address: {}", e);
                    }
                }
            }

            peer_search_task_count.fetch_sub(1, Ordering::Release);
        });
    }

    pub fn update_neighbour_stats(
        &self,
        peer_id: &AdnlNodeIdShort,
        roundtrip: u64,
        success: bool,
        is_rldp: bool,
        update_attempts: bool,
    ) {
        let neighbour = match self.cache.get(peer_id) {
            Some(neighbour) => neighbour,
            None => return,
        };

        neighbour.update_stats(roundtrip, success, is_rldp, update_attempts);
        if update_attempts {
            self.all_attempts.fetch_add(1, Ordering::Release);
            if !success {
                self.failed_attempts.fetch_add(1, Ordering::Release);
            }
        }
    }

    pub fn set_neighbour_capabilities(
        &self,
        peer_id: &AdnlNodeIdShort,
        capabilities: &ton::ton_node::Capabilities,
    ) {
        if let Some(neighbour) = self.cache.get(peer_id) {
            neighbour.update_proto_version(capabilities);
        }
    }

    async fn update_capabilities(self: &Arc<Self>, neighbour: Arc<Neighbour>) -> Result<()> {
        let query = TLObject::new(ton::rpc::ton_node::GetCapabilities);
        log::trace!(
            "Query capabilities from {} in {}",
            neighbour.peer_id(),
            self.overlay_shard.id()
        );

        let timeout = Some(
            self.dht
                .adnl()
                .compute_query_timeout(neighbour.roundtrip_adnl()),
        );

        let now = Instant::now();
        neighbour.set_last_ping(self.elapsed());

        match self
            .overlay_shard
            .query(neighbour.peer_id(), &query, timeout)
            .await
        {
            Ok(Some(answer)) => {
                let capabilities = parse_answer::<ton::ton_node::Capabilities>(answer)?;
                log::debug!(
                    "Got capabilities from {} {}: {:?}",
                    neighbour.peer_id(),
                    self.overlay_shard.id(),
                    capabilities
                );

                let roundtrip = now.elapsed().as_millis() as u64;
                self.update_neighbour_stats(neighbour.peer_id(), roundtrip, true, false, false);
                self.set_neighbour_capabilities(neighbour.peer_id(), &capabilities);

                Ok(())
            }
            _ => Err(NeighboursError::NoCapabilitiesReceived(*neighbour.peer_id()).into()),
        }
    }

    fn process_neighbours(&self, peers: PeersCache) -> Result<()> {
        let mut cache = self.cache.write();

        let mut rng = rand::thread_rng();
        for peer_id in peers {
            if cache.contains(&peer_id) {
                continue;
            }

            let (hint, unreliable_peer) = cache.insert_or_replace_unreliable(&mut rng, peer_id);
            if let Some(unreliable_peer) = unreliable_peer {
                self.overlay_shard.delete_public_peer(&unreliable_peer);
                self.overlay_peers.remove(&unreliable_peer);
            }

            if hint == NeighboursCacheHint::DefinitelyFull {
                break;
            }
        }

        Ok(())
    }

    fn elapsed(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[derive(Debug, Copy, Clone)]
pub struct NeighboursMetrics {
    pub peer_search_task_count: usize,
}

#[derive(thiserror::Error, Debug)]
enum NeighboursError {
    #[error("No peers in overlay {}", .0)]
    NoPeersInOverlay(OverlayIdShort),
    #[error("No capabilities received for {}", .0)]
    NoCapabilitiesReceived(AdnlNodeIdShort),
}
