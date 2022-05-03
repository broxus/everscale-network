use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::OutgoingBroadcastInfo;
use anyhow::Result;
use ton_api::ton::TLObject;

use super::neighbour::Neighbour;
use super::neighbours::Neighbours;
use crate::overlay_node::{IncomingBroadcastInfo, OverlayShard};
use crate::rldp_node::RldpNode;
use crate::utils::*;

pub struct OverlayClient {
    rldp: Arc<RldpNode>,
    neighbours: Arc<Neighbours>,
    overlay_shard: Arc<OverlayShard>,
}

impl OverlayClient {
    pub fn new(
        rldp: Arc<RldpNode>,
        neighbours: Arc<Neighbours>,
        overlay_shard: Arc<OverlayShard>,
    ) -> Self {
        Self {
            rldp,
            neighbours,
            overlay_shard,
        }
    }

    pub fn overlay_id(&self) -> &OverlayIdShort {
        self.overlay_shard.id()
    }

    pub fn neighbours(&self) -> &Arc<Neighbours> {
        &self.neighbours
    }

    pub fn overlay_shard(&self) -> &Arc<OverlayShard> {
        &self.overlay_shard
    }

    pub fn resolve_ip(&self, neighbour: &Neighbour) -> Option<AdnlAddressUdp> {
        self.overlay_shard
            .adnl()
            .get_peer_ip(self.overlay_shard.overlay_key().id(), neighbour.peer_id())
    }

    pub async fn send_rldp_query<Q, A>(
        &self,
        query: &Q,
        neighbour: Arc<Neighbour>,
        attempt: u32,
    ) -> Result<A>
    where
        Q: ton_api::BoxedSerialize + std::fmt::Debug,
        A: ton_api::BoxedDeserialize,
    {
        let (answer, neighbour, roundtrip) = self
            .send_rldp_query_to_neighbour(neighbour, query, attempt)
            .await?;
        match ton_api::Deserializer::new(&mut answer.as_slice()).read_boxed() {
            Ok(answer) => {
                neighbour.query_succeeded(roundtrip, true);
                Ok(answer)
            }
            Err(e) => {
                self.neighbours.update_neighbour_stats(
                    neighbour.peer_id(),
                    roundtrip,
                    false,
                    true,
                    true,
                );
                Err(anyhow::Error::msg(e))
            }
        }
    }

    pub async fn send_rldp_query_raw<Q>(
        &self,
        neighbour: Arc<Neighbour>,
        query: &Q,
        attempt: u32,
    ) -> Result<Vec<u8>>
    where
        Q: ton_api::BoxedSerialize + std::fmt::Debug,
    {
        let (answer, neighbour, roundtrip) = self
            .send_rldp_query_to_neighbour(neighbour, query, attempt)
            .await?;
        neighbour.query_succeeded(roundtrip, true);
        Ok(answer)
    }

    pub async fn send_adnl_query<Q, A>(
        &self,
        query: Q,
        attempts: Option<u32>,
        timeout: Option<u64>,
        explicit_neighbour: Option<&Arc<Neighbour>>,
    ) -> Result<(A, Arc<Neighbour>)>
    where
        Q: ton_api::AnyBoxedSerialize,
        A: ton_api::AnyBoxedSerialize,
    {
        const NO_NEIGHBOURS_DELAY: u64 = 1000; // Milliseconds

        let query = TLObject::new(query);
        let attempts = attempts.unwrap_or(DEFAULT_ADNL_ATTEMPTS);

        for _ in 0..attempts {
            let neighbour = match explicit_neighbour {
                Some(neighbour) => neighbour.clone(),
                None => match self.neighbours.choose_neighbour() {
                    Some(neighbour) => neighbour,
                    None => {
                        tokio::time::sleep(Duration::from_millis(NO_NEIGHBOURS_DELAY)).await;
                        return Err(OverlayClientError::NeNeighboursFound.into());
                    }
                },
            };

            if let Some(answer) = self
                .send_adnl_query_to_neighbour::<Q, A>(&neighbour, &query, timeout)
                .await?
            {
                return Ok((answer, neighbour));
            }
        }

        Err(OverlayClientError::AdnlQueryFailed(query, attempts).into())
    }

    pub fn broadcast(
        &self,
        data: Vec<u8>,
        source: Option<&Arc<StoredAdnlNodeKey>>,
    ) -> Result<OutgoingBroadcastInfo> {
        self.overlay_shard.broadcast(data, source)
    }

    pub async fn wait_for_broadcast(&self) -> IncomingBroadcastInfo {
        self.overlay_shard.wait_for_broadcast().await
    }

    async fn send_adnl_query_to_neighbour<Q, A>(
        &self,
        neighbour: &Neighbour,
        query: &TLObject,
        timeout: Option<u64>,
    ) -> Result<Option<A>>
    where
        Q: ton_api::AnyBoxedSerialize,
        A: ton_api::AnyBoxedSerialize,
    {
        let timeout = timeout.or_else(|| {
            Some(
                self.overlay_shard
                    .adnl()
                    .compute_query_timeout(neighbour.roundtrip_adnl()),
            )
        });
        let peer_id = neighbour.peer_id();

        let now = Instant::now();
        let answer = self.overlay_shard.query(peer_id, query, timeout).await?;
        let roundtrip = now.elapsed().as_millis() as u64;

        match answer.map(|answer| answer.downcast::<A>()) {
            Some(Ok(answer)) => {
                neighbour.query_succeeded(roundtrip, false);
                return Ok(Some(answer));
            }
            Some(Err(answer)) => {
                log::warn!(
                    "Wrong answer {answer:?} to {query:?} from {peer_id} ({})",
                    ResolvedIp(self.resolve_ip(neighbour))
                );
            }
            None => {
                log::warn!(
                    "No reply to {query:?} from {peer_id} ({})",
                    ResolvedIp(self.resolve_ip(neighbour))
                );
            }
        }

        self.neighbours
            .update_neighbour_stats(peer_id, roundtrip, false, false, true);
        Ok(None)
    }

    async fn send_rldp_query_to_neighbour<Q>(
        &self,
        neighbour: Arc<Neighbour>,
        query: &Q,
        attempt: u32,
    ) -> Result<(Vec<u8>, Arc<Neighbour>, u64)>
    where
        Q: ton_api::BoxedSerialize + std::fmt::Debug,
    {
        const MAX_ANSWER_SIZE: i64 = 10 * 1024 * 1024; // 10 MB
        const ATTEMPT_INTERVAL: u64 = 50; // Milliseconds

        let mut data = self.overlay_shard.query_prefix().clone();
        serialize_append(&mut data, query)?;

        let (answer, roundtrip) = self
            .overlay_shard
            .query_via_rldp(
                neighbour.peer_id(),
                data,
                &self.rldp,
                Some(MAX_ANSWER_SIZE),
                neighbour
                    .roundtrip_rldp()
                    .map(|roundtrip| roundtrip + attempt as u64 * ATTEMPT_INTERVAL),
            )
            .await?;

        match answer {
            Some(answer) => Ok((answer, neighbour, roundtrip)),
            None => {
                self.neighbours.update_neighbour_stats(
                    neighbour.peer_id(),
                    roundtrip,
                    false,
                    true,
                    true,
                );
                Err(OverlayClientError::NoRldpQueryAnswer(*neighbour.peer_id()).into())
            }
        }
    }
}

const DEFAULT_ADNL_ATTEMPTS: u32 = 50;

struct ResolvedIp(Option<AdnlAddressUdp>);

impl std::fmt::Display for ResolvedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(ip) => ip.fmt(f),
            None => f.write_str("unknown"),
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum OverlayClientError {
    #[error("No neighbours found")]
    NeNeighboursFound,
    #[error("Failed to send adnl query {:?} in {} attempts", .0, .1)]
    AdnlQueryFailed(TLObject, u32),
    #[error("No RLDP query answer from {}", .0)]
    NoRldpQueryAnswer(AdnlNodeIdShort),
}
