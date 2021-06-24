use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashSet;
use ton_api::ton::TLObject;

use super::neighbour::Neighbour;
use super::neighbours::Neighbours;
use crate::adnl_node::AdnlNode;
use crate::overlay_node::OverlayNode;
use crate::rldp_node::RldpNode;
use crate::utils::*;

pub struct OverlayClient {
    overlay_id: OverlayIdShort,
    overlay: Arc<OverlayNode>,
    rldp: Arc<RldpNode>,
    neighbours: Arc<Neighbours>,
}

impl OverlayClient {
    pub fn new(
        overlay: Arc<OverlayNode>,
        rldp: Arc<RldpNode>,
        neighbours: Arc<Neighbours>,
        overlay_id: OverlayIdShort,
    ) -> Self {
        Self {
            overlay_id,
            overlay,
            rldp,
            neighbours,
        }
    }

    pub fn overlay_id(&self) -> &OverlayIdShort {
        &self.overlay_id
    }

    pub fn overlay(&self) -> &Arc<OverlayNode> {
        &self.overlay
    }

    pub fn neighbours(&self) -> &Arc<Neighbours> {
        &self.neighbours
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
        match ton_api::Deserializer::new(&mut std::io::Cursor::new(answer)).read_boxed() {
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
        active_peers: Option<&Arc<DashSet<AdnlNodeIdShort>>>,
    ) -> Result<(A, Arc<Neighbour>)>
    where
        Q: ton_api::AnyBoxedSerialize,
        A: ton_api::AnyBoxedSerialize,
    {
        const NO_NEIGHBOURS_DELAY: u64 = 1000; // Milliseconds

        let query = TLObject::new(query);
        let attempts = attempts.unwrap_or(DEFAULT_ADNL_ATTEMPTS);

        for _ in 0..attempts {
            let neighbour = match self.neighbours.choose_neighbour() {
                Some(neighbour) => neighbour,
                None => {
                    tokio::time::sleep(Duration::from_millis(NO_NEIGHBOURS_DELAY)).await;
                    return Err(OverlayClientError::NeNeighboursFound.into());
                }
            };

            if let Some(active_peers) = active_peers {
                active_peers.insert(*neighbour.peer_id());
            }

            match self
                .send_adnl_query_to_neighbour::<Q, A>(&neighbour, &query, timeout)
                .await
            {
                Ok(Some(answer)) => return Ok((answer, neighbour)),
                Ok(None) => {
                    if let Some(active_peers) = active_peers {
                        active_peers.remove(neighbour.peer_id());
                    }
                }
                Err(e) => {
                    if let Some(active_peers) = active_peers {
                        active_peers.remove(neighbour.peer_id());
                    }
                    return Err(e);
                }
            }
        }

        Err(OverlayClientError::AdnlQueryFailed(query, attempts).into())
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
        let now = Instant::now();
        let timeout =
            timeout.or_else(|| Some(AdnlNode::compute_query_timeout(neighbour.roundtrip_adnl())));

        let answer = self
            .overlay
            .query(&self.overlay_id, neighbour.peer_id(), query, timeout)
            .await?;

        let roundtrip = now.elapsed().as_millis() as u64;

        match answer.map(|answer| answer.downcast::<A>()) {
            Some(Ok(answer)) => {
                neighbour.query_succeeded(roundtrip, false);
                return Ok(Some(answer));
            }
            Some(Err(answer)) => {
                log::warn!(
                    "Wrong answer {:?} to {:?} from {}",
                    answer,
                    query,
                    neighbour.peer_id()
                );
            }
            None => {
                log::warn!("No reply to {:?} from {}", query, neighbour.peer_id());
            }
        }

        self.neighbours
            .update_neighbour_stats(neighbour.peer_id(), roundtrip, false, false, true);
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

        let mut data = self.overlay.get_query_prefix(&self.overlay_id)?;
        serialize_append(&mut data, query)?;
        let data = Arc::new(data);

        let (answer, roundtrip) = self
            .overlay
            .query_via_rldp(
                &self.overlay_id,
                neighbour.peer_id(),
                &data,
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

#[derive(thiserror::Error, Debug)]
enum OverlayClientError {
    #[error("No neighbours found")]
    NeNeighboursFound,
    #[error("Failed to send adnl query {:?} in {} attempts", .0, .1)]
    AdnlQueryFailed(TLObject, u32),
    #[error("No RLDP query answer from {}", .0)]
    NoRldpQueryAnswer(AdnlNodeIdShort),
}
