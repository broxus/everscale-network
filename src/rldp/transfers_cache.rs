use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;
use tl_proto::{TlRead, TlWrite};
use tokio::sync::mpsc;

use super::incoming_transfer::*;
use super::outgoing_transfer::*;
use super::RldpNodeOptions;
use crate::adnl::AdnlNode;
use crate::proto;
use crate::subscriber::*;
use crate::utils::*;

pub struct TransfersCache {
    transfers: Arc<FxDashMap<TransferId, RldpTransfer>>,
    subscribers: Arc<Vec<Arc<dyn QuerySubscriber>>>,
    query_options: QueryOptions,
    max_answer_size: u32,
    force_compression: bool,
}

impl TransfersCache {
    pub fn new(subscribers: Vec<Arc<dyn QuerySubscriber>>, options: RldpNodeOptions) -> Self {
        Self {
            transfers: Arc::new(Default::default()),
            subscribers: Arc::new(subscribers),
            query_options: QueryOptions {
                query_wave_len: options.query_wave_len,
                query_wave_interval_ms: options.query_wave_interval_ms,
                query_min_timeout_ms: options.query_min_timeout_ms,
                query_max_timeout_ms: options.query_max_timeout_ms,
            },
            max_answer_size: options.max_answer_size,
            force_compression: options.force_compression,
        }
    }

    /// Sends serialized query and waits answer
    pub async fn query(
        &self,
        adnl: &Arc<AdnlNode>,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: Vec<u8>,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        // Initiate outgoing transfer with new id
        let outgoing_transfer = OutgoingTransfer::new(data, None);
        let outgoing_transfer_id = *outgoing_transfer.transfer_id();
        let outgoing_transfer_state = outgoing_transfer.state().clone();
        self.transfers.insert(
            outgoing_transfer_id,
            RldpTransfer::Outgoing(outgoing_transfer_state.clone()),
        );

        // Initiate incoming transfer with derived id
        let incoming_transfer_id = negate_id(outgoing_transfer_id);
        let incoming_transfer = IncomingTransfer::new(incoming_transfer_id, self.max_answer_size);
        let incoming_transfer_state = incoming_transfer.state().clone();
        let (parts_tx, parts_rx) = mpsc::unbounded_channel();
        self.transfers
            .insert(incoming_transfer_id, RldpTransfer::Incoming(parts_tx));

        // Prepare contexts
        let outgoing_context = OutgoingContext {
            adnl: adnl.clone(),
            local_id: *local_id,
            peer_id: *peer_id,
            transfer: outgoing_transfer,
        };

        let mut incoming_context = IncomingContext {
            adnl: adnl.clone(),
            local_id: *local_id,
            peer_id: *peer_id,
            parts_rx,
            transfer: incoming_transfer,
            transfer_id: outgoing_transfer_id,
        };

        // Start query transfer loop
        let barrier = Arc::new(Mutex::new(None));

        // Spawn receiver
        tokio::spawn({
            let barrier = barrier.clone();
            async move {
                incoming_context
                    .receive(Some(outgoing_transfer_state))
                    .await;
                *barrier.lock() = Some(incoming_context.transfer);
            }
        });

        // Send data and wait until something is received
        let result = outgoing_context.send(self.query_options, roundtrip).await;
        if result.is_ok() {
            self.transfers
                .insert(outgoing_transfer_id, RldpTransfer::Done);
        }

        let result = match result {
            Ok((true, mut roundtrip)) => {
                let mut start = Instant::now();
                let mut updates = incoming_transfer_state.updates();
                let mut timeout = self.query_options.compute_timeout(Some(roundtrip));

                loop {
                    // Wait until `updates` will be the same for one interval
                    tokio::time::sleep(Duration::from_millis(TRANSFER_LOOP_INTERVAL)).await;

                    let new_updates = incoming_transfer_state.updates();
                    if new_updates > updates {
                        // Reset start timestamp on update
                        timeout = self.query_options.update_roundtrip(&mut roundtrip, &start);
                        updates = new_updates;
                        start = Instant::now();
                    } else if is_timed_out(&start, timeout, updates) {
                        // Stop polling on timeout
                        break Ok((None, roundtrip));
                    }

                    // Check barrier data
                    if let Some(reply) = barrier.lock().take() {
                        self.query_options.update_roundtrip(&mut roundtrip, &start);
                        break Ok((Some(reply.into_data()), roundtrip));
                    }
                }
            }
            Ok((false, roundtrip)) => Ok((None, roundtrip)),
            Err(e) => {
                // Reset transfer entries
                self.transfers
                    .insert(outgoing_transfer_id, RldpTransfer::Done);
                Err(e)
            }
        };

        self.transfers
            .insert(incoming_transfer_id, RldpTransfer::Done);

        // Clear transfers in background
        tokio::spawn({
            let transfers = self.transfers.clone();
            let interval = self.query_options.completion_interval();
            async move {
                tokio::time::sleep(interval).await;
                transfers.remove(&outgoing_transfer_id);
                transfers.remove(&incoming_transfer_id);
            }
        });

        // Done
        result
    }

    pub fn len(&self) -> usize {
        self.transfers.len()
    }

    /// Handles incoming message
    pub async fn handle_message(
        &self,
        adnl: &Arc<AdnlNode>,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        message: proto::rldp::MessagePart<'_>,
    ) -> Result<()> {
        match message {
            proto::rldp::MessagePart::MessagePart {
                transfer_id,
                fec_type,
                part,
                total_size,
                seqno,
                data,
            } => loop {
                // Trying to get existing transfer
                match self.transfers.get(transfer_id) {
                    // If transfer exists
                    Some(item) => match item.value() {
                        // Forward message part on `incoming` state
                        RldpTransfer::Incoming(parts_tx) => {
                            let _ = parts_tx.send(MessagePart {
                                fec_type,
                                part,
                                total_size,
                                seqno,
                                data: data.to_vec(),
                            });
                            break;
                        }
                        // Blindly confirm receiving in case of other states
                        _ => {
                            drop(item); // drop item ref to prevent DashMap deadlocks

                            // Send confirm message
                            let mut buffer = Vec::with_capacity(44);
                            proto::rldp::MessagePart::Confirm {
                                transfer_id,
                                part,
                                seqno,
                            }
                            .write_to(&mut buffer);
                            adnl.send_custom_message(local_id, peer_id, &buffer)?;

                            // Send complete message
                            buffer.clear();
                            proto::rldp::MessagePart::Complete { transfer_id, part }
                                .write_to(&mut buffer);
                            adnl.send_custom_message(local_id, peer_id, &buffer)?;

                            // Done
                            break;
                        }
                    },
                    // If transfer doesn't exist (it is a query from other node)
                    None => match self
                        .create_answer_handler(adnl, local_id, peer_id, *transfer_id)
                        .await?
                    {
                        // Forward message part on `incoming` state (for newly created transfer)
                        Some(parts_tx) => {
                            let _ = parts_tx.send(MessagePart {
                                fec_type,
                                part,
                                total_size,
                                seqno,
                                data: data.to_vec(),
                            });
                            break;
                        }
                        // In case of intermediate state - retry
                        None => continue,
                    },
                }
            },
            proto::rldp::MessagePart::Confirm {
                transfer_id,
                part,
                seqno,
            } => {
                if let Some(transfer) = self.transfers.get(transfer_id) {
                    if let RldpTransfer::Outgoing(state) = transfer.value() {
                        if state.part() == part as u32 {
                            state.set_seqno_in(seqno as u32);
                        }
                    }
                }
            }
            proto::rldp::MessagePart::Complete { transfer_id, part } => {
                if let Some(transfer) = self.transfers.get(transfer_id) {
                    if let RldpTransfer::Outgoing(state) = transfer.value() {
                        state.set_part(part as u32 + 1);
                    }
                }
            }
        };

        // Done
        Ok(())
    }

    /// Receives incoming query and sends answer
    async fn create_answer_handler(
        &self,
        adnl: &Arc<AdnlNode>,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        transfer_id: TransferId,
    ) -> Result<Option<MessagePartsTx>> {
        use dashmap::mapref::entry::Entry;

        let (parts_tx, parts_rx) = match self.transfers.entry(transfer_id) {
            // Create new transfer
            Entry::Vacant(entry) => {
                let (parts_tx, parts_rx) = mpsc::unbounded_channel();
                entry.insert(RldpTransfer::Incoming(parts_tx.clone()));
                (parts_tx, parts_rx)
            }
            // Or do nothing if it already exists
            Entry::Occupied(_) => return Ok(None),
        };

        // Prepare context
        let mut incoming_context = IncomingContext {
            adnl: adnl.clone(),
            local_id: *local_id,
            peer_id: *peer_id,
            parts_rx,
            transfer: IncomingTransfer::new(transfer_id, self.max_answer_size),
            transfer_id,
        };

        // Spawn processing task
        let subscribers = self.subscribers.clone();
        let transfers = self.transfers.clone();
        let query_options = self.query_options;
        let force_compression = self.force_compression;
        tokio::spawn(async move {
            // Wait until incoming query is received
            incoming_context.receive(None).await;
            transfers.insert(transfer_id, RldpTransfer::Done);

            // Process query
            let outgoing_transfer_id = incoming_context
                .answer(
                    transfers.clone(),
                    subscribers,
                    query_options,
                    force_compression,
                )
                .await
                .unwrap_or_default();

            // Clear transfers in background
            tokio::time::sleep(query_options.completion_interval()).await;
            if let Some(outgoing_transfer_id) = outgoing_transfer_id {
                transfers.remove(&outgoing_transfer_id);
            }
            transfers.remove(&transfer_id);
        });

        // Clear incoming transfer on timeout
        let transfers = self.transfers.clone();
        let interval = self.query_options.completion_interval();
        tokio::spawn(async move {
            tokio::time::sleep(interval).await;
            transfers.insert(transfer_id, RldpTransfer::Done);
        });

        // Done
        Ok(Some(parts_tx))
    }
}

enum RldpTransfer {
    Incoming(MessagePartsTx),
    Outgoing(Arc<OutgoingTransferState>),
    Done,
}

struct IncomingContext {
    adnl: Arc<AdnlNode>,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    parts_rx: MessagePartsRx,
    transfer: IncomingTransfer,
    transfer_id: TransferId,
}

impl IncomingContext {
    #[tracing::instrument(level = "debug", skip_all)]
    async fn receive(&mut self, mut outgoing_transfer_state: Option<Arc<OutgoingTransferState>>) {
        // For each incoming message part
        while let Some(message) = self.parts_rx.recv().await {
            // Trying to process its data
            match self.transfer.process_chunk(message) {
                // If some data was successfully processed
                Ok(Some(reply)) => {
                    // Send `complete` or `confirm` message as reply
                    if let Err(e) =
                        self.adnl
                            .send_custom_message(&self.local_id, &self.peer_id, reply)
                    {
                        tracing::warn!("RLDP query error: {e}");
                    }
                }
                Err(e) => tracing::warn!("RLDP error: {e}"),
                _ => {}
            }

            // Increase `updates` counter
            self.transfer.state().increase_updates();

            // Notify state, that some reply was received
            if let Some(outgoing_transfer_state) = outgoing_transfer_state.take() {
                outgoing_transfer_state.set_reply();
            }

            // Exit loop if all bytes were received
            match self.transfer.total_size() {
                Some(total_size) if total_size == self.transfer.data().len() => {
                    break;
                }
                None => {
                    tracing::warn!("total size mismatch");
                }
                _ => {}
            }
        }

        // Close and clear parts channel
        self.parts_rx.close();
        while self.parts_rx.recv().await.is_some() {}
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn answer(
        mut self,
        transfers: Arc<FxDashMap<TransferId, RldpTransfer>>,
        subscribers: Arc<Vec<Arc<dyn QuerySubscriber>>>,
        query_options: QueryOptions,
        force_compression: bool,
    ) -> Result<Option<TransferId>> {
        // Deserialize incoming query
        let query = match OwnedRldpMessageQuery::from_data(self.transfer.take_data()) {
            Some(query) => query,
            None => return Err(TransfersCacheError::UnexpectedMessage.into()),
        };

        // Process query
        let ctx = SubscriberContext {
            adnl: &self.adnl,
            local_id: &self.local_id,
            peer_id: &self.peer_id,
        };
        let answer = match process_rldp_query(ctx, &subscribers, query, force_compression).await? {
            QueryProcessingResult::Processed(Some(answer)) => answer,
            QueryProcessingResult::Processed(None) => return Ok(None),
            QueryProcessingResult::Rejected => {
                return Err(TransfersCacheError::NoSubscribers.into())
            }
        };

        // Create outgoing transfer
        let outgoing_transfer_id = negate_id(self.transfer_id);
        let outgoing_transfer = OutgoingTransfer::new(answer, Some(outgoing_transfer_id));
        transfers.insert(
            outgoing_transfer_id,
            RldpTransfer::Outgoing(outgoing_transfer.state().clone()),
        );

        // Prepare context
        let outgoing_context = OutgoingContext {
            adnl: self.adnl.clone(),
            local_id: self.local_id,
            peer_id: self.peer_id,
            transfer: outgoing_transfer,
        };

        // Send answer
        outgoing_context.send(query_options, None).await?;

        // Done
        Ok(Some(outgoing_transfer_id))
    }
}

struct OutgoingContext {
    adnl: Arc<AdnlNode>,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    transfer: OutgoingTransfer,
}

impl OutgoingContext {
    #[tracing::instrument(level = "debug", skip_all)]
    async fn send(
        mut self,
        query_options: QueryOptions,
        roundtrip: Option<u64>,
    ) -> Result<(bool, u64)> {
        // Prepare timeout
        let mut timeout = query_options.compute_timeout(roundtrip);
        let mut roundtrip = roundtrip.unwrap_or_default();

        let waves_interval = Duration::from_millis(query_options.query_wave_interval_ms);

        // For each outgoing message part
        while let Some(packet_count) = self.transfer.start_next_part()? {
            let wave_len = std::cmp::min(packet_count, query_options.query_wave_len);

            let part = self.transfer.state().part();

            let mut start = Instant::now();

            let mut incoming_seqno = 0;
            'part: loop {
                // Send parts in waves
                for _ in 0..wave_len {
                    self.adnl.send_custom_message(
                        &self.local_id,
                        &self.peer_id,
                        self.transfer.prepare_chunk()?,
                    )?;

                    if self.transfer.is_finished_or_next_part(part)? {
                        break 'part;
                    }
                }

                tokio::time::sleep(waves_interval).await;
                if self.transfer.is_finished_or_next_part(part)? {
                    break 'part;
                }

                // Update timeout on incoming packets
                let new_incoming_seqno = self.transfer.state().seqno_in();
                if new_incoming_seqno > incoming_seqno {
                    timeout = query_options.update_roundtrip(&mut roundtrip, &start);
                    incoming_seqno = new_incoming_seqno;
                    start = Instant::now();
                } else if is_timed_out(&start, timeout, incoming_seqno) {
                    return Ok((false, query_options.big_roundtrip(roundtrip)));
                }
            }

            // Update timeout
            timeout = query_options.update_roundtrip(&mut roundtrip, &start);
        }

        // Done
        Ok((true, roundtrip))
    }
}

#[derive(Copy, Clone)]
struct QueryOptions {
    query_wave_len: u32,
    query_wave_interval_ms: u64,
    query_min_timeout_ms: u64,
    query_max_timeout_ms: u64,
}

impl QueryOptions {
    /// Updates provided roundtrip and returns timeout
    fn update_roundtrip(&self, roundtrip: &mut u64, time: &Instant) -> u64 {
        *roundtrip = if *roundtrip == 0 {
            time.elapsed().as_millis() as u64
        } else {
            (*roundtrip + time.elapsed().as_millis() as u64) / 2
        };
        self.compute_timeout(Some(*roundtrip))
    }

    /// Clamps roundtrip to get valid timeout
    fn compute_timeout(&self, roundtrip: Option<u64>) -> u64 {
        match roundtrip {
            Some(roundtrip) if roundtrip > self.query_max_timeout_ms => self.query_max_timeout_ms,
            Some(roundtrip) => std::cmp::max(roundtrip, self.query_min_timeout_ms),
            None => self.query_max_timeout_ms,
        }
    }

    /// Computes roundtrip for invalid query
    fn big_roundtrip(&self, roundtrip: u64) -> u64 {
        std::cmp::min(roundtrip * 2, self.query_max_timeout_ms)
    }

    fn completion_interval(&self) -> Duration {
        Duration::from_millis(self.query_max_timeout_ms * 2)
    }
}

async fn process_rldp_query<'a>(
    ctx: SubscriberContext<'a>,
    subscribers: &[Arc<dyn QuerySubscriber>],
    mut query: OwnedRldpMessageQuery,
    force_compression: bool,
) -> Result<QueryProcessingResult<Vec<u8>>> {
    let answer_compression = match compression::decompress(&query.data) {
        Some(decompressed) => {
            query.data = decompressed;
            true
        }
        None => force_compression,
    };

    match process_query(ctx, subscribers, Cow::Owned(query.data)).await? {
        QueryProcessingResult::Processed(answer) => Ok(match answer {
            Some(mut answer) => {
                if answer_compression {
                    if let Err(e) = compression::compress(&mut answer) {
                        tracing::warn!("Failed to compress RLDP answer: {e:?}");
                    }
                }
                if answer.len() > query.max_answer_size as usize {
                    return Err(TransfersCacheError::AnswerSizeExceeded.into());
                }

                QueryProcessingResult::Processed(Some(tl_proto::serialize(
                    proto::rldp::Message::Answer {
                        query_id: &query.query_id,
                        data: &answer,
                    },
                )))
            }
            None => QueryProcessingResult::Processed(None),
        }),
        _ => Ok(QueryProcessingResult::Rejected),
    }
}

struct OwnedRldpMessageQuery {
    query_id: [u8; 32],
    max_answer_size: u64,
    data: Vec<u8>,
}

impl OwnedRldpMessageQuery {
    fn from_data(mut data: Vec<u8>) -> Option<Self> {
        #[derive(TlRead, TlWrite)]
        #[tl(boxed, id = 0x8a794d69)]
        struct Query {
            #[tl(size_hint = 32)]
            query_id: [u8; 32],
            max_answer_size: u64,
            timeout: u32,
        }

        let mut offset = 0;
        let params = Query::read_from(&data, &mut offset).ok()?;
        unsafe {
            let remaining = data.len() - offset;
            std::ptr::copy(data.as_ptr().add(offset), data.as_mut_ptr(), remaining);
            data.set_len(remaining);
        };

        Some(Self {
            query_id: params.query_id,
            max_answer_size: params.max_answer_size,
            data,
        })
    }
}

fn is_timed_out(time: &Instant, timeout: u64, updates: u32) -> bool {
    time.elapsed().as_millis() as u64 > timeout + timeout * (updates as u64) / 100
}

fn negate_id(id: [u8; 32]) -> [u8; 32] {
    id.map(|item| item ^ 0xff)
}

type MessagePartsTx = mpsc::UnboundedSender<MessagePart>;
type MessagePartsRx = mpsc::UnboundedReceiver<MessagePart>;

pub type TransferId = [u8; 32];

const TRANSFER_LOOP_INTERVAL: u64 = 10; // Milliseconds

#[derive(thiserror::Error, Debug)]
enum TransfersCacheError {
    #[error("Unexpected message")]
    UnexpectedMessage,
    #[error("No subscribers for query")]
    NoSubscribers,
    #[error("Answer size exceeded")]
    AnswerSizeExceeded,
}
