use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use ton_api::ton;

use super::incoming_transfer::*;
use super::outgoing_transfer::*;
use super::MessagePart;
use crate::adnl_node::AdnlNode;
use crate::subscriber::*;
use crate::utils::RldpMessagePartView;
use crate::utils::*;

#[derive(Clone)]
pub struct TransfersCache {
    adnl: Arc<AdnlNode>,
    transfers: Arc<FxDashMap<TransferId, RldpTransfer>>,
    subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    force_compression: bool,
}

impl TransfersCache {
    pub fn new(
        adnl: Arc<AdnlNode>,
        subscribers: Vec<Arc<dyn Subscriber>>,
        force_compression: bool,
    ) -> Self {
        Self {
            adnl,
            transfers: Arc::new(Default::default()),
            subscribers: Arc::new(subscribers),
            force_compression,
        }
    }

    /// Sends serialized query and waits answer
    pub async fn query(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        data: Vec<u8>,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        // Initiate outgoing transfer with new id
        let mut outgoing_transfer = OutgoingTransfer::new(data, None);
        let outgoing_transfer_id = outgoing_transfer.message().transfer_id.0;
        let outgoing_transfer_state = outgoing_transfer.state().clone();
        self.transfers.insert(
            outgoing_transfer_id,
            RldpTransfer::Outgoing(outgoing_transfer_state.clone()),
        );

        // Initiate incoming transfer with derived id
        let incoming_transfer_id = negate_id(outgoing_transfer_id);
        let incoming_transfer = IncomingTransfer::new(incoming_transfer_id);
        let incoming_transfer_state = incoming_transfer.state().clone();
        let (parts_tx, parts_rx) = mpsc::unbounded_channel();
        self.transfers
            .insert(incoming_transfer_id, RldpTransfer::Incoming(parts_tx));

        // Prepare contexts
        let outgoing_context = OutgoingContext {
            adnl: self.adnl.clone(),
            local_id: *local_id,
            peer_id: *peer_id,
            transfer: outgoing_transfer,
        };

        let mut incoming_context = IncomingContext {
            adnl: self.adnl.clone(),
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
                receive_loop(&mut incoming_context, Some(outgoing_transfer_state)).await;
                *barrier.lock() = Some(incoming_context.transfer);
            }
        });

        // Send data and wait until something is received
        let result = match send_loop(outgoing_context, roundtrip).await.map(|result| {
            self.transfers
                .insert(outgoing_transfer_id, RldpTransfer::Done);
            result
        }) {
            Ok((true, mut roundtrip)) => {
                let mut start = Instant::now();
                let mut updates = incoming_transfer_state.updates();
                let mut timeout = compute_timeout(Some(roundtrip));

                loop {
                    // Wait until `updates` will be the same for one interval
                    tokio::time::sleep(Duration::from_millis(TRANSFER_LOOP_INTERVAL)).await;

                    let new_updates = incoming_transfer_state.updates();
                    if new_updates > updates {
                        // Reset start timestamp on update
                        timeout = update_roundtrip(&mut roundtrip, &start);
                        updates = new_updates;
                        start = Instant::now();
                    } else if is_timed_out(&start, timeout, updates) {
                        // Stop polling on timeout
                        break Ok((None, roundtrip));
                    }

                    // Check barrier data
                    if let Some(reply) = barrier.lock().take() {
                        update_roundtrip(&mut roundtrip, &start);
                        break Ok((Some(reply.into_data()), roundtrip));
                    }
                }
            }
            Ok((false, roundtrip)) => Ok((None, roundtrip)),
            Err(e) => Err(e),
        };

        // Reset transfer entries
        if result.is_err() {
            self.transfers
                .insert(outgoing_transfer_id, RldpTransfer::Done);
        }
        self.transfers
            .insert(incoming_transfer_id, RldpTransfer::Done);

        // Clear transfers in background
        tokio::spawn({
            let transfers = self.transfers.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(MAX_TIMEOUT * 2)).await;
                transfers.remove(&outgoing_transfer_id);
                transfers.remove(&incoming_transfer_id);
            }
        });

        // Done
        result
    }

    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.transfers.len()
    }

    /// Handles incoming message
    pub async fn handle_message(
        &self,
        local_id: &AdnlNodeIdShort,
        peer_id: &AdnlNodeIdShort,
        message: RldpMessagePartView<'_>,
    ) -> Result<()> {
        match message {
            RldpMessagePartView::MessagePart {
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
                                fec_type: fec_type.into(),
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
                            let reply = serialize_boxed(ton::rldp::messagepart::Confirm {
                                transfer_id: ton::int256(*transfer_id),
                                part,
                                seqno,
                            })?;
                            self.adnl.send_custom_message(local_id, peer_id, &reply)?;

                            // Send complete message
                            let reply = serialize_boxed(ton::rldp::messagepart::Complete {
                                transfer_id: ton::int256(*transfer_id),
                                part,
                            })?;
                            self.adnl.send_custom_message(local_id, peer_id, &reply)?;

                            // Done
                            break;
                        }
                    },
                    // If transfer doesn't exist (it is a query from other node)
                    None => match self
                        .create_answer_handler(local_id, peer_id, *transfer_id)
                        .await?
                    {
                        // Forward message part on `incoming` state (for newly created transfer)
                        Some(parts_tx) => {
                            let _ = parts_tx.send(MessagePart {
                                fec_type: fec_type.into(),
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
            RldpMessagePartView::Confirm {
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
            RldpMessagePartView::Complete { transfer_id, part } => {
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
            adnl: self.adnl.clone(),
            local_id: *local_id,
            peer_id: *peer_id,
            parts_rx,
            transfer: IncomingTransfer::new(transfer_id),
            transfer_id,
        };

        // Spawn processing task
        tokio::spawn({
            let subscribers = self.subscribers.clone();
            let transfers = self.transfers.clone();
            let force_compression = self.force_compression;
            async move {
                // Wait until incoming query is received
                receive_loop(&mut incoming_context, None).await;
                transfers.insert(transfer_id, RldpTransfer::Done);

                // Process query
                let outgoing_transfer_id = answer_loop(
                    incoming_context,
                    transfers.clone(),
                    subscribers,
                    force_compression,
                )
                .await
                .unwrap_or_default();

                // Clear transfers in background
                tokio::time::sleep(Duration::from_millis(MAX_TIMEOUT * 2)).await;
                if let Some(outgoing_transfer_id) = outgoing_transfer_id {
                    transfers.remove(&outgoing_transfer_id);
                }
                transfers.remove(&transfer_id);
            }
        });

        // Clear incoming transfer on timeout
        tokio::spawn({
            let transfers = self.transfers.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(MAX_TIMEOUT)).await;
                transfers.insert(transfer_id, RldpTransfer::Done);
            }
        });

        // Done
        Ok(Some(parts_tx))
    }
}

pub fn make_query(data: Vec<u8>, max_answer_size: Option<i64>) -> Result<(QueryId, Vec<u8>)> {
    use rand::Rng;

    let query_id: QueryId = rand::thread_rng().gen();
    let data = serialize_boxed(ton::rldp::message::Query {
        query_id: ton::int256(query_id),
        max_answer_size: max_answer_size.unwrap_or(128 * 1024),
        timeout: now() + MAX_TIMEOUT as i32 / 1000,
        data: ton::bytes(data),
    })?;

    Ok((query_id, data))
}

async fn receive_loop(
    incoming_context: &mut IncomingContext,
    mut outgoing_transfer_state: Option<Arc<OutgoingTransferState>>,
) {
    // For each incoming message part
    while let Some(message) = incoming_context.parts_rx.recv().await {
        // Trying to process its data
        match incoming_context.transfer.process_chunk(message) {
            // If some data was successfully processed
            Ok(Some(reply)) => {
                // Send `complete` or `confirm` message as reply
                if let Err(e) = incoming_context.adnl.send_custom_message(
                    &incoming_context.local_id,
                    &incoming_context.peer_id,
                    reply,
                ) {
                    log::warn!("RLDP query error: {}", e);
                }
            }
            Err(e) => log::warn!("RLDP error: {}", e),
            _ => {}
        }

        // Increase `updates` counter
        incoming_context.transfer.state().increase_updates();

        // Notify state, that some reply was received
        if let Some(outgoing_transfer_state) = outgoing_transfer_state.take() {
            outgoing_transfer_state.set_reply();
        }

        // Exit loop if all bytes were received
        match incoming_context.transfer.total_size() {
            Some(total_size) if total_size == incoming_context.transfer.data().len() => {
                break;
            }
            None => {
                log::warn!("total size mismatch");
            }
            _ => {}
        }
    }

    // Close and clear parts channel
    incoming_context.parts_rx.close();
    while incoming_context.parts_rx.recv().await.is_some() {}
}

async fn send_loop(
    mut outgoing_context: OutgoingContext,
    roundtrip: Option<u64>,
) -> Result<(bool, u64)> {
    const MAX_TRANSFER_WAVE: u32 = 10;

    // Prepare timeout
    let mut timeout = compute_timeout(roundtrip);
    let mut roundtrip = roundtrip.unwrap_or_default();

    // For each outgoing message part
    while let Some(transfer_wave) = outgoing_context.transfer.start_next_part()? {
        let transfer_wave = std::cmp::min(transfer_wave, MAX_TRANSFER_WAVE);

        let part = outgoing_context.transfer.state().part();
        let mut start = Instant::now();
        let mut incoming_seqno = 0;

        'part: loop {
            // Trying to send message chunks
            for _ in 0..transfer_wave {
                outgoing_context.adnl.send_custom_message(
                    &outgoing_context.local_id,
                    &outgoing_context.peer_id,
                    outgoing_context.transfer.prepare_chunk()?,
                )?;

                if outgoing_context.transfer.is_finished_or_next_part(part)? {
                    break 'part;
                }
            }

            tokio::time::sleep(Duration::from_millis(TRANSFER_LOOP_INTERVAL)).await;

            if outgoing_context.transfer.is_finished_or_next_part(part)? {
                break;
            }

            // Update timeout on incoming packets
            let new_incoming_seqno = outgoing_context.transfer.state().seqno_in();
            if new_incoming_seqno > incoming_seqno {
                timeout = update_roundtrip(&mut roundtrip, &start);
                incoming_seqno = new_incoming_seqno;
                start = Instant::now();
            } else if is_timed_out(&start, timeout, incoming_seqno) {
                return Ok((false, std::cmp::min(roundtrip * 2, MAX_TIMEOUT)));
            }
        }

        // Update timeout
        timeout = update_roundtrip(&mut roundtrip, &start);
    }

    // Done
    Ok((true, roundtrip))
}

async fn answer_loop(
    mut incoming_context: IncomingContext,
    transfers: Arc<FxDashMap<TransferId, RldpTransfer>>,
    subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    force_compression: bool,
) -> Result<Option<TransferId>> {
    // Deserialize incoming query
    let query = match deserialize(&incoming_context.transfer.take_data())?
        .downcast::<ton::rldp::Message>()
    {
        Ok(ton::rldp::Message::Rldp_Query(query)) => query,
        _ => return Err(TransfersCacheError::UnexpectedMessage.into()),
    };

    let max_answer_size = query.max_answer_size as usize;

    // Process query
    let answer = match process_message_rldp_query(
        &incoming_context.local_id,
        &incoming_context.peer_id,
        &subscribers,
        *query,
        force_compression,
    )
    .await?
    {
        QueryProcessingResult::Processed(Some(answer)) => answer,
        QueryProcessingResult::Processed(None) => return Ok(None),
        QueryProcessingResult::Rejected => return Err(TransfersCacheError::NoSubscribers.into()),
    };

    // Check answer
    if answer.data.len() > max_answer_size {
        return Err(TransfersCacheError::AnswerSizeExceeded.into());
    }

    // Create outgoing transfer
    let answer = serialize_boxed(answer)?;
    let outgoing_transfer_id = negate_id(incoming_context.transfer_id);
    let outgoing_transfer = OutgoingTransfer::new(answer, Some(outgoing_transfer_id));
    transfers.insert(
        outgoing_transfer_id,
        RldpTransfer::Outgoing(outgoing_transfer.state().clone()),
    );

    // Prepare context
    let outgoing_context = OutgoingContext {
        adnl: incoming_context.adnl.clone(),
        local_id: incoming_context.local_id,
        peer_id: incoming_context.peer_id,
        transfer: outgoing_transfer,
    };

    // Send answer
    send_loop(outgoing_context, None).await?;

    // Done
    Ok(Some(outgoing_transfer_id))
}

fn update_roundtrip(roundtrip: &mut u64, time: &Instant) -> u64 {
    *roundtrip = if *roundtrip == 0 {
        time.elapsed().as_millis() as u64
    } else {
        *roundtrip + (time.elapsed().as_millis() as u64) / 2
    };
    compute_timeout(Some(*roundtrip))
}

fn compute_timeout(roundtrip: Option<u64>) -> u64 {
    std::cmp::max(roundtrip.unwrap_or(MAX_TIMEOUT), MIN_TIMEOUT)
}

fn is_timed_out(time: &Instant, timeout: u64, updates: u32) -> bool {
    time.elapsed().as_millis() as u64 > timeout + timeout * (updates as u64) / 100
}

fn negate_id(mut id: [u8; 32]) -> [u8; 32] {
    for symbol in &mut id {
        *symbol ^= 0xff;
    }
    id
}

enum RldpTransfer {
    Incoming(MessagePartsTx),
    Outgoing(Arc<OutgoingTransferState>),
    Done,
}

struct OutgoingContext {
    adnl: Arc<AdnlNode>,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    transfer: OutgoingTransfer,
}

struct IncomingContext {
    adnl: Arc<AdnlNode>,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    parts_rx: MessagePartsRx,
    transfer: IncomingTransfer,
    transfer_id: TransferId,
}

impl From<FecTypeView> for Option<ton::fec::type_::RaptorQ> {
    fn from(ty: FecTypeView) -> Self {
        match ty {
            FecTypeView::RaptorQ {
                data_size,
                symbol_size,
                symbols_count,
            } => Some(ton::fec::type_::RaptorQ {
                data_size,
                symbol_size,
                symbols_count,
            }),
            _ => None,
        }
    }
}

type MessagePartsTx = mpsc::UnboundedSender<MessagePart>;
type MessagePartsRx = mpsc::UnboundedReceiver<MessagePart>;

pub type TransferId = [u8; 32];

const MIN_TIMEOUT: u64 = 500;
const MAX_TIMEOUT: u64 = 10000; // Milliseconds
const TRANSFER_LOOP_INTERVAL: u64 = 10; // Milliseconds

#[derive(thiserror::Error, Debug)]
enum TransfersCacheError {
    #[error("Unexpected message")]
    UnexpectedMessage,
    #[error("Answer size exceeded")]
    AnswerSizeExceeded,
    #[error("No subscribers for query")]
    NoSubscribers,
}
