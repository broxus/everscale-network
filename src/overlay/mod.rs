//! ## Overlay - virtual subnetwork
//!
//! An overlay (sub)network is simply a (virtual) network implemented inside some larger network.
//! Only some nodes of the larger network participate in the overlay subnetwork,
//! and only some "links" between these nodes, physical or virtual, are part of the overlay
//! sub-network.
//!
//! TODO

pub use node::OverlayNode;
pub use overlay_shard::{
    IncomingBroadcastInfo, OutgoingBroadcastInfo, OverlayShard, OverlayShardMetrics,
    OverlayShardOptions, ReceivedPeersMap,
};

mod broadcast_receiver;
mod node;
mod overlay_shard;

/// Max allowed known peer count
pub const MAX_OVERLAY_PEERS: usize = 65536;
