use std::sync::Arc;
use std::time::Instant;

use crate::adnl_node::AdnlNode;
use crate::subscriber::*;

mod decoder;
mod encoder;

pub struct RldpNode {
    adnl: Arc<AdnlNode>,
    subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
}

impl RldpNode {
    pub fn with_adnl_node(adnl: Arc<AdnlNode>, subscribers: Vec<Arc<dyn Subscriber>>) -> Arc<Self> {
        Arc::new(Self {
            adnl,
            subscribers: Arc::new(subscribers),
        })
    }

    // TODO
}

#[async_trait::async_trait]
impl Subscriber for RldpNode {
    // TODO
}
