use std::borrow::{Borrow, Cow};
use std::sync::Arc;

use anyhow::Result;
use tl_proto::BoxedConstructor;

use super::futures::StoreValue;
use super::node::Node;
use super::streams::DhtValuesStream;
use crate::adnl;
use crate::proto;
use crate::util::now;

/// DHT entry builder
#[must_use]
#[derive(Copy, Clone)]
pub struct Entry<'a> {
    dht: &'a Arc<Node>,
    id: &'a [u8; 32],
    name: &'a str,
    key_index: u32,
}

impl<'a> Entry<'a> {
    pub(super) fn new<T>(dht: &'a Arc<Node>, id: &'a T, name: &'a str) -> Self
    where
        T: Borrow<[u8; 32]>,
    {
        Self {
            dht,
            id: id.borrow(),
            name,
            key_index: 0,
        }
    }

    /// Sets the key index. Default: `0`
    pub fn with_key_index(mut self, idx: u32) -> Self {
        self.key_index = idx;
        self
    }

    /// Creates a new builder which can store the value in the DHT.
    ///
    /// See [`with_data_raw`] for raw API
    ///
    /// [`with_data_raw`]: fn@crate::dht::Entry::with_data_raw
    pub fn with_data<T>(self, data: T) -> EntryWithData<'a>
    where
        T: tl_proto::TlWrite<Repr = tl_proto::Boxed>,
    {
        EntryWithData {
            inner: self,
            data: Cow::Owned(tl_proto::serialize(data)),
            expire_at: None,
        }
    }

    /// Creates a new builder which can store the value in the DHT.
    ///
    /// See [`with_data`] for more convenient API
    ///
    /// [`with_data`]: fn@crate::dht::Entry::with_data
    pub fn with_data_raw(self, data: &'a [u8]) -> EntryWithData<'a> {
        EntryWithData {
            inner: self,
            data: Cow::Borrowed(data),
            expire_at: None,
        }
    }

    /// Returns a stream of values for this entry.
    pub fn values<T>(self) -> DhtValuesStream<T>
    where
        for<'tl> T: tl_proto::TlRead<'tl, Repr = tl_proto::Boxed> + Send + 'static,
    {
        DhtValuesStream::new(self.dht.clone(), self.key())
    }

    /// Queries a value from the given peer.
    pub async fn value_from<T>(
        self,
        peer_id: &adnl::NodeIdShort,
    ) -> Result<Option<(proto::dht::KeyDescriptionOwned, T)>>
    where
        for<'tl> T: tl_proto::TlRead<'tl, Repr = tl_proto::Boxed> + Send + 'static,
    {
        let key_id = tl_proto::hash_as_boxed(self.key());
        let query = tl_proto::serialize(proto::rpc::DhtFindValue { key: &key_id, k: 6 }).into();

        match self.dht.query_raw(peer_id, query).await? {
            Some(result) => self.dht.parse_value_result(&result),
            None => Ok(None),
        }
    }

    /// Returns TL representation of the entry key.
    pub fn key(&self) -> proto::dht::Key<'a> {
        proto::dht::Key {
            id: self.id,
            name: self.name.as_bytes(),
            idx: self.key_index,
        }
    }
}

pub struct EntryWithData<'a> {
    inner: Entry<'a>,
    data: Cow<'a, [u8]>,
    expire_at: Option<u32>,
}

impl<'a> EntryWithData<'a> {
    /// Sets the expiration time for the value.
    pub fn expire_at(mut self, timestamp: u32) -> Self {
        self.expire_at = Some(timestamp);
        self
    }

    /// Sets expiration time for the value as `now + ttl`
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.expire_at = Some(now() + ttl);
        self
    }

    /// Creates signed TL representation of the entry.
    pub fn sign(self, key: &adnl::Key) -> proto::dht::ValueOwned {
        let mut value = self.make_value(key);

        let key_signature = key.sign(value.key.as_boxed());
        value.key.signature = &key_signature;

        let value_signature = key.sign(value.as_boxed());
        value.signature = &value_signature;

        value.as_equivalent_owned()
    }

    /// Creates signed TL representation of the entry and stores it in the DHT.
    ///
    /// See [`StoreValue`]
    pub fn sign_and_store(self, key: &adnl::Key) -> Result<StoreValue> {
        let mut value = self.make_value(key);

        let key_signature = key.sign(value.key.as_boxed());
        value.key.signature = &key_signature;

        let value_signature = key.sign(value.as_boxed());
        value.signature = &value_signature;

        StoreValue::new(self.inner.dht.clone(), value)
    }

    fn make_value<'b>(&'b self, key: &'b adnl::Key) -> proto::dht::Value<'b>
    where
        'a: 'b,
    {
        proto::dht::Value {
            key: proto::dht::KeyDescription {
                key: self.inner.key(),
                id: key.full_id().as_tl(),
                update_rule: proto::dht::UpdateRule::Signature,
                signature: Default::default(),
            },
            value: &self.data,
            ttl: self
                .expire_at
                .unwrap_or_else(|| now() + self.inner.dht.options().value_ttl_sec),
            signature: Default::default(),
        }
    }
}
