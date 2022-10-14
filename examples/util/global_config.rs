use std::net::SocketAddrV4;

use everscale_network::proto;
use serde::{de::Error, Deserialize, Deserializer};

#[derive(Deserialize)]
pub struct GlobalConfig {
    pub zero_state: ZeroState,
    pub dht_nodes: Vec<DhtNode>,
}

pub struct ZeroState {
    pub file_hash: [u8; 32],
}

impl<'de> Deserialize<'de> for ZeroState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Entry {
            file_hash: String,
        }

        let entry = Entry::deserialize(deserializer)?;

        Ok(ZeroState {
            file_hash: base64::decode(entry.file_hash)
                .map_err(Error::custom)?
                .try_into()
                .map_err(|_| Error::custom("invalid zerostate file hash"))?,
        })
    }
}

pub struct DhtNode(pub proto::dht::NodeOwned);

impl<'de> Deserialize<'de> for DhtNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Entry {
            pubkey: String,
            addr_list: AddrList,
            version: u32,
            signature: String,
        }

        #[derive(Deserialize)]
        struct AddrList {
            address: Option<SocketAddrV4>,
            expire_at: u32,
            reinit_date: u32,
            version: u32,
        }

        let entry = Entry::deserialize(deserializer)?;

        let addr_list = proto::adnl::AddressList {
            address: entry
                .addr_list
                .address
                .map(|addr| proto::adnl::Address::Udp {
                    ip: u32::from_be_bytes(addr.ip().octets()),
                    port: addr.port() as u32,
                }),
            version: entry.addr_list.version,
            reinit_date: entry.addr_list.reinit_date,
            expire_at: entry.addr_list.expire_at,
        };

        let node = proto::dht::NodeOwned {
            id: everscale_crypto::tl::PublicKeyOwned::Ed25519 {
                key: hex::decode(entry.pubkey)
                    .map_err(Error::custom)?
                    .try_into()
                    .map_err(|_| Error::custom("invalid pubkey"))?,
            },
            addr_list,
            version: entry.version,
            signature: base64::decode(entry.signature)
                .map_err(|_| Error::custom("invalid signature"))?
                .into(),
        };

        Ok(Self(node))
    }
}
