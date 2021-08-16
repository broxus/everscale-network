use std::io::Write;

use smallvec::SmallVec;

use super::prelude::*;

#[derive(Debug, Clone)]
pub enum OwnedPublicKey {
    Aes { key: [u8; 32] },
    Ed25519 { key: [u8; 32] },
    Overlay { name: SmallVec<[u8; 32]> },
}

impl OwnedPublicKey {
    pub fn as_view(&self) -> PublicKeyView {
        match self {
            Self::Aes { key } => PublicKeyView::Aes { key },
            Self::Ed25519 { key } => PublicKeyView::Ed25519 { key },
            Self::Overlay { name } => PublicKeyView::Overlay {
                name: name.as_slice(),
            },
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum PublicKeyView<'a> {
    Aes { key: HashRef<'a> },
    Ed25519 { key: HashRef<'a> },
    Overlay { name: &'a [u8] },
}

impl Boxed for PublicKeyView<'_> {}

impl AsOwned for PublicKeyView<'_> {
    type Owned = OwnedPublicKey;

    fn as_owned(&self) -> Self::Owned {
        match *self {
            Self::Aes { key } => OwnedPublicKey::Aes { key: *key },
            Self::Ed25519 { key } => OwnedPublicKey::Ed25519 { key: *key },
            Self::Overlay { name } => OwnedPublicKey::Overlay { name: name.into() },
        }
    }
}

impl<'a> ReadFromPacket<'a> for PublicKeyView<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            ID_PUBLIC_KEY_AES => Ok(Self::Aes {
                key: read_fixed_bytes(packet, offset)?,
            }),
            ID_PUBLIC_KEY_ED25519 => Ok(Self::Ed25519 {
                key: read_fixed_bytes(packet, offset)?,
            }),
            ID_PUBLIC_KEY_OVERLAY => Ok(Self::Overlay {
                name: read_bytes(packet, offset)?,
            }),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

impl WriteToPacket for PublicKeyView<'_> {
    #[inline]
    fn max_size_hint(&self) -> usize {
        4 + match self {
            Self::Aes { key } => key.max_size_hint(),
            Self::Ed25519 { key } => key.max_size_hint(),
            Self::Overlay { name } => name.max_size_hint(),
        }
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Aes { key } => {
                ID_PUBLIC_KEY_AES.write_to(packet)?;
                key.write_to(packet)
            }
            Self::Ed25519 { key } => {
                ID_PUBLIC_KEY_ED25519.write_to(packet)?;
                key.write_to(packet)
            }
            Self::Overlay { name } => {
                ID_PUBLIC_KEY_OVERLAY.write_to(packet)?;
                name.write_to(packet)
            }
        }
    }
}

const ID_PUBLIC_KEY_AES: u32 = 0x2dbcadd4;
const ID_PUBLIC_KEY_ED25519: u32 = 0x4813b4c6;
const ID_PUBLIC_KEY_OVERLAY: u32 = 0x34ba45cb;
