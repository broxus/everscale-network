use std::borrow::Borrow;
use std::io::Write;

use smallvec::SmallVec;

pub fn deserialize_view<'a, T>(packet: &'a [u8]) -> PacketContentsResult<T>
where
    T: ReadFromPacket<'a>,
{
    let mut offset = 0;
    let view = T::read_from(packet, &mut offset)?;
    Ok(view)
}

#[derive(Debug, Clone)]
pub struct BoxedWrapper<T, V>(T, std::marker::PhantomData<V>);

impl<T, V> BoxedWrapper<T, V>
where
    T: Borrow<V>,
{
    #[inline]
    pub fn into_inner(self) -> V {
        self.0
    }

    #[inline]
    pub fn inner(&self) -> &V {
        self.0.borrow()
    }
}

impl<T, V> WriteToPacket for BoxedWrapper<T, V>
where
    T: Borrow<V>,
    V: BoxedConstructor + WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        4 + self.0.borrow().max_size_hint()
    }

    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        V::ID.write_to(packet)?;
        self.0.borrow().write_to(packet)
    }
}

pub trait BoxedConstructor {
    const ID: u32;

    fn wrap(&self) -> BoxedWrapper<&Self, Self> {
        BoxedWrapper(self, Default::default())
    }
}

pub struct RawPacketData<'a>(pub &'a [u8]);

impl<'a> ReadFromPacket<'a> for RawPacketData<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let mut len = packet.len() - std::cmp::min(*offset, packet.len());
        let result = unsafe { std::slice::from_raw_parts(packet.as_ptr().add(*offset), len) };
        *offset += len;
        Ok(Self(result))
    }
}

impl WriteToPacket for RawPacketData<'_> {
    fn max_size_hint(&self) -> usize {
        self.0.len()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        packet.write_all(self.0)
    }
}

pub struct IntermediateBytes<T>(pub T);

impl<'a, T> ReadFromPacket<'a> for IntermediateBytes<T>
where
    T: ReadFromPacket<'a>,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let intermediate = read_bytes(packet, offset)?;
        deserialize_view(intermediate)
    }
}

impl<T> WriteToPacket for IntermediateBytes<T>
where
    T: WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        bytes_max_size_hint(self.0.max_size_hint())
    }

    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        let len = self.0.max_size_hint();
        let mut have_written = write_bytes_len(len, packet)?;

        self.0.write_to(packet)?;
        have_written += len;

        let remainder = have_written % 4;
        if remainder != 0 {
            let buf = [0u8; 4];
            packet.write_all(&buf[remainder..])?;
        }

        Ok(())
    }
}

pub trait ReadFromPacket<'a>: Sized {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self>;
}

impl<'a> ReadFromPacket<'a> for &'a [u8] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_bytes(packet, offset)
    }
}

impl<'a, const N: usize> ReadFromPacket<'a> for &'a [u8; N] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_fixed_bytes(packet, offset)
    }
}

impl<'a, const N: usize> ReadFromPacket<'a> for [u8; N] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_fixed_bytes(packet, offset).map(|&t| t)
    }
}

impl<'a, T, const N: usize> ReadFromPacket<'a> for SmallVec<[T; N]>
where
    [T; N]: smallvec::Array,
    <[T; N] as smallvec::Array>::Item: ReadFromPacket<'a>,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let len = i32::read_from(packet, offset)?;
        let mut items = SmallVec::<[T; N]>::with_capacity(len as usize);
        for _ in 0..len {
            items.push(ReadFromPacket::read_from(packet, offset)?);
        }
        Ok(items)
    }
}

pub trait WriteToPacket {
    fn max_size_hint(&self) -> usize;

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write;
}

impl<'a> WriteToPacket for &'a [u8] {
    #[inline]
    fn max_size_hint(&self) -> usize {
        bytes_max_size_hint(self.len())
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        write_bytes(self, packet)
    }
}

impl<'a, const N: usize> WriteToPacket for &'a [u8; N] {
    #[inline]
    fn max_size_hint(&self) -> usize {
        N
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        packet.write_all(self.as_ref())
    }
}

impl<T, const N: usize> WriteToPacket for SmallVec<[T; N]>
where
    [T; N]: smallvec::Array,
    <[T; N] as smallvec::Array>::Item: WriteToPacket,
{
    #[inline]
    fn max_size_hint(&self) -> usize {
        4 + self.iter().map(WriteToPacket::max_size_hint).sum::<usize>()
    }

    #[inline]
    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        (self.len() as i32).write_to(packet)?;
        for item in self {
            item.write_to(packet)?;
        }
        Ok(())
    }
}

impl<T> WriteToPacket for Option<T>
where
    T: WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        if let Some(item) = self {
            item.max_size_hint()
        } else {
            0
        }
    }

    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        if let Some(item) = self {
            item.write_to(packet)
        } else {
            Ok(())
        }
    }
}

pub trait UpdateSignatureHasher {
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write;
}

macro_rules! impl_read_for_primitive {
    ($type:ident) => {
        impl ReadFromPacket<'_> for $type {
            #[inline]
            fn read_from(packet: &[u8], offset: &mut usize) -> PacketContentsResult<Self> {
                if packet.len() < *offset + std::mem::size_of::<$type>() {
                    Err(PacketContentsError::UnexpectedEof)
                } else {
                    let value = $type::from_le_bytes(unsafe {
                        *(packet.as_ptr().add(*offset) as *const [u8; std::mem::size_of::<$type>()])
                    });
                    *offset += std::mem::size_of::<$type>();
                    Ok(value)
                }
            }
        }

        impl WriteToPacket for $type {
            #[inline]
            fn max_size_hint(&self) -> usize {
                std::mem::size_of::<$type>()
            }

            #[inline]
            fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
            where
                T: Write,
            {
                packet.write_all(&self.to_le_bytes())
            }
        }
    };
}

impl_read_for_primitive!(u32);
impl_read_for_primitive!(i32);
impl_read_for_primitive!(i64);

#[inline]
pub(crate) fn read_optional<'a, T>(
    packet: &'a [u8],
    offset: &mut usize,
    flag: bool,
) -> PacketContentsResult<Option<T>>
where
    T: ReadFromPacket<'a>,
{
    Ok(if flag {
        Some(T::read_from(packet, offset)?)
    } else {
        None
    })
}

#[inline]
pub(crate) fn read_fixed_bytes<'a, const N: usize>(
    packet: &'a [u8],
    offset: &mut usize,
) -> PacketContentsResult<&'a [u8; N]> {
    if packet.len() < *offset + N {
        Err(PacketContentsError::UnexpectedEof)
    } else {
        let ptr = unsafe { &*(packet.as_ptr().add(*offset) as *const [u8; N]) };
        *offset += N;
        Ok(ptr)
    }
}

#[inline]
pub(crate) fn bytes_max_size_hint(mut len: usize) -> usize {
    if len < 254 {
        len += 1;
    } else {
        len += 4;
    }

    let remainder = len % 4;
    if remainder != 0 {
        len += 4 - remainder;
    }

    len
}

#[inline]
pub(crate) fn write_bytes<T>(bytes: &[u8], packet: &mut T) -> std::io::Result<()>
where
    T: Write,
{
    let len = bytes.len();
    let mut have_written = write_bytes_len(len, packet)?;

    packet.write_all(bytes)?;
    have_written += len;

    let remainder = have_written % 4;
    if remainder != 0 {
        let buf = [0u8; 4];
        packet.write_all(&buf[remainder..])?;
    }

    Ok(())
}

#[inline]
fn write_bytes_len<T>(len: usize, packet: &mut T) -> std::io::Result<usize>
where
    T: Write,
{
    Ok(if len < 254 {
        packet.write_all(&[len as u8])?;
        1
    } else {
        packet.write_all(&[254, len as u8, (len >> 8) as u8, (len >> 16) as u8])?;
        4
    })
}

#[inline]
pub(crate) fn read_bytes<'a>(
    packet: &'a [u8],
    offset: &mut usize,
) -> PacketContentsResult<&'a [u8]> {
    let packet_len = packet.len();
    let current_offset = *offset;

    if packet_len <= current_offset {
        return Err(PacketContentsError::UnexpectedEof);
    }

    let first_bytes = packet[current_offset];
    let (len, have_read) = if first_bytes != 254 {
        (first_bytes as usize, 1)
    } else {
        if packet_len < current_offset + 4 {
            return Err(PacketContentsError::UnexpectedEof);
        }

        let mut len = packet[current_offset + 1] as usize;
        len |= (packet[current_offset + 2] as usize) << 8;
        len |= (packet[current_offset + 3] as usize) << 16;
        (len, 4)
    };

    let remainder = {
        let excess = (have_read + len) % 4;
        if excess == 0 {
            0
        } else {
            4 - excess
        }
    };

    if packet_len < current_offset + have_read + len + remainder {
        return Err(PacketContentsError::UnexpectedEof);
    }

    let result =
        unsafe { std::slice::from_raw_parts(packet.as_ptr().add(current_offset + have_read), len) };

    *offset += have_read + len + remainder;
    Ok(result)
}

pub type HashRef<'a> = &'a [u8; 32];

pub type PacketContentsResult<T> = Result<T, PacketContentsError>;

#[derive(thiserror::Error, Debug)]
pub enum PacketContentsError {
    #[error("Unexpected packet EOF")]
    UnexpectedEof,
    #[error("Unknown constructor")]
    UnknownConstructor,
}
