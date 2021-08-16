use std::io::Write;

use either::Either;
use smallvec::SmallVec;

/// Tries to decode TL data
pub fn deserialize_view<'a, T>(packet: &'a [u8]) -> PacketContentsResult<T>
where
    T: ReadFromPacket<'a>,
{
    let mut offset = 0;
    let view = T::read_from(packet, &mut offset)?;
    Ok(view)
}

/// Encodes object as TL bytes
pub fn serialize_view<T>(data: T) -> std::io::Result<Vec<u8>>
where
    T: WriteToPacket,
{
    let mut result = Vec::with_capacity(data.max_size_hint());
    data.write_to(&mut result)?;
    Ok(result)
}

/// Marks type as it is already boxed
pub trait Boxed {}

impl<T> Boxed for &T where T: Boxed {}

/// Simple helper which contains inner value and constructor id.
///
/// Used mostly for serialization, so can contain references
#[derive(Debug, Clone)]
pub struct BoxedWrapper<T>(pub T);

impl<T> Boxed for BoxedWrapper<T> {}

impl<T> WriteToPacket for BoxedWrapper<T>
where
    T: BoxedConstructor + WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        4 + self.0.max_size_hint()
    }

    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        T::ID.write_to(packet)?;
        self.0.write_to(packet)
    }
}

impl<'a, T> ReadFromPacket<'a> for BoxedWrapper<T>
where
    T: BoxedConstructor + ReadFromPacket<'a>,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        match u32::read_from(packet, offset)? {
            T::ID => T::read_from(packet, offset).map(BoxedWrapper),
            _ => Err(PacketContentsError::UnknownConstructor),
        }
    }
}

/// Marks bare type with the appropriate constructor id  
pub trait BoxedConstructor: Sized {
    const ID: u32;

    /// Wraps bare type reference into `BoxedWrapper`
    fn wrap(&self) -> BoxedWrapper<&Self> {
        BoxedWrapper(self)
    }

    fn into_wrapped(self) -> BoxedWrapper<Self> {
        BoxedWrapper(self)
    }
}

impl<T> BoxedConstructor for &T
where
    T: BoxedConstructor,
{
    const ID: u32 = T::ID;
}

/// Indicates the type to which the referenced view type can be converted
pub trait AsOwned {
    type Owned;

    fn as_owned(&self) -> Self::Owned;
}

impl<T> AsOwned for &T
where
    T: AsOwned,
{
    type Owned = T::Owned;

    fn as_owned(&self) -> Self::Owned {
        T::as_owned(self)
    }
}

/// Helper type which is used to represent field value as bytes
#[derive(Debug, Clone)]
pub struct IntermediateBytes<T>(pub T);

impl<T> IntermediateBytes<T>
where
    T: AsRef<[u8]>,
{
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> IntermediateBytes<T>
where
    T: WriteToPacket,
{
    pub fn as_owned_raw_bytes(&self) -> std::io::Result<IntermediateBytes<OwnedRawBytes>> {
        serialize_view(&self.0)
            .map(OwnedRawBytes)
            .map(IntermediateBytes)
    }
}

impl<T> AsOwned for IntermediateBytes<T>
where
    T: AsOwned,
{
    type Owned = IntermediateBytes<T::Owned>;

    fn as_owned(&self) -> Self::Owned {
        IntermediateBytes(self.0.as_owned())
    }
}

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

/// Owned version of `RawBytes`
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OwnedRawBytes(pub Vec<u8>);

impl AsRef<[u8]> for OwnedRawBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl WriteToPacket for OwnedRawBytes {
    #[inline]
    fn max_size_hint(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        packet.write_all(self.0.as_slice())
    }
}

/// Helper type which reads remaining packet as is
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RawBytes<'a>(pub &'a [u8]);

impl AsRef<[u8]> for RawBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsOwned for RawBytes<'_> {
    type Owned = OwnedRawBytes;

    fn as_owned(&self) -> Self::Owned {
        OwnedRawBytes(self.0.to_vec())
    }
}

impl<'a> ReadFromPacket<'a> for RawBytes<'a> {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let mut len = packet.len() - std::cmp::min(*offset, packet.len());
        let result = unsafe { std::slice::from_raw_parts(packet.as_ptr().add(*offset), len) };
        *offset += len;
        Ok(Self(result))
    }
}

impl WriteToPacket for RawBytes<'_> {
    #[inline]
    fn max_size_hint(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        packet.write_all(self.0)
    }
}

/// Specifies how this type can read from the packet
pub trait ReadFromPacket<'a>: Sized {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self>;
}

/// `ton::bytes` - 1 or 4 bytes of `len`, then `len` bytes of data (aligned to 4)
impl<'a> ReadFromPacket<'a> for &'a [u8] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_bytes(packet, offset)
    }
}

/// `ton::bytes` - 1 or 4 bytes of `len`, then `len` bytes of data (aligned to 4)
impl<'a> ReadFromPacket<'a> for Vec<u8> {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        Ok(read_bytes(packet, offset)?.to_vec())
    }
}

/// `ton::int128 | ton::int256` - N bytes of data
impl<'a, const N: usize> ReadFromPacket<'a> for &'a [u8; N] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_fixed_bytes(packet, offset)
    }
}

/// `ton::int128 | ton::int256` - N bytes of data
impl<'a, const N: usize> ReadFromPacket<'a> for [u8; N] {
    #[inline]
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        read_fixed_bytes(packet, offset).map(|&t| t)
    }
}

/// `ton::vector` - 4 bytes of `len`, then `len` items
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

/// `ton::vector` - 4 bytes of `len`, then `len` items
impl<'a, T> ReadFromPacket<'a> for Vec<T>
where
    T: ReadFromPacket<'a>,
{
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let len = i32::read_from(packet, offset)?;
        let mut items = Vec::with_capacity(len as usize);
        for _ in 0..len {
            items.push(ReadFromPacket::read_from(packet, offset)?);
        }
        Ok(items)
    }
}

/// Specifies how this type can be written to the packet
pub trait WriteToPacket {
    /// Max required number of bytes
    fn max_size_hint(&self) -> usize;

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write;
}

impl<T> WriteToPacket for &T
where
    T: WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        T::max_size_hint(self)
    }

    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        T::write_to(self, packet)
    }
}

impl<T1, T2> WriteToPacket for Either<T1, T2>
where
    T1: WriteToPacket,
    T2: WriteToPacket,
{
    fn max_size_hint(&self) -> usize {
        match self {
            Self::Left(l) => l.max_size_hint(),
            Self::Right(r) => r.max_size_hint(),
        }
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        match self {
            Self::Left(l) => l.write_to(packet),
            Self::Right(r) => r.write_to(packet),
        }
    }
}

/// `ton::bytes` - 1 or 4 bytes of `len`, then `len` bytes of data (aligned to 4)
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

/// `ton::bytes` - 1 or 4 bytes of `len`, then `len` bytes of data (aligned to 4)
impl<'a> WriteToPacket for Vec<u8> {
    #[inline]
    fn max_size_hint(&self) -> usize {
        bytes_max_size_hint(self.len())
    }

    #[inline]
    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        write_bytes(self.as_slice(), packet)
    }
}

/// `ton::int128 | ton::int256` - N bytes of data
impl<'a, const N: usize> WriteToPacket for [u8; N] {
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

impl<T> WriteToPacket for &'_ [T]
where
    T: WriteToPacket,
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
        for item in self.iter() {
            item.write_to(packet)?;
        }
        Ok(())
    }
}

/// `ton::vector` - 4 bytes of `len`, then `len` items
impl<T, const N: usize> WriteToPacket for SmallVec<[T; N]>
where
    [T; N]: smallvec::Array,
    <[T; N] as smallvec::Array>::Item: WriteToPacket,
{
    #[inline]
    fn max_size_hint(&self) -> usize {
        self.as_slice().max_size_hint()
    }

    #[inline]
    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        self.as_slice().write_to(packet)
    }
}

/// `ton::vector` - 4 bytes of `len`, then `len` items
impl<T> WriteToPacket for Vec<T>
where
    T: WriteToPacket,
{
    #[inline]
    fn max_size_hint(&self) -> usize {
        self.as_slice().max_size_hint()
    }

    #[inline]
    fn write_to<P>(&self, packet: &mut P) -> std::io::Result<()>
    where
        P: Write,
    {
        self.as_slice().write_to(packet)
    }
}

/// Skips serialization if `None`, serializes as `T` otherwise
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

/// Implements `ReadFromPacket` and `WriteToPacket` for native types
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

/// Implements `ReadFromPacket` and `WriteToPacket` for tuples
macro_rules! impl_read_for_tuple {
    ($($num:tt $type:ident),+) => {
        impl<'a, $($type),*> ReadFromPacket<'a> for ($($type),*)
        where
            $($type: ReadFromPacket<'a>),*
        {
            #[inline]
            fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
                Ok(($($type::read_from(packet, offset)?),*))
            }
        }

        impl<$($type),*> WriteToPacket for ($($type),*)
        where
            $($type: WriteToPacket),*
        {
            #[inline]
            fn max_size_hint(&self) -> usize {
                let mut result = 0;
                $(result += self.$num.max_size_hint());*;
                result
            }

            #[inline]
            fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
            where
                T: Write,
            {
                $(self.$num.write_to(packet)?);*;
                Ok(())
            }
        }
    };
}

impl_read_for_tuple!(0 T1, 1 T2);
impl_read_for_tuple!(0 T1, 1 T2, 2 T3);

/// Trait for types which can be signed. Can be used to overwrite serialization for signer
pub trait UpdateSignatureHasher {
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write;
}

impl<T> UpdateSignatureHasher for &T
where
    T: UpdateSignatureHasher,
{
    fn update_hasher<H>(&self, hasher: &mut H) -> std::io::Result<()>
    where
        H: Write,
    {
        T::update_hasher(self, hasher)
    }
}

/// Marker trait for signatures
pub trait DataSignature: AsRef<[u8]> {}

/// Signature as a `'static` type with reserved 64 bytes on stack
#[derive(Debug, Clone, Default)]
pub struct OwnedSignature(SmallVec<[u8; 64]>);

impl DataSignature for OwnedSignature {}

impl AsOwned for OwnedSignature {
    type Owned = Self;

    fn as_owned(&self) -> Self::Owned {
        self.clone()
    }
}

impl<'a> ReadFromPacket<'a> for OwnedSignature {
    fn read_from(packet: &'a [u8], offset: &mut usize) -> PacketContentsResult<Self> {
        let bytes = read_bytes(packet, offset)?;
        Ok(Self(bytes.into()))
    }
}

impl WriteToPacket for OwnedSignature {
    fn max_size_hint(&self) -> usize {
        self.0.len()
    }

    fn write_to<T>(&self, packet: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        self.0.as_slice().write_to(packet)
    }
}

impl AsRef<[u8]> for OwnedSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::Deref for OwnedSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl From<[u8; 64]> for OwnedSignature {
    fn from(value: [u8; 64]) -> Self {
        Self(value.into())
    }
}

/// Signature as a bytes view
pub type SignatureRef<'a> = &'a [u8];

impl DataSignature for SignatureRef<'_> {}

impl AsOwned for SignatureRef<'_> {
    type Owned = OwnedSignature;

    fn as_owned(&self) -> Self::Owned {
        OwnedSignature(SmallVec::from_slice(self))
    }
}

/// `ton::int256` view
pub type HashRef<'a> = &'a [u8; 32];

/// Parser result type
pub type PacketContentsResult<T> = Result<T, PacketContentsError>;

/* Helper methods */

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

#[derive(thiserror::Error, Debug)]
pub enum PacketContentsError {
    #[error("Unexpected packet EOF")]
    UnexpectedEof,
    #[error("Unknown constructor")]
    UnknownConstructor,
}
