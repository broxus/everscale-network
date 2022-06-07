use std::ops::{Index, IndexMut, Range, RangeFrom, RangeTo};

pub struct PacketView<'a> {
    bytes: &'a mut [u8],
}

impl<'a> PacketView<'a> {
    #[inline(always)]
    pub const fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }

    #[inline(always)]
    pub const fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn remove_prefix(&mut self, prefix_len: usize) {
        let len = self.bytes.len();
        let ptr = self.bytes.as_mut_ptr();
        // SAFETY: `bytes` is already a reference bounded by a lifetime
        self.bytes =
            unsafe { std::slice::from_raw_parts_mut(ptr.add(prefix_len), len - prefix_len) };
    }
}

impl Index<RangeTo<usize>> for PacketView<'_> {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        self.bytes.index(index)
    }
}

impl Index<Range<usize>> for PacketView<'_> {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        self.bytes.index(index)
    }
}

impl IndexMut<Range<usize>> for PacketView<'_> {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        self.bytes.index_mut(index)
    }
}

impl Index<RangeFrom<usize>> for PacketView<'_> {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        self.bytes.index(index)
    }
}

impl IndexMut<RangeFrom<usize>> for PacketView<'_> {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output {
        self.bytes.index_mut(index)
    }
}

impl<'a> From<&'a mut [u8]> for PacketView<'a> {
    fn from(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}
