use std::ops::{Index, IndexMut, Range, RangeFrom};

pub struct PacketView<'a> {
    bytes: &'a mut [u8],
}

impl<'a> PacketView<'a> {
    pub const fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn remove_prefix(&mut self, prefix_len: usize) {
        let len = self.bytes.len();
        let ptr = self.bytes.as_mut_ptr();
        // SAFETY: `bytes` is already a reference bounded by a lifetime
        self.bytes =
            unsafe { std::slice::from_raw_parts_mut(ptr.add(prefix_len), len - prefix_len) };
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
