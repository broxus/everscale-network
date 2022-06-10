pub fn compress(data: &mut Vec<u8>) -> std::io::Result<()> {
    let uncompressed = data.len();
    if uncompressed <= COMPRESSION_THRESHOLD {
        return Ok(());
    }

    let mut result = Vec::with_capacity(data.len() + 1);
    zstd::stream::copy_encode(&mut data.as_slice(), &mut result, COMPRESSION_LEVEL)?;
    zstd::stream::copy_encode(
        &mut (uncompressed as u32).to_be_bytes().as_slice(),
        &mut result,
        COMPRESSION_LEVEL,
    )?;
    result.push(TAG_COMPRESSED);

    *data = result;
    Ok(())
}

pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.last() != Some(&TAG_COMPRESSED) {
        return None;
    }

    let len = data.len();
    match zstd::stream::decode_all(&mut &data[..len - 1]) {
        Ok(mut data) if data.len() >= 4 => {
            let len = data.len();

            let src_len = ((data[len - 4] as usize) << 24)
                | ((data[len - 3] as usize) << 16)
                | ((data[len - 2] as usize) << 8)
                | (data[len - 1] as usize);

            if src_len != len - 4 {
                return None;
            }

            data.truncate(src_len);
            Some(data)
        }
        _ => None,
    }
}

const COMPRESSION_THRESHOLD: usize = 256;
const COMPRESSION_LEVEL: i32 = 3;

const TAG_COMPRESSED: u8 = 0x80;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn correct_compression() {
        let data = std::iter::repeat_with(|| rand::thread_rng().gen())
            .take(1000)
            .collect::<Vec<u8>>();

        let mut compressed = data.clone();
        compress(&mut compressed).unwrap();

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
