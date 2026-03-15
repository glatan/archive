/// Generate deterministic compressible data of the given size.
///
/// Uses a simple LCG to produce byte values biased toward ASCII text,
/// giving compression algorithms a realistic mix of redundancy.
pub fn generate_text_data(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
    let words: &[&[u8]] = &[
        b"the ",
        b"quick ",
        b"brown ",
        b"fox ",
        b"jumps ",
        b"over ",
        b"lazy ",
        b"dog ",
        b"archive ",
        b"compress ",
        b"benchmark ",
        b"data ",
        b"test ",
        b"rust ",
        b"format ",
        b"encode ",
        b"decode ",
        b"stream ",
        b"block ",
        b"header ",
        b"checksum ",
        b"entry ",
    ];
    while buf.len() < size {
        // LCG step
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let idx = ((state >> 33) as usize) % words.len();
        let word = words[idx];
        let remaining = size - buf.len();
        if remaining >= word.len() {
            buf.extend_from_slice(word);
        } else {
            buf.extend_from_slice(&word[..remaining]);
        }
        // Occasionally add a newline
        if buf.len() < size && (state >> 40) & 0x07 == 0 {
            buf.push(b'\n');
        }
    }
    buf.truncate(size);
    buf
}

/// Generate deterministic binary data (less compressible) of the given size.
#[allow(dead_code)]
pub fn generate_binary_data(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut state: u64 = 0x0123_4567_89AB_CDEF;
    while buf.len() < size {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1442695040888963407);
        buf.extend_from_slice(&state.to_le_bytes());
    }
    buf.truncate(size);
    buf
}
