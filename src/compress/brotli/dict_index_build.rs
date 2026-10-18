// Static-dictionary index shared by the Brotli encoder and `build.rs`.
// `build.rs` includes this file and writes the little-endian image.
// The encoder includes it for the length tables and the test that checks
// the generated image.

const SIZE_BITS_BY_LENGTH: [u8; 32] = [
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5, 0, 0, 0, 0,
    0, 0, 0,
];
const OFFSETS_BY_LENGTH: [usize; 32] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864,
    104704, 106752, 108928, 113536, 115968, 118528, 119872, 121280, 122016, 122784, 122784, 122784,
    122784, 122784, 122784, 122784,
];
const DICT_HASH_SIZE: usize = 1 << 17;
/// Low 15 bits, the same mask as the encoder's 32768-slot hash table.
const DICT_WORD_HASH_MASK: usize = (1 << 15) - 1;

fn dict_hash(data: &[u8]) -> usize {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    (v.wrapping_mul(0x1E35_A7BD) >> 17) as usize
}

#[cfg_attr(not(test), allow(dead_code))]
struct BuiltDictIndex {
    head: Vec<u32>,
    next: Vec<u32>,
    entry: Vec<u32>,
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_dict_index(dictionary: &[u8]) -> BuiltDictIndex {
    let mut head = vec![u32::MAX; DICT_HASH_SIZE];
    let mut next = Vec::new();
    let mut entry = Vec::new();
    for word_len in 4..=24usize {
        let shift = SIZE_BITS_BY_LENGTH[word_len];
        if shift == 0 {
            continue;
        }
        let num_words = 1usize << shift;
        let base_offset = OFFSETS_BY_LENGTH[word_len];
        for word_idx in 0..num_words {
            let dict_offset = base_offset + word_idx * word_len;
            if dict_offset + word_len > dictionary.len() {
                break;
            }
            let h = dict_hash(&dictionary[dict_offset..]) & DICT_WORD_HASH_MASK & (DICT_HASH_SIZE - 1);
            entry.push(((word_len as u32) << 20) | word_idx as u32);
            next.push(head[h]);
            head[h] = entry.len() as u32 - 1;
        }
    }
    BuiltDictIndex { head, next, entry }
}
