//! LZSA integration tests.
//!
//! Reference vectors were produced by the upstream `lzsa` tool v1.4.1
//! (Emmanuel Marty, zlib license); no reference code is included here.

use archive::compress::lzsa;

const TEXT: &[u8] = b"The quick brown fox jumps over the lazy dog. ";

fn text200() -> Vec<u8> {
    let mut v = Vec::with_capacity(TEXT.len() * 200);
    for _ in 0..200 {
        v.extend_from_slice(TEXT);
    }
    v
}

/// `lzsa -f1` output for 200 repetitions of `TEXT`.
const TEXT_LZSA1: &[u8] = &[
    0x7b, 0x9e, 0x00, 0x34, 0x00, 0x00, 0x7f, 0x26, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70,
    0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20,
    0x64, 0x6f, 0x67, 0x2e, 0x20, 0xd3, 0xee, 0xfb, 0x22, 0x00, 0x00, 0x00, 0x00,
];

/// `lzsa -f2` output for the same input.
const TEXT_LZSA2: &[u8] = &[
    0x7b, 0x9e, 0x20, 0x34, 0x00, 0x00, 0x19, 0xf0, 0x0e, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69,
    0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d,
    0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x5f, 0x7f, 0x6c, 0x61, 0x7a, 0x79, 0x20,
    0x64, 0x6f, 0x67, 0x2e, 0x20, 0xd3, 0xe9, 0xfb, 0x22, 0x00, 0x00, 0x00, 0x00,
];

/// `lzsa -f1 -r` raw block for the same input.
const TEXT_RLZSA1: &[u8] = &[
    0x7f, 0x26, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
    0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0xd3,
    0xee, 0xfb, 0x22, 0x0f, 0x00, 0xee, 0x00, 0x00,
];

/// `lzsa -f2 -r` raw block for the same input.
const TEXT_RLZSA2: &[u8] = &[
    0x19, 0xf0, 0x0e, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f,
    0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65,
    0x72, 0x20, 0x74, 0x5f, 0x7f, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0xd3,
    0xe9, 0xfb, 0x22, 0xe7, 0xf0, 0xe8,
];

#[test]
fn lzsa1_stream_reference_vector() {
    assert_eq!(lzsa::decode(TEXT_LZSA1).unwrap(), text200());
}

#[test]
fn lzsa2_stream_reference_vector() {
    // Rep-matches, nibble-encoded extension fields and the 5-bit offset
    // form are all exercised by this reference-compressed stream.
    assert_eq!(lzsa::decode(TEXT_LZSA2).unwrap(), text200());
}

#[test]
fn lzsa1_raw_block_reference_vector() {
    assert_eq!(lzsa::decode_lzsa1_block(TEXT_RLZSA1).unwrap(), text200());
}

#[test]
fn lzsa2_raw_block_reference_vector() {
    assert_eq!(lzsa::decode_lzsa2_block(TEXT_RLZSA2).unwrap(), text200());
}

#[test]
fn decode_bounded_enforces_limit() {
    assert!(lzsa::decode_bounded(TEXT_LZSA1, 8999).is_err());
    assert_eq!(lzsa::decode_bounded(TEXT_LZSA1, 9000).unwrap(), text200());
}

#[test]
fn encode_roundtrips_and_redecodes() {
    let data = text200();
    assert_eq!(lzsa::decode(&lzsa::encode(&data)).unwrap(), data);
    assert_eq!(lzsa::decode(&lzsa::encode_lzsa2(&data)).unwrap(), data);
    // Encoded output must at least not grow for highly redundant input.
    assert!(lzsa::encode(&data).len() < data.len());
}

#[test]
fn multi_frame_roundtrip() {
    let mut data = Vec::new();
    for i in 0u32..40000 {
        data.extend_from_slice(&i.to_le_bytes());
    }
    data.extend_from_slice(&text200());
    assert_eq!(lzsa::decode(&lzsa::encode(&data)).unwrap(), data);
    assert_eq!(lzsa::decode(&lzsa::encode_lzsa2(&data)).unwrap(), data);
}

// ---------------------------------------------------------------
// Variant coverage: -D dictionary (external history prefix).
// ---------------------------------------------------------------

#[test]
fn lzsa1_block_with_dictionary() {
    // token 0x10: L=1 'a'; 1-byte offset 0xfa -> distance 6 reaching
    // into the 5-byte dictionary "HELLO"; match len 3; then EOD.
    let raw = [0x10, b'a', 0xfa, 0x0f, 0x00, 238, 0x00, 0x00];
    assert!(lzsa::decode_lzsa1_block(&raw).is_err());
    assert_eq!(
        lzsa::decode_lzsa1_block_with_prefix(&raw, b"HELLO").unwrap(),
        b"aHEL"
    );
}

#[test]
fn lzsa2_block_with_dictionary() {
    // token 0x29: XYZ=001 L=1 M=1; 'a'; offset nibble 0xd -> distance
    // 6, len 3; rep-match token 0xe7 + nibble 15 + 232 = EOD.
    let raw = [0x29, b'a', 0xdf, 0xe7, 0xe8];
    assert!(lzsa::decode_lzsa2_block(&raw).is_err());
    assert_eq!(
        lzsa::decode_lzsa2_block_with_prefix(&raw, b"HELLO").unwrap(),
        b"aHEL"
    );
}

#[test]
fn lzsa_stream_with_dictionary() {
    // LZSA1 frame: one command = literal 'a' + match distance 6 len 3
    // reaching into the dictionary.
    let stream = [
        0x7b, 0x9e, 0x00, 0x03, 0x00, 0x00, 0x10, b'a', 0xfa, 0x00, 0x00, 0x00,
    ];
    assert!(lzsa::decode(&stream).is_err());
    assert_eq!(
        lzsa::decode_with_prefix(&stream, b"HELLO").unwrap(),
        b"aHEL"
    );
}

// ---------------------------------------------------------------
// Variant coverage: -b backwards raw blocks. The wire format is a
// pure byte-reversal wrapper over the same block grammar (raw `-r`
// blocks only; it does not apply to the stream container).
// ---------------------------------------------------------------

const TEXT2: &[u8] = b"the quick brown fox jumps over the lazy dog. the quick brown fox.\n";

/// `lzsa -r -b -f1` raw block for `TEXT2`.
const TEXT_RLZSA1B: &[u8] = &[
    0x00, 0x00, 0xee, 0x00, 0x0f, 0x01, 0xd3, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76,
    0x65, 0x72, 0x04, 0x7f, 0xf2, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66,
    0x6f, 0x78, 0x2e, 0x0a, 0x18, 0x72,
];

/// `lzsa -r -b -f2` raw block for `TEXT2`.
const TEXT_RLZSA2B: &[u8] = &[
    0xe8, 0xf0, 0xe7, 0xd3, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x8a,
    0x5f, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x71,
    0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x2e, 0x0a,
    0x0d, 0xf9, 0x3b,
];

#[test]
fn lzsa1_raw_block_backwards_reference_vector() {
    assert_eq!(
        lzsa::decode_lzsa1_block_backwards(TEXT_RLZSA1B).unwrap(),
        TEXT2
    );
    // A backwards block is not silently accepted by the forward decoder.
    assert!(lzsa::decode_lzsa1_block(TEXT_RLZSA1B).is_err());
}

#[test]
fn lzsa2_raw_block_backwards_reference_vector() {
    assert_eq!(
        lzsa::decode_lzsa2_block_backwards(TEXT_RLZSA2B).unwrap(),
        TEXT2
    );
    assert!(lzsa::decode_lzsa2_block(TEXT_RLZSA2B).is_err());
}

#[test]
fn backwards_block_byte_reversal_property() {
    // decode_bwd(B) == rev(decode_fwd(rev(B))) on the reference vector.
    let mut fwd_block = TEXT_RLZSA1B.to_vec();
    fwd_block.reverse();
    let mut expect = lzsa::decode_lzsa1_block(&fwd_block).unwrap();
    expect.reverse();
    assert_eq!(expect, TEXT2);
    let mut fwd_block = TEXT_RLZSA2B.to_vec();
    fwd_block.reverse();
    let mut expect = lzsa::decode_lzsa2_block(&fwd_block).unwrap();
    expect.reverse();
    assert_eq!(expect, TEXT2);
    // encode_bwd(data) == rev(encode_fwd(rev(data))) for our encoder.
    let mut rev = TEXT2.to_vec();
    rev.reverse();
    let mut expect = lzsa::encode_lzsa1_block(&rev).unwrap();
    expect.reverse();
    assert_eq!(lzsa::encode_lzsa1_block_backwards(TEXT2).unwrap(), expect);
    let mut expect = lzsa::encode_lzsa2_block(&rev).unwrap();
    expect.reverse();
    assert_eq!(lzsa::encode_lzsa2_block_backwards(TEXT2).unwrap(), expect);
}

#[test]
fn backwards_raw_block_roundtrip() {
    let data = text200();
    for enc in [
        lzsa::encode_lzsa1_block_backwards(&data).unwrap(),
        lzsa::encode_lzsa2_block_backwards(&data).unwrap(),
    ] {
        // Forward decoders reject (or never reproduce) backwards data.
        if let Ok(v) = lzsa::decode_lzsa1_block(&enc) {
            assert_ne!(v, data);
        }
    }
    assert_eq!(
        lzsa::decode_lzsa1_block_backwards(&lzsa::encode_lzsa1_block_backwards(&data).unwrap())
            .unwrap(),
        data
    );
    assert_eq!(
        lzsa::decode_lzsa2_block_backwards(&lzsa::encode_lzsa2_block_backwards(&data).unwrap())
            .unwrap(),
        data
    );
}

#[test]
fn backwards_block_with_dictionary() {
    // In backwards mode the prefix is forward-order history: upstream
    // reverses only the new block data, never the history window.
    // Byte-reversed copies of the dictionary blocks above.
    let raw1 = [0x00, 0x00, 238, 0x00, 0x0f, 0xfa, b'a', 0x10];
    assert_eq!(
        lzsa::decode_lzsa1_block_backwards_with_prefix(&raw1, b"HELLO").unwrap(),
        b"LEHa"
    );
    let raw2 = [0xe8, 0xe7, 0xdf, b'a', 0x29];
    assert_eq!(
        lzsa::decode_lzsa2_block_backwards_with_prefix(&raw2, b"HELLO").unwrap(),
        b"LEHa"
    );
    // Encode side: matches may reach into the forward-order prefix.
    let prefix = b"0123456789abcdef";
    let mut input = b" fedcba9876543210".to_vec(); // space + reverse(prefix)
    input.extend_from_slice(b" tail tail tail");
    let b1 = lzsa::encode_lzsa1_block_backwards_with_prefix(&input, prefix).unwrap();
    let b2 = lzsa::encode_lzsa2_block_backwards_with_prefix(&input, prefix).unwrap();
    assert_eq!(
        lzsa::decode_lzsa1_block_backwards_with_prefix(&b1, prefix).unwrap(),
        input
    );
    assert_eq!(
        lzsa::decode_lzsa2_block_backwards_with_prefix(&b2, prefix).unwrap(),
        input
    );
}
