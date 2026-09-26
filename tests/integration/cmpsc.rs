use super::*;

// ============================================================
// CMPSC (basic method) tests
// ============================================================
//
// Dictionaries below are hand-built per the z/Architecture POP
// Appendix D layouts:
// - compression entries: CCT/ACT/CPTR/EC/CC fields at the architected
//   bit positions (format-0 sibling descriptors at 8-byte slots)
// - expansion entries: PSL/CSL (unpreceded) or PSL/PPTR/EC/OFST
//   (preceded)

const E: usize = 8;

fn alphabet_edict(entries: usize) -> Vec<u8> {
    let mut d = vec![0u8; entries * E];
    for i in 0..256usize {
        d[i * E] = 1 << 2; // PSL=0, CSL=1
        d[i * E + 1] = i as u8;
    }
    d
}

fn pack(symbols: &[u16], sym_size: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut n = 0u32;
    for &s in symbols {
        for i in (0..sym_size).rev() {
            acc = (acc << 1) | (((s >> i) & 1) as u32);
            n += 1;
            if n == 8 {
                out.push(acc as u8);
                acc = 0;
                n = 0;
            }
        }
    }
    if n > 0 {
        out.push((acc << (8 - n)) as u8);
    }
    out
}

/// 512-entry pair (9-bit symbols):
/// - 'A' has children "AB" (256) and "AX" (257); "AB" has child "ABC" (258)
/// - 'S' has children "SA".."SE" (259-263) plus a format-0 sibling
///   descriptor at 264 designating "SF".."SH" (265-267)
fn test_dictionaries() -> (Vec<u8>, Vec<u8>) {
    let mut cd = vec![0u8; 512 * E];
    let mut ed = alphabet_edict(512);

    cd[65 * E] = 2 << 5;
    cd[65 * E + 1] = (256 >> 8) as u8;
    cd[65 * E + 2] = 0;
    cd[65 * E + 3] = b'B';
    cd[65 * E + 4] = b'X';

    cd[256 * E] = 1 << 5;
    cd[256 * E + 1] = (258 >> 8) as u8;
    cd[256 * E + 2] = (258 & 0xff) as u8;
    cd[256 * E + 3] = b'C';

    cd[83 * E] = 6 << 5;
    cd[83 * E + 1] = (259 >> 8) as u8;
    cd[83 * E + 2] = (259 & 0xff) as u8;
    cd[83 * E + 3..83 * E + 8].copy_from_slice(b"ABCDE");

    cd[264 * E] = 3 << 5;
    cd[264 * E + 1] = b'F';
    cd[264 * E + 2] = b'G';
    cd[264 * E + 3] = b'H';

    ed[256 * E] = 1 << 5;
    ed[256 * E + 1] = 65;
    ed[256 * E + 2] = b'B';
    ed[256 * E + 7] = 1;
    ed[257 * E] = 1 << 5;
    ed[257 * E + 1] = 65;
    ed[257 * E + 2] = b'X';
    ed[257 * E + 7] = 1;
    ed[258 * E] = (1 << 5) | 1;
    ed[258 * E + 1] = 0;
    ed[258 * E + 2] = b'C';
    ed[258 * E + 7] = 2;
    for (k, idx) in (259..=263usize).enumerate() {
        ed[idx * E] = 1 << 5;
        ed[idx * E + 1] = 83;
        ed[idx * E + 2] = b'A' + k as u8;
        ed[idx * E + 7] = 1;
    }
    for (k, idx) in (265..=267usize).enumerate() {
        ed[idx * E] = 1 << 5;
        ed[idx * E + 1] = 83;
        ed[idx * E + 2] = b'F' + k as u8;
        ed[idx * E + 7] = 1;
    }
    (cd, ed)
}

#[test]
fn cmpsc_expand_alphabet_and_chains() {
    let (_, ed) = test_dictionaries();
    let data = pack(&[258, 259, 262, 265], 9);
    assert_eq!(cmpsc::expand(&ed, 9, &data, 1 << 20).unwrap(), b"ABCSASDSF");
}

#[test]
fn cmpsc_compress_expand_roundtrip() {
    let (cd, ed) = test_dictionaries();
    let c = cmpsc::compress(&cd, 9, b"ABCSASF").unwrap();
    assert_eq!(cmpsc::expand(&ed, 9, &c, 1 << 20).unwrap(), b"ABCSASF");
    // 'S'+'F' must be found via the sibling descriptor.
    assert_eq!(c, pack(&[258, 259, 265], 9));
}

#[test]
fn cmpsc_method16_roundtrip() {
    let input: Vec<u8> = (0..5000u32).map(|i| (i * 31 + 5) as u8).collect();
    let s = cmpsc::encode(&input);
    // Header: version=1, flags 0x80 | symsize 9, BE dict len = 4096.
    assert_eq!(&s[..6], &[1, 0x89, 0, 0, 0x10, 0]);
    assert_eq!(s.len(), 6 + 4096 + (input.len() * 9).div_ceil(8));
    assert_eq!(cmpsc::decode(&s, 1 << 20).unwrap(), input);
}

#[test]
fn cmpsc_method16_explicit_vector() {
    // Hand-built method-16 stream: 256-entry... full 512-entry alphabet
    // dict, then symbols [258] which index 258 does not exist in an
    // alphabet-only dict -> use symbols that exist.
    let mut s = vec![1u8, 0x89, 0, 0, 0x10, 0];
    s.extend_from_slice(&alphabet_edict(512));
    s.extend_from_slice(&pack(&[b'H' as u16, b'i' as u16, b'!' as u16], 9));
    assert_eq!(cmpsc::decode(&s, 1 << 20).unwrap(), b"Hi!");
}

#[test]
fn cmpsc_rejects_malformed() {
    // Truncated header / bad version / missing dict flag / reserved flag.
    assert!(cmpsc::decode(&[1, 0x89], 1 << 20).is_err());
    assert!(cmpsc::decode(&[2, 0x89, 0, 0, 0, 0], 1 << 20).is_err());
    assert!(cmpsc::decode(&[1, 0x09, 0, 0, 0, 0], 1 << 20).is_err());
    assert!(cmpsc::decode(&[1, 0xc9, 0, 0, 0, 0], 1 << 20).is_err());
    // Dictionary length overrunning input.
    assert!(cmpsc::decode(&[1, 0x89, 0, 0, 0x20, 0, 0, 0], 1 << 20).is_err());
    // Index symbol beyond dictionary entries.
    let (_, ed) = test_dictionaries();
    assert!(cmpsc::expand(&ed[..256 * E], 9, &pack(&[300], 9), 1 << 20).is_err());
    // Symbol size outside 9-13.
    assert!(cmpsc::expand(&ed, 7, &pack(&[1], 7), 1 << 20).is_err());
}
