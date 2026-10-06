//! LZW compression (Unix compress `.Z` format).
//!
//! Compresses data using the LZW algorithm, producing output compatible
//! with the Unix `compress` utility.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lzw::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec;
use alloc::vec::Vec;

use super::should_bump_encode_code_width;

/// Magic bytes for Unix compress format.
const MAGIC: [u8; 2] = [0x1F, 0x9D];

/// Block mode flag (bit 7 of flags byte).
const BLOCK_MODE: u8 = 0x80;

/// Clear code used in block mode.
const CLEAR_CODE: u16 = 256;

/// First available dictionary code.
const FIRST_CODE: u16 = 257;

/// Default maximum code bits.
const DEFAULT_MAX_BITS: u8 = 16;

/// Input-byte interval between compression-ratio checks, matching
/// `CHECK_GAP` in compress42.c. In block mode the encoder re-evaluates
/// the ratio every `CHECK_GAP` input bytes and emits a CLEAR code when
/// the ratio has worsened since the previous check (adaptive reset).
const CHECK_GAP: u64 = 10000;

/// Compress data using LZW (Unix compress `.Z` format).
///
/// Uses 16-bit maximum code size with block mode enabled.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, LZW!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_options(input, DEFAULT_MAX_BITS)
}

/// Compress data using LZW with a specified maximum code size (9-16 bits).
///
/// Lower values use less memory but may compress less effectively.
/// Block mode (clear code) is always enabled.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, LZW!";
/// let compressed = encode::encode_with_options(data, 12);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_with_options(input: &[u8], max_bits: u8) -> Vec<u8> {
    let max_bits = max_bits.clamp(9, 16);

    let flags = BLOCK_MODE | max_bits;
    let mut output = Vec::new();
    output.push(MAGIC[0]);
    output.push(MAGIC[1]);
    output.push(flags);
    output.extend_from_slice(&encode_body(input, max_bits, true));
    output
}

/// Emit a headerless Unix compress LZW codestream.
///
/// Produces the variable-width code stream without the 3-byte `.Z`
/// header. Used by ARC methods 8 (Crunched) and 9 (Squashed) and the
/// Spark `0x7f` method, which wrap the stream in their own member
/// records. `max_bits` is the maximum code width (9-16); `block_mode`
/// reserves clear code 256 and emits it with the group-of-8 padding
/// when the dictionary fills or when the adaptive ratio check
/// (CHECK_GAP input-byte intervals, compress42.c `cl_block()`) detects
/// a worsening compression ratio. The dict-full CLEAR is emitted the
/// moment the dictionary becomes exactly full — emit #256 of the run —
/// so a run never exceeds 256 codes at max_bits=9. compress42.c's
/// decoder widens with no `n_bits < maxbits` guard (the `phantom
/// bump`, decompress L1698-1710): it would read a run's 257th code
/// at 10 bits even in a -b9 stream, so a later CLEAR would land off
/// the decoder's resync lattice. Group-of-8 alignment is measured
/// from the current block-run origin (compress42.c `boff`): the
/// landing of the most recent width bump or clear pad, which is the
/// body start for the first run.
pub(crate) fn encode_body(input: &[u8], max_bits: u8, block_mode: bool) -> Vec<u8> {
    let max_bits = max_bits.clamp(9, 16);
    let max_code = (1u32 << max_bits) - 1;

    let mut output = Vec::new();

    if input.is_empty() {
        return output;
    }

    // Dictionary: hash table mapping (prefix_code, byte) → code
    // Use a simple hash table with open addressing.
    let table_size = 1 << (max_bits + 1); // power of 2 for fast modulo
    // u32 + u32::MAX sentinel: at max_bits=16 the prefix 65535 is a real code
    // and must not collide with the empty-slot marker.
    let mut hash_prefix = vec![u32::MAX; table_size as usize];
    let mut hash_suffix = vec![0u8; table_size as usize];
    let mut hash_code = vec![0u16; table_size as usize];

    // u32: next_code must reach max_code + 1 (65536 at max_bits=16) without
    // wrapping — a full dictionary is signaled by next_code > max_code.
    let mut next_code: u32 = if block_mode { FIRST_CODE as u32 } else { 256 };
    let mut code_bits: u32 = 9;
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    // Byte offset (relative to `output`) where the current block run's
    // group-of-8 lattice begins — compress42.c's `boff`. Both the
    // group-of-8 pad after a CLEAR and the decoder's resync are
    // measured from the previous resync landing, not from the body
    // start. Width bumps and CLEAR pads re-origin the lattice to their
    // landing point.
    let mut run_start: usize = 0;

    // Helper: flush bits to output
    let flush_bits = |bit_buf: &mut u64, bit_count: &mut u32, output: &mut Vec<u8>| {
        while *bit_count >= 8 {
            output.push(*bit_buf as u8);
            *bit_buf >>= 8;
            *bit_count -= 8;
        }
    };

    // Helper: write a code
    let write_code = |code: u32,
                      code_bits: u32,
                      bit_buf: &mut u64,
                      bit_count: &mut u32,
                      output: &mut Vec<u8>| {
        *bit_buf |= (code as u64) << *bit_count;
        *bit_count += code_bits;
        flush_bits(bit_buf, bit_count, output);
    };

    // Helper: clear the hash table
    let clear_table = |hash_prefix: &mut [u32]| {
        for p in hash_prefix.iter_mut() {
            *p = u32::MAX;
        }
    };

    // Helper: hash function
    let hash = |prefix: u16, byte: u8, table_size: usize| -> usize {
        let h = ((prefix as u32) << 8 | byte as u32).wrapping_mul(2654435761);
        (h as usize) & (table_size - 1)
    };

    // Helper: look up or insert into hash table
    let lookup = |prefix: u16,
                  byte: u8,
                  hash_prefix: &[u32],
                  hash_suffix: &[u8],
                  hash_code: &[u16],
                  table_size: usize|
     -> Option<u16> {
        let mut idx = hash(prefix, byte, table_size);
        loop {
            if hash_prefix[idx] == u32::MAX {
                return None; // empty slot
            }
            if hash_prefix[idx] == prefix as u32 && hash_suffix[idx] == byte {
                return Some(hash_code[idx]);
            }
            idx = (idx + 1) & (table_size - 1);
        }
    };

    let insert = |prefix: u16,
                  byte: u8,
                  code: u16,
                  hash_prefix: &mut [u32],
                  hash_suffix: &mut [u8],
                  hash_code: &mut [u16],
                  table_size: usize| {
        let mut idx = hash(prefix, byte, table_size);
        loop {
            if hash_prefix[idx] == u32::MAX {
                hash_prefix[idx] = prefix as u32;
                hash_suffix[idx] = byte;
                hash_code[idx] = code;
                return;
            }
            idx = (idx + 1) & (table_size - 1);
        }
    };

    // Emit the CLEAR code, align the output to the group-of-8 boundary,
    // and reset the dictionary. Shared by the dict-full path and the
    // adaptive ratio-check path.
    let emit_clear = |bit_buf: &mut u64,
                      bit_count: &mut u32,
                      code_bits: &mut u32,
                      next_code: &mut u32,
                      hash_prefix: &mut [u32],
                      run_start: &mut usize,
                      output: &mut Vec<u8>| {
        write_code(CLEAR_CODE as u32, *code_bits, bit_buf, bit_count, output);

        // Pad to code_bits-aligned boundary (Unix compress behavior):
        // Codes are packed in groups of 8 into code_bits bytes.
        // After clear, remaining bits in the group are discarded.
        // Flush remaining bits first.
        if *bit_count > 0 {
            output.push(*bit_buf as u8);
            *bit_buf = 0;
            *bit_count = 0;
        }
        // Pad output so the current run fills a whole number of
        // code_bits-byte groups. The group lattice is measured from
        // the block-run start (compress42.c `boff`) — the landing of
        // the previous width bump or clear pad — not from the body
        // start. A CLEAR arriving mid-run after a width bump would
        // otherwise be padded to the wrong offset.
        let group_bytes = *code_bits as usize;
        let remainder = (output.len() - *run_start) % group_bytes;
        if remainder != 0 {
            let pad = group_bytes - remainder;
            output.resize(output.len() + pad, 0);
        }
        // The padded landing point re-origins the group lattice.
        *run_start = output.len();

        // Reset dictionary
        clear_table(hash_prefix);
        *next_code = FIRST_CODE as u32;
        *code_bits = 9;
    };

    let table_sz = table_size as usize;

    // Adaptive-reset state (compress42.c `cl_block()`): the compression
    // ratio is re-evaluated every CHECK_GAP input bytes; `old_ratio`
    // holds the baseline established by the previous check.
    let mut bytes_in: u64 = 1; // input[0] is already the initial prefix
    let mut checkpoint: u64 = CHECK_GAP;
    let mut old_ratio: u64 = 0;

    // Start with first byte as the current prefix (not output yet)
    let mut w = input[0] as u16;

    for &byte in &input[1..] {
        bytes_in += 1;
        if let Some(code) = lookup(w, byte, &hash_prefix, &hash_suffix, &hash_code, table_sz) {
            // String w+byte is in dictionary
            w = code;
        } else {
            // Output code for w
            write_code(
                w as u32,
                code_bits,
                &mut bit_buf,
                &mut bit_count,
                &mut output,
            );

            // Add w+byte to dictionary
            if next_code <= max_code {
                insert(
                    w,
                    byte,
                    next_code as u16,
                    &mut hash_prefix,
                    &mut hash_suffix,
                    &mut hash_code,
                    table_sz,
                );
                next_code += 1;

                // The encoder widens after the newly allocated code would no
                // longer fit in the current width.
                if should_bump_encode_code_width(next_code, code_bits, max_bits as u32) {
                    // compress42.c L1404-1405: before widening, pad the
                    // output with zero bits up to the next old-width
                    // group-of-8 boundary measured from the block-run
                    // origin `boff`, then re-origin the lattice at the
                    // landing. In block mode the bump always lands
                    // exactly on the lattice (2^k - 256 codes into the
                    // run ≡ 0 mod 8) so the pad is a no-op; in non-block
                    // mode the bump lands mid-group and real pad bits
                    // are emitted.
                    let group_bits = code_bits as usize * 8;
                    let pos_bits = output.len() * 8 + bit_count as usize;
                    let rem = (pos_bits - run_start * 8) % group_bits;
                    if rem != 0 {
                        // bit_buf's bits above bit_count are always zero,
                        // so crediting pad bits and flushing emits zeros.
                        bit_count += (group_bits - rem) as u32;
                        flush_bits(&mut bit_buf, &mut bit_count, &mut output);
                    }
                    // Group landings are byte-aligned.
                    debug_assert_eq!(bit_count, 0);
                    run_start = output.len();
                    code_bits += 1;
                }

                // compress42.c's decoder widens whenever free_ent exceeds
                // the current-width maxcode — WITHOUT an n_bits < maxbits
                // guard (decompress L1698-1710, the "phantom bump"): even
                // in a max_bits=9 stream it switches to 10-bit reads once
                // a run's 256th code has been consumed. Emitting the
                // dict-full CLEAR only on the *next* miss (emit #257)
                // would cross that boundary: the decoder then reads CLEAR
                // at 10 bits and resyncs onto an 80-bit group lattice the
                // encoder never wrote, rejecting the stream as corrupt
                // (gzip "corrupt input"). Emit CLEAR immediately when the
                // dictionary becomes exactly full instead, so it is emit
                // #256 — the last code the decoder reads at the current
                // width — and no run ever exceeds 256 codes at
                // max_bits=9. (ncompress's own -b9 encoder lacks this —
                // it keeps writing 9-bit codes past the boundary, which
                // is why `compress -b9` output is undecodable even by
                // ncompress itself: fuzz known issue B.)
                if block_mode && next_code > max_code {
                    emit_clear(
                        &mut bit_buf,
                        &mut bit_count,
                        &mut code_bits,
                        &mut next_code,
                        &mut hash_prefix,
                        &mut run_start,
                        &mut output,
                    );
                    // Reset the ratio baseline, as compress42.c `cl_block()`
                    // does after every clear, so the next ratio check
                    // cannot trigger immediately after this clear.
                    old_ratio = 0;
                }
            }
            // Non-block mode: when the dictionary is full, simply stop
            // inserting (no clear code exists). In block mode the
            // dictionary can never be full at miss-entry — it was
            // cleared immediately when it filled.

            // compress42.c `cl_block()` (lines 1418-1446): every
            // CHECK_GAP input bytes, recompute the compression ratio as
            //     ratio = (bytes_in << 8) / bytes_out
            // (input bytes per output byte, with 8 fractional bits).
            // If the ratio has not improved since the last check, the
            // dictionary has gone stale for the new input — emit CLEAR
            // and reset it.
            if block_mode && bytes_in >= checkpoint {
                checkpoint = bytes_in + CHECK_GAP;
                let bytes_out = output.len() as u64;
                let ratio = (bytes_in << 8).checked_div(bytes_out).unwrap_or(u64::MAX);
                if ratio > old_ratio {
                    old_ratio = ratio;
                } else {
                    emit_clear(
                        &mut bit_buf,
                        &mut bit_count,
                        &mut code_bits,
                        &mut next_code,
                        &mut hash_prefix,
                        &mut run_start,
                        &mut output,
                    );
                    old_ratio = 0;
                }
            }

            w = byte as u16;
        }
    }

    // Output the last code
    write_code(
        w as u32,
        code_bits,
        &mut bit_buf,
        &mut bit_count,
        &mut output,
    );

    // Flush remaining bits
    if bit_count > 0 {
        output.push(bit_buf as u8);
    }

    output
}

/// Compress data using LZW with full control over max bits and block mode.
///
/// When `block_mode` is `true`, code 256 is reserved as a clear code and
/// the dictionary resets when full or when the adaptive ratio check
/// detects worsening compression (same as [`encode_with_options`]).
///
/// When `block_mode` is `false`, no clear code is reserved, dictionary
/// codes start at 256, and once the dictionary is full new entries are
/// simply not inserted.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, LZW!";
/// let compressed = encode::encode_with_full_options(data, 16, false);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_with_full_options(input: &[u8], max_bits: u8, block_mode: bool) -> Vec<u8> {
    if block_mode {
        return encode_with_options(input, max_bits);
    }

    let max_bits = max_bits.clamp(9, 16);

    // Non-block mode: bit 7 is clear, just max_bits
    let flags = max_bits;
    let mut output = Vec::new();
    output.push(MAGIC[0]);
    output.push(MAGIC[1]);
    output.push(flags);
    output.extend_from_slice(&encode_body(input, max_bits, false));
    output
}

/// Compress data using LZW and write to a writer.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::encode;
///
/// let data = b"Hello, writer!";
/// let mut output = Vec::new();
/// let size = encode::encode_writer(data, &mut output).unwrap();
/// assert!(size > 0);
/// ```
#[cfg(feature = "std")]
pub fn encode_writer<W: std::io::Write>(input: &[u8], mut writer: W) -> std::io::Result<usize> {
    let encoded = encode(input);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::lzw::should_bump_decode_code_width;

    /// Deterministic pseudo-random bytes (xorshift32) for tests.
    fn prng_bytes(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9u32;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 16) as u8
            })
            .collect()
    }

    /// Reference model of the compress42.c/gzip `unlzw` codestream walk
    /// for a headerless block-mode body: the group-of-8 resync lattice
    /// is measured from the block-run origin — compress42.c's `boff`,
    /// the landing of the most recent width bump or CLEAR pad —
    /// not from the body start.
    ///
    /// Returns the decoded payload and the code width at which each
    /// CLEAR code was encountered. Panics on malformed input, like
    /// `uncompress: corrupt input`.
    fn reference_unlzw(body: &[u8], max_bits: u8) -> (Vec<u8>, Vec<u32>) {
        let (out, clear_widths, _) = reference_unlzw_impl(body, max_bits, false);
        (out, clear_widths)
    }

    /// gzip/ncompress-faithful variant of `reference_unlzw` WITHOUT the
    /// `code_bits < max_bits` guard on the width bump: compress42.c's
    /// decompress bumps `n_bits` whenever `free_ent > maxcode`
    /// (L1698-1710), even past `maxbits` — the "phantom bump". At
    /// maxbits=9 the real decoder therefore reads only the first 256
    /// codes of a run at 9 bits and switches to 10 bits from code #257,
    /// so a conforming stream must never let a block run exceed 256
    /// codes. Our own decoder deliberately keeps the cap instead (the
    /// only real-world -b9 producer, ncompress, writes no-bump output),
    /// which is why a separate model is needed here: `reference_unlzw`
    /// shares the encoder's blind spot and cannot see the phantom bump.
    ///
    /// Returns the decoded payload and the number of codes read in each
    /// block run (a run ends at its CLEAR or at EOF; the CLEAR counts
    /// toward its run).
    fn reference_unlzw_gzip(body: &[u8], max_bits: u8) -> (Vec<u8>, Vec<u32>) {
        let (out, _, run_lengths) = reference_unlzw_impl(body, max_bits, true);
        (out, run_lengths)
    }

    /// Shared codestream walk behind `reference_unlzw` and
    /// `reference_unlzw_gzip`. `phantom_bump` selects the width-bump
    /// rule: `false` mirrors our decoder (`code_bits < max_bits` cap);
    /// `true` mirrors compress42.c/gzip (`free_ent > maxcode` with no
    /// maxbits guard, `maxcode` becoming `maxmaxcode` once `n_bits`
    /// reaches `maxbits`).
    ///
    /// Returns (decoded payload, CLEAR widths, per-run code counts).
    fn reference_unlzw_impl(
        body: &[u8],
        max_bits: u8,
        phantom_bump: bool,
    ) -> (Vec<u8>, Vec<u32>, Vec<u32>) {
        // compress42.c `maxmaxcode` = 1<<maxbits; `free_ent` (== our
        // `next_code`) is capped just below it.
        let maxmaxcode = 1u32 << max_bits;
        let cap = maxmaxcode as usize;
        let mut prefix = vec![0u16; cap];
        let mut suffix = vec![0u8; cap];
        for (i, s) in suffix.iter_mut().enumerate().take(256) {
            *s = i as u8;
        }

        let mut next_code: u32 = FIRST_CODE as u32;
        let mut code_bits: u32 = 9;
        // compress42.c `maxcode`: (1<<n_bits)-1 normally, maxmaxcode once
        // n_bits reaches maxbits (set on the bump, not at init — which is
        // exactly why a maxbits=9 stream still bumps 9->10).
        let mut maxcode: u32 = (1u32 << code_bits) - 1;
        let mut bit_pos: usize = 0;
        let mut run_start: usize = 0;
        let mut run_codes: u32 = 0;
        let mut clear_widths = Vec::new();
        let mut run_lengths = Vec::new();
        let mut out = Vec::new();
        let mut stack: Vec<u8> = Vec::new();
        let mut prev: Option<u16> = None;

        // Advance `pos` to the next `group_bits`-multiple boundary
        // measured from `run_start` (compress42.c resync formula), then
        // re-origin the lattice at the landing.
        macro_rules! resync {
            () => {{
                let group_bits = code_bits as usize * 8;
                let rem = (bit_pos - run_start) % group_bits;
                if rem != 0 {
                    bit_pos += group_bits - rem;
                }
                run_start = bit_pos;
            }};
        }

        loop {
            // compress42.c checks `free_ent > maxcode` before reading
            // each code; the phantom variant applies it literally, the
            // capped variant applies our decoder's semantics.
            let bump = if phantom_bump {
                next_code > maxcode
            } else {
                should_bump_decode_code_width(next_code, code_bits, max_bits as u32)
            };
            if bump {
                // Resync at the OLD width before widening.
                resync!();
                code_bits += 1;
                if phantom_bump {
                    maxcode = if code_bits == max_bits as u32 {
                        maxmaxcode
                    } else {
                        (1u32 << code_bits) - 1
                    };
                }
            }

            let cb = code_bits as usize;
            if bit_pos + cb > body.len() * 8 {
                if run_codes > 0 {
                    run_lengths.push(run_codes);
                }
                break;
            }
            let mut code = 0u32;
            for i in 0..cb {
                let bit = (body[(bit_pos + i) / 8] >> ((bit_pos + i) % 8)) & 1;
                code |= (bit as u32) << i;
            }
            bit_pos += cb;
            run_codes += 1;

            if code == CLEAR_CODE as u32 && prev.is_some() {
                clear_widths.push(code_bits);
                run_lengths.push(run_codes);
                run_codes = 0;
                resync!();
                next_code = FIRST_CODE as u32;
                code_bits = 9;
                maxcode = (1u32 << 9) - 1; // MAXCODE(INIT_BITS)-1
                prev = None;
                continue;
            }

            let Some(p) = prev else {
                assert!(code < 256, "run's first code must be a literal, got {code}");
                out.push(code as u8);
                prev = Some(code as u16);
                continue;
            };

            stack.clear();
            let kwkwk = code == next_code;
            assert!(
                kwkwk || code < next_code,
                "corrupt input: code {code} >= next_code {next_code}"
            );
            let mut c = if kwkwk { p as u32 } else { code };
            while c > 255 {
                stack.push(suffix[c as usize]);
                c = u32::from(prefix[c as usize]);
            }
            stack.push(c as u8);
            let first_byte = c as u8;
            if kwkwk {
                // KwKwK emits str(prev) + first_byte(str(prev)); the
                // stack is in reverse order so the appended byte sits
                // at index 0 (emitted last).
                stack.insert(0, first_byte);
            }
            for &b in stack.iter().rev() {
                out.push(b);
            }

            if next_code < maxmaxcode {
                prefix[next_code as usize] = p;
                suffix[next_code as usize] = first_byte;
                next_code += 1;
            }
            prev = Some(code as u16);
        }
        (out, clear_widths, run_lengths)
    }

    /// Scan a headerless block-mode codestream and count the CLEAR codes
    /// (256) it contains. The scanner mirrors the encoder's code-width
    /// progression and the group-of-8 resync after each clear.
    fn count_clear_codes(body: &[u8], max_bits: u8) -> usize {
        let max_code = (1u32 << max_bits) - 1;
        let mut next_code: u32 = FIRST_CODE as u32;
        let mut code_bits: u32 = 9;
        let mut bit_pos: usize = 0;
        // Bit position of the current block-run origin (compress42.c
        // `boff`): group-of-8 resyncs are measured from the previous
        // resync landing, not from the body start.
        let mut run_start: usize = 0;
        let mut clears = 0usize;
        // The first code of the stream (and of each post-clear segment)
        // emits no new dictionary entry.
        let mut saw_first = false;
        loop {
            let cb = code_bits as usize;
            if bit_pos + cb > body.len() * 8 {
                break;
            }
            let mut code = 0u32;
            for i in 0..cb {
                let bit = (body[(bit_pos + i) / 8] >> ((bit_pos + i) % 8)) & 1;
                code |= (bit as u32) << i;
            }
            bit_pos += cb;

            if code == CLEAR_CODE as u32 {
                clears += 1;
                // Codes are packed in groups of 8 (cb * 8 bits); the
                // rest of the current group is padding after a clear.
                let group_bits = cb * 8;
                let rem = (bit_pos - run_start) % group_bits;
                if rem != 0 {
                    bit_pos += group_bits - rem;
                }
                run_start = bit_pos;
                next_code = FIRST_CODE as u32;
                code_bits = 9;
                saw_first = false;
                continue;
            }

            if !saw_first {
                saw_first = true;
                continue;
            }
            if next_code <= max_code {
                next_code += 1;
                // Decode-side boundary: the scanner walks the emitted
                // stream, so it widens one code earlier than the
                // encoder's insertion check (decoder semantics).
                if should_bump_decode_code_width(next_code, code_bits, max_bits as u32) {
                    // Resync to the next old-width group boundary
                    // relative to the run start, then re-origin.
                    let group_bits = code_bits as usize * 8;
                    let rem = (bit_pos - run_start) % group_bits;
                    if rem != 0 {
                        bit_pos += group_bits - rem;
                    }
                    run_start = bit_pos;
                    code_bits += 1;
                }
            }
        }
        clears
    }

    #[test]
    fn test_should_bump_encode_code_width_at_boundary() {
        assert!(!should_bump_encode_code_width(511, 9, 10));
        assert!(!should_bump_encode_code_width(512, 9, 10));
        assert!(should_bump_encode_code_width(513, 9, 10));
        assert!(!should_bump_encode_code_width(513, 9, 9));
    }

    #[test]
    fn test_header_format() {
        let compressed = encode(b"A");
        assert_eq!(compressed[0], 0x1F);
        assert_eq!(compressed[1], 0x9D);
        assert_eq!(compressed[2] & 0x1F, 16); // default max_bits
        assert_ne!(compressed[2] & BLOCK_MODE, 0); // block mode on
    }

    #[test]
    fn test_empty_input() {
        let compressed = encode(b"");
        assert_eq!(compressed.len(), 3); // header only
        assert_eq!(compressed[0], 0x1F);
        assert_eq!(compressed[1], 0x9D);
    }

    #[test]
    fn test_max_bits_clamping() {
        // Too low → clamps to 9
        let c1 = encode_with_options(b"test", 5);
        assert_eq!(c1[2] & 0x1F, 9);

        // Too high → clamps to 16
        let c2 = encode_with_options(b"test", 20);
        assert_eq!(c2[2] & 0x1F, 16);
    }

    #[test]
    fn test_compression_ratio() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = encode(data);
        // LZW should compress repetitive data
        assert!(
            compressed.len() < data.len(),
            "compressed {} >= original {}",
            compressed.len(),
            data.len()
        );
    }

    #[test]
    fn test_encode_with_options_max_bits_9() {
        let data = b"Hello, World!";
        let compressed = encode_with_options(data, 9);
        assert_eq!(compressed[2] & 0x1F, 9);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_clear_code_emitted_when_dict_full() {
        // With max_bits=9, dictionary can hold codes 257..=511 (255 entries).
        // Feed enough unique byte pairs to fill the dictionary and force a
        // clear code. Verify the encoder produces a stream that round-trips.
        let data: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();
        let compressed = encode_with_options(&data, 9);
        // The compressed data should be valid and decodable.
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_non_block_mode() {
        let data = b"Hello, non-block mode LZW! ABABABABABABAB";
        let compressed = encode_with_full_options(data, 16, false);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_non_block_mode_header_flag() {
        let compressed = encode_with_full_options(b"test", 12, false);
        // Header byte 2: block_mode bit (0x80) should be clear
        assert_eq!(
            compressed[2] & BLOCK_MODE,
            0,
            "block mode bit should be clear"
        );
        // max_bits should be 12
        assert_eq!(compressed[2] & 0x1F, 12);
    }

    #[test]
    fn test_ratio_clear_on_worsening_input() {
        // Highly compressible prefix followed by incompressible data:
        // the cumulative ratio is high at the first CHECK_GAP boundary
        // and drops below it at the second, forcing an adaptive CLEAR
        // (compress42.c cl_block).
        let mut data = vec![b'A'; 12_000];
        let mut x: u32 = 0x9E37_79B9;
        for _ in 0..12_000 {
            // deterministic pseudo-random tail (xorshift32)
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            data.push((x >> 16) as u8);
        }
        let compressed = encode(&data);
        // The dictionary cannot fill at max_bits=16 on this input size,
        // so any CLEAR in the stream must come from the ratio check.
        assert!(
            count_clear_codes(&compressed[3..], 16) >= 1,
            "expected at least one ratio-based CLEAR code"
        );
        // The CLEAR lands mid-run at a widened code width, so its
        // group-of-8 pad must be measured from the block-run origin —
        // verify against the compress42.c `boff` reference model.
        let (reference_decoded, clear_widths) = reference_unlzw(&compressed[3..], 16);
        assert!(
            clear_widths.iter().any(|&w| w > 9),
            "expected a CLEAR at a widened code width, got {clear_widths:?}"
        );
        assert_eq!(reference_decoded, data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_clear_pad_originates_at_block_run_start() {
        // Fuzz-found regression: with max_bits=10 the dictionary fills
        // (767 entries) and the dict-full CLEAR is emitted at code width
        // 10 — after the 9→10 bump re-origined the group-of-8 lattice at
        // body bit 2304 (288 bytes), which is not a multiple of the
        // 10-byte group size. Padding the CLEAR group relative to the
        // body start — the pre-fix bug — shifts the post-CLEAR codes off
        // the lattice that gzip/ncompress resync to ("corrupt input").
        let data = prng_bytes(4096);
        let compressed = encode_with_options(&data, 10);
        let (reference_decoded, clear_widths) = reference_unlzw(&compressed[3..], 10);
        assert!(
            clear_widths.contains(&10),
            "expected a dict-full CLEAR at width 10, got clears at {clear_widths:?}"
        );
        assert_eq!(reference_decoded, data);
        assert_eq!(super::super::decode::decode(&compressed).unwrap(), data);
    }

    #[test]
    fn test_clear_pad_run_relative_multiple_runs() {
        // Exhaustively re-check the resync basis across several
        // consecutive block runs: every CLEAR pad landing must satisfy
        // (landing - previous_landing) % old_width == 0. This is the
        // property gzip's `resetbuf` slide relies on.
        let data = prng_bytes(20_000);
        let compressed = encode_with_options(&data, 12);
        let (reference_decoded, clear_widths) = reference_unlzw(&compressed[3..], 12);
        assert!(
            clear_widths.len() >= 2,
            "expected multiple dict-full CLEARs, got {clear_widths:?}"
        );
        assert_eq!(reference_decoded, data);
        assert_eq!(super::super::decode::decode(&compressed).unwrap(), data);
    }

    #[test]
    fn test_fuzz_regression_clear_pad_run_start() {
        // Fuzz-found regression (lzw / lzw-bits9 original-decompress):
        // the encoder padded CLEAR groups relative to the body start
        // instead of the block-run origin (compress42.c `boff`), so a
        // CLEAR landing after a width bump drifted off the resync
        // lattice and gzip/ncompress rejected the stream as
        // "corrupt input". Validate this input against the reference
        // model at both max_bits settings the harness exercises.
        let input = include_bytes!("../../../tests/fixtures/fuzz/lzw_clear_pad_run_start.bin");
        for max_bits in [9u8, 16] {
            let compressed = encode_with_options(input, max_bits);
            let (reference_decoded, clear_widths) = reference_unlzw(&compressed[3..], max_bits);
            assert!(
                !clear_widths.is_empty(),
                "expected CLEAR codes for max_bits={max_bits}"
            );
            assert_eq!(
                reference_decoded,
                &input[..],
                "reference-model decode failed for max_bits={max_bits}"
            );
            // The capped model shares our decoder's phantom-bump blind
            // spot, so also validate with the gzip-faithful model.
            let (gzip_decoded, run_lengths) = reference_unlzw_gzip(&compressed[3..], max_bits);
            assert_eq!(
                gzip_decoded,
                &input[..],
                "phantom-bump reference decode failed for max_bits={max_bits}"
            );
            if max_bits == 9 {
                assert!(
                    run_lengths.iter().all(|&n| n <= 256),
                    "run exceeds 256 codes at max_bits=9: {run_lengths:?}"
                );
            }
            assert_eq!(
                super::super::decode::decode(&compressed).unwrap(),
                &input[..],
                "decode failed for max_bits={max_bits}"
            );
        }
    }

    #[test]
    fn test_dict_full_clear_is_emit_256_max_bits_9() {
        // Fuzz-found regression (lzw-bits9 original-decompress,
        // run-1791251880): compress42.c's decoder widens whenever
        // free_ent > maxcode WITHOUT an n_bits < maxbits guard (the
        // "phantom bump"), so in a max_bits=9 stream it reads only the
        // first 256 codes of a block run at 9 bits and switches to 10
        // bits from code #257. The encoder used to emit the dict-full
        // CLEAR on the miss AFTER the dictionary filled — emit #257 —
        // which the real decoder reads at 10 bits, misaligning every
        // subsequent code ("gzip: stdin: corrupt input"). The CLEAR
        // must instead be emitted the moment the dictionary becomes
        // exactly full — emit #256 — so every run stays within the
        // decoder's pre-bump reach.
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let compressed = encode_with_options(&data, 9);
        let (gzip_decoded, run_lengths) = reference_unlzw_gzip(&compressed[3..], 9);
        assert!(
            run_lengths.len() >= 2,
            "expected dict-full CLEAR-terminated runs, got {run_lengths:?}"
        );
        assert!(
            run_lengths.iter().all(|&n| n <= 256),
            "block run exceeds 256 codes — gzip would phantom-bump: {run_lengths:?}"
        );
        assert_eq!(gzip_decoded, data, "phantom-bump reference decode failed");
        assert_eq!(super::super::decode::decode(&compressed).unwrap(), data);
    }

    #[test]
    fn test_fuzz_regression_bits9_phantom_bump_artifacts() {
        // The two inputs behind the run-1791251880 failure artifacts,
        // reconstructed from fuzz/src/datagen.rs generators:
        // `incrementing-511` and `high-entropy-257`. Both fill the
        // max_bits=9 dictionary and previously produced streams that
        // gzip rejected ("corrupt input") or silently misdecoded.
        let incrementing_511: Vec<u8> = (0..511u32).map(|i| (i % 256) as u8).collect();
        let high_entropy_257: Vec<u8> = (0..257u32).map(|i| ((i * 73 + 19) % 256) as u8).collect();
        for data in [incrementing_511, high_entropy_257] {
            let compressed = encode_with_options(&data, 9);
            let (gzip_decoded, run_lengths) = reference_unlzw_gzip(&compressed[3..], 9);
            assert!(
                run_lengths.iter().all(|&n| n <= 256),
                "block run exceeds 256 codes at max_bits=9: {run_lengths:?}"
            );
            assert_eq!(
                gzip_decoded,
                data,
                "phantom-bump reference decode failed (len={})",
                data.len()
            );
            assert_eq!(super::super::decode::decode(&compressed).unwrap(), data);
        }
    }

    #[test]
    fn test_phantom_bump_compat_all_max_bits() {
        // The dict-full CLEAR moved one emit earlier for every
        // max_bits, not just 9. Validate against the gzip-faithful
        // phantom-bump model across the whole range with an input that
        // fills the dictionary repeatedly.
        let data = prng_bytes(20_000);
        for max_bits in 9..=16u8 {
            let compressed = encode_with_options(&data, max_bits);
            let (gzip_decoded, run_lengths) = reference_unlzw_gzip(&compressed[3..], max_bits);
            assert_eq!(
                gzip_decoded, data,
                "phantom-bump reference decode failed for max_bits={max_bits} (runs: {run_lengths:?})"
            );
            assert_eq!(
                super::super::decode::decode(&compressed).unwrap(),
                data,
                "decode failed for max_bits={max_bits}"
            );
        }
    }

    #[test]
    fn test_no_ratio_clear_when_ratio_improves() {
        // Uniformly compressible input keeps improving the cumulative
        // ratio, so no adaptive CLEAR is emitted across the CHECK_GAP
        // checkpoints.
        let data = vec![b'B'; 30_000];
        let compressed = encode(&data);
        assert_eq!(count_clear_codes(&compressed[3..], 16), 0);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_code_width_grows_at_boundary() {
        // With max_bits=10, verify that the encoder correctly bumps code width
        // from 9 to 10 bits when next_code exceeds 2^9 = 512. Use enough
        // unique byte pairs to push next_code past 512. Verify roundtrip.
        let data: Vec<u8> = (0..600u32).map(|i| (i % 256) as u8).collect();
        let compressed = encode_with_options(&data, 10);
        assert_eq!(compressed[2] & 0x1F, 10);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
