//! Whirlpool-2003 hash (ISO/IEC 10118-3) for PEA EAX256 key derivation.
//!
//! Table-driven implementation: the C tables gather each byte
//! position's S-box contribution through the circulant diffusion row
//! [1,1,4,1,8,5,2,9] over GF(2^8) (mod x^8+x^4+x^3+x+1) and are
//! computed from the spec S-box at compile time. Not constant-time.

/// Whirlpool substitution box (Whirlpool spec, Section 4.2).
const SBOX: [u8; 256] = [
    0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52,
    0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57,
    0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85,
    0xBD, 0x5D, 0x10, 0xF4, 0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8,
    0xFB, 0xEE, 0x7C, 0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33,
    0x63, 0x02, 0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0,
    0xE9, 0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
    0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D, 0x3D,
    0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF,
    0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92, 0x75, 0x06, 0x8A,
    0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4C,
    0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C, 0x1E, 0x43, 0xC7, 0xFC, 0x04,
    0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB, 0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB,
    0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7, 0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9,
    0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C, 0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1,
    0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0, 0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86,
];

/// Multiply in GF(2^8) modulo the Whirlpool polynomial x^8+x^4+x^3+x+1.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    product
}

/// C tables: C[k][x] rotates the diffusion row applied to SBOX[x]
/// into byte position k of a state word (big-endian lane order).
const C: [[u64; 256]; 8] = {
    let mut c = [[0u64; 256]; 8];
    let mut x = 0usize;
    while x < 256 {
        let s = SBOX[x];
        let row = u64::from_be_bytes([
            s,
            s,
            gf_mul(s, 4),
            s,
            gf_mul(s, 8),
            gf_mul(s, 5),
            gf_mul(s, 2),
            gf_mul(s, 9),
        ]);
        let mut k = 0usize;
        while k < 8 {
            c[k][x] = row.rotate_right(8 * k as u32);
            k += 1;
        }
        x += 1;
    }
    c
};

/// Round constants: RC[r] is the S-box applied to inputs 8r..8r+7.
const RC: [u64; 10] = {
    let mut rc = [0u64; 10];
    let mut r = 0usize;
    while r < 10 {
        rc[r] = u64::from_be_bytes([
            SBOX[8 * r],
            SBOX[8 * r + 1],
            SBOX[8 * r + 2],
            SBOX[8 * r + 3],
            SBOX[8 * r + 4],
            SBOX[8 * r + 5],
            SBOX[8 * r + 6],
            SBOX[8 * r + 7],
        ]);
        r += 1;
    }
    rc
};

/// One Whirlpool round (gamma, pi, theta) over a 512-bit state.
fn round(x: &[u64; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = C[0][(x[i] >> 56) as usize & 0xFF]
            ^ C[1][(x[(i + 7) & 7] >> 48) as usize & 0xFF]
            ^ C[2][(x[(i + 6) & 7] >> 40) as usize & 0xFF]
            ^ C[3][(x[(i + 5) & 7] >> 32) as usize & 0xFF]
            ^ C[4][(x[(i + 4) & 7] >> 24) as usize & 0xFF]
            ^ C[5][(x[(i + 3) & 7] >> 16) as usize & 0xFF]
            ^ C[6][(x[(i + 2) & 7] >> 8) as usize & 0xFF]
            ^ C[7][x[(i + 1) & 7] as usize & 0xFF];
    }
    out
}

fn compress(state: &mut [u64; 8], block: &[u8; 64]) {
    let mut key = *state;
    let mut m = [0u64; 8];
    let mut s = [0u64; 8];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        s[i] = *w ^ key[i];
    }
    for rc in RC {
        key = round(&key);
        key[0] ^= rc;
        s = round(&s);
        for i in 0..8 {
            s[i] ^= key[i];
        }
    }
    for i in 0..8 {
        state[i] ^= s[i] ^ m[i];
    }
}

/// Compute the Whirlpool digest of data.
pub fn whirlpool(data: &[u8]) -> [u8; 64] {
    let mut hasher = Whirlpool::new();
    hasher.update(data);
    hasher.finish()
}

/// Incremental Whirlpool hasher.
#[derive(Debug, Clone)]
pub struct Whirlpool {
    state: [u64; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Whirlpool {
    fn default() -> Self {
        Self::new()
    }
}

impl Whirlpool {
    pub const fn new() -> Self {
        Self {
            state: [0; 8],
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let to_copy = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];

            if self.buffer_len == 64 {
                let block = self.buffer;
                compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            compress(&mut self.state, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 64] {
        let bit_len = self.total_len.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // the 256-bit message length field occupies the last 32 bytes
        if self.buffer_len > 32 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        compress(&mut self.state, &block);

        let mut out = [0u8; 64];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn parse_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn expect(data: &[u8], digest: &str) {
        assert_eq!(whirlpool(data), parse_hex(digest).as_slice());
    }

    #[test]
    fn test_whirlpool_empty() {
        expect(
            b"",
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
        );
    }

    #[test]
    fn test_whirlpool_abc() {
        expect(
            b"abc",
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
        );
    }

    #[test]
    fn test_whirlpool_incremental() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let mut h = Whirlpool::new();
        h.update(&msg[..30]);
        h.update(&msg[30..]);
        assert_eq!(h.finish(), whirlpool(msg));
        expect(
            msg,
            "526b2394d85683e24b29acd0fd37f7d5027f61366a1407262dc2a6a345d9e240c017c1833db1e6db6a46bd444b0c69520c856e7c6e9c366d150a7da3aeb160d1",
        );
    }

    #[test]
    fn test_whirlpool_padding_boundary() {
        // 32-byte tail: padding byte overflows into a second block
        let msg = [0xABu8; 100];
        expect(
            &msg,
            "9048885b41080e7b5dbef210ef8b11a528addf713dff430176f42997a5e75269363b6f879b95cd23bef0c680f01b794199f872fd30686825e0a2e2660d2b80e1",
        );
    }
}
