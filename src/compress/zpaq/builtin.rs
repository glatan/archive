//! Native HCOMP for the built-in levels 1-3.
//!
//! Each function is the level's HCOMP program with the same register
//! and memory updates as the ZPAQL interpreter. `CustomModel` keeps
//! the interpreter.

/// `(a + m[b] + 512) * 773`, the HCOMP byte-hash step.
#[inline]
fn hash_byte(a: u32, m: u8) -> u32 {
    a.wrapping_add(u32::from(m))
        .wrapping_add(512)
        .wrapping_mul(773)
}

/// Level 1 (`min.cfg`): a 4-byte ring hashed into two contexts.
#[derive(Clone)]
pub(crate) struct Hcomp1 {
    b: u32,
    m: [u8; 4],
    h: [u32; 2],
}

impl Hcomp1 {
    pub(crate) fn new() -> Self {
        Self {
            b: 0,
            m: [0; 4],
            h: [0; 2],
        }
    }

    pub(crate) fn hashes(&self) -> &[u32] {
        &self.h
    }

    pub(crate) fn update(&mut self, input: u8) {
        self.m[(self.b as usize) & 3] = input;
        let mut a = 0u32;
        let mut d = 0u32;
        a = hash_byte(a, self.m[(self.b as usize) & 3]);
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(a, self.m[(self.b as usize) & 3]);
        self.h[(d as usize) & 1] = a;
        d = d.wrapping_add(1);
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(a, self.m[(self.b as usize) & 3]);
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(a, self.m[(self.b as usize) & 3]);
        self.h[(d as usize) & 1] = a;
    }
}

/// Level 2 (`mid.cfg`): an 8-byte ring and eight hash slots.
#[derive(Clone)]
pub(crate) struct Hcomp2 {
    b: u32,
    c: u32,
    m: [u8; 8],
    h: [u32; 8],
}

impl Hcomp2 {
    pub(crate) fn new() -> Self {
        Self {
            b: 0,
            c: 0,
            m: [0; 8],
            h: [0; 8],
        }
    }

    pub(crate) fn hashes(&self) -> &[u32] {
        &self.h
    }

    pub(crate) fn update(&mut self, input: u8) {
        self.c = self.c.wrapping_add(1);
        self.m[(self.c as usize) & 7] = input;
        self.b = self.c;
        let mut a = 0u32;
        let mut d = 1u32;
        for _ in 0..5 {
            a = hash_byte(a, self.m[(self.b as usize) & 7]);
            self.h[(d as usize) & 7] = a;
            self.b = self.b.wrapping_sub(1);
            d = d.wrapping_add(1);
        }
        a = hash_byte(a, self.m[(self.b as usize) & 7]);
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(a, self.m[(self.b as usize) & 7]);
        self.h[(d as usize) & 7] = a;
        d = d.wrapping_add(1);
        a = u32::from(self.m[(self.c as usize) & 7]);
        a <<= 8;
        self.h[(d as usize) & 7] = a;
    }
}

/// Level 3 (`max.cfg`): a 512-byte ring and 32 hash slots.
#[derive(Clone)]
pub(crate) struct Hcomp3 {
    b: u32,
    c: u32,
    m: [u8; 512],
    h: [u32; 32],
}

impl Hcomp3 {
    pub(crate) fn new() -> Self {
        Self {
            b: 0,
            c: 0,
            m: [0; 512],
            h: [0; 32],
        }
    }

    pub(crate) fn hashes(&self) -> &[u32] {
        &self.h
    }

    fn m_get(&self, i: u32) -> u8 {
        self.m[(i as usize) & 511]
    }

    fn m_set(&mut self, i: u32, v: u8) {
        self.m[(i as usize) & 511] = v;
    }

    fn h_get(&self, d: u32) -> u32 {
        self.h[(d as usize) & 31]
    }

    fn h_set(&mut self, d: u32, v: u32) {
        self.h[(d as usize) & 31] = v;
    }

    pub(crate) fn update(&mut self, input: u8) {
        self.c = self.c.wrapping_add(1);
        self.m_set(self.c, input);
        self.b = self.c;
        let mut a = 0u32;
        let mut d = 2u32;
        for _ in 0..5 {
            a = hash_byte(a, self.m_get(self.b));
            self.h_set(d, a);
            self.b = self.b.wrapping_sub(1);
            d = d.wrapping_add(1);
        }
        a = hash_byte(a, self.m_get(self.b));
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(a, self.m_get(self.b));
        self.h_set(d, a);
        self.b = self.b.wrapping_sub(1);
        d = d.wrapping_add(1);
        a = hash_byte(a, self.m_get(self.b));
        self.h_set(d, a);
        self.b = self.b.wrapping_sub(1);
        d = d.wrapping_add(1);

        a = u32::from(self.m_get(self.c));
        a &= !32;
        let letter = a > 64 && a < 91;
        if letter {
            d = d.wrapping_add(1);
            let mixed = self
                .h_get(d)
                .wrapping_add(a)
                .wrapping_add(512)
                .wrapping_mul(773);
            self.h_set(d, mixed);
            d = d.wrapping_sub(1);
            let old_a = a;
            a = self.h_get(d);
            self.h_set(d, old_a);
            a = a.wrapping_add(self.h_get(d));
            a = a.wrapping_mul(20);
            self.h_set(d, a);
        } else {
            a = self.h_get(d);
            if a != 0 {
                d = d.wrapping_add(1);
                self.h_set(d, a);
                d = d.wrapping_sub(1);
            }
            self.h_set(d, 0);
        }

        d = d.wrapping_add(2);
        self.b = self.c.wrapping_sub(1);
        a = hash_byte(0, self.m_get(self.b));
        self.h_set(d, a);
        d = d.wrapping_add(1);
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(0, self.m_get(self.b));
        self.h_set(d, a);
        d = d.wrapping_add(1);
        self.b = self.b.wrapping_sub(1);
        a = hash_byte(0, self.m_get(self.b));
        self.h_set(d, a);
        d = d.wrapping_add(1);

        a = self.b.wrapping_sub(212);
        self.b = a;
        a = hash_byte(0, self.m_get(self.b));
        self.h_set(d, a);
        // A<>B; A-216; A<>B leaves B = old_B - 216 and A = the hash.
        self.b = self.b.wrapping_sub(216);
        a = u32::from(self.m_get(self.b));
        a &= 60;
        let mixed = self
            .h_get(d)
            .wrapping_add(a)
            .wrapping_add(512)
            .wrapping_mul(773);
        self.h_set(d, mixed);
        d = d.wrapping_add(1);
        a = u32::from(self.m_get(self.c));
        a <<= 9;
        self.h_set(d, a);
        d = d.wrapping_add(5);
        self.h_set(d, a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::zpaq::models::model_zpaql;

    fn check(level: u32, data: &[u8]) {
        let mut z = model_zpaql(level).unwrap();
        z.inith().unwrap();
        let n = z.component_count();
        let mut h1 = Hcomp1::new();
        let mut h2 = Hcomp2::new();
        let mut h3 = Hcomp3::new();
        for (pos, &byte) in data.iter().enumerate() {
            z.run(u32::from(byte)).unwrap();
            let got: Vec<u32> = match level {
                1 => {
                    h1.update(byte);
                    h1.hashes().to_vec()
                }
                2 => {
                    h2.update(byte);
                    h2.hashes().to_vec()
                }
                _ => {
                    h3.update(byte);
                    h3.hashes()[..n].to_vec()
                }
            };
            for (i, slot) in got.iter().enumerate() {
                assert_eq!(*slot, z.hash_at(i), "level {level} byte {pos} slot {i}");
            }
        }
    }

    #[test]
    fn native_hcomp_matches_interpreter() {
        let samples: [&[u8]; 4] = [
            b"Hello, ZPAQ!",
            b"BANANA",
            b"The quick brown fox jumps over the lazy dog.",
            &(0u8..=255).collect::<Vec<_>>(),
        ];
        for level in 1..=3 {
            for sample in samples {
                check(level, sample);
            }
        }
    }
}
