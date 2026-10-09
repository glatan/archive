//! Delta filter shared by XZ / 7z style filter chains.
//!
//! Ported from the public-domain liblzma delta filter
//! (`delta_encoder.c` / `delta_decoder.c`; `delta_coder.c` holds the
//! shared init/dispatch). See
//! `THIRD_PARTY_NOTICES` section 2.

use alloc::vec::Vec;

use crate::error::Error;

/// Stateful byte-wise Delta filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    distance: usize,
    history: [u8; 256],
    pos: usize,
}

impl Filter {
    /// Create a new Delta filter.
    pub fn new(distance: usize) -> Result<Self, Error> {
        if !(1..=256).contains(&distance) {
            return Err(Error::InvalidData("delta: distance must be 1..=256"));
        }
        Ok(Self {
            distance,
            history: [0; 256],
            pos: 0,
        })
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) {
        for byte in buffer {
            let prev = self.history[self.distance.wrapping_add(self.pos) & 0xFF];
            let input = *byte;
            self.history[self.pos & 0xFF] = input;
            self.pos = self.pos.wrapping_sub(1);
            *byte = input.wrapping_sub(prev);
        }
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) {
        for byte in buffer {
            let decoded =
                byte.wrapping_add(self.history[self.distance.wrapping_add(self.pos) & 0xFF]);
            self.history[self.pos & 0xFF] = decoded;
            self.pos = self.pos.wrapping_sub(1);
            *byte = decoded;
        }
    }
}

/// Encode bytes using the Delta filter.
pub fn encode(input: &[u8], distance: usize) -> Result<Vec<u8>, Error> {
    let mut filter = Filter::new(distance)?;
    let mut output = input.to_vec();
    filter.encode_in_place(&mut output);
    Ok(output)
}

/// Decode bytes using the Delta filter.
pub fn decode(input: &[u8], distance: usize) -> Result<Vec<u8>, Error> {
    let mut filter = Filter::new(distance)?;
    let mut output = input.to_vec();
    filter.decode_in_place(&mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_delta_known_vector_distance_one() {
        let input = b"BANANA";
        let encoded = encode(input, 1).unwrap();
        assert_eq!(encoded, vec![66, 255, 13, 243, 13, 243]);
        assert_eq!(decode(&encoded, 1).unwrap(), input);
    }

    #[test]
    fn test_delta_roundtrip_distance_four() {
        let input = (0u8..=255).cycle().take(1024).collect::<Vec<_>>();
        let encoded = encode(&input, 4).unwrap();
        let decoded = decode(&encoded, 4).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_delta_streaming_matches_one_shot() {
        let input = (0u8..=63).cycle().take(300).collect::<Vec<_>>();
        let one_shot = encode(&input, 3).unwrap();

        let mut streaming = input.clone();
        let mut filter = Filter::new(3).unwrap();
        filter.encode_in_place(&mut streaming[..120]);
        filter.encode_in_place(&mut streaming[120..]);
        assert_eq!(streaming, one_shot);

        let mut decoder = Filter::new(3).unwrap();
        decoder.decode_in_place(&mut streaming[..111]);
        decoder.decode_in_place(&mut streaming[111..]);
        assert_eq!(streaming, input);
    }

    #[test]
    fn test_delta_rejects_invalid_distance() {
        assert!(Filter::new(0).is_err());
        assert!(Filter::new(257).is_err());
    }
}
