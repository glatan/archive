//! CRC-16/ARC checksum (poly 0x8005, reflected, init 0x0000, xorout 0).
//!
//! Used by LHA headers/data and SEA ARC member CRCs.

/// Compute the CRC-16/ARC value for `data`.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        // CRC-16/ARC check value from the CRC catalogue.
        assert_eq!(crc16(b"123456789"), 0xBB3D);
        assert_eq!(crc16(b""), 0x0000);
    }
}
