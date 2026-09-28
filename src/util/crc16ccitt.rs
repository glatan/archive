//! CRC-16 with poly 0x1021, MSB-first, init 0x0000 (a.k.a. CRC-16/XMODEM,
//! the "CCITT" variant used by MacBinary II and BinHex 4.0).

fn update(mut crc: u16, b: u8) -> u16 {
    crc ^= (b as u16) << 8;
    for _ in 0..8 {
        crc = if crc & 0x8000 != 0 {
            (crc << 1) ^ 0x1021
        } else {
            crc << 1
        };
    }
    crc
}

/// Compute the CRC-16/CCITT value for `data`.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    data.iter().fold(0, |crc, &b| update(crc, b))
}

/// Compute the CRC-16/CCITT value for `data` followed by two zero bytes.
///
/// BinHex 4.0 stores the CRC state after processing the data plus two
/// 0x00 bytes ("augmented" form); empty forks therefore checksum to 0.
pub fn crc16_ccitt_aug(data: &[u8]) -> u16 {
    let crc = crc16_ccitt(data);
    update(update(crc, 0), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        // CRC-16/XMODEM check value from the CRC catalogue.
        assert_eq!(crc16_ccitt(b"123456789"), 0x31C3);
        assert_eq!(crc16_ccitt(b""), 0x0000);
    }

    #[test]
    fn augmented() {
        // Augmented form = CRC over data || 0x00 0x00.
        assert_eq!(crc16_ccitt_aug(b""), 0x0000);
        assert_eq!(crc16_ccitt_aug(b"123456789"), crc16_ccitt(b"123456789\0\0"));
    }
}
