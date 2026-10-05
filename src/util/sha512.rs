//! SHA-512 (FIPS 180-4) implementation for XAR "sha512" digests.

const INITIAL_STATE: [u64; 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

const K: [u64; 80] = [
    0x428A_2F98_D728_AE22,
    0x7137_4491_23EF_65CD,
    0xB5C0_FBCF_EC4D_3B2F,
    0xE9B5_DBA5_8189_DBBC,
    0x3956_C25B_F348_B538,
    0x59F1_11F1_B605_D019,
    0x923F_82A4_AF19_4F9B,
    0xAB1C_5ED5_DA6D_8118,
    0xD807_AA98_A303_0242,
    0x1283_5B01_4570_6FBE,
    0x2431_85BE_4EE4_B28C,
    0x550C_7DC3_D5FF_B4E2,
    0x72BE_5D74_F27B_896F,
    0x80DE_B1FE_3B16_96B1,
    0x9BDC_06A7_25C7_1235,
    0xC19B_F174_CF69_2694,
    0xE49B_69C1_9EF1_4AD2,
    0xEFBE_4786_384F_25E3,
    0x0FC1_9DC6_8B8C_D5B5,
    0x240C_A1CC_77AC_9C65,
    0x2DE9_2C6F_592B_0275,
    0x4A74_84AA_6EA6_E483,
    0x5CB0_A9DC_BD41_FBD4,
    0x76F9_88DA_8311_53B5,
    0x983E_5152_EE66_DFAB,
    0xA831_C66D_2DB4_3210,
    0xB003_27C8_98FB_213F,
    0xBF59_7FC7_BEEF_0EE4,
    0xC6E0_0BF3_3DA8_8FC2,
    0xD5A7_9147_930A_A725,
    0x06CA_6351_E003_826F,
    0x1429_2967_0A0E_6E70,
    0x27B7_0A85_46D2_2FFC,
    0x2E1B_2138_5C26_C926,
    0x4D2C_6DFC_5AC4_2AED,
    0x5338_0D13_9D95_B3DF,
    0x650A_7354_8BAF_63DE,
    0x766A_0ABB_3C77_B2A8,
    0x81C2_C92E_47ED_AEE6,
    0x9272_2C85_1482_353B,
    0xA2BF_E8A1_4CF1_0364,
    0xA81A_664B_BC42_3001,
    0xC24B_8B70_D0F8_9791,
    0xC76C_51A3_0654_BE30,
    0xD192_E819_D6EF_5218,
    0xD699_0624_5565_A910,
    0xF40E_3585_5771_202A,
    0x106A_A070_32BB_D1B8,
    0x19A4_C116_B8D2_D0C8,
    0x1E37_6C08_5141_AB53,
    0x2748_774C_DF8E_EB99,
    0x34B0_BCB5_E19B_48A8,
    0x391C_0CB3_C5C9_5A63,
    0x4ED8_AA4A_E341_8ACB,
    0x5B9C_CA4F_7763_E373,
    0x682E_6FF3_D6B2_B8A3,
    0x748F_82EE_5DEF_B2FC,
    0x78A5_636F_4317_2F60,
    0x84C8_7814_A1F0_AB72,
    0x8CC7_0208_1A64_39EC,
    0x90BE_FFFA_2363_1E28,
    0xA450_6CEB_DE82_BDE9,
    0xBEF9_A3F7_B2C6_7915,
    0xC671_78F2_E372_532B,
    0xCA27_3ECE_EA26_619C,
    0xD186_B8C7_21C0_C207,
    0xEADA_7DD6_CDE0_EB1E,
    0xF57D_4F7F_EE6E_D178,
    0x06F0_67AA_7217_6FBA,
    0x0A63_7DC5_A2C8_98A6,
    0x113F_9804_BEF9_0DAE,
    0x1B71_0B35_131C_471B,
    0x28DB_77F5_2304_7D84,
    0x32CA_AB7B_40C7_2493,
    0x3C9E_BE0A_15C9_BEBC,
    0x431D_67C4_9C10_0D4C,
    0x4CC5_D4BE_CB3E_42B6,
    0x597F_299C_FC65_7E2A,
    0x5FCB_6FAB_3AD6_FAEC,
    0x6C44_198C_4A47_5817,
];

#[inline]
const fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

#[inline]
const fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
const fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
const fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
const fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
const fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

fn compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for (i, chunk) in block.as_chunks::<8>().0.iter().enumerate() {
        w[i] = u64::from_be_bytes(*chunk);
    }
    for i in 16..80 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..80 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Compute the SHA-512 digest of a byte slice.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut state = INITIAL_STATE;
    let (blocks, rem) = data.as_chunks::<128>();
    for block in blocks {
        compress(&mut state, block);
    }
    let mut tail = [0u8; 256];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let bit_len = (data.len() as u128).wrapping_mul(8);
    if rem.len() >= 112 {
        tail[240..256].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut state, &tail[..128]);
        compress(&mut state, &tail[128..]);
    } else {
        tail[112..128].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut state, &tail[..128]);
    }

    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_lower(data: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for b in data {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn test_sha512_empty() {
        assert_eq!(
            hex_lower(&sha512(b"")),
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
    }

    #[test]
    fn test_sha512_abc() {
        assert_eq!(
            hex_lower(&sha512(b"abc")),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn test_sha512_two_block() {
        // FIPS 180-4 example: the 112-byte message leaves no room for
        // the length field in its own block, so padding requires a
        // second block.
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(msg.len(), 112);
        assert_eq!(
            hex_lower(&sha512(msg)),
            concat!(
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018",
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            )
        );
    }

    #[test]
    fn test_sha512_million_a() {
        let data = alloc::vec![b'a'; 1_000_000];
        assert_eq!(
            hex_lower(&sha512(&data)),
            concat!(
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb",
                "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            )
        );
    }

    #[test]
    fn test_sha512_padding_boundary() {
        // Exercise both padding paths around the 112-byte boundary:
        // each length must still produce a stable, distinct digest.
        let mut prev = [0u8; 64];
        for len in [0usize, 111, 112, 113, 127, 128] {
            let data = alloc::vec![0x61u8; len];
            let digest = sha512(&data);
            assert_ne!(digest, prev, "len {len}");
            prev = digest;
        }
    }
}
