#![cfg(all(
    feature = "deflate",
    feature = "gzip",
    feature = "zlib",
    feature = "bzip2",
    feature = "lz4",
    feature = "zstd",
    feature = "snappy",
    feature = "xz",
    feature = "lzip",
    feature = "lzma-alone",
    feature = "tar",
    feature = "cpio"
))]

#[cfg(feature = "sevenz")]
use archive::archive::sevenz;
#[cfg(feature = "zip")]
use archive::archive::zip;
use archive::archive::{cpio, tar};
#[cfg(feature = "brotli")]
use archive::compress::brotli as brotli_codec;
#[cfg(feature = "packbits")]
use archive::compress::packbits;
use archive::compress::{
    bzip2, cmpsc, deflate, fastlz, gzip, lrzip, lz4, lzf, lzip, lzma_alone, lzo, lzrw1, lzrw1a,
    lzrw2, lzrw3, lzrw3a, lzs, lzsa, lzw, lzxd, mppc, rzip, snappy, vcdiff, xca, xz, zlib, zpaq,
    zstd, zx0, zx1, zx2, zx5,
};
use proptest::prelude::*;

type DecodeFn = fn(&[u8], usize) -> Result<Vec<u8>, archive::error::Error>;

fn entry_name() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z][a-z0-9_]{0,15}").unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn deflate_roundtrip(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        for level in [
            deflate::encode::Level::NoCompression,
            deflate::encode::Level::Fast,
            deflate::encode::Level::Default,
        ] {
            let encoded = deflate::encode::encode(&data, level);
            prop_assert_eq!(deflate::decode::decode(&encoded).unwrap(), data.clone());
        }
    }

    #[test]
    fn gzip_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = gzip::encode::encode(&data, deflate::encode::Level::Default);
        prop_assert_eq!(gzip::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn zlib_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = zlib::encode::encode(&data);
        prop_assert_eq!(zlib::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn bzip2_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = bzip2::encode::encode(&data);
        prop_assert_eq!(bzip2::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn lz4_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = lz4::encode::encode(&data);
        prop_assert_eq!(lz4::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn zstd_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = zstd::encode::encode(&data);
        prop_assert_eq!(zstd::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn snappy_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = snappy::encode::encode(&data);
        prop_assert_eq!(snappy::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn xz_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let encoded = xz::encode::encode(&data);
        prop_assert_eq!(xz::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn lzip_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let encoded = lzip::encode::encode(&data);
        prop_assert_eq!(lzip::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn lzma_alone_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let encoded = lzma_alone::encode::encode(&data);
        prop_assert_eq!(lzma_alone::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn tar_roundtrip(entries in prop::collection::vec((entry_name(), prop::collection::vec(any::<u8>(), 0..512)), 0..5)) {
        let mut encoder = tar::encode::TarEncoder::new();
        for (name, data) in &entries {
            encoder.add_file(name, data);
        }
        let encoded = encoder.finish();
        let decoded = tar::decode::decode(&encoded).unwrap();
        let got: Vec<(String, Vec<u8>)> = decoded
            .into_iter()
            .map(|entry| (entry.header.name, entry.data))
            .collect();
        prop_assert_eq!(got, entries);
    }

    #[test]
    fn cpio_roundtrip(entries in prop::collection::vec((entry_name(), prop::collection::vec(any::<u8>(), 0..512)), 0..5)) {
        let mut encoder = cpio::encode::CpioEncoder::new();
        for (name, data) in &entries {
            encoder.add_file(name, data);
        }
        let encoded = encoder.finish();
        let decoded = cpio::decode::decode(&encoded).unwrap();
        let got: Vec<(String, Vec<u8>)> = decoded
            .into_iter()
            .map(|entry| (entry.name, entry.data))
            .collect();
        prop_assert_eq!(got, entries);
    }

    #[test]
    fn random_inputs_do_not_panic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = deflate::decode::decode_bounded(&data, 1 << 20);
        let _ = gzip::decode::decode_bounded(&data, 1 << 20);
        let _ = zlib::decode::decode_bounded(&data, 1 << 20);
        let _ = bzip2::decode::decode_bounded(&data, 1 << 20);
        let _ = lz4::decode::decode_bounded(&data, 1 << 20);
        let _ = zstd::decode::decode_bounded(&data, 1 << 20);
        let _ = snappy::decode::decode_bounded(&data, 1 << 20);
        let _ = xz::decode::decode_bounded(&data, 1 << 20);
        let _ = lzip::decode::decode_bounded(&data, 1 << 20);
        let _ = lzma_alone::decode::decode_bounded(&data, 1 << 20);
        let _ = tar::decode::decode(&data);
        let _ = cpio::decode::decode(&data);
    }

    #[test]
    fn truncated_streams_do_not_panic(
        data in prop::collection::vec(any::<u8>(), 0..2048),
        cut in any::<usize>(),
    ) {
        let cases: [(Vec<u8>, DecodeFn); 10] = [
            (
                deflate::encode::encode(&data, deflate::encode::Level::Default),
                deflate::decode::decode_bounded,
            ),
            (
                gzip::encode::encode(&data, deflate::encode::Level::Default),
                gzip::decode::decode_bounded,
            ),
            (
                zlib::encode::encode(&data),
                zlib::decode::decode_bounded,
            ),
            (bzip2::encode::encode(&data), bzip2::decode::decode_bounded),
            (lz4::encode::encode(&data), lz4::decode::decode_bounded),
            (zstd::encode::encode(&data), zstd::decode::decode_bounded),
            (
                snappy::encode::encode(&data),
                snappy::decode::decode_bounded,
            ),
            (xz::encode::encode(&data), xz::decode::decode_bounded),
            (lzip::encode::encode(&data), lzip::decode::decode_bounded),
            (
                lzma_alone::encode::encode(&data),
                lzma_alone::decode::decode_bounded,
            ),
        ];
        for (encoded, decode) in &cases {
            let end = cut % (encoded.len() + 1);
            let _ = decode(&encoded[..end], 1 << 20);
        }
    }

    #[cfg(feature = "zip")]
    #[test]
    fn zip_roundtrip(entries in prop::collection::vec((entry_name(), prop::collection::vec(any::<u8>(), 0..512)), 0..5)) {
        let mut encoder = zip::encode::ZipEncoder::new();
        for (name, data) in &entries {
            encoder.add_file(name, data);
        }
        let encoded = encoder.finish().unwrap();
        let decoded = zip::decode::decode(&encoded).unwrap();
        let got: Vec<(String, Vec<u8>)> = decoded
            .into_iter()
            .map(|entry| (entry.name, entry.data))
            .collect();
        prop_assert_eq!(got, entries);
    }

    #[cfg(feature = "sevenz")]
    #[test]
    fn sevenz_copy_roundtrip(entries in prop::collection::vec((entry_name(), prop::collection::vec(any::<u8>(), 0..512)), 0..5)) {
        let mut encoder = sevenz::encode::SevenZEncoder::new();
        encoder.set_method(sevenz::encode::SevenZMethod::Copy);
        for (name, data) in &entries {
            encoder.add_file(name, data);
        }
        let encoded = encoder.finish().unwrap();
        let decoded = sevenz::decode::decode(&encoded).unwrap();
        let got: Vec<(String, Vec<u8>)> = decoded
            .into_iter()
            .map(|entry| (entry.name, entry.data))
            .collect();
        prop_assert_eq!(got, entries);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn brotli_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = brotli_codec::encode::encode(&data);
        prop_assert_eq!(brotli_codec::decode::decode(&encoded).unwrap(), data);
    }

    #[cfg(feature = "packbits")]
    #[test]
    fn packbits_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = packbits::encode(&data);
        prop_assert_eq!(packbits::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn lzrw_family_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert_eq!(lzrw1::decode(&lzrw1::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(lzrw1a::decode(&lzrw1a::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(lzrw2::decode(&lzrw2::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(lzrw3::decode(&lzrw3::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(lzrw3a::decode(&lzrw3a::encode(&data)).unwrap(), data);
    }

    #[test]
    fn zx_family_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert_eq!(zx0::decode(&zx0::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(zx1::decode(&zx1::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(zx2::decode(&zx2::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(zx5::decode(&zx5::encode(&data)).unwrap(), data);
    }

    #[test]
    fn lzsa_lzf_fastlz_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert_eq!(lzsa::decode(&lzsa::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(lzf::decode(&lzf::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(fastlz::decode(&fastlz::encode(&data)).unwrap(), data);
    }

    #[test]
    fn vcdiff_mppc_lzs_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        prop_assert_eq!(vcdiff::decode(&vcdiff::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(mppc::decode(&mppc::encode(&data).unwrap()).unwrap(), data.clone());
        prop_assert_eq!(lzs::decode(&lzs::encode(&data).unwrap()).unwrap(), data);
    }

    #[test]
    fn lzo_lzw_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert_eq!(lzo::decode::decode(&lzo::encode::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(lzw::decode::decode(&lzw::encode::encode(&data)).unwrap(), data);
    }

    #[test]
    fn lrzip_rzip_roundtrip(data in prop::collection::vec(any::<u8>(), 0..512)) {
        prop_assert_eq!(lrzip::decode::decode(&lrzip::encode::encode(&data)).unwrap(), data.clone());
        prop_assert_eq!(rzip::decode::decode(&rzip::encode::encode(&data)).unwrap(), data);
    }

    #[test]
    fn zstd_seekable_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = zstd::seekable::encode(&data, 1024);
        prop_assert_eq!(zstd::seekable::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn zpaq_roundtrip(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = zpaq::encode::encode(&data, 1);
        prop_assert_eq!(zpaq::decode::decode(&encoded).unwrap(), data);
    }

    #[test]
    fn lzxd_cmpsc_xca_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let lzxd = lzxd::encode(&data);
        prop_assert_eq!(lzxd::decode(&lzxd, 1 << 17, &[], data.len()).unwrap(), data.clone());
        prop_assert_eq!(cmpsc::decode(&cmpsc::encode(&data), 1 << 20).unwrap(), data.clone());
        let huff = xca::huffman::encode(&data);
        prop_assert_eq!(xca::huffman::decode(&huff).unwrap(), data.clone());
        let lznt1 = xca::lznt1::encode(&data);
        prop_assert_eq!(xca::lznt1::decode(&lznt1).unwrap(), data);
    }
}
