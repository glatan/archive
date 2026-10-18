mod helpers;

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const SIZES: &[(&str, usize)] = &[("4KiB", 4 * 1024), ("256KiB", 256 * 1024)];

fn bench_roundtrip(
    c: &mut Criterion,
    group: &str,
    inputs: &[helpers::BenchInput],
    encode: fn(&[u8]) -> Vec<u8>,
    decode: fn(&[u8], &mut Vec<u8>),
) {
    let mut g = c.benchmark_group(group);
    let mut large_tuned = false;
    for input in inputs {
        if input.large && !large_tuned {
            // Criterion 0.8 defaults to 100 samples. A 4MiB iteration of the
            // slow kernels does not finish under that budget.
            g.sample_size(10);
            g.measurement_time(Duration::from_secs(5));
            large_tuned = true;
        }
        let compressed = encode(&input.data);
        g.throughput(Throughput::Bytes(input.data.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("encode", &input.label),
            &input.data,
            |b, data| {
                b.iter(|| encode(data));
            },
        );
        g.throughput(Throughput::Bytes(compressed.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("decode", &input.label),
            &compressed,
            |b, compressed| {
                b.iter(|| {
                    let mut output = Vec::new();
                    decode(compressed, &mut output);
                    std::hint::black_box(output);
                });
            },
        );
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// DEFLATE
// ---------------------------------------------------------------------------
#[cfg(feature = "deflate")]
mod bench_deflate {
    use super::*;
    use archive::compress::deflate::{decode, encode};

    fn encode_default(data: &[u8]) -> Vec<u8> {
        encode::encode(data, encode::Level::Default)
    }

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, true);
        super::bench_roundtrip(c, "deflate", &inputs, encode_default, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------
#[cfg(feature = "gzip")]
mod bench_gzip {
    use super::*;
    use archive::compress::deflate::encode::Level;
    use archive::compress::gzip::{decode, encode};

    fn encode_default(data: &[u8]) -> Vec<u8> {
        encode::encode(data, Level::Default)
    }

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "gzip", &inputs, encode_default, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// zlib
// ---------------------------------------------------------------------------
#[cfg(feature = "zlib")]
mod bench_zlib {
    use super::*;
    use archive::compress::zlib::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "zlib", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// zstd
// ---------------------------------------------------------------------------
#[cfg(feature = "zstd")]
mod bench_zstd {
    use super::*;
    use archive::compress::zstd::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, true);
        super::bench_roundtrip(c, "zstd", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------
#[cfg(feature = "bzip2")]
mod bench_bzip2 {
    use super::*;
    use archive::compress::bzip2::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, true);
        super::bench_roundtrip(c, "bzip2", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// lzip
// ---------------------------------------------------------------------------
#[cfg(feature = "lzip")]
mod bench_lzip {
    use super::*;
    use archive::compress::lzip::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "lzip", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// LZMA-Alone
// ---------------------------------------------------------------------------
#[cfg(feature = "lzma-alone")]
mod bench_lzma_alone {
    use super::*;
    use archive::compress::lzma_alone::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        // One 4MiB random encode took 7.5s in release, past the 5s
        // measurement window. This group stays at 256KiB. lzip and xz
        // call the same finder and were not given a separate 4MiB size.
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "lzma-alone", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// LZW
// ---------------------------------------------------------------------------
#[cfg(feature = "lzw")]
mod bench_lzw {
    use super::*;
    use archive::compress::lzw::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "lzw", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// LZ4
// ---------------------------------------------------------------------------
#[cfg(feature = "lz4")]
mod bench_lz4 {
    use super::*;
    use archive::compress::lz4::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "lz4", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// LZO
// ---------------------------------------------------------------------------
#[cfg(feature = "lzo")]
mod bench_lzo {
    use super::*;
    use archive::compress::lzo::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "lzo", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// Snappy
// ---------------------------------------------------------------------------
#[cfg(feature = "snappy")]
mod bench_snappy {
    use super::*;
    use archive::compress::snappy::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "snappy", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// Brotli
// ---------------------------------------------------------------------------
#[cfg(feature = "brotli")]
mod bench_brotli {
    use super::*;
    use archive::compress::brotli::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, true);
        super::bench_roundtrip(c, "brotli", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// xz
// ---------------------------------------------------------------------------
#[cfg(feature = "xz")]
mod bench_xz {
    use super::*;
    use archive::compress::xz::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "xz", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// rzip
// ---------------------------------------------------------------------------
#[cfg(feature = "rzip")]
mod bench_rzip {
    use super::*;
    use archive::compress::rzip::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, true);
        super::bench_roundtrip(c, "rzip", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// ZPAQ
// ---------------------------------------------------------------------------
#[cfg(feature = "zpaq")]
mod bench_zpaq {
    use super::*;
    use archive::compress::zpaq::{decode, encode};

    fn encode_level1(data: &[u8]) -> Vec<u8> {
        encode::encode(data, 1)
    }

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        // ZPAQ is slow; keep the historical 1KiB / 4KiB sizes. No 4MiB.
        let zpaq_sizes: &[(&str, usize)] = &[("1KiB", 1024), ("4KiB", 4 * 1024)];
        let inputs = helpers::compression_inputs(zpaq_sizes, false);
        super::bench_roundtrip(c, "zpaq", &inputs, encode_level1, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// lrzip
// ---------------------------------------------------------------------------
#[cfg(feature = "lrzip")]
mod bench_lrzip {
    use super::*;
    use archive::compress::lrzip::{decode, encode};

    fn decode_unwrap(data: &[u8], output: &mut Vec<u8>) {
        decode::decode_into(data, output, None).unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let inputs = helpers::compression_inputs(SIZES, false);
        super::bench_roundtrip(c, "lrzip", &inputs, encode::encode, decode_unwrap);
    }
}

// ---------------------------------------------------------------------------
// Stubs for disabled features — keeps criterion_group! happy regardless of
// which feature flags are active.
// ---------------------------------------------------------------------------

macro_rules! bench_stub {
    ($mod:ident, $feat:literal) => {
        #[cfg(not(feature = $feat))]
        mod $mod {
            pub fn bench(_c: &mut criterion::Criterion) {}
        }
    };
}

bench_stub!(bench_deflate, "deflate");
bench_stub!(bench_gzip, "gzip");
bench_stub!(bench_zlib, "zlib");
bench_stub!(bench_zstd, "zstd");
bench_stub!(bench_bzip2, "bzip2");
bench_stub!(bench_lzip, "lzip");
bench_stub!(bench_lzma_alone, "lzma-alone");
bench_stub!(bench_lzw, "lzw");
bench_stub!(bench_lz4, "lz4");
bench_stub!(bench_lzo, "lzo");
bench_stub!(bench_snappy, "snappy");
bench_stub!(bench_brotli, "brotli");
bench_stub!(bench_xz, "xz");
bench_stub!(bench_rzip, "rzip");
bench_stub!(bench_zpaq, "zpaq");
bench_stub!(bench_lrzip, "lrzip");

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_deflate::bench,
    bench_gzip::bench,
    bench_zlib::bench,
    bench_zstd::bench,
    bench_bzip2::bench,
    bench_lzip::bench,
    bench_lzma_alone::bench,
    bench_lzw::bench,
    bench_lz4::bench,
    bench_lzo::bench,
    bench_snappy::bench,
    bench_brotli::bench,
    bench_xz::bench,
    bench_rzip::bench,
    bench_zpaq::bench,
    bench_lrzip::bench,
);

criterion_main!(benches);
