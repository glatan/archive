mod helpers;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const SIZES: &[(&str, usize)] = &[("4KiB", 4 * 1024), ("256KiB", 256 * 1024)];

// ---------------------------------------------------------------------------
// DEFLATE
// ---------------------------------------------------------------------------
#[cfg(feature = "deflate")]
mod bench_deflate {
    use super::*;
    use archive::compress::deflate::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("deflate");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data, encode::Level::Default);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data, encode::Level::Default));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
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

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("gzip");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data, Level::Default);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data, Level::Default));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// zlib
// ---------------------------------------------------------------------------
#[cfg(feature = "zlib")]
mod bench_zlib {
    use super::*;
    use archive::compress::zlib::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("zlib");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// zstd
// ---------------------------------------------------------------------------
#[cfg(feature = "zstd")]
mod bench_zstd {
    use super::*;
    use archive::compress::zstd::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("zstd");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------
#[cfg(feature = "bzip2")]
mod bench_bzip2 {
    use super::*;
    use archive::compress::bzip2::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("bzip2");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// lzip
// ---------------------------------------------------------------------------
#[cfg(feature = "lzip")]
mod bench_lzip {
    use super::*;
    use archive::compress::lzip::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("lzip");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// LZMA-Alone
// ---------------------------------------------------------------------------
#[cfg(feature = "lzma-alone")]
mod bench_lzma_alone {
    use super::*;
    use archive::compress::lzma_alone::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("lzma-alone");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// LZW
// ---------------------------------------------------------------------------
#[cfg(feature = "lzw")]
mod bench_lzw {
    use super::*;
    use archive::compress::lzw::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("lzw");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// LZ4
// ---------------------------------------------------------------------------
#[cfg(feature = "lz4")]
mod bench_lz4 {
    use super::*;
    use archive::compress::lz4::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("lz4");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// LZO
// ---------------------------------------------------------------------------
#[cfg(feature = "lzo")]
mod bench_lzo {
    use super::*;
    use archive::compress::lzo::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("lzo");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// Snappy
// ---------------------------------------------------------------------------
#[cfg(feature = "snappy")]
mod bench_snappy {
    use super::*;
    use archive::compress::snappy::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("snappy");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// Brotli
// ---------------------------------------------------------------------------
#[cfg(feature = "brotli")]
mod bench_brotli {
    use super::*;
    use archive::compress::brotli::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("brotli");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// xz
// ---------------------------------------------------------------------------
#[cfg(feature = "xz")]
mod bench_xz {
    use super::*;
    use archive::compress::xz::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("xz");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// rzip
// ---------------------------------------------------------------------------
#[cfg(feature = "rzip")]
mod bench_rzip {
    use super::*;
    use archive::compress::rzip::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("rzip");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// ZPAQ
// ---------------------------------------------------------------------------
#[cfg(feature = "zpaq")]
mod bench_zpaq {
    use super::*;
    use archive::compress::zpaq::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("zpaq");
        // ZPAQ is slow; use smaller sizes.
        let zpaq_sizes: &[(&str, usize)] = &[("1KiB", 1024), ("4KiB", 4 * 1024)];
        for &(label, size) in zpaq_sizes {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data, 1);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data, 1));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// lrzip
// ---------------------------------------------------------------------------
#[cfg(feature = "lrzip")]
mod bench_lrzip {
    use super::*;
    use archive::compress::lrzip::{decode, encode};

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("lrzip");
        for &(label, size) in SIZES {
            let data = helpers::generate_text_data(size);
            let compressed = encode::encode(&data);

            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_with_input(BenchmarkId::new("encode", label), &data, |b, data| {
                b.iter(|| encode::encode(data));
            });
            g.throughput(Throughput::Bytes(compressed.len() as u64));
            g.bench_with_input(
                BenchmarkId::new("decode", label),
                &compressed,
                |b, compressed| {
                    b.iter(|| decode::decode(compressed).unwrap());
                },
            );
        }
        g.finish();
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
