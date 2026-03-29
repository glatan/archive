mod helpers;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Number of files to pack into each test archive.
const FILE_COUNT: usize = 50;
/// Size of each file payload.
const FILE_SIZE: usize = 4 * 1024;

/// Build a set of (name, data) pairs for archive benchmarks.
fn build_entries() -> Vec<(String, Vec<u8>)> {
    (0..FILE_COUNT)
        .map(|i| {
            let name = format!("dir/file_{i:03}.txt");
            let data = helpers::generate_text_data(FILE_SIZE);
            (name, data)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// tar
// ---------------------------------------------------------------------------
#[cfg(feature = "tar")]
mod bench_tar {
    use super::*;
    use archive::archive::tar::{decode, encode};

    fn encode_tar(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut enc = encode::TarEncoder::new();
        for (name, data) in entries {
            enc.add_file(name, data);
        }
        enc.finish()
    }

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("tar");
        let entries = build_entries();
        let archive_bytes = encode_tar(&entries);

        g.throughput(Throughput::Bytes(archive_bytes.len() as u64));
        g.bench_with_input(BenchmarkId::new("encode", "50x4KiB"), &entries, |b, e| {
            b.iter(|| encode_tar(e));
        });
        g.bench_with_input(
            BenchmarkId::new("decode", "50x4KiB"),
            &archive_bytes,
            |b, data| {
                b.iter(|| decode::decode(data).unwrap());
            },
        );
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// cpio
// ---------------------------------------------------------------------------
#[cfg(feature = "cpio")]
mod bench_cpio {
    use super::*;
    use archive::archive::cpio::{decode, encode};

    fn encode_cpio(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut enc = encode::CpioEncoder::new();
        for (name, data) in entries {
            enc.add_file(name, data);
        }
        enc.finish()
    }

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("cpio");
        let entries = build_entries();
        let archive_bytes = encode_cpio(&entries);

        g.throughput(Throughput::Bytes(archive_bytes.len() as u64));
        g.bench_with_input(BenchmarkId::new("encode", "50x4KiB"), &entries, |b, e| {
            b.iter(|| encode_cpio(e));
        });
        g.bench_with_input(
            BenchmarkId::new("decode", "50x4KiB"),
            &archive_bytes,
            |b, data| {
                b.iter(|| decode::decode(data).unwrap());
            },
        );
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// ar
// ---------------------------------------------------------------------------
#[cfg(feature = "ar")]
mod bench_ar {
    use super::*;
    use archive::archive::ar::{decode, encode};

    fn encode_ar(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut enc = encode::ArEncoder::new();
        for (name, data) in entries {
            // ar member names have no directory component; use the filename only.
            let short_name = name.rsplit('/').next().unwrap_or(name);
            enc.add_file(short_name, data);
        }
        enc.finish().unwrap()
    }

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("ar");
        let entries = build_entries();
        let archive_bytes = encode_ar(&entries);

        g.throughput(Throughput::Bytes(archive_bytes.len() as u64));
        g.bench_with_input(BenchmarkId::new("encode", "50x4KiB"), &entries, |b, e| {
            b.iter(|| encode_ar(e));
        });
        g.bench_with_input(
            BenchmarkId::new("decode", "50x4KiB"),
            &archive_bytes,
            |b, data| {
                b.iter(|| decode::decode(data).unwrap());
            },
        );
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// zip
// ---------------------------------------------------------------------------
#[cfg(feature = "zip")]
mod bench_zip {
    use super::*;
    use archive::archive::zip::{decode, encode};

    fn encode_zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut enc = encode::ZipEncoder::new();
        for (name, data) in entries {
            enc.add_file(name, data);
        }
        enc.finish().unwrap()
    }

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("zip");
        let entries = build_entries();
        let archive_bytes = encode_zip(&entries);

        g.throughput(Throughput::Bytes(archive_bytes.len() as u64));
        g.bench_with_input(BenchmarkId::new("encode", "50x4KiB"), &entries, |b, e| {
            b.iter(|| encode_zip(e));
        });
        g.bench_with_input(
            BenchmarkId::new("decode", "50x4KiB"),
            &archive_bytes,
            |b, data| {
                b.iter(|| decode::decode(data).unwrap());
            },
        );
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------
#[cfg(feature = "sevenz")]
mod bench_sevenz {
    use super::*;
    use archive::archive::sevenz::{decode, encode};

    fn encode_sevenz(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut enc = encode::SevenZEncoder::new();
        for (name, data) in entries {
            enc.add_file(name, data);
        }
        enc.finish().unwrap()
    }

    pub fn bench(c: &mut Criterion) {
        let mut g = c.benchmark_group("7z");
        let entries = build_entries();
        let archive_bytes = encode_sevenz(&entries);

        g.throughput(Throughput::Bytes(archive_bytes.len() as u64));
        g.bench_with_input(BenchmarkId::new("encode", "50x4KiB"), &entries, |b, e| {
            b.iter(|| encode_sevenz(e));
        });
        g.bench_with_input(
            BenchmarkId::new("decode", "50x4KiB"),
            &archive_bytes,
            |b, data| {
                b.iter(|| decode::decode(data).unwrap());
            },
        );
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// Stubs for disabled features
// ---------------------------------------------------------------------------

macro_rules! bench_stub {
    ($mod:ident, $feat:literal) => {
        #[cfg(not(feature = $feat))]
        mod $mod {
            pub fn bench(_c: &mut criterion::Criterion) {}
        }
    };
}

bench_stub!(bench_tar, "tar");
bench_stub!(bench_cpio, "cpio");
bench_stub!(bench_ar, "ar");
bench_stub!(bench_zip, "zip");
bench_stub!(bench_sevenz, "sevenz");

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_tar::bench,
    bench_cpio::bench,
    bench_ar::bench,
    bench_zip::bench,
    bench_sevenz::bench,
);

criterion_main!(benches);
