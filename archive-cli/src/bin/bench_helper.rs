//! Internal helper for the cross-implementation benchmark harness.
//!
//! The helper reuses the CLI's production adapter dispatch and reports
//! timings measured around library calls only. Process startup, argument
//! parsing, and input-file reads happen before the timed region.
//!
//! This binary is intentionally not part of the user-facing CLI surface.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

use ::archive::compress as archive_compress;
use archive_cli::adapters::{read, write_archive, write_compress};
use archive_cli::detect::{ArchiveFormat, CompressionFormat};
use archive_cli::error::CliError;

#[derive(Debug, Parser)]
#[command(name = "archive-bench-helper", about = "Internal benchmark helper")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Time a codec encode or decode operation.
    Codec(CodecArgs),
    /// Time an archive pack or decode operation.
    Archive(ArchiveArgs),
    /// Print the supported helper format names.
    List,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CodecOp {
    Encode,
    Decode,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ArchiveOp {
    Encode,
    Decode,
}

#[derive(Debug, Parser)]
struct TimingArgs {
    /// Warmup iterations before sampling.
    #[arg(long, default_value_t = 1)]
    warmup: usize,
    /// Timed iterations.
    #[arg(long, default_value_t = 5)]
    iterations: usize,
}

#[derive(Debug, Parser)]
struct CodecArgs {
    #[arg(value_enum)]
    op: CodecOp,
    #[arg(long)]
    format: CompressionFormat,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Compression level when the format exposes one.
    #[arg(long)]
    level: Option<u8>,
    /// lrzip backend.
    #[arg(long)]
    backend: Option<String>,
    #[command(flatten)]
    timing: TimingArgs,
}

#[derive(Debug, Parser)]
struct ArchiveArgs {
    #[arg(value_enum)]
    op: ArchiveOp,
    #[arg(long)]
    format: ArchiveFormat,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Base directory for archive entry names.
    #[arg(long)]
    base_dir: Option<PathBuf>,
    #[command(flatten)]
    timing: TimingArgs,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code().into());
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Codec(args) => run_codec(args),
        Command::Archive(args) => run_archive(args),
        Command::List => {
            println!("{}", supported_formats_json());
            Ok(())
        }
    }
}

fn run_codec(args: CodecArgs) -> Result<(), CliError> {
    let input = fs::read(&args.input)?;
    let backend = args.backend.as_deref();

    match args.op {
        CodecOp::Encode => {
            let mut last = Vec::new();
            for _ in 0..args.timing.warmup {
                last = write_compress::compress_bytes(args.format, &input, args.level, backend)?;
            }
            let mut samples_ns = Vec::with_capacity(args.timing.iterations);
            for _ in 0..args.timing.iterations {
                let start = Instant::now();
                last = write_compress::compress_bytes(args.format, &input, args.level, backend)?;
                samples_ns.push(start.elapsed().as_nanos() as u64);
            }
            fs::write(&args.output, &last)?;
            print_json(json!({
                "mode": "codec",
                "op": "encode",
                "format": format_name(args.format),
                "input_len": input.len(),
                "output_len": last.len(),
                "warmup": args.timing.warmup,
                "samples_ns": samples_ns,
                "output_hash": fnv1a64(&last),
            }));
            Ok(())
        }
        CodecOp::Decode => {
            let path = Path::new(&args.input);
            let mut last = Vec::new();
            for _ in 0..args.timing.warmup {
                last = decode_codec(args.format, path, &input)?;
                std::hint::black_box(&last);
            }
            let mut samples_ns = Vec::with_capacity(args.timing.iterations);
            for _ in 0..args.timing.iterations {
                let start = Instant::now();
                last = decode_codec(args.format, path, &input)?;
                samples_ns.push(start.elapsed().as_nanos() as u64);
            }
            fs::write(&args.output, &last)?;
            print_json(json!({
                "mode": "codec",
                "op": "decode",
                "format": format_name(args.format),
                "input_len": input.len(),
                "output_len": last.len(),
                "warmup": args.timing.warmup,
                "samples_ns": samples_ns,
                "output_hash": fnv1a64(&last),
            }));
            Ok(())
        }
    }
}

fn run_archive(args: ArchiveArgs) -> Result<(), CliError> {
    match args.op {
        ArchiveOp::Encode => {
            let entries = write_archive::collect_entries(
                std::slice::from_ref(&args.input),
                args.base_dir.as_deref(),
            )?;
            let input_len = entries
                .iter()
                .filter_map(|entry| entry.data.as_ref().map(Vec::len))
                .sum::<usize>();
            let mut last = Vec::new();
            for _ in 0..args.timing.warmup {
                last = write_archive::pack_entries(args.format, &entries, None)?;
            }
            let mut samples_ns = Vec::with_capacity(args.timing.iterations);
            for _ in 0..args.timing.iterations {
                let start = Instant::now();
                last = write_archive::pack_entries(args.format, &entries, None)?;
                samples_ns.push(start.elapsed().as_nanos() as u64);
            }
            fs::write(&args.output, &last)?;
            print_json(json!({
                "mode": "archive",
                "op": "encode",
                "format": format_name_archive(args.format),
                "input_len": input_len,
                "entry_count": entries.len(),
                "output_len": last.len(),
                "warmup": args.timing.warmup,
                "samples_ns": samples_ns,
                "output_hash": fnv1a64(&last),
            }));
            Ok(())
        }
        ArchiveOp::Decode => {
            let input = fs::read(&args.input)?;
            let path = Path::new(&args.input);
            let mut last = Vec::new();
            for _ in 0..args.timing.warmup {
                let (_, payloads) =
                    read::decode_payloads(path, &input, format_of_archive(args.format), None)?;
                last = payloads;
                std::hint::black_box(&last);
            }
            let mut samples_ns = Vec::with_capacity(args.timing.iterations);
            for _ in 0..args.timing.iterations {
                let start = Instant::now();
                let (_, payloads) =
                    read::decode_payloads(path, &input, format_of_archive(args.format), None)?;
                last = payloads;
                samples_ns.push(start.elapsed().as_nanos() as u64);
            }
            let manifest = payload_manifest(&last);
            fs::write(&args.output, serde_json::to_vec_pretty(&manifest).unwrap())?;
            print_json(json!({
                "mode": "archive",
                "op": "decode",
                "format": format_name_archive(args.format),
                "input_len": input.len(),
                "output_len": last.iter().map(|payload| payload.data.len()).sum::<usize>(),
                "entry_count": last.len(),
                "warmup": args.timing.warmup,
                "samples_ns": samples_ns,
                "output_hash": manifest_hash(&manifest),
            }));
            Ok(())
        }
    }
}

fn decode_codec(format: CompressionFormat, path: &Path, input: &[u8]) -> Result<Vec<u8>, CliError> {
    // `Format::Zpaq` in the CLI dispatch means the journaling archive.
    // The compression helper writes a raw ZPAQ stream, so decode that
    // directly instead of routing through the archive reader.
    if matches!(format, CompressionFormat::Zpaq) {
        return archive_compress::zpaq::decode::decode(input)
            .map_err(|error| CliError::from_archive_error(error, false));
    }
    let (_, payloads) = read::decode_payloads(path, input, format_of(format), None)?;
    Ok(payloads
        .into_iter()
        .flat_map(|payload| payload.data)
        .collect())
}

fn payload_manifest(payloads: &[read::DecodedPayload]) -> Value {
    let entries: Vec<Value> = payloads
        .iter()
        .map(|payload| {
            json!({
                "name": payload.name,
                "len": payload.data.len(),
                "hash": fnv1a64(&payload.data),
            })
        })
        .collect();
    json!({ "entries": entries })
}

fn manifest_hash(manifest: &Value) -> u64 {
    let bytes = serde_json::to_vec(manifest).unwrap();
    fnv1a64(&bytes)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn supported_formats_json() -> Value {
    fn names<T: ValueEnum>() -> Vec<String> {
        T::value_variants()
            .iter()
            .filter_map(|value| {
                value
                    .to_possible_value()
                    .map(|name| name.get_name().to_owned())
            })
            .collect()
    }
    json!({
        "codec": names::<CompressionFormat>(),
        "archive": names::<ArchiveFormat>(),
    })
}

fn format_name(format: CompressionFormat) -> String {
    format.to_possible_value().unwrap().get_name().to_owned()
}

fn format_name_archive(format: ArchiveFormat) -> String {
    format.to_possible_value().unwrap().get_name().to_owned()
}

fn format_of(format: CompressionFormat) -> archive_cli::detect::Format {
    use archive_cli::detect::Format;
    match format {
        CompressionFormat::Gzip => Format::Gzip,
        CompressionFormat::Zstd => Format::Zstd,
        CompressionFormat::ZstdSeekable => Format::ZstdSeekable,
        CompressionFormat::Bzip2 => Format::Bzip2,
        CompressionFormat::Lzip => Format::Lzip,
        CompressionFormat::LzmaAlone => Format::LzmaAlone,
        CompressionFormat::Lzw => Format::Lzw,
        CompressionFormat::Lz4 => Format::Lz4,
        CompressionFormat::Lzo => Format::Lzo,
        CompressionFormat::Lrzip => Format::Lrzip,
        CompressionFormat::Rzip => Format::Rzip,
        CompressionFormat::Zlib => Format::Zlib,
        CompressionFormat::Snappy => Format::Snappy,
        CompressionFormat::Brotli => Format::Brotli,
        CompressionFormat::Deflate => Format::Deflate,
        CompressionFormat::Xz => Format::Xz,
        CompressionFormat::Zpaq => Format::Zpaq,
        CompressionFormat::Xpress => Format::Xpress,
        CompressionFormat::XpressHuff => Format::XpressHuff,
        CompressionFormat::Lznt1 => Format::Lznt1,
        CompressionFormat::Lzf => Format::Lzf,
        CompressionFormat::Fastlz => Format::Fastlz,
        CompressionFormat::Lzrw1 => Format::Lzrw1,
        CompressionFormat::Lzrw1a => Format::Lzrw1a,
        CompressionFormat::Lzrw2 => Format::Lzrw2,
        CompressionFormat::Lzrw3 => Format::Lzrw3,
        CompressionFormat::Lzrw3a => Format::Lzrw3a,
        CompressionFormat::Lzsa => Format::Lzsa,
        CompressionFormat::Lzsa2 => Format::Lzsa,
        CompressionFormat::Zx0 => Format::Zx0,
        CompressionFormat::Zx1 => Format::Zx1,
        CompressionFormat::Zx2 => Format::Zx2,
        CompressionFormat::Zx5 => Format::Zx5,
        CompressionFormat::Zx0b => Format::Zx0b,
        CompressionFormat::Zx1b => Format::Zx1b,
        CompressionFormat::Zx2b => Format::Zx2b,
        CompressionFormat::Zx5b => Format::Zx5b,
        CompressionFormat::Vcdiff => Format::Vcdiff,
        CompressionFormat::Mppc => Format::Mppc,
        CompressionFormat::Lzs => Format::Lzs,
        CompressionFormat::Lzxd => Format::Lzxd,
        CompressionFormat::Cmpsc => Format::Cmpsc,
    }
}

fn format_of_archive(format: ArchiveFormat) -> archive_cli::detect::Format {
    use archive_cli::detect::Format;
    match format {
        ArchiveFormat::Tar => Format::Tar,
        ArchiveFormat::Cpio => Format::Cpio,
        ArchiveFormat::Ar => Format::Ar,
        ArchiveFormat::Zpaq => Format::Zpaq,
        ArchiveFormat::Zip => Format::Zip,
        ArchiveFormat::SevenZ => Format::SevenZ,
        ArchiveFormat::Lha => Format::Lha,
        ArchiveFormat::Arj => Format::Arj,
        ArchiveFormat::Arc => Format::Arc,
        ArchiveFormat::GitPack => Format::GitPack,
        ArchiveFormat::Xar => Format::Xar,
    }
}

fn print_json(value: Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}
