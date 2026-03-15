use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::detect::{ArchiveFormat, CompressionFormat, Format};

#[derive(Debug, Parser)]
#[command(
    name = "archive",
    version,
    about = "Inspect, test, list, extract, pack, and compress supported archive formats"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "List archive entries or summarize a single compressed payload")]
    List(ListCommand),
    #[command(about = "Extract an archive or restore a single compressed payload")]
    Extract(ExtractCommand),
    #[command(about = "Create a new archive from files or directories")]
    Pack(PackCommand),
    #[command(about = "Compress one file into a single-payload format")]
    Compress(CompressCommand),
    #[command(about = "Inspect detected format, scope notes, and entry metadata")]
    Inspect(InspectCommand),
    #[command(about = "Decode and verify an input without extracting it")]
    Test(TestCommand),
}

#[derive(Debug, Args)]
pub struct ListCommand {
    #[arg(help = "Input archive or compressed file to inspect")]
    pub input: PathBuf,
    #[arg(long, help = "Show size, mode, mtime, and extra metadata")]
    pub long: bool,
    #[arg(long, help = "Render entries as a tree view")]
    pub tree: bool,
    #[arg(long, help = "Emit machine-readable JSON instead of text")]
    pub json: bool,
    #[arg(long, help = "Password for encrypted zip/7z inputs")]
    pub password: Option<String>,
    #[arg(long, help = "Override automatic format detection")]
    pub format: Option<Format>,
    #[arg(long, help = "Disable pager (less) even when stdout is a terminal")]
    pub no_pager: bool,
}

#[derive(Debug, Args)]
pub struct ExtractCommand {
    #[arg(help = "Input archive or compressed file to extract")]
    pub input: PathBuf,
    #[arg(help = "Optional entry paths to extract from an archive")]
    pub paths: Vec<String>,
    #[arg(long, help = "Output directory for extracted files")]
    pub out: Option<PathBuf>,
    #[arg(long, help = "Overwrite existing files in the output directory")]
    pub overwrite: bool,
    #[arg(long, help = "Password for encrypted zip/7z inputs")]
    pub password: Option<String>,
    #[arg(long, help = "Override automatic format detection")]
    pub format: Option<Format>,
}

#[derive(Debug, Args)]
pub struct PackCommand {
    #[arg(help = "Archive format to create")]
    pub format: ArchiveFormat,
    #[arg(help = "Input files or directories to add to the archive")]
    pub input: Vec<PathBuf>,
    #[arg(short = 'o', long, help = "Output archive path")]
    pub output: PathBuf,
    #[arg(long, help = "Base directory used to derive stored entry paths")]
    pub base_dir: Option<PathBuf>,
    #[arg(long, help = "Overwrite an existing output archive")]
    pub overwrite: bool,
    #[arg(long, help = "Password for encrypted zip/7z output")]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct CompressCommand {
    #[arg(help = "Compression format to create")]
    pub format: CompressionFormat,
    #[arg(help = "Input file to compress")]
    pub input: PathBuf,
    #[arg(short = 'o', long, help = "Output compressed file path")]
    pub output: PathBuf,
    #[arg(long, help = "Compression level when the selected format exposes one")]
    pub level: Option<u8>,
    #[arg(long, help = "Backend selection for lrzip output")]
    pub backend: Option<String>,
}

#[derive(Debug, Args)]
pub struct InspectCommand {
    #[arg(help = "Input archive or compressed file to inspect")]
    pub input: PathBuf,
    #[arg(long, help = "Emit machine-readable JSON instead of text")]
    pub json: bool,
    #[arg(long, help = "Password for encrypted zip/7z inputs")]
    pub password: Option<String>,
    #[arg(long, help = "Override automatic format detection")]
    pub format: Option<Format>,
}

#[derive(Debug, Args)]
pub struct TestCommand {
    #[arg(help = "Input archive or compressed file to verify")]
    pub input: PathBuf,
    #[arg(long, help = "Emit machine-readable JSON instead of text")]
    pub json: bool,
    #[arg(long, help = "Password for encrypted zip/7z inputs")]
    pub password: Option<String>,
    #[arg(long, help = "Override automatic format detection")]
    pub format: Option<Format>,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};
    use crate::detect::{ArchiveFormat, CompressionFormat, Format};

    #[test]
    fn parse_inspect_command() {
        let cli = Cli::try_parse_from(["archive", "inspect", "sample.gz", "--json"]).unwrap();
        match cli.command {
            Command::Inspect(command) => {
                assert_eq!(command.input.to_string_lossy(), "sample.gz");
                assert!(command.json);
                assert!(command.format.is_none());
            }
            _ => panic!("expected inspect command"),
        }
    }

    #[test]
    fn parse_pack_command() {
        let cli =
            Cli::try_parse_from(["archive", "pack", "zip", "a.txt", "-o", "out.zip"]).unwrap();
        match cli.command {
            Command::Pack(command) => {
                assert_eq!(command.format, ArchiveFormat::Zip);
                assert_eq!(command.input.len(), 1);
            }
            _ => panic!("expected pack command"),
        }
    }

    #[test]
    fn parse_compress_command() {
        let cli =
            Cli::try_parse_from(["archive", "compress", "gzip", "a.txt", "-o", "out.gz"]).unwrap();
        match cli.command {
            Command::Compress(command) => {
                assert_eq!(command.format, CompressionFormat::Gzip);
                assert_eq!(command.input.to_string_lossy(), "a.txt");
            }
            _ => panic!("expected compress command"),
        }
    }

    #[test]
    fn parse_test_format_override() {
        let cli =
            Cli::try_parse_from(["archive", "test", "payload.bin", "--format", "deflate"]).unwrap();
        match cli.command {
            Command::Test(command) => assert_eq!(command.format, Some(Format::Deflate)),
            _ => panic!("expected test command"),
        }
    }

    #[test]
    fn parse_list_tree_command() {
        let cli = Cli::try_parse_from(["archive", "list", "sample.tar", "--tree"]).unwrap();
        match cli.command {
            Command::List(command) => {
                assert_eq!(command.input.to_string_lossy(), "sample.tar");
                assert!(command.tree);
            }
            _ => panic!("expected list command"),
        }
    }
}
