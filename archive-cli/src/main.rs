use std::process::ExitCode;

use clap::Parser;

use archive_cli::args::{Cli, Command};
use archive_cli::error::CliError;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::List(command) => archive_cli::commands::list::run(command),
        Command::Extract(command) => archive_cli::commands::extract::run(command),
        Command::Pack(command) => archive_cli::commands::pack::run(command),
        Command::Compress(command) => archive_cli::commands::compress::run(command),
        Command::Inspect(command) => archive_cli::commands::inspect::run(command),
        Command::Test(command) => archive_cli::commands::test::run(command),
    }
}
