mod adapters;
mod args;
mod commands;
mod detect;
mod error;
mod output;
mod pager;

use std::process::ExitCode;

use clap::Parser;

use crate::args::{Cli, Command};
use crate::error::CliError;

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
        Command::List(command) => commands::list::run(command),
        Command::Extract(command) => commands::extract::run(command),
        Command::Pack(command) => commands::pack::run(command),
        Command::Compress(command) => commands::compress::run(command),
        Command::Inspect(command) => commands::inspect::run(command),
        Command::Test(command) => commands::test::run(command),
    }
}
