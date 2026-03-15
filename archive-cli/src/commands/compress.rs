use crate::adapters::write_compress;
use crate::args::CompressCommand;
use crate::error::CliError;

pub fn run(command: CompressCommand) -> Result<(), CliError> {
    write_compress::compress_input(command)
}
