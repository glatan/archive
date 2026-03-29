use crate::adapters::write_archive;
use crate::args::PackCommand;
use crate::error::CliError;

pub fn run(command: PackCommand) -> Result<(), CliError> {
    write_archive::pack_inputs(command)
}
