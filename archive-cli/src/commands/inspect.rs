use crate::adapters::read;
use crate::args::InspectCommand;
use crate::detect::choose_format;
use crate::error::CliError;
use crate::output;

pub fn run(command: InspectCommand) -> Result<(), CliError> {
    let input = std::fs::read(&command.input)?;
    let format = choose_format(&input, command.format)?;
    let report = read::inspect_path(&command.input, format, command.password.as_deref())?;
    output::print_inspect(&report, command.json)
}
