use crate::adapters::extract;
use crate::args::ExtractCommand;
use crate::detect::choose_format;
use crate::error::CliError;

pub fn run(command: ExtractCommand) -> Result<(), CliError> {
    let input = std::fs::read(&command.input)?;
    let format = choose_format(&input, command.format)?;
    extract::extract_input(
        &command.input,
        &input,
        format,
        command.password.as_deref(),
        command.out.as_deref(),
        &command.paths,
        command.overwrite,
    )
}
