use crate::args::ListCommand;
use crate::detect::choose_format;
use crate::error::CliError;
use crate::{adapters::read, output};

pub fn run(command: ListCommand) -> Result<(), CliError> {
    if command.tree && command.json {
        return Err(CliError::Unsupported(
            "`archive list --tree` is human-readable only; use plain `--json` without `--tree`"
                .to_owned(),
        ));
    }
    let input = std::fs::read(&command.input)?;
    let format = choose_format(&input, command.format)?;
    let report = read::list_bytes(&command.input, &input, format, command.password.as_deref())?;
    output::print_list(
        &report,
        command.long,
        command.tree,
        command.json,
        !command.no_pager,
    )
}
