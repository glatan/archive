use crate::adapters::read;
use crate::args::TestCommand;
use crate::detect::{choose_format, scope_notes};
use crate::error::CliError;
use crate::output::{self, TestReport};

pub fn run(command: TestCommand) -> Result<(), CliError> {
    let input = std::fs::read(&command.input)?;
    let format = choose_format(&input, command.format)?;

    match read::analyze_bytes(&command.input, &input, format, command.password.as_deref()) {
        Ok(analysis) => {
            let report = TestReport {
                detected_format: format,
                ok: true,
                verified_checksums: analysis.verified_checksums,
                warnings: analysis.notes,
                failure: None,
            };
            output::print_test(&report, command.json)
        }
        Err(error) => {
            let report = TestReport {
                detected_format: format,
                ok: false,
                verified_checksums: false,
                warnings: scope_notes(format),
                failure: Some(error.to_string()),
            };
            output::print_test(&report, command.json)?;
            Err(error)
        }
    }
}
