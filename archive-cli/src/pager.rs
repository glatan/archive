use std::io::{self, IsTerminal, Write};
use std::process::{Command, Stdio};

use crate::error::CliError;

/// Write `content` through a pager when stdout is a terminal.
///
/// Uses `$PAGER` if set, otherwise defaults to `less -FRX`.
/// Falls back to direct stdout write if the pager cannot be spawned.
pub fn write_with_pager(content: &str) -> Result<(), CliError> {
    let stdout = io::stdout();
    if !stdout.is_terminal() {
        return write_direct(content);
    }

    let (program, args) = pager_command();
    let child = Command::new(&program)
        .args(&args)
        .stdin(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(child) => child,
        Err(_) => return write_direct(content),
    };

    let write_result = if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(content.as_bytes())
    } else {
        return write_direct(content);
    };

    // Drop stdin so the pager sees EOF.
    drop(child.stdin.take());

    if let Err(err) = write_result {
        if err.kind() == io::ErrorKind::BrokenPipe {
            // User quit the pager early — not an error.
            let _ = child.wait();
            return Ok(());
        }
        let _ = child.wait();
        return Err(CliError::Io(err));
    }

    let _ = child.wait();
    Ok(())
}

fn write_direct(content: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    match stdout.write_all(content.as_bytes()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(CliError::Io(err)),
    }
}

fn pager_command() -> (String, Vec<String>) {
    pager_command_from(std::env::var("PAGER").ok().as_deref())
}

fn pager_command_from(pager: Option<&str>) -> (String, Vec<String>) {
    if let Some(pager) = pager {
        let parts: Vec<&str> = pager.split_whitespace().collect();
        if let Some((&program, args)) = parts.split_first() {
            return (
                program.to_owned(),
                args.iter().map(|s| (*s).to_owned()).collect(),
            );
        }
    }
    ("less".to_owned(), vec!["-FRX".to_owned()])
}

#[cfg(test)]
mod tests {
    use super::pager_command_from;

    #[test]
    fn parses_pager_program_and_arguments() {
        assert_eq!(
            pager_command_from(Some("less -FRX")),
            ("less".to_owned(), vec!["-FRX".to_owned()])
        );
        assert_eq!(
            pager_command_from(Some("more  -f")),
            ("more".to_owned(), vec!["-f".to_owned()])
        );
    }

    #[test]
    fn falls_back_to_less_for_unset_or_empty_pager() {
        assert_eq!(
            pager_command_from(None),
            ("less".to_owned(), vec!["-FRX".to_owned()])
        );
        assert_eq!(
            pager_command_from(Some("   ")),
            ("less".to_owned(), vec!["-FRX".to_owned()])
        );
    }
}
