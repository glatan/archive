use std::fmt;
use std::io;

#[derive(Debug)]
pub enum CliError {
    Io(io::Error),
    Archive(archive::error::Error),
    Detect(String),
    Unsupported(String),
    Password(String),
}

impl CliError {
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Unsupported(_) => 2,
            Self::Password(_) => 3,
            Self::Io(_) | Self::Archive(_) | Self::Detect(_) => 1,
        }
    }

    pub fn from_archive_error(error: archive::error::Error, password_provided: bool) -> Self {
        match error {
            archive::error::Error::Unsupported(message) => Self::Unsupported(message.to_owned()),
            archive::error::Error::InvalidData(message)
                if is_password_error(message, password_provided) =>
            {
                Self::Password(message.to_owned())
            }
            other => Self::Archive(other),
        }
    }
}

fn is_password_error(message: &str, password_provided: bool) -> bool {
    message.contains("password") || (!password_provided && message.contains("encrypted"))
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Archive(error) => write!(f, "{error}"),
            Self::Detect(message) => write!(f, "{message}"),
            Self::Unsupported(message) => write!(f, "{message}"),
            Self::Password(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
