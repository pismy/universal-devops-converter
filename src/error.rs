use std::fmt;

/// Every failure surfaced by the CLI. Kept flat on purpose: the tool has a
/// single job, so a deep error hierarchy would only add noise.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Bad options, unknown format id, category mismatch — anything the user
    /// can fix by changing the command line.
    #[error("{0}")]
    Config(String),

    /// The input could not be understood as the format it claims to be.
    #[error("cannot parse {format} input: {message}")]
    Parse { format: String, message: String },

    /// `--input-format auto` could not settle on a single format.
    #[error("cannot detect the input format: {0}")]
    Detect(String),

    /// `--strict` was set and the conversion would have lost information.
    #[error("conversion is lossy and --strict is set ({count} warning(s), see above)")]
    Strict { count: usize },
}

impl Error {
    pub fn config(msg: impl fmt::Display) -> Self {
        Error::Config(msg.to_string())
    }

    pub fn parse(format: impl fmt::Display, msg: impl fmt::Display) -> Self {
        Error::Parse {
            format: format.to_string(),
            message: msg.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
