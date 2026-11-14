use thiserror::Error;

/// Errors raised by the core crate. Messages never contain field values, so they are safe
/// to log.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid event: {0}")]
    Invalid(String),
    #[error("timestamp out of range")]
    TimestampOutOfRange,
    #[error("text field too long to encode")]
    FieldTooLong,
    #[error("detector pattern failed to compile: {0}")]
    Pattern(#[from] regex::Error),
}
