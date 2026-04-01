use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvsGateError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("Authentication failed: wrong password")]
    AuthenticationFailed,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key expired: {key} (expired at {expired_at})")]
    KeyExpired { key: String, expired_at: String },

    #[error("FUSE error: {0}")]
    Fuse(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, EnvsGateError>;
