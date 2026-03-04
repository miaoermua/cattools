/* src/error.rs */

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CatoolsError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[allow(dead_code)]
    #[error("UCI error: {0}")]
    UciError(String),

    #[allow(dead_code)]
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Command error: {0}")]
    CommandError(String),

    #[error("Dialog error: {0}")]
    DialogError(#[from] dialoguer::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CatoolsError>;
