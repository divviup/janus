//! This crate contains functionality useful for Janus integration tests.

use std::{
    env::{self, VarError},
    path::PathBuf,
    str::FromStr,
};

#[cfg(feature = "daphne")]
pub mod daphne;
pub mod janus;

/// log_export_path returns the path to export container logs to, or None if container logs are not
/// configured to be exported.
///
/// The resulting value is based directly on the JANUS_E2E_LOGS_PATH environment variable.
fn log_export_path() -> Option<PathBuf> {
    match env::var("JANUS_E2E_LOGS_PATH") {
        Ok(logs_path) => Some(PathBuf::from_str(&logs_path).unwrap()),
        Err(VarError::NotPresent) => None,
        Err(err) => panic!("Failed to parse JANUS_E2E_LOGS_PATH: {err}"),
    }
}
