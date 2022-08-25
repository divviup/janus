//! This crate contains functionality useful for Janus integration tests.

#[cfg(feature = "daphne")]
pub mod daphne;
pub mod janus;

lazy_static::lazy_static! {
    static ref CONTAINER_CLIENT: testcontainers::clients::Cli =
        testcontainers::clients::Cli::default();
}
