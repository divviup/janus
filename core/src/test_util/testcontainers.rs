//! Testing functionality that interacts with the testcontainers library.

use std::{borrow::Cow, process::Command};
use testcontainers::{core::WaitFor, Image};

/// A [`testcontainers::Image`] that provides a Postgres server.
#[derive(Debug, Default)]
pub struct Postgres {
    entrypoint: Option<String>,
}

impl Postgres {
    const NAME: &'static str = "postgres";
    const TAG: &'static str = "15-alpine";

    pub fn with_entrypoint(entrypoint: String) -> Self {
        Self {
            entrypoint: Some(entrypoint),
        }
    }
}

impl Image for Postgres {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn tag(&self) -> &str {
        Self::TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        Vec::from([WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        )])
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        [
            ("POSTGRES_DB", "postgres"),
            ("POSTGRES_HOST_AUTH_METHOD", "trust"),
        ]
    }

    fn entrypoint(&self) -> Option<&str> {
        self.entrypoint.as_deref()
    }
}

/// A temporary Docker volume. The volume will be cleaned up on drop.
pub struct Volume {
    name: String,
}

impl Volume {
    pub fn new() -> Self {
        let output = Command::new("docker")
            .args(["volume", "create"])
            .output()
            .expect("failed to create docker volume");
        assert!(
            output.status.success(),
            "failed to create docker volume: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let name = String::from_utf8(output.stdout)
            .expect("could not decode docker output")
            .trim()
            .to_owned();
        Self { name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Default for Volume {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        let output = Command::new("docker")
            .args(["volume", "rm", &self.name])
            .output()
            .expect("failed to delete docker volume");
        assert!(
            output.status.success(),
            "failed to delete docker volume: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
