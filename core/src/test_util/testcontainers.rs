//! Testing functionality that interacts with the testcontainers library.

use std::{
    collections::HashMap,
    process::Command,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use testcontainers::{clients::Cli, core::WaitFor, Image};

/// Returns a container client, possibly shared with other callers to this function.
pub fn container_client() -> Arc<Cli> {
    // Once `Weak::new` is const in stable Rust, in version 1.73, this should be replaced by a
    // static variable initialized to `Mutex::new(Weak::new())`.
    static CONTAINER_CLIENT_MU: OnceLock<Mutex<Weak<Cli>>> = OnceLock::new();

    let mut container_client = CONTAINER_CLIENT_MU
        .get_or_init(|| Mutex::new(Weak::new()))
        .lock()
        .unwrap();
    container_client.upgrade().unwrap_or_else(|| {
        let client = Arc::new(Cli::default());
        *container_client = Arc::downgrade(&client);
        client
    })
}

/// A [`testcontainers::Image`] that provides a Postgres server.
#[derive(Debug)]
pub struct Postgres {
    env_vars: HashMap<String, String>,
    entrypoint: Option<String>,
}

impl Postgres {
    const NAME: &'static str = "postgres";
    const TAG: &'static str = "15-alpine";

    fn build_environment() -> HashMap<String, String> {
        HashMap::from([
            ("POSTGRES_DB".to_owned(), "postgres".to_owned()),
            ("POSTGRES_HOST_AUTH_METHOD".to_owned(), "trust".to_owned()),
        ])
    }

    pub fn with_entrypoint(entrypoint: String) -> Self {
        Self {
            env_vars: Self::build_environment(),
            entrypoint: Some(entrypoint),
        }
    }
}

impl Default for Postgres {
    fn default() -> Self {
        Self {
            env_vars: Self::build_environment(),
            entrypoint: None,
        }
    }
}

impl Image for Postgres {
    type Args = Vec<String>;

    fn name(&self) -> String {
        Self::NAME.to_owned()
    }

    fn tag(&self) -> String {
        Self::TAG.to_owned()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        Vec::from([WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        )])
    }

    fn env_vars(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.env_vars.iter())
    }

    fn entrypoint(&self) -> Option<String> {
        self.entrypoint.clone()
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
