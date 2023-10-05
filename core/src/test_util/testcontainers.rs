//! Testing functionality that interacts with the testcontainers library.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};
use testcontainers::{clients::Cli, core::WaitFor, Image};

/// Returns a container client, possibly shared with other callers to this function.
pub fn container_client() -> Arc<Cli> {
    // Once `Weak::new` is const in stable Rust, this should be replaced by a static variable
    // initialized to `Mutex::new(Weak::new())`. [https://github.com/rust-lang/rust/issues/95091]
    lazy_static::lazy_static! {
        static ref CONTAINER_CLIENT_MU: Mutex<Weak<Cli>> = Mutex::new(Weak::new());
    }

    let mut container_client = CONTAINER_CLIENT_MU.lock().unwrap();
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
}

impl Postgres {
    const NAME: &str = "postgres";
    const TAG: &str = "14-alpine";
}

impl Default for Postgres {
    fn default() -> Self {
        Self {
            env_vars: HashMap::from([
                ("POSTGRES_DB".to_owned(), "postgres".to_owned()),
                ("POSTGRES_HOST_AUTH_METHOD".to_owned(), "trust".to_owned()),
            ]),
        }
    }
}

impl Image for Postgres {
    type Args = ();

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
}
