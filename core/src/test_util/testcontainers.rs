//! Testing functionality that interacts with the testcontainers library.

use std::collections::HashMap;
use testcontainers::{core::WaitFor, Image};

/// A [`testcontainers::Image`] that provides a Postgres server.
#[derive(Debug)]
pub struct Postgres {
    env_vars: HashMap<String, String>,
}

impl Postgres {
    const NAME: &'static str = "postgres";
    const TAG: &'static str = "14-alpine";
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
