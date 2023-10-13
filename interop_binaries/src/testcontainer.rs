//! Provides a testcontainer image to allow container-based testing of Janus.
//!
//! Images must be provided via environment variables. Use `cargo xtask test-docker` to build images
//! and provide them.

use std::env;
use testcontainers::{core::WaitFor, Image};

// Note that testcontainers always assembles image names in the format "$NAME:$TAG". Images will
// typically be provided as digests, of the form "sha256:$HASH". We will parse these into a 'name'
// and 'tag' by splitting on a colon, and then rely on testcontainers reassembling the full image
// name later.

fn parse_image(environment_variable_name: &str) -> Result<(String, String), env::VarError> {
    let image = env::var(environment_variable_name)?;
    match image.split_once(':') {
        Some((name, tag)) => Ok((name.to_owned(), tag.to_owned())),
        None => Ok((image, "latest".to_owned())),
    }
}

/// Represents a Janus Client as a testcontainer image.
#[non_exhaustive]
pub struct Client {
    name: String,
    tag: String,
}

impl Client {
    /// The internal port that the Client serves on.
    pub const INTERNAL_SERVING_PORT: u16 = 8080;
}

impl Default for Client {
    fn default() -> Self {
        let (name, tag) = parse_image("JANUS_INTEROP_CLIENT_IMAGE")
            .expect("the environment variable JANUS_INTEROP_CLIENT_IMAGE must be set");
        Self { name, tag }
    }
}

impl Image for Client {
    type Args = ();

    fn name(&self) -> String {
        self.name.clone()
    }

    fn tag(&self) -> String {
        self.tag.clone()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        Vec::new()
    }
}

/// Represents a Janus Aggregator as a testcontainer image.
#[non_exhaustive]
pub struct Aggregator {
    name: String,
    tag: String,
}

impl Aggregator {
    /// The internal port that the Aggregator serves on.
    pub const INTERNAL_SERVING_PORT: u16 = 8080;
}

impl Default for Aggregator {
    fn default() -> Self {
        let (name, tag) = parse_image("JANUS_INTEROP_AGGREGATOR_IMAGE")
            .expect("the environment variable JANUS_INTEROP_AGGREGATOR_IMAGE must be set");
        Self { name, tag }
    }
}

impl Image for Aggregator {
    type Args = ();

    fn name(&self) -> String {
        self.name.clone()
    }

    fn tag(&self) -> String {
        self.tag.clone()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        Vec::new()
    }
}

/// Represents a Janus Collector as a testcontainer image.
#[non_exhaustive]
pub struct Collector {
    name: String,
    tag: String,
}

impl Collector {
    /// The internal port that the Collector serves on.
    pub const INTERNAL_SERVING_PORT: u16 = 8080;
}

impl Default for Collector {
    fn default() -> Self {
        let (name, tag) = parse_image("JANUS_INTEROP_COLLECTOR_IMAGE")
            .expect("the environment variable JANUS_INTEROP_COLLECTOR_IMAGE must be set");
        Self { name, tag }
    }
}

impl Image for Collector {
    type Args = ();

    fn name(&self) -> String {
        self.name.clone()
    }

    fn tag(&self) -> String {
        self.tag.clone()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        Vec::new()
    }
}
