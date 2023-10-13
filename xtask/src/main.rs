use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::{
    collections::HashMap,
    env::{self},
    fs::File,
    process::Command,
};
use tempfile::tempdir;

#[derive(Parser)]
enum Subcommand {
    /// Build container images and run Docker-based integration tests
    TestDocker,
}

fn main() -> Result<()> {
    let subcommand = Subcommand::parse();
    match subcommand {
        Subcommand::TestDocker => test_docker()?,
    }
    Ok(())
}

fn test_docker() -> Result<()> {
    let images = build_container_images()?;
    run_docker_tests(images)?;
    Ok(())
}

#[derive(Deserialize)]
struct DockerBakeTargetMetadata {
    #[serde(rename = "containerimage.config.digest")]
    digest: String,
}

/// Janus interop test container image identifiers.
struct ContainerImages {
    client: String,
    aggregator: String,
    collector: String,
}

fn build_container_images() -> Result<ContainerImages> {
    let metadata_directory = tempdir()?;
    let metadata_file_path = metadata_directory.path().join("metadata.json");

    let status = Command::new("docker")
        .args([
            "buildx",
            "bake",
            "interop_binaries_small",
            "--load",
            "--metadata-file",
        ])
        .arg(&metadata_file_path)
        .status()?;

    if !status.success() {
        return Err(anyhow!("docker buildx bake failed"));
    }

    let file = File::open(&metadata_file_path)?;
    let metadata: HashMap<String, DockerBakeTargetMetadata> = serde_json::from_reader(file)?;

    let client = metadata
        .get("janus_interop_client_small")
        .context("missing metadata for janus_interop_client_small")?
        .digest
        .clone();
    let aggregator = metadata
        .get("janus_interop_aggregator_small")
        .context("missing metadata for janus_interop_aggregator_small")?
        .digest
        .clone();
    let collector = metadata
        .get("janus_interop_collector_small")
        .context("missing metadata for janus_interop_collector_small")?
        .digest
        .clone();

    Ok(ContainerImages {
        client,
        aggregator,
        collector,
    })
}

fn run_docker_tests(images: ContainerImages) -> Result<()> {
    let cargo_path = env::var_os("CARGO").context("CARGO environment variable was not set")?;
    let status = Command::new(cargo_path)
        .args([
            "test",
            "--package=janus_interop_binaries",
            "--package=janus_integration_tests",
            "--features=testcontainer",
        ])
        .envs([
            ("JANUS_INTEROP_CLIENT_IMAGE", &images.client),
            ("JANUS_INTEROP_AGGREGATOR_IMAGE", &images.aggregator),
            ("JANUS_INTEROP_COLLECTOR_IMAGE", &images.collector),
        ])
        .status()?;
    if !status.success() {
        return Err(anyhow!("cargo test exited with status code {status}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::Subcommand;
    use clap::CommandFactory;

    #[test]
    fn verify_app() {
        Subcommand::command().debug_assert();
    }
}
