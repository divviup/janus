use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env::{self},
    fs::File,
    process::Command,
};
use tempfile::tempdir;

/// Command line arguments that will get passed through to Cargo.
#[derive(Args)]
struct CargoArgs {
    /// Build artifacts with the specified profile
    #[clap(long)]
    profile: Option<String>,

    /// Require Cargo.lock is up to date
    #[clap(long, action)]
    locked: bool,
}

#[derive(Parser)]
enum Subcommand {
    /// Build container images for use in Docker-based integration tests
    BuildDocker,

    /// Build container images and run Docker-based integration tests
    TestDocker {
        #[clap(flatten)]
        cargo_args: CargoArgs,
    },

    /// Run Docker-based integration tests with a provided set of container images
    TestDockerWithImages {
        #[clap(flatten)]
        images: ContainerImages,

        #[clap(flatten)]
        cargo_args: CargoArgs,
    },
}

fn main() -> Result<()> {
    let subcommand = Subcommand::parse();
    match subcommand {
        Subcommand::BuildDocker => {
            let images = build_container_images()?;
            println!("{images:#?}");
        }
        Subcommand::TestDocker { cargo_args } => test_docker(cargo_args)?,
        Subcommand::TestDockerWithImages { images, cargo_args } => {
            run_docker_tests(images, cargo_args)?
        }
    }
    Ok(())
}

fn test_docker(cargo_args: CargoArgs) -> Result<()> {
    let images = build_container_images()?;
    run_docker_tests(images, cargo_args)?;
    Ok(())
}

#[derive(Deserialize)]
struct DockerBakeTargetMetadata {
    #[serde(rename = "containerimage.config.digest")]
    digest: String,
}

/// Janus interop test container image identifiers.
#[derive(Args, Debug)]
struct ContainerImages {
    /// Container image for janus_interop_client
    client: String,
    /// Container image for janus_interop_aggregator
    aggregator: String,
    /// Container image for janus_interop_collector
    collector: String,
}

fn build_container_images() -> Result<ContainerImages> {
    let metadata_directory = tempdir()?;
    let metadata_file_path = metadata_directory.path().join("metadata.json");

    let status = Command::new("docker")
        .args([
            "buildx",
            "bake",
            "interop_binaries_ci",
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
        .get("janus_interop_client_ci")
        .context("missing metadata for janus_interop_client_ci")?
        .digest
        .clone();
    let aggregator = metadata
        .get("janus_interop_aggregator_ci")
        .context("missing metadata for janus_interop_aggregator_ci")?
        .digest
        .clone();
    let collector = metadata
        .get("janus_interop_collector_ci")
        .context("missing metadata for janus_interop_collector_ci")?
        .digest
        .clone();

    Ok(ContainerImages {
        client,
        aggregator,
        collector,
    })
}

fn run_docker_tests(images: ContainerImages, cargo_args: CargoArgs) -> Result<()> {
    let cargo_path = env::var_os("CARGO").context("CARGO environment variable was not set")?;
    let mut command = Command::new(cargo_path);
    command.arg("test");
    if let Some(profile) = cargo_args.profile {
        command.arg(format!("--profile={profile}"));
    }
    if cargo_args.locked {
        command.arg("--locked");
    }
    command.args([
        "--package=janus_interop_binaries",
        "--package=janus_integration_tests",
        "--features=testcontainer",
    ]);
    command.envs([
        ("JANUS_INTEROP_CLIENT_IMAGE", &images.client),
        ("JANUS_INTEROP_AGGREGATOR_IMAGE", &images.aggregator),
        ("JANUS_INTEROP_COLLECTOR_IMAGE", &images.collector),
    ]);
    let status = command.status()?;
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
