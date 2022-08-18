fn main() {
    // We only build the container image if the `testcontainer` feature is enabled, in order to
    // avoid infinite recursion in our build process (since building the container image builds this
    // package, among other things.)
    #[cfg(feature = "testcontainer")]
    {
        use std::{env, process::Command};

        println!("cargo:rerun-if-changed=../Dockerfile.interop_aggregator");

        // These directives should match the dependencies copied into Dockerfile.interop_aggregator.
        println!("cargo:rerun-if-changed=../Cargo.lock");
        println!("cargo:rerun-if-changed=../Cargo.toml");
        println!("cargo:rerun-if-changed=../db/schema.sql");
        println!("cargo:rerun-if-changed=../interop_binaries");
        println!("cargo:rerun-if-changed=../janus_core");
        println!("cargo:rerun-if-changed=../janus_client");
        println!("cargo:rerun-if-changed=../janus_server");
        println!("cargo:rerun-if-changed=../monolithic_integration_test");

        // Build & save off a container image for the interop_aggregator.
        // Note: `docker build` has an `--output` flag which writes the output to somewhere, which
        // may be a tarfile. But `docker build --output` only exports the image filesystem, and not
        // any other image metadata (such as exposed ports, the entrypoint, etc), so we can't easily
        // use it.
        let build_output = Command::new("docker")
            .args([
                "build",
                "--file=Dockerfile.interop_aggregator",
                "--quiet",
                ".",
            ])
            .current_dir("..")
            .env("DOCKER_BUILDKIT", "1")
            .output()
            .expect("Failed to execute `docker build` for interop aggregator");
        assert!(
            build_output.status.success(),
            "Docker build of interop aggregator failed:\n{}",
            String::from_utf8_lossy(&build_output.stderr)
        );
        let image_id = String::from_utf8(build_output.stdout).unwrap();
        let image_id = image_id.trim();

        let save_output = Command::new("docker")
            .args([
                "save",
                &format!(
                    "--output={}/interop_aggregator.tar",
                    env::var("OUT_DIR").unwrap()
                ),
                image_id,
            ])
            .output()
            .expect("Failed to execute `docker save` for interop aggregator");
        assert!(
            save_output.status.success(),
            "Docker save of interop_aggregator failed:\n{}",
            String::from_utf8_lossy(&build_output.stderr)
        );

        // Make a best-effort attempt to clean up after ourselves.
        Command::new("docker")
            .args(["rmi", image_id])
            .output()
            .expect("Failed to execute `docker rmi` for interop aggregator");
    }
}
