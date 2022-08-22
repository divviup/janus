fn main() {
    // We only build the container image if the `testcontainer` feature is enabled, in order to
    // avoid infinite recursion in our build process (since building the container image builds this
    // package, among other things.)
    #[cfg(feature = "testcontainer")]
    {
        use build_script_utils::save_zstd_compressed_docker_image;
        use std::{env, fs::File, process::Command};

        println!("cargo:rerun-if-env-changed=JANUS_INTEROP_CONTAINER");
        let container_strategy = env::var("JANUS_INTEROP_CONTAINER")
            .ok()
            .unwrap_or_else(|| "build".to_string());

        match container_strategy.as_str() {
            "build" => {
                // The "build" strategy causes us to build a container image based on the current
                // repository, and embed it in the test library.
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
                        "--build-arg",
                        "PROFILE=small",
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

                let image_file = File::create(format!(
                    "{}/interop_aggregator.tar.zst",
                    env::var("OUT_DIR").unwrap()
                ))
                .expect("Couldn't create interop aggregator image file");
                save_zstd_compressed_docker_image(image_id, &image_file);
                image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(image_file);

                // Make a best-effort attempt to clean up after ourselves.
                Command::new("docker")
                    .args(["rmi", image_id])
                    .status()
                    .expect("Failed to execute `docker rmi` for interop aggregator");
            }

            "skip" => {
                // The "skip" strategy causes us to skip building a container at all. Tests
                // depending on having the image available will fail.

                // We create an empty file since it's necessary for compilation to succeed; the
                // consumer (testcontainer.rs) will panic if someone attempts to instantiate a Janus
                // instance in this case.
                let image_file = File::create(format!(
                    "{}/interop_aggregator.tar.zst",
                    env::var("OUT_DIR").unwrap()
                ))
                .expect("Couldn't create interop aggregator image file");
                image_file.sync_all().expect("Couldn't write interop aggregator image file");
            }

            _ => panic!("Unexpected JANUS_INTEROP_CONTAINER value {container_strategy:?} (valid values are \"build\" & \"skip\")")
        }
    }
}
