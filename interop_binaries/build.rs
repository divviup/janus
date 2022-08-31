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
                println!("cargo:rerun-if-changed=../Dockerfile.interop");
                println!("cargo:rerun-if-changed=../Dockerfile.interop_aggregator");

                // These directives should match the dependencies copied into the build stage in
                // Dockerfile.interop & Dockerfile.interop_aggregator.
                println!("cargo:rerun-if-changed=../Cargo.lock");
                println!("cargo:rerun-if-changed=../Cargo.toml");
                println!("cargo:rerun-if-changed=../db/schema.sql");
                println!("cargo:rerun-if-changed=../integration_tests");
                println!("cargo:rerun-if-changed=../interop_binaries");
                println!("cargo:rerun-if-changed=../janus_core");
                println!("cargo:rerun-if-changed=../janus_client");
                println!("cargo:rerun-if-changed=../janus_server");

                // Build containers.
                // Note: `docker build` has an `--output` flag which writes the output to somewhere, which
                // may be a tarfile. But `docker build --output` only exports the image filesystem, and not
                // any other image metadata (such as exposed ports, the entrypoint, etc), so we can't easily
                // use it.
                let client_image_id = {
                    let client_build_output = Command::new("docker")
                        .args([
                            "build",
                            "--quiet",
                            "--file=Dockerfile.interop",
                            "--build-arg=PROFILE=small",
                            "--build-arg=BINARY=janus_interop_client",
                            ".",
                        ])
                        .current_dir("..")
                        .env("DOCKER_BUILDKIT", "1")
                        .output()
                        .expect("Failed to execute `docker build` for interop client");
                    assert!(
                        client_build_output.status.success(),
                        "Docker build of interop client failed:\n{}",
                        String::from_utf8_lossy(&client_build_output.stderr)
                    );
                    String::from_utf8(client_build_output.stdout).unwrap().trim().to_string()
                };

                let aggregator_image_id = {
                    let aggregator_build_output = Command::new("docker")
                        .args([
                            "build",
                            "--quiet",
                            "--file=Dockerfile.interop_aggregator",
                            "--build-arg=PROFILE=small",
                            ".",
                        ])
                        .current_dir("..")
                        .env("DOCKER_BUILDKIT", "1")
                        .output()
                        .expect("Failed to execute `docker build` for interop aggregator");
                    assert!(
                        aggregator_build_output.status.success(),
                        "Docker build of interop aggregator failed:\n{}",
                        String::from_utf8_lossy(&aggregator_build_output.stderr)
                    );
                    String::from_utf8(aggregator_build_output.stdout).unwrap().trim().to_string()
                };

                let collector_image_id = {
                    let collector_build_output = Command::new("docker")
                        .args([
                            "build",
                            "--quiet",
                            "--file=Dockerfile.interop",
                            "--build-arg=PROFILE=small",
                            "--build-arg=BINARY=janus_interop_collector",
                            "."
                        ])
                        .current_dir("..")
                        .env("DOCKER_BUILDKIT", "1")
                        .output()
                        .expect("Failed to execute `docker build` for interop collector");
                    assert!(
                        collector_build_output.status.success(),
                        "Docker build of interop collector failed:\n{}",
                        String::from_utf8_lossy(&collector_build_output.stderr)
                    );
                    String::from_utf8(collector_build_output.stdout).unwrap().trim().to_string()
                };

                // Save off containers to disk.
                let client_image_file = File::create(format!(
                    "{}/interop_client.tar.zst",
                    env::var("OUT_DIR").unwrap()
                ))
                .expect("Couldn't create interop client image file");
                save_zstd_compressed_docker_image(&client_image_id, &client_image_file);
                client_image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(client_image_file);

                let aggregator_image_file = File::create(format!(
                    "{}/interop_aggregator.tar.zst",
                    env::var("OUT_DIR").unwrap()
                ))
                .expect("Couldn't create interop aggregator image file");
                save_zstd_compressed_docker_image(&aggregator_image_id, &aggregator_image_file);
                aggregator_image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(aggregator_image_file);

                let collector_image_file = File::create(format!(
                    "{}/interop_collector.tar.zst",
                    env::var("OUT_DIR").unwrap()
                ))
                .expect("Couldn't create interop collector image file");
                save_zstd_compressed_docker_image(&collector_image_id, &collector_image_file);
                collector_image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(collector_image_file);

                // Make a best-effort attempt to clean up Docker's post-build state.
                Command::new("docker")
                    .args(["image", "rm", &client_image_id, &aggregator_image_id, &collector_image_id])
                    .status()
                    .expect("Failed to execute `docker image remove`");
            }

            "skip" => {
                // The "skip" strategy causes us to skip building containers at all. Tests which
                // depend on having interop test images available will fail.

                // We create empty image files since these files are required for compilation to
                // succeed; the consumer (testcontainer.rs) will panic if someone attempts to
                // instantiate a container in this case.
                for filename in ["interop_client", "interop_aggregator", "interop_collector"] {
                    let image_file = File::create(format!(
                        "{}/{filename}.tar.zst",
                        env::var("OUT_DIR").unwrap()
                    ))
                    .expect("Couldn't create empty image file");
                    image_file.sync_all().expect("Couldn't write empty image file");
                }
            }

            _ => panic!("Unexpected JANUS_INTEROP_CONTAINER value {container_strategy:?} (valid values are \"build\" & \"skip\")")
        }
    }
}
