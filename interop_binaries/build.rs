use std::env;

fn main() {
    // Skip running this build script for rust-analyzer.
    println!("cargo:rerun-if-env-changed=RUSTC_WRAPPER");
    if let Ok(rustc_wrapper) = env::var("RUSTC_WRAPPER") {
        if rustc_wrapper.ends_with("/rust-analyzer") {
            #[allow(clippy::needless_return)]
            return;
        }
    }

    // We only build the container image if the `testcontainer` feature is enabled, in order to
    // avoid infinite recursion in our build process (since building the container image builds this
    // crate, among other things.)
    #[cfg(feature = "testcontainer")]
    {
        use janus_build_script_utils::save_zstd_compressed_docker_image;
        use std::{fs::File, io::Read, process::Command};

        println!("cargo:rerun-if-env-changed=JANUS_INTEROP_CONTAINER");
        let container_strategy = env::var("JANUS_INTEROP_CONTAINER")
            .ok()
            .unwrap_or_else(|| "build".to_string());
        let out_dir = env::var("OUT_DIR").unwrap();

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
                println!("cargo:rerun-if-changed=../aggregator");
                println!("cargo:rerun-if-changed=../client");
                println!("cargo:rerun-if-changed=../core");
                println!("cargo:rerun-if-changed=../db");
                println!("cargo:rerun-if-changed=../integration_tests");
                println!("cargo:rerun-if-changed=../interop_binaries");
                println!("cargo:rerun-if-changed=../messages");

                // Build containers.
                // Note: `docker build` has an `--output` flag which writes the output to somewhere, which
                // may be a tarfile. But `docker build --output` only exports the image filesystem, and not
                // any other image metadata (such as exposed ports, the entrypoint, etc), so we can't easily
                // use it.
                let client_image_id = {
                    let image_id_file_name = format!("{out_dir}/janus_interop_client_image_id.txt");

                    let client_build_output = Command::new("docker")
                        .args([
                            "buildx",
                            "build",
                            "--file=Dockerfile.interop",
                            "--build-arg=PROFILE=small",
                            "--build-arg=BINARY=janus_interop_client",
                            "--load",
                            &format!("--iidfile={image_id_file_name}"),
                            &format!(
                                "--cache-from=type=gha,scope={}-interop-small",
                                env::var("GITHUB_REF_NAME").unwrap_or_else(|_| "main".to_string())
                            ),
                            ".",
                        ])
                        .current_dir("..")
                        .output()
                        .expect("Failed to execute `docker build` for interop client");
                    assert!(
                        client_build_output.status.success(),
                        "Docker build of interop client failed:\n{}",
                        String::from_utf8_lossy(&client_build_output.stderr)
                    );
                    let mut image_id = String::new();
                    File::open(image_id_file_name)
                        .expect("Failed to open image ID file")
                        .read_to_string(&mut image_id)
                        .expect("Failed to read image ID file");
                    image_id.trim().to_string()
                };

                let aggregator_image_id = {
                    let image_id_file_name =
                        format!("{out_dir}/janus_interop_aggregator_image_id.txt");

                    let aggregator_build_output = Command::new("docker")
                        .args([
                            "buildx",
                            "build",
                            "--file=Dockerfile.interop_aggregator",
                            "--build-arg=PROFILE=small",
                            "--load",
                            &format!("--iidfile={image_id_file_name}"),
                            &format!(
                                "--cache-from=type=gha,scope={}-interop-small",
                                env::var("GITHUB_REF_NAME").unwrap_or_else(|_| "main".to_string())
                            ),
                            ".",
                        ])
                        .current_dir("..")
                        .output()
                        .expect("Failed to execute `docker build` for interop aggregator");
                    assert!(
                        aggregator_build_output.status.success(),
                        "Docker build of interop aggregator failed:\n{}",
                        String::from_utf8_lossy(&aggregator_build_output.stderr)
                    );
                    let mut image_id = String::new();
                    File::open(image_id_file_name)
                        .expect("Failed to open image ID file")
                        .read_to_string(&mut image_id)
                        .expect("Failed to read image ID file");
                    image_id.trim().to_string()
                };

                let collector_image_id = {
                    let image_id_file_name =
                        format!("{out_dir}/janus_interop_collector_image_id.txt");

                    let collector_build_output = Command::new("docker")
                        .args([
                            "buildx",
                            "build",
                            "--file=Dockerfile.interop",
                            "--build-arg=PROFILE=small",
                            "--build-arg=BINARY=janus_interop_collector",
                            "--load",
                            &format!("--iidfile={image_id_file_name}"),
                            &format!(
                                "--cache-from=type=gha,scope={}-interop-small",
                                env::var("GITHUB_REF_NAME").unwrap_or_else(|_| "main".to_string())
                            ),
                            ".",
                        ])
                        .current_dir("..")
                        .output()
                        .expect("Failed to execute `docker build` for interop collector");
                    assert!(
                        collector_build_output.status.success(),
                        "Docker build of interop collector failed:\n{}",
                        String::from_utf8_lossy(&collector_build_output.stderr)
                    );
                    let mut image_id = String::new();
                    File::open(image_id_file_name)
                        .expect("Failed to open image ID file")
                        .read_to_string(&mut image_id)
                        .expect("Failed to read image ID file");
                    image_id.trim().to_string()
                };

                // Save off containers to disk.
                let client_image_file = File::create(format!("{out_dir}/interop_client.tar.zst"))
                    .expect("Couldn't create interop client image file");
                save_zstd_compressed_docker_image(&client_image_id, &client_image_file);
                client_image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(client_image_file);

                let aggregator_image_file =
                    File::create(format!("{out_dir}/interop_aggregator.tar.zst"))
                        .expect("Couldn't create interop aggregator image file");
                save_zstd_compressed_docker_image(&aggregator_image_id, &aggregator_image_file);
                aggregator_image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(aggregator_image_file);

                let collector_image_file =
                    File::create(format!("{out_dir}/interop_collector.tar.zst"))
                        .expect("Couldn't create interop collector image file");
                save_zstd_compressed_docker_image(&collector_image_id, &collector_image_file);
                collector_image_file
                    .sync_all()
                    .expect("Couldn't write compressed image file");
                drop(collector_image_file);

                // Make a best-effort attempt to clean up Docker's post-build state.
                Command::new("docker")
                    .args([
                        "image",
                        "rm",
                        &client_image_id,
                        &aggregator_image_id,
                        &collector_image_id,
                    ])
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
                    let image_file = File::create(format!("{out_dir}/{filename}.tar.zst"))
                        .expect("Couldn't create empty image file");
                    image_file
                        .sync_all()
                        .expect("Couldn't write empty image file");
                }
            }

            _ => panic!(
                "Unexpected JANUS_INTEROP_CONTAINER value {container_strategy:?} (valid values \
                 are \"build\" & \"skip\")"
            ),
        }
    }
}
