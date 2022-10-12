fn main() {
    #[cfg(feature = "daphne")]
    {
        use janus_build_script_utils::save_zstd_compressed_docker_image;
        use serde_json::json;
        use std::{env, fs::File, process::Command};
        use tempfile::tempdir;

        // This build script is self-contained, so we only need to rebuild if the build script
        // itself or one of its inputs changes.
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-env-changed=DAPHNE_INTEROP_CONTAINER");

        let container_strategy = env::var("DAPHNE_INTEROP_CONTAINER")
            .ok()
            .unwrap_or_else(|| "build".to_string());

        if container_strategy == "build" {
            // Check out Daphne repository at a fixed hash, then build & save off a container image for
            // the test Daphne instance.
            const DAPHNE_COMMIT_HASH: &str = "80b53c4b0f2c93d5f9df66dfce237b20756c9147";
            let daphne_checkout_dir = tempdir().unwrap();
            let clone_output = Command::new("git")
                .args(["clone", "-n", "https://github.com/cloudflare/daphne", "."])
                .current_dir(&daphne_checkout_dir)
                .output()
                .expect("Failed to execute `git clone` for Daphne repository");
            assert!(
                clone_output.status.success(),
                "Git clone of Daphne repository failed:\n{}",
                String::from_utf8_lossy(&clone_output.stderr)
            );
            let checkout_output = Command::new("git")
                .args(["checkout", DAPHNE_COMMIT_HASH])
                .current_dir(&daphne_checkout_dir)
                .output()
                .expect("Failed to execute `git checkout` for Daphne repository");
            assert!(
                checkout_output.status.success(),
                "Git checkout of Daphne repository failed:\n{}",
                String::from_utf8_lossy(&checkout_output.stderr)
            );

            // Note: `docker build` has an `--output` flag which writes the output to somewhere, which
            // may be a tarfile. But `docker build --output` only exports the image filesystem, and not
            // any other image metadata (such as exposed ports, the entrypoint, etc), so we can't easily
            // use it.
            let build_output = Command::new("docker")
                .args([
                    "build",
                    "--file=daphne_worker_test/docker/miniflare.Dockerfile",
                    "--quiet",
                    ".",
                ])
                .current_dir(&daphne_checkout_dir)
                .output()
                .expect("Failed to execute `docker build` for test Daphne");
            assert!(
                build_output.status.success(),
                "Docker build of test Daphne failed:\n{}",
                String::from_utf8_lossy(&build_output.stderr)
            );
            let image_id = String::from_utf8(build_output.stdout).unwrap();
            let image_id = image_id.trim();

            let image_file = File::create(format!(
                "{}/test_daphne.tar.zst",
                env::var("OUT_DIR").unwrap()
            ))
            .expect("Couldn't create test Daphne image file");
            save_zstd_compressed_docker_image(image_id, &image_file);
            image_file
                .sync_all()
                .expect("Couldn't write compressed image file");
            drop(image_file);

            // Write metadata file instructing runtime to reference the container we built.
            let metadata_file = File::create(format!(
                "{}/test_daphne.metadata",
                env::var("OUT_DIR").unwrap()
            ))
            .expect("Couldn't create test Daphne metadata file");
            serde_json::to_writer(&metadata_file, &json!({"strategy": "build"}))
                .expect("Couldn't write metadata file");
            metadata_file
                .sync_all()
                .expect("Couldn't write metadata file");
            drop(metadata_file);

            // Make a best-effort attempt to clean up after ourselves.
            Command::new("docker")
                .args(["image", "remove", image_id])
                .status()
                .expect("Failed to execute `docker image remove` for test Daphne");
        } else if container_strategy.starts_with("prebuilt=") {
            let (image_name, image_tag) = container_strategy
                .strip_prefix("prebuilt=")
                .unwrap()
                .split_once(':')
                .unwrap();

            // Write empty image file (required for compilation to succeed).
            let image_file = File::create(format!(
                "{}/test_daphne.tar.zst",
                env::var("OUT_DIR").unwrap()
            ))
            .expect("Couldn't create test Daphne image file");
            image_file
                .sync_all()
                .expect("Couldn't write compressed image file");
            drop(image_file);

            // Write metadata file instructing runtime to reference our prebuilt container.
            let metadata_file = File::create(format!(
                "{}/test_daphne.metadata",
                env::var("OUT_DIR").unwrap()
            ))
            .expect("Couldn't create test Daphne metadata file");
            serde_json::to_writer(
                &metadata_file,
                &json!({
                    "strategy": "prebuilt",
                    "image_name": image_name,
                    "image_tag": image_tag,
                }),
            )
            .expect("Couldn't write metadata file");
            metadata_file
                .sync_all()
                .expect("Couldn't write metadata file");
            drop(metadata_file);
        } else if container_strategy == "skip" {
            // The "skip" strategy causes us to skip building a container at all. Tests which
            // depend on having Daphne interop test images available will fail.

            // Write empty image file (required for compilation to succeed).
            let image_file = File::create(format!(
                "{}/test_daphne.tar.zst",
                env::var("OUT_DIR").unwrap()
            ))
            .expect("Couldn't create test Daphne image file");
            image_file
                .sync_all()
                .expect("Couldn't write compressed image file");
            drop(image_file);

            // Write metadata file instructing runtime that we skipped the container build (which
            // will cause anyone attempting to instantiate the container to panic).
            let metadata_file = File::create(format!(
                "{}/test_daphne.metadata",
                env::var("OUT_DIR").unwrap()
            ))
            .expect("Couldn't create test Daphne metadata file");
            serde_json::to_writer(&metadata_file, &json!({"strategy": "skip"}))
                .expect("Couldn't write metadata file");
            metadata_file
                .sync_all()
                .expect("Couldn't write metadata file");
            drop(metadata_file);
        } else {
            panic!("Unexpected DAPHNE_INTEROP_CONTAINER value {container_strategy:?} (valid values are \"build\", \"prebuilt=image_name:image_tag\", & \"skip\")")
        }
    }
}
