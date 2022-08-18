fn main() {
    #[cfg(feature = "daphne")]
    {
        use build_script_utils::save_zstd_compressed_docker_image;
        use std::{env, fs::File, process::Command};

        println!("cargo:rerun-if-changed=Dockerfile.test_daphne");

        // These directives should match the dependencies copied into Dockerfile.test_daphne.
        println!("cargo:rerun-if-changed=artifacts/wrangler.toml");
        println!("cargo:rerun-if-changed=artifacts/daphne_compiled/");

        // Build & save off a container image for the test Daphne instance.
        // Note: `docker build` has an `--output` flag which writes the output to somewhere, which
        // may be a tarfile. But `docker build --output` only exports the image filesystem, and not
        // any other image metadata (such as exposed ports, the entrypoint, etc), so we can't easily
        // use it.
        let build_output = Command::new("docker")
            .args(["build", "--file=Dockerfile.test_daphne", "--quiet", "."])
            .env("DOCKER_BUILDKIT", "1")
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

        // Make a best-effort attempt to clean up after ourselves.
        Command::new("docker")
            .args(["rmi", image_id])
            .status()
            .expect("Failed to execute `docker rmi` for test Daphne");
    }
}
