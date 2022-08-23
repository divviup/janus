fn main() {
    #[cfg(feature = "daphne")]
    {
        use build_script_utils::save_zstd_compressed_docker_image;
        use std::{env, fs::File, process::Command};
        use tempfile::tempdir;

        // This build script is self-contained, so we only need to rebuild if the build script
        // itself changes.
        println!("cargo:rerun-if-changed=build.rs");

        // Check out Daphne repository at a fixed hash, then build & save off a container image for
        // the test Daphne instance.
        const DAPHNE_COMMIT_HASH: &str = "6228556c7b87a7fe85e414a3186a2511407896f0";
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

        // Make a best-effort attempt to clean up after ourselves.
        Command::new("docker")
            .args(["rmi", image_id])
            .status()
            .expect("Failed to execute `docker rmi` for test Daphne");
    }
}
