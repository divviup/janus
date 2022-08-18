fn main() {
    #[cfg(feature = "daphne")]
    {
        use std::{env, process::Command};

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

        let save_output = Command::new("docker")
            .args([
                "save",
                &format!("--output={}/test_daphne.tar", env::var("OUT_DIR").unwrap()),
                image_id,
            ])
            .output()
            .expect("Failed to execute `docker save` for test Daphne");
        assert!(
            save_output.status.success(),
            "Docker save of test Daphne failed:\n{}",
            String::from_utf8_lossy(&build_output.stderr)
        );

        // Make a best-effort attempt to clean up after ourselves.
        let rmi_output = Command::new("docker")
            .args(["rmi", image_id])
            .output()
            .expect("Failed to execute `docker rmi` for test Daphne");
        assert!(
            rmi_output.status.success(),
            "Docker image removal of test Daphne failed:\n{}",
            String::from_utf8_lossy(&build_output.stderr)
        );
    }
}
