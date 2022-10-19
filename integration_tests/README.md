# Integration Test Notes

## Daphne

Note: The Daphne integration test has been temporarily disabled to accommodate implementation of
DAP-02 and upgrading [`hpke`](https://crates.io/crates/hpke) to version 0.10.0.

The [Daphne](https://github.com/cloudflare/daphne) testing functionality is implemented by running a
compiled version of Daphne inside a container. The test container is built by this package's build
script based on the test Dockerfile in the Daphne repository; the test container is included in
necessary test binaries which know how to load the image into Docker themselves.

Daphne is compiled from commit [`80b53c4b0f2c93d5f9df66dfce237b20756c9147`](
https://github.com/cloudflare/daphne/commit/80b53c4b0f2c93d5f9df66dfce237b20756c9147).

### Running Daphne integration tests

First, make sure your workstation is set up per the instructions in the repository root's README.md.

Then, run `cargo test` to run the Daphne integration tests.

### Updating the version of Daphne under test

To update the version of Daphne in use:

1. Update `Cargo.toml` in this directory to reference the new commit of Daphne.
1. Update `build.rs` in this directory to reference the new commit of Daphne.
1. Update this README to note the new commit of Daphne.
1. If using a prebuilt Daphne image, rebuild it as described below.

### Using a prebuilt Daphne

It is possible to instruct Janus' tests to use a prebuilt Docker image for the Janus/Daphne
integration tests, rather than building an image as part of the build process. To do this, set the
`DAPHNE_INTEROP_CONTAINER` environment variable to `prebuilt=${IMAGE_NAME}:${IMAGE_TAG}`. For
example, to use an image named `test_daphne` with the `latest` tag, set
`DAPHNE_INTEROP_CONTAINER=prebuilt=test_daphne:latest`.

To build a new Daphne image suitable for use as a prebuilt image, clone the [Daphne repository](
https://github.com/cloudflare/daphne), check out the commit of interest, and then run a command like
`docker build --file=daphne_worker_test/docker/miniflare.Dockerfile --tag=test_daphne:$(git rev-parse --short=8 HEAD) .`.
This command will generate an image named `test_daphne` tagged with a prefix of the git commit hash
used to generate it.

Note that even when using prebuilt container images, it is still important to match the image
version with the version of Daphne referenced by this package in `Cargo.toml`.
