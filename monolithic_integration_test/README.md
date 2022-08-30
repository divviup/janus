# Integration Test Notes

## Daphne

The [Daphne](https://github.com/cloudflare/daphne) testing functionality is implemented by running a
compiled version of Daphne inside a container. The test container is built by this package's build
script based on the test Dockerfile in the Daphne repository; the test container is included in
necessary test binaries which know how to load the image into Docker themselves.

Daphne is compiled from commit [`e1b503eb2aefadfe2717abb0a359892848175534`](
https://github.com/cloudflare/daphne/commit/6228556c7b87a7fe85e414a3186a2511407896f0).

### Running Daphne integration tests

First, make sure your workstation is set up per the instructions in the repository root's README.md.

Then, run `cargo test` to run the Daphne integration tests.

### Updating the version of Daphne under test

To update the version of Daphne in use:

1. Update `Cargo.toml` in this directory to reference the new commit of Daphne.
1. Update `build.rs` in this directory to reference the new commit of Daphne.
1. Update this README to note the new commit of Daphne.

### Using a prebuilt Daphne

It is possible to instruct Janus' tests to use a prebuilt Docker image for the Janus/Daphne
integration tests, rather than building an image as part of the build process. To do this, set the
`DAPHNE_INTEROP_CONTAINER` environment variable to `prebuilt=${IMAGE_NAME}:${IMAGE_TAG}`. For
example, to use an image named `test_daphne` with the `latest` tag, set
`DAPHNE_INTEROP_CONTAINER=prebuilt=test_daphne:latest`.

To build a new Daphne image suitable for use as a prebuilt image, clone the [Daphne repository](
https://github.com/cloudflare/daphne), check out the commit of interest, and then run a command like
`docker build --file=daphne_worker_test/docker/miniflare.Dockerfile --tag=test_daphne:$(git rev-parse HEAD | head -c8) .`.
This command will generate an image named `test_daphne` tagged with a prefix of the git commit hash
used to generate it.

Note that even when using prebuilt container images, it is still important to match the image
version with the version of Daphne referenced by this package in `Cargo.toml`.