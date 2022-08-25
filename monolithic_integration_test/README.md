# Integration Test Notes

## Daphne

The [Daphne](https://github.com/cloudflare/daphne) testing functionality is implemented by running a
compiled version of Daphne inside a container. The test container is built by this package's build
script based on the test Dockerfile in the Daphne repository; the test container is included in
necessary test binaries which know how to load the image into Docker themselves.

Daphne is compiled from commit [`6228556c7b87a7fe85e414a3186a2511407896f0`](
https://github.com/cloudflare/daphne/commit/6228556c7b87a7fe85e414a3186a2511407896f0).

### Running Daphne integration tests

First, make sure your workstation is set up per the instructions in the repository root's README.md.

Then, run `cargo test` to run the Daphne integration tests.

### Updating the version of Daphne under test

To update the version of Daphne in use:

1. Update `Cargo.toml` in this directory to reference the new commit of Daphne.
1. Update `build.rs` in this directory to reference the new commit of Daphne.
1. Update this README to note the new commit of Daphne.
