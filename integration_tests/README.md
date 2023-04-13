# Integration Test Notes

## Daphne

The [Daphne](https://github.com/cloudflare/daphne) testing functionality is
implemented by running a containerized version of Daphne.

### Running Daphne integration tests

First, make sure your workstation is set up per the instructions in the
repository root's README.md.

Then, run `cargo test` to run the Daphne integration tests.

### Updating the version of Daphne under test

To update the version of Daphne in use, update the container image tag in
`integration_tests/src/daphne.rs`.
