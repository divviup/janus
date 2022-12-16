# `janus_client`
[![Build Status]][actions] [![latest version]][crates.io] [![docs badge]][docs.rs]

[Build Status]: https://github.com/divviup/janus/workflows/ci-build/badge.svg
[actions]: https://github.com/divviup/janus/actions?query=branch%3Amain
[latest version]: https://img.shields.io/crates/v/janus_client.svg
[crates.io]: https://crates.io/crates/janus_client
[docs badge]: https://img.shields.io/badge/docs.rs-rustdoc-green
[docs.rs]: https://docs.rs/janus_client/

`janus_client` is a self-contained implementation of the [Distributed Aggregation Protocol](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)'s client role. It is intended for use with [Janus](https://github.com/divviup/janus) and [Divvi Up](https://divviup.org), [ISRG](https://abetterinternet.org)'s privacy-respecting metrics service. `janus_client` is published to crates.io by a GitHub Action that runs when a `janus` release is created.
