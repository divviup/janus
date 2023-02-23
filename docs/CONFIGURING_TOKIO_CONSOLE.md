# Monitoring with `tokio-console`

Optional support is included to monitor the async runtime using `tokio-console`.
When enabled, a separate tracing subscriber will be installed to monitor when
the async runtime polls tasks, and expose that information to diagnostic tools
via a gRPC server. Currently, this requires both changes to the aggregator
configuration and to the build flags used at compilation. Add a stanza similar
to the following to the configuration file.

```yaml
logging_config:
  tokio_console_config:
    enabled: true
    listen_address: 127.0.0.1:6669
```

Compile with the `tokio-console` feature enabled, and provide the flag `--cfg
tokio_unstable` to `rustc`, as follows. (If `tokio-console` support is enabled
in a build without the `tokio_unstable` flag, the server will panic upon
startup)

```bash
RUSTFLAGS="--cfg tokio_unstable" CARGO_TARGET_DIR=target/tokio_unstable cargo build --features tokio-console
```

Install `tokio-console`, run the server, and run `tokio-console
http://127.0.0.1:6669` to connect to it and monitor tasks.
