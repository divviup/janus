FROM rust:1.62.1-alpine as builder
ARG BINARY=aggregator
# openssl-dev is required to compile Daphne, which uses OpenSSL for TLS.
RUN apk add libc-dev openssl-dev

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY janus_core /src/janus_core
COPY janus_client /src/janus_client
COPY janus_server /src/janus_server
COPY monolithic_integration_test /src/monolithic_integration_test
COPY db/schema.sql /src/db/schema.sql
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --bin $BINARY --features=prometheus && cp /src/target/release/$BINARY /$BINARY

FROM alpine:3.16.1
ARG BINARY=aggregator
COPY --from=builder /src/db/schema.sql /db/schema.sql
COPY --from=builder /$BINARY /$BINARY
# Store the build argument in an environment variable so we can reference it
# from the ENTRYPOINT at runtime.
ENV BINARY=$BINARY
ENTRYPOINT ["/bin/sh", "-c", "exec /$BINARY \"$0\" \"$@\""]
