FROM rust:1.61.0-alpine as builder
ARG BINARY=aggregator
RUN apk add libc-dev

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY janus /src/janus
COPY janus_client /src/janus_client
COPY janus_server /src/janus_server
COPY monolithic_integration_test /src/monolithic_integration_test
COPY test_util /src/test_util
COPY db/schema.sql /src/db/schema.sql
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --bin $BINARY --features=prometheus && cp /src/target/release/$BINARY /$BINARY

FROM alpine:3.16.0
ARG BINARY=aggregator
COPY --from=builder /src/db/schema.sql /db/schema.sql
COPY --from=builder /$BINARY /$BINARY
# Store the build argument in an environment variable so we can reference it
# from the ENTRYPOINT at runtime.
ENV BINARY=$BINARY
ENTRYPOINT ["/bin/sh", "-c", "exec /$BINARY \"$0\" \"$@\""]
