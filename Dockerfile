FROM rust:1.64.0-alpine as builder
ARG BINARY=aggregator
RUN apk add libc-dev protobuf-dev protoc
WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY build_script_utils /src/build_script_utils
COPY db /src/db
COPY integration_tests /src/integration_tests
COPY interop_binaries /src/interop_binaries
COPY janus_collector /src/janus_collector
COPY janus_core /src/janus_core
COPY janus_client /src/janus_client
COPY janus_messages /src/janus_messages
COPY janus_server /src/janus_server
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release -p janus_server --bin $BINARY --features=prometheus && cp /src/target/release/$BINARY /$BINARY

FROM alpine:3.16.2
ARG BINARY=aggregator
COPY --from=builder /src/db/schema.sql /db/schema.sql
COPY --from=builder /$BINARY /$BINARY
# Store the build argument in an environment variable so we can reference it
# from the ENTRYPOINT at runtime.
ENV BINARY=$BINARY
ENTRYPOINT ["/bin/sh", "-c", "exec /$BINARY \"$0\" \"$@\""]
