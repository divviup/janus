FROM rust:1.70.0-alpine AS chef
RUN apk add --no-cache libc-dev
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo install cargo-chef --version 0.1.60 && \
    rm -r $CARGO_HOME/registry
WORKDIR /src

FROM chef AS planner
COPY Cargo.toml Cargo.lock /src/
COPY aggregator /src/aggregator
COPY aggregator_api /src/aggregator_api
COPY aggregator_core /src/aggregator_core
COPY build_script_utils /src/build_script_utils
COPY client /src/client
COPY collector /src/collector
COPY core /src/core
COPY integration_tests /src/integration_tests
COPY interop_binaries /src/interop_binaries
COPY messages /src/messages
COPY tools /src/tools
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json /src/recipe.json
RUN cargo chef cook --release -p janus_aggregator --features=prometheus
COPY Cargo.toml Cargo.lock /src/
COPY aggregator /src/aggregator
COPY aggregator_api /src/aggregator_api
COPY aggregator_core /src/aggregator_core
COPY build_script_utils /src/build_script_utils
COPY client /src/client
COPY collector /src/collector
COPY core /src/core
COPY db /src/db
COPY integration_tests /src/integration_tests
COPY interop_binaries /src/interop_binaries
COPY messages /src/messages
COPY tools /src/tools
ARG BINARY=aggregator
ARG GIT_REVISION=unknown
ENV GIT_REVISION ${GIT_REVISION}
RUN cargo build --release -p janus_aggregator --bin $BINARY --features=prometheus

FROM alpine:3.18.0 AS final
ARG BINARY=aggregator
ARG GIT_REVISION=unknown
LABEL revision ${GIT_REVISION}
COPY --from=builder /src/target/release/$BINARY /$BINARY
# Store the build argument in an environment variable so we can reference it
# from the ENTRYPOINT at runtime.
ENV BINARY=$BINARY
ENTRYPOINT ["/bin/sh", "-c", "exec /$BINARY \"$0\" \"$@\""]
