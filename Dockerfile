FROM rust:1.80.1-alpine AS chef
ENV CARGO_INCREMENTAL=0
RUN apk add --no-cache libc-dev cmake make
RUN cargo install cargo-chef --version 0.1.60 && \
    rm -r $CARGO_HOME/registry
WORKDIR /src

FROM chef AS planner
COPY Cargo.toml Cargo.lock /src/
COPY aggregator /src/aggregator
COPY aggregator_api /src/aggregator_api
COPY aggregator_core /src/aggregator_core
COPY client /src/client
COPY collector /src/collector
COPY core /src/core
COPY integration_tests /src/integration_tests
COPY interop_binaries /src/interop_binaries
COPY messages /src/messages
COPY tools /src/tools
COPY xtask /src/xtask
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json /src/recipe.json
RUN cargo chef cook --release -p janus_aggregator --features=prometheus,otlp
COPY Cargo.toml Cargo.lock /src/
COPY aggregator /src/aggregator
COPY aggregator_api /src/aggregator_api
COPY aggregator_core /src/aggregator_core
COPY client /src/client
COPY collector /src/collector
COPY core /src/core
COPY db /src/db
COPY integration_tests /src/integration_tests
COPY interop_binaries /src/interop_binaries
COPY messages /src/messages
COPY tools /src/tools
COPY xtask /src/xtask
ARG GIT_REVISION=unknown
ENV GIT_REVISION ${GIT_REVISION}
RUN cargo build --release -p janus_aggregator --features=prometheus,otlp

FROM alpine:3.20.2 AS final
ARG BINARY=aggregator
ARG GIT_REVISION=unknown
LABEL revision=${GIT_REVISION}
COPY --from=builder /src/target/release/janus_aggregator /janus_aggregator
RUN ln -s /janus_aggregator /aggregator && \
    ln -s /janus_aggregator /garbage_collector && \
    ln -s /janus_aggregator /aggregation_job_creator && \
    ln -s /janus_aggregator /aggregation_job_driver && \
    ln -s /janus_aggregator /collection_job_driver && \
    ln -s /janus_aggregator /janus_cli
# Store the build argument in an environment variable so we can reference it
# from the ENTRYPOINT at runtime.
ENV BINARY=$BINARY
ENTRYPOINT ["/bin/sh", "-c", "exec /$BINARY \"$0\" \"$@\""]
