FROM rust:1.60.0-alpine as builder
RUN apk add libc-dev

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY janus_server /src/janus_server
COPY db/schema.sql /src/db/schema.sql
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --bin aggregator && cp /src/target/release/aggregator /aggregator

FROM alpine:3.15.4
COPY --from=builder /src/db/schema.sql /db/schema.sql
COPY --from=builder /aggregator /aggregator
ENTRYPOINT ["/aggregator"]
