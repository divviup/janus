FROM rust:1.60.0-alpine as builder
RUN apk add libc-dev protoc

WORKDIR /src/janus_server
COPY janus_server/Cargo.toml /src/janus_server/Cargo.toml
COPY janus_server/Cargo.lock /src/janus_server/Cargo.lock
COPY janus_server/src /src/janus_server/src
COPY db/schema.sql /src/db/schema.sql
RUN cargo build --release --bin aggregator

FROM alpine:3.15.0
RUN apk add libgcc
COPY --from=builder /src/db/schema.sql /db/schema.sql
COPY --from=builder /src/janus_server/target/release/aggregator /aggregator
ENTRYPOINT ["/aggregator"]
