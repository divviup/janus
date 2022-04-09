FROM rust:1.60.0-alpine as builder
RUN apk add libc-dev protoc

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY janus_server /src/janus_server
COPY db/schema.sql /src/db/schema.sql
RUN cargo build --release --bin aggregator

FROM alpine:3.15.4
RUN apk add libgcc
COPY --from=builder /src/db/schema.sql /db/schema.sql
COPY --from=builder /src/target/release/aggregator /aggregator
ENTRYPOINT ["/aggregator"]
