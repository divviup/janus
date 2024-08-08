# `aggregator_core`

`aggregator_core` contains helper code for the `aggregator` crate. It mainly consists of data
structures that are only pertinent to a DAP aggregator, and subroutines for talking to a PostgreSQL
database.

It is not published to crates.io and should not be depended on directly by users of Janus.

## PostgreSQL Logs

During tests, you can have PostgreSQL dump its logs to stdout by setting
`JANUS_TEST_DUMP_POSTGRESQL_LOGS`. The test database is set to log all query plans.

Example:
```
JANUS_TEST_DUMP_POSTGRESQL_LOGS= RUST_LOG=debug cargo test datastore::tests::roundtrip_task::case_1 -- --exact --nocapture
```
