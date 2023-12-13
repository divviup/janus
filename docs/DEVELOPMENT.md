# Janus Development

## Database schema

The Janus aggregator database schema is defined by a series of SQL migration
scripts in the [`db`](../db) directory. Janus database migrations are
reversible, meaning they come in pairs named `*.up.sql` and `*.down.sql`. They
are applied via [`sqlx`][sqlx-cli].

To create a new migration:

* Create a pair of files in the [`db`](../db) directory named
  `$NUMBER_$NAME.up.sql` and `$NUMBER_$NAME.down.sql`, where `$NUMBER` is the
  next migration number in sequence (zero-padded), like `00000000000001`, and
  `$NAME` is a human-readable name for the migration, like `my_migration_name`.
* Fill the `up.sql` file with the migration script you wish to run.
* Fill the `down.sql` file with a script which undoes the migration.
* Add the new migration version number to the list in the
  `supported_schema_versions!` invocation in `datastore.rs`. (Depending on the
  Janus code changes associated with the migration, you may also need to remove
  no-longer-functional versions of the schema from the
  `supported_schema_versions!` invocation.)

[sqlx-cli]: https://crates.io/crates/sqlx-cli

## Code style

* Functions & methods should take the type of argument (reference, mutable
  reference, or value) that they need. For example, a function that computes a
  predicate on its argument, or returns a reference to some part of its
  argument, should take a reference. A function that mutates its argument should
  take a mutable reference. A function that moves its argument into a
  newly-constructed struct which will be returned should take its arguments by
  value.

  * This should always be followed for non-`Copy` types to avoid expensive
    `clone()` calls. Even when using `Copy` types, it is a best practice to
    follow this rule.

  * In particular, when writing a constructor, receive the fields by value. Do
    not take a reference and then call `clone()` on it. Doing so may incur an
    extra `clone()` if the caller already has a value in hand which they are OK
    handing off. (And if they have a reference, or a value that they wish to
    keep ownership of, they can call `clone()` themselves.)

* Structured data intended for "public" use (i.e. outside of the current module
  & its descendants) should not include public fields & should instead provide
  getters which return references to the internal data. This allows the
  structure to enforce invariants at time of construction, allows the fields in
  the structure to be different from the public API, and permits the structures
  to be refactored to a greater degree while requiring fewer updates to users of
  the structure.

* Types should generally implement traits rather than custom methods, where it
  makes sense to do so. This is because these traits will "fit in" better with
  libraries written to work with these traits.

  * For example, don't write an `as_bytes() -> &[u8]` method; instead, implement
    `AsRef<[u8]>`. Don't write a `random()` or `generate()` method; instead,
    `impl Distribution<Type> on Standard`. Consider implementing `From` rather
    than `new` if the type conceptually is the thing it is being created from
    (for example, a newtype over an array of bytes might implement
    `From<Vec<u8>>`).

* Follow documented best practices of the crates Janus depends on. For example,
  the `rand` crate suggests using `random()` to generate random data, falling
  back to `thread_rng()` to gain more control as-needed.

* Prefer `tokio_postgres::Row::get()` over `tokio_postgres::Row::try_get()`.
  The former panics if the column is not found in the row, or if the `FromSql`
  conversion fails. In cases where a column is not present in a query, or when
  it is not of the right Postgres data type, this represents a programmer error,
  so a panic is appropriate. (Note that some `FromSql` implementations may
  return errors for other reasons, such as out-of-range values or serde
  deserialization falures)

* In production code, use of `.unwrap()` should be preceded by a comment
  that asserts the safety of the unwrap.

  Example:
  ```rust
  // Unwrap safety: The constructor checks that max_concurrent_job_workers 
  // can be converted to a u32.
  // Unwrap safety: Semaphore::acquire is documented as only returning an error
  // if the semaphore is closed, and we never close this semaphore.
  let _: SemaphorePermit<'_> = sem
      .acquire_many(u32::try_from(self.max_concurrent_job_workers).unwrap())
      .await
      .unwrap();
  ```

  If unwrapping a mutex lock, where panic is a desired outcome of mutex poisoning,
  you can simply state:
  ```rust
  // Unwrap safety: panic on mutex poisoning.
  mutex.lock().unwrap();
  ```

  Explanation of `.unwrap()` is not necessary in test code.
