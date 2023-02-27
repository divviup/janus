# Code Style

* Functions & methods should take the type of argument (reference, mutable reference, or value) that
  they need. For example, a function that computes a predicate on its argument, or returns a
  reference to some part of its argument, should take a reference. A function that mutates its
  argument should take a mutable reference. A function that moves its argument into a
  newly-constructed struct which will be returned should take its arguments by value.

  * This should always be followed for non-`Copy` types to avoid expensive `clone()` calls. Even
    when using `Copy` types, it is a best practice to follow this rule.

  * In particular, when writing a constructor, receive the fields by value. Do not take a reference
    and then call `clone()` on it. Doing so may incur an extra `clone()` if the caller already has a
    value in hand which they are OK handing off. (And if they have a reference, or a value that
    they wish to keep ownership of, they can call `clone()` themselves.)

* Structured data intended for "public" use (i.e. outside of the current module & its descendants)
  should not include public fields & should instead provide getters which return references to the
  internal data. This allows the structure to enforce invariants at time of construction, allows
  the fields in the structure to be different from the public API, and permits the structures to be
  refactored to a greater degree while requiring fewer updates to users of the structure.

* Types should generally implement traits rather than custom methods, where it makes sense to do so.
  This is because these traits will "fit in" better with libraries written to work with these
  traits.

  * For example, don't write an `as_bytes() -> &[u8]` method; instead, implement `AsRef<[u8]>`.
    Don't write a `random()` or `generate()` method; instead, `impl Distribution<Type> on Standard`.
    Consider implementing `From` rather than `new` if the type conceptually is the thing it is being
    created from (for example, a newtype over an array of bytes might implement `From<Vec<u8>>`).

* Follow documented best practices of the crates Janus depends on. For exmaple, the `rand` crate
  suggests using `random()` to generate random data, falling back to `thread_rng()` to gain more
  control as-needed.
