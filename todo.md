# To-Do List for `selfhash`

-   Ideally get rid of NamedHashFunction so that there's no need for the crate to track what hash functions are allowed -- perhaps create a HashFunctionRegistry that is passed in with self_hash and verify_self_hashes that produces the appropriate hashers.  Then client programs can add hash functions without needing to modify `selfhash` crate.
-   Implement a proc macro for deriving `SelfHashable` on structures.
-   Add specific test vectors to ensure that the specific encoding/decoding of the KERIHash type is correct.
-   Change `SelfHashable::write_digest_data` to take `HashFunction` and `&mut dyn std::io::Write` instead of `&mut dyn Hasher`, so that it could e.g. be printed to logs or `format!` macro.
-   Perhaps make a "static" `SelfHashable` trait which specifies certain types for (at least) `Hash`, since most of the time you'll be operating with a particular format of hash (e.g. KERIHash or HashBytes).  This would potentially simplify the type signatures because it wouldn't require the `dyn` fanciness.
-   Make SelfHashableJSON use JSONPath to specify its self-hash and self-hash URL slots.  This way, they don't all have to be top-level fields.
-   Consider breaking out the `&mut self` methods of `SelfHashable` into a separate trait called `SelfHashableMut`.  This is tricky though, because to verify a `SelfHashable`, a mutable copy has to be made and its self-hash slots set to the placeholder value.  This could only be done if the future-immutable `SelfHashable` is clonable or can otherwise feed itself into the hasher with self-hash slots set to placeholder values.
