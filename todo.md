# To-Do List for `selfhash`

-   Ideally get rid of NamedHashFunction so that there's no need for the crate to track what hash functions are allowed -- perhaps create a HashFunctionRegistry that is passed in with self_hash and verify_self_hashes that produces the appropriate hashers.  Then client programs can add hash functions without needing to modify `selfhash` crate.
-   Implement a proc macro for deriving `SelfHashable` on structures.
-   Add specific test vectors to ensure that the specific encoding/decoding of the KERIHash type is correct.
