# To-Do List for `selfhash`

-   Change `SelfHashableT::write_digest_data` to take `HashFunctionT` and `&mut dyn std::io::Write` instead of a hasher, so that it could e.g. be printed to logs or `format!` macro.
-   Add CLI args to specify base and hash function for self-hashing in selfhash-bin.
