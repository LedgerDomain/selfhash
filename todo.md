# To-Do List for `selfhash`

-   Change `SelfHashableT::write_digest_data` to take `HashFunctionT` and `&mut dyn std::io::Write` instead of a hasher, so that it could e.g. be printed to logs or `format!` macro.
