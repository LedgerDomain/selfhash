# selfhash-bin

CLI tool for generating and verifying self-hashed JSON.

## Installation

Run:

    cargo install --path <path-to-this-dir>

## Usage

### Help messages

Run:

    selfhash

Output:

    Operate on JSON as self-hashable data -- data which is self-validating.  In particular, self-hashable data is data which has at least one "self-hash slot" which is used during the computation and verification of the data's self-hash.  During the computation of the data's self-hash, all the self-hash slots are set to a placeholder value which encodes which hash function will be used, the data is serialized into JCS (JSON Canonicalization Scheme), and then hashed.  This hash value is then used to set all the self-hash slots. The data is then serialized into JCS again, and at this point is self-hashed and fully self-verifiable

    Usage: selfhash <COMMAND>

    Commands:
      compute  Read JSON from stdin, compute its self-hash, and output canonical JSON (JCS) with its self-hash [URL] field(s) set (see --self-hash-field-name and --self-hash-url-field-name), overwriting any existing self-hash [URL] field(s)
      verify   Read JSON from stdin, verify its self-hash(es) (see --self-hash-field-name and --self-hash-url-field-name), and print the verified self-hash
      help     Print this message or the help of the given subcommand(s)
    
    Options:
      -h, --help     Print help
      -V, --version  Print version

Run:

    selfhash compute --help

Output:
    
    Read JSON from stdin, compute its self-hash, and output canonical JSON (JCS) with its self-hash [URL] field(s) set (see --self-hash-field-name and --self-hash-url-field-name), overwriting any existing self-hash [URL] field(s)
    
    Usage: selfhash compute [OPTIONS]
    
    Options:
      -n, --no-newline
              If specified, don't print a trailing newline in the output [default: print newline]
      -s, --self-hash-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash slots [default: selfHash]
      -u, --self-hash-url-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash URL slots [default: ]
      -h, --help
              Print help
    
Run:

    selfhash verify --help

Output:

    Read JSON from stdin, verify its self-hash(es) (see --self-hash-field-name and --self-hash-url-field-name), and print the verified self-hash
    
    Usage: selfhash verify [OPTIONS]
    
    Options:
      -n, --no-newline
              If specified, don't print a trailing newline in the output [default: print newline]
      -s, --self-hash-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash slots [default: selfHash]
      -u, --self-hash-url-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash URL slots [default: ]
      -h, --help
              Print help

## Example Usage

### `selfhash compute`

Run:

    echo '{"blah": 3}' | selfhash compute

Output:

    {"blah":3,"selfHash":"ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThjE"}

Run:

    echo '{"blah": 3}' | selfhash compute -s selfie

Output (notice that it's different from above in which the self-hash slot field name is "selfHash"):

    {"blah":3,"selfie":"EeXcy67Z7JJnJDRRynMq5qU4u1DtaRzMPkxlViJZg6Ds"}

Run:

    echo '{"blah": 3}' | selfhash compute -s selfie,xyz

Output (notice multiple self-hash slots):

    {"blah":3,"selfie":"EjJGQzju-fXng-_BloBqgy8T1s-tGl3ecGlWVKOne2ds","xyz":"EjJGQzju-fXng-_BloBqgy8T1s-tGl3ecGlWVKOne2ds"}

Run:

    echo '{"blah": 3, "selfHash": ["this is", true, "garbage"]}' | selfhash compute

Output (notice that the existing "selfHash" field was ignored and overwritten, and the result is equal to the original example):

    {"blah":3,"selfHash":"ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThjE"}

Run:

    echo '{"blah": 3}' | selfhash compute -s '' 

Output (no self-hash slots were defined):

    self-hash failed: Error("This object has no self-hash slots, and therefore can't be self-hashed.")

Run (note the single quotes around `$id`):

    echo '{"blah": 3, "$id": "vjson:///"}' | selfhash compute -s '' -u '$id'

Output (self-hash configured to be a self-hash URL field):

    {"$id":"vjson:///ECwrqzmX9xCkhj_sLzbc9tZKkK5cqUJZIolDp8qqDcc8","blah":3}

### `selfhash verify`

Run:

    echo '{"blah":3,"selfHash":"ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThjE"}' | selfhash verify

Output (it prints the verified self-hash):

    ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThjE

Run:

    echo '{"blah":3,"selfHash":"ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThxE"}' | selfhash verify

Output (it prints the expected error; notice the altered "selfHash" value in the input):

    self-hash verification failed: Error("This object's computed self-hash (ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThjE) does not match the object's claimed self-hash (ELP15fovJ9WZ9lY4yS3qQm4cbl2yL4jquMx0kD2xThxE).")

Run:

    echo '{"blah":3,"selfie":"EeXcy67Z7JJnJDRRynMq5qU4u1DtaRzMPkxlViJZg6Ds"}' | selfhash verify -s selfie

Output (it prints the verified self-hash):

    EeXcy67Z7JJnJDRRynMq5qU4u1DtaRzMPkxlViJZg6Ds

Run:

    echo '{"blah":3,"selfie":"EeXcy67Z7JJnJDRRynMq5qU4u1DtaRzMPkxlViJZg6Ds"}' | selfhash verify

Output (it prints the expected error):

    Input JSON has no "selfHash" field (expected because of argument --self-hash-field-names "selfHash"), and therefore can't be verified.

Run:

    echo '{"blah":3,"selfie":"EjJGQzju-fXng-_BloBqgy8T1s-tGl3ecGlWVKOne2ds","xyz":"EjJGQzju-fXng-_BloBqgy8T1s-tGl3ecGlWVKOne2ds"}' | selfhash verify -s selfie,xyz

Output:

    EjJGQzju-fXng-_BloBqgy8T1s-tGl3ecGlWVKOne2ds

Run (note the single quotes around `$id`):

    echo '{"$id":"vjson:///ECwrqzmX9xCkhj_sLzbc9tZKkK5cqUJZIolDp8qqDcc8","blah":3}' | selfhash verify -s '' -u '$id'

Output:

    ECwrqzmX9xCkhj_sLzbc9tZKkK5cqUJZIolDp8qqDcc8

