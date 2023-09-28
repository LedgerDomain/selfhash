# selfhash

A Rust crate providing traits and data types to define self-hashing data.  Inspired by the Self-Addressing Identifier concept in [KERI](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).  This implementation is not necessarily compatible with KERI.  At the moment, it's a very initial implementation, and is a work in progress.

## Overview

In the context of cryptography, it's not possible to directly include a hash within the message being hashed.  However, it is possible to define slightly altered hashing and verification procedures for a given data structure which in a way does contain a hash over itself.

The idea is that the data structure has at least one "slot" for the hash.  Hereafter, these will be referred to as self-hash slots.  Each self-hash slot is meant to represent the same value within the data structure.  The purpose for having multiple slots is to be able to have the self-hash data appear in multiple places within the data structure (e.g. in the definition of a DID document, in which the self-hash-containing DID itself must appear several places within the DID document).  The self-hash procedure is as follows:

### Self-Hashing

Let the hash function be `H`.  Let the data to be self-hashed be `D`.  The self-hash slots of `D` are well-defined and enumerable.

The steps to self-hash are:
1. Set all of `D`'s self-hash slots to the "placeholder" value for that hash function (this encodes the hash function and an all-zeros dummy signature value).
2. Serialize `D` with an agreed-upon and deterministic serialization format, producing message `msg`.
3. Compute the hash of `msg` using `H`, producing hash value `digest`.
4. Set all of `D`'s self-hash slots to `digest`.

At this point, `D` is self-hashed, and can be self-verified successfully.

### Self-Verifying

When verifying self-hashed data `D`, the hash function is not known ahead of time but rather is determined from `D`.

The steps to self-verify are:
1. Check that all of `D`'s self-hash slots are equal to each other.  Let this value be `claimed_digest`.
2. Set all of `D`'s self-hash slots to the "placeholder" value for that hash function (this is the same as in step 1 of self-signing).
3. Serialize `D` with an agreed-upon and deterministic serialization format, producing message `msg`.
4. Compute the hash of `msg` using `H`, producing hash value `computed_digest`.
5. If `computed_digest` equals `claimed_digest`, then the `D` is defined to be validly self-hashed.

## Serialization Formats

Note that JSON isn't the only usable serialization format (and it's not even a good one, in particular because it doesn't have a canonical form and so may have interoperability issues between different implementations), but it does make for human-readable examples.  [CESR](https://www.ietf.org/archive/id/draft-ssmith-cesr-03.html) is the intended solution to this problem within the KERI ecosystem.  There are a wide range of possible solutions, each fitting different needs.  One that will be elaborated upon later within this git repository will be a process for computing the message digest on a binary serialization of the data in a streaming manner, thereby eliminating allocations and other representational issues that can plague human-readable serialization formats.

## Examples

The examples come from the tests.  To run them:

    cargo test --all-features -- --nocapture

The `--all-features` is necessary for now.

### Example 1 -- Simplest

Here is a simple example in which a data structure has a single self-hash slot.  Here is the primary data, with self-hash slot unpopulated:

```json
{"previous":null,"name":"hippodonkey","stuff_count":42,"data_byte_v":[1,2,3],"self_hash":null}
```

During the self-hashing process, the `self_hash` field is set to the appropriate placeholder value (in this case the prefix `"E"` indicating use of the BLAKE3 hash function, followed by the base64url-no-pad-encoding of 256 bits of 0):

```json
{"previous":null,"name":"hippodonkey","stuff_count":42,"data_byte_v":[1,2,3],"self_hash":"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

After the self-hashing process, the `self_hash` field has been populated:

```json
{"previous":null,"name":"hippodonkey","stuff_count":42,"data_byte_v":[1,2,3],"self_hash":"E172jdGSSxO1jzThzmGPgY5ocmklgBlYGAjF3l8Ar540"}
```

Now, a second data structure is created which includes the self-hash of the previous data, thereby forming a microledger.  With self-hash unpopulated:

```json
{"previous":"E172jdGSSxO1jzThzmGPgY5ocmklgBlYGAjF3l8Ar540","name":"grippoponkey","stuff_count":43,"data_byte_v":[1,2,4,8,16,32,64,128],"self_hash":null}
```

With placeholder hash:

```json
{"previous":"E172jdGSSxO1jzThzmGPgY5ocmklgBlYGAjF3l8Ar540","name":"grippoponkey","stuff_count":43,"data_byte_v":[1,2,4,8,16,32,64,128],"self_hash":"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

Fully self-hashed:

```json
{"previous":"E172jdGSSxO1jzThzmGPgY5ocmklgBlYGAjF3l8Ar540","name":"grippoponkey","stuff_count":43,"data_byte_v":[1,2,4,8,16,32,64,128],"self_hash":"En4Oq_qmG3jvzA3O-F3hEUmNxWi1VsDS0yoPkC8aebwU"}
```

### Example 2 -- Multiple Self-Hash Slots

Here is an example involving a data structure that has multiple self-hash slots.  In particular, there is a URI, part of which is formed by the self-hash, as well as a stand-alone self-hash field.  The URI is initially populated with an arbitrary placeholder value (it just happens to be the hash function placeholder in this example), as the URI data structure, in order to be simpler, does not use `Option` semantics like in the previous example.  However, the self-hash process will replace it with the appropriate placeholder value.  In this case, the hash function being used is SHA-512, indicated by the `"0G"` prefix.

Initial data.  There are two self-hash slots -- one in part of the "uri" field, and one in the "self_hash" field:

```json
{"uri":"https://example.com/fancy_data/0GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","stuff":"hippopotapotamus","things":[1,2,3,4,5],"self_hash":null}
```

With placeholder hash (note that both self-hash slots have been populated with the placeholder hash):

```json
{"uri":"https://example.com/fancy_data/0GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","stuff":"hippopotapotamus","things":[1,2,3,4,5],"self_hash":"0GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

Fully self-hashed (note that both self-hash slots have the same self-hash value):

```json
{"uri":"https://example.com/fancy_data/0G7SVDUy5LznZrCWms17XvST_1S34ZW5NKfkT62SLSb4xnMjdHxlvfHOVUf9mjmxDcAVb0fwV6EhbVlXGXb8eAig","stuff":"hippopotapotamus","things":[1,2,3,4,5],"self_hash":"0G7SVDUy5LznZrCWms17XvST_1S34ZW5NKfkT62SLSb4xnMjdHxlvfHOVUf9mjmxDcAVb0fwV6EhbVlXGXb8eAig"}
```

## References

-   https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf
-   https://github.com/THCLab/cesrox
-   https://github.com/WebOfTrust/keriox
-   https://www.ietf.org/archive/id/draft-ssmith-cesr-03.html

## Copyright

Copyright 2023 LedgerDomain

## License

Apache 2.0
