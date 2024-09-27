use selfhash::{Blake3, HashFunction, SelfHashable, SelfHashableJSON};
use std::{
    borrow::Cow,
    collections::HashSet,
    io::{Read, Write},
};

/// Operate on JSON as self-hashable data -- data which is self-validating.  In particular, self-hashable data is
/// data which has at least one "self-hash slot" which is used during the computation and verification of the
/// data's self-hash.  During the computation of the data's self-hash, all the self-hash slots are set to a
/// placeholder value which encodes which hash function will be used, the data is serialized into JCS (JSON
/// Canonicalization Scheme), and then hashed.  This hash value is then used to set all the self-hash slots.
/// The data is then serialized into JCS again, and at this point is self-hashed and fully self-verifiable.
#[derive(clap::Parser)]
#[clap(version, about)]
enum CLI {
    /// Read JSON from stdin, compute its self-hash, and output canonical JSON (JCS) with its self-hash [URL]
    /// field(s) set (see --self-hash-field-name and --self-hash-url-field-name), overwriting any existing
    /// self-hash [URL] field(s).
    Compute(Compute),
    /// Read JSON from stdin, verify its self-hash(es) (see --self-hash-field-name and --self-hash-url-field-name),
    /// and print the verified self-hash.
    Verify(Verify),
}

impl CLI {
    fn handle(self) {
        match self {
            Self::Compute(x) => x.handle(),
            Self::Verify(x) => x.handle(),
        }
    }
}

#[derive(clap::Args)]
struct SelfHashArgs {
    /// Optionally specify a comma-delimited list of top-level field names that are considered self-hash slots.
    #[arg(short, long, default_value = "selfHash", value_name = "FIELD_NAME")]
    self_hash_field_names: String,
    /// Optionally specify a comma-delimited list of top-level field names that are considered self-hash URL slots.
    #[arg(short = 'u', long, default_value = "", value_name = "FIELD_NAME")]
    self_hash_url_field_names: String,
}

impl SelfHashArgs {
    fn parse_self_hash_field_names(&self) -> HashSet<Cow<'_, str>> {
        let self_hash_field_names = self.self_hash_field_names.trim();
        if self_hash_field_names.is_empty() {
            maplit::hashset! {}
        } else {
            self_hash_field_names
                .split(',')
                .map(|s| Cow::Borrowed(s))
                .collect::<HashSet<_>>()
        }
    }
    fn parse_self_hash_url_field_names(&self) -> HashSet<Cow<'_, str>> {
        let self_hash_url_field_names = self.self_hash_url_field_names.trim();
        if self_hash_url_field_names.is_empty() {
            maplit::hashset! {}
        } else {
            self_hash_url_field_names
                .split(',')
                .map(|s| Cow::Borrowed(s))
                .collect::<HashSet<_>>()
        }
    }
}

#[derive(clap::Args)]
struct Compute {
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
    #[command(flatten)]
    self_hash_args: SelfHashArgs,
}

impl Compute {
    fn handle(self) {
        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let value = serde_json::from_str(&input).unwrap();

        // Parse the self-hash related arguments.
        let self_hash_field_name_s = self.self_hash_args.parse_self_hash_field_names();
        let self_hash_url_field_name_s = self.self_hash_args.parse_self_hash_url_field_names();

        // Set up the context for self-hashable JSON.
        let mut json = SelfHashableJSON::new(
            value,
            Cow::Borrowed(&self_hash_field_name_s),
            Cow::Borrowed(&self_hash_url_field_name_s),
        )
        .unwrap();

        // Self-hash the JSON.
        // TODO: Arg to specify the hash function
        json.self_hash(Blake3.new_hasher())
            .expect("self-hash failed");

        // Verify the self-hash.  This is mostly a sanity check.
        json.verify_self_hashes()
            .expect("programmer error: self-hash verification failed");

        // Print the self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(json.value(), &mut std::io::stdout()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

#[derive(clap::Args)]
struct Verify {
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
    #[command(flatten)]
    self_hash_args: SelfHashArgs,
}

impl Verify {
    fn handle(self) {
        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let value: serde_json::Value = serde_json::from_str(&input).unwrap();

        // Parse the self-hash related arguments.
        let self_hash_field_name_s = self.self_hash_args.parse_self_hash_field_names();
        let self_hash_url_field_name_s = self.self_hash_args.parse_self_hash_url_field_names();

        // Check for the existence of the self-hash [URL] field(s).  This is to produce a better error
        // message than the one that would be produced by verify_self_hashes.
        for self_hash_field_name in self_hash_field_name_s.iter().map(std::ops::Deref::deref) {
            if value.get(self_hash_field_name).is_none() {
                eprintln!("Input JSON has no {:?} field (expected because of argument --self-hash-field-names {:?}), and therefore can't be verified.", self_hash_field_name, self.self_hash_args.self_hash_field_names);
                std::process::exit(1);
            }
        }
        for self_hash_url_field_name in self_hash_url_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            if value.get(self_hash_url_field_name).is_none() {
                eprintln!("Input JSON has no {:?} field (expected because of argument --self-hash-url-field-names {:?}), and therefore can't be verified.", self_hash_url_field_name, self.self_hash_args.self_hash_url_field_names);
                std::process::exit(1);
            }
        }

        // Set up the context for self-hashable JSON.
        let json = SelfHashableJSON::new(
            value,
            Cow::Borrowed(&self_hash_field_name_s),
            Cow::Borrowed(&self_hash_url_field_name_s),
        )
        .unwrap();

        // Verify the self-hash.
        let self_hash = json
            .verify_self_hashes()
            .expect("self-hash verification failed")
            .to_keri_hash();

        // Print the verified self-hash with optional newline.
        std::io::stdout().write(self_hash.as_bytes()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

fn main() {
    use clap::Parser;
    CLI::parse().handle();
}
