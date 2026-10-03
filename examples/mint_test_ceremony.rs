//! CIRISPersist#973 — mint the SOFTWARE re-mint ceremony for a dry run: the
//! anchor block (stdout, compose lines) and the bundle the real ceremony
//! outputs (written to `out_dir`).
//!
//! ```text
//! cargo run --example mint_test_ceremony --features test-anchor -- \
//!     <out_dir> <holder_seed_b64> <holder_seed_b64> <holder_seed_b64> <node_seed_b64>
//! ```
//!
//! Writes `<out_dir>/canonical_seed.json`: the bundle, the only genesis
//! artifact (v53.0.0, CC rc7 — the `ciris-canonical` birth is a member of it).

fn main() {
    use ciris_persist::federation::genesis::{decode_seed_b64, mint_test_ceremony};
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        eprintln!("usage: mint_test_ceremony <out_dir> <holder_seed_b64> ×3 <node_seed_b64>");
        std::process::exit(2);
    }
    let seed = |a: &String| {
        decode_seed_b64(a).unwrap_or_else(|e| {
            eprintln!("seed {a:?}: {e}");
            std::process::exit(2)
        })
    };
    let holders = [seed(&args[1]), seed(&args[2]), seed(&args[3])];
    let outputs =
        mint_test_ceremony(&holders, &seed(&args[4]), chrono::Utc::now()).unwrap_or_else(|e| {
            eprintln!("mint_test_ceremony: {e}");
            std::process::exit(1)
        });
    let dir = std::path::Path::new(&args[0]);
    let write = |name: &str, body: Result<String, ciris_persist::federation::Error>| {
        let body = body.unwrap_or_else(|e| {
            eprintln!("{name}: {e}");
            std::process::exit(1)
        });
        std::fs::write(dir.join(name), body).unwrap_or_else(|e| {
            eprintln!("write {name}: {e}");
            std::process::exit(1)
        });
    };
    write("canonical_seed.json", outputs.bundle_json());
    print!("{}", outputs.block.compose_lines());
}
