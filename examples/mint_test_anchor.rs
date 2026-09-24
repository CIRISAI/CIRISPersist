//! v47.4.0 (CIRISPersist#805) — print the `CIRIS_TEST_TRUST_ROOT*` compose
//! block for the pair that compiled this binary.
//!
//! ```text
//! cargo run --example mint_test_anchor --features test-anchor [seed_b64 ...]
//! ```
//!
//! No argument mints the seed every harness shares, so the output is the
//! block they already carry — with the scrubs that verify under THIS
//! persist/verify pair, and the seventh line naming it.

fn main() {
    use ciris_persist::federation::genesis::{
        decode_seed_b64, mint_test_anchor_block, TEST_ANCHOR_SHARED_SEED_B64,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seeds: Vec<[u8; 32]> = if args.is_empty() {
        vec![decode_seed_b64(TEST_ANCHOR_SHARED_SEED_B64).expect("the shared seed decodes")]
    } else {
        args.iter()
            .map(|a| {
                decode_seed_b64(a).unwrap_or_else(|e| {
                    eprintln!("seed {a:?}: {e}");
                    std::process::exit(2)
                })
            })
            .collect()
    };
    match mint_test_anchor_block(&seeds) {
        Ok(block) => print!("{}", block.compose_lines()),
        Err(e) => {
            eprintln!("mint_test_anchor_block: {e}");
            std::process::exit(1)
        }
    }
}
