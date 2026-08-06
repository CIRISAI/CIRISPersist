//! The Rust snippet in README.md, compiled.
//!
//! A README example that cannot compile is how documentation rots silently:
//! nothing checks it, so it drifts one refactor at a time until it is actively
//! misleading. This file is built by `cargo build --examples` and linted by the
//! `--all-targets` clippy leg, so the snippet either compiles or CI is red.
//!
//! **Keep this and the README block in sync.** If you change one, change both.
//! It does not RUN in CI — it opens no database and reads no key file — it is
//! compiled, which is the property that catches a wrong signature or a renamed
//! field.
#[cfg(feature = "sqlite")]
async fn readme_example() -> Result<(), Box<dyn std::error::Error>> {
    use ciris_persist::signing::{LocalSigner, LocalSignerConfig};
    use ciris_persist::Engine;
    use std::sync::Arc;

    let signer = Arc::new(LocalSigner::from_config(&LocalSignerConfig {
        key_id: "my-node".to_owned(),
        key_path: "/run/keys/ed25519.seed".into(),
        pqc_key_id: None,
        pqc_key_path: None,
    })?);

    // Migrations run as part of construction; the Engine is ready to use.
    let engine = Engine::with_signer(signer, "sqlite:///./node.db").await?;
    let _ = engine;
    Ok(())
}

fn main() {
    // Compiled, not executed: running it would need a real key file on disk.
    #[cfg(feature = "sqlite")]
    let _ = readme_example;
    println!("README example compiles.");
}
