//! Emit `PersistExtras` JSON for the build manifest.
//!
//! v0.1.9 — invoked from CI before `ciris-build-sign` to produce the
//! primitive-specific extras blob the BuildManifest references. Reads
//! the source tree directly (migrations + Cargo.toml + the runtime's
//! `SUPPORTED_VERSIONS` constant) so the extras are deterministic
//! per checkout.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --bin emit-persist-extras > persist-extras.json
//! ```
//!
//! Output is compact JSON on stdout. Non-zero exit = something broke;
//! the JSON in stdout is incomplete and MUST NOT be signed.

use std::io::Read;

use ciris_persist::manifest::PersistExtras;
use ciris_persist::schema::SUPPORTED_VERSIONS;
use sha2::{Digest, Sha256};

fn main() {
    let extras = match build() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("emit_persist_extras: {e}");
            std::process::exit(1);
        }
    };
    // Compact JSON; the BuildManifest's manifest_hash covers the
    // canonical-bytes form so trailing whitespace doesn't change it,
    // but compact form is the convention.
    let json = serde_json::to_string(&extras).expect("PersistExtras serialises");
    println!("{json}");
}

fn build() -> Result<PersistExtras, String> {
    let supported_schema_versions: Vec<String> =
        SUPPORTED_VERSIONS.iter().map(|s| (*s).to_owned()).collect();
    let migration_set_sha256 = hash_migration_set("migrations/postgres/lens")
        .map_err(|e| format!("migration_set_sha256: {e}"))?;
    let dep_tree_sha256 = hash_dep_tree().map_err(|e| format!("dep_tree_sha256: {e}"))?;
    Ok(PersistExtras {
        supported_schema_versions,
        migration_set_sha256,
        dep_tree_sha256,
    })
}

/// SHA-256 over the lex-sorted concatenation of `V*.sql` files in
/// `dir`, with line endings normalised to LF and a trailing
/// newline-after-each-file so the same files in any order produce
/// the same hash (deterministic across operating systems and
/// filesystem traversal order).
fn hash_migration_set(dir: &str) -> Result<String, String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("read_dir({dir}): {e}"))?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with('V') && s.ends_with(".sql"))
                    .unwrap_or(false)
        })
        .collect();
    entries.sort();

    if entries.is_empty() {
        return Err(format!("no V*.sql files found in {dir}"));
    }

    let mut hasher = Sha256::new();
    for path in &entries {
        let mut content = String::new();
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_string(&mut content))
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        // Normalise line endings to LF so a Windows checkout of the
        // tree produces the same hash as Linux.
        let normalised = content.replace("\r\n", "\n");
        hasher.update(normalised.as_bytes());
        // Separator byte ensures concatenation of "abc" + "def" ≠
        // "ab" + "cdef": include the path's filename so a renamed
        // migration also produces a different hash.
        hasher.update(b"\n--FILE-SEP--\n");
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// SHA-256 over a normalised `cargo tree` output. Reads the lockfile-
/// like dep snapshot from `cargo tree --target <triple> --features
/// postgres,server,pyo3 --prefix none --no-dedupe`, sorts the lines
/// to remove order non-determinism, and hashes.
///
/// The target triple comes from `CIRIS_PERSIST_DEP_TARGET` (CI sets
/// it; defaults to the host triple for local dev).
fn hash_dep_tree() -> Result<String, String> {
    let target = std::env::var("CIRIS_PERSIST_DEP_TARGET").ok();
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("tree")
        .arg("--features")
        .arg("postgres,server,pyo3")
        .arg("--prefix")
        .arg("none")
        .arg("--no-dedupe");
    if let Some(t) = target.as_ref() {
        cmd.arg("--target").arg(t);
    }
    let output = cmd.output().map_err(|e| format!("spawn cargo tree: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("cargo tree output not UTF-8: {e}"))?;
    // Sort lines for order-stability across cargo versions / OSes.
    let mut lines: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| !l.contains("(*)")) // drop dedupe markers; we asked for --no-dedupe
        .collect();
    lines.sort_unstable();
    lines.dedup();
    let normalised = lines.join("\n");
    let mut hasher = Sha256::new();
    hasher.update(normalised.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}
