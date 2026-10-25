//! v60.0.0 (CIRISPersist#691) — **a from-disk gate binds its verdict to the
//! tree it read.**
//!
//! `store::parity` and `store::schema_parity` read the backend sources and the
//! migrations from disk while they run, which is what lets the postgres arm be
//! scanned under `--features sqlite` and under no features at all. Their
//! findings are all positive detections, so text from a tree that moved under
//! the run (a `git checkout` in another shell, an editor, a `cargo fmt`) reads
//! GREEN: the gate could not tell "I scanned the source under test" from "I
//! scanned some other source". Two bindings close that:
//!
//! - [`read_compiled`] — a backend source this test binary embedded at compile
//!   time (`include_str!`) must be byte-identical on disk, or the tree moved
//!   since the build;
//! - [`read`] + [`assert_unmoved`] — every other file is digested on its first
//!   read in this process and re-read at the end of a scan; a file that changed
//!   in between is a tree that moved during the run.
//!
//! Either fails loudly with the HEAD it found. A dirty tree is the normal
//! development case and stays green: the check is "did it CHANGE".

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The files read in one process: path -> digest of the first read.
struct Seen(Mutex<BTreeMap<PathBuf, u64>>);

static SEEN: Seen = Seen(Mutex::new(BTreeMap::new()));

fn digest(text: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// `git rev-parse HEAD` in the manifest dir, for the failure message only.
fn head() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "<no git>".to_owned(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        )
}

fn moved(path: &Path, what: &str) -> ! {
    panic!(
        "CIRISPersist#691: {} {what} — the tree moved under this run (HEAD now {}). A \
         from-disk gate's verdict is about the text it read; re-run on a still tree.",
        path.display(),
        head()
    )
}

impl Seen {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<PathBuf, u64>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn read(&self, path: &Path) -> String {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let d = digest(&text);
        let first = *self.map().entry(path.to_path_buf()).or_insert(d);
        if first != d {
            moved(path, "changed between two reads of this run");
        }
        text
    }

    fn read_compiled(&self, path: &Path, compiled: &str) -> String {
        let text = self.read(path);
        if text != compiled {
            moved(path, "is not the text this test binary was compiled from");
        }
        text
    }

    fn assert_unmoved(&self) {
        let seen: Vec<(PathBuf, u64)> = self.map().iter().map(|(p, d)| (p.clone(), *d)).collect();
        for (path, first) in seen {
            let now = std::fs::read_to_string(&path).map(|t| digest(&t)).ok();
            if now != Some(first) {
                moved(&path, "changed while the scan ran");
            }
        }
    }
}

/// Read `path`, digesting it on its first read in this process; a later read
/// that differs is a tree that moved during the run.
pub(crate) fn read(path: &Path) -> String {
    SEEN.read(path)
}

/// Read `path` and require it to be the text this binary was compiled with
/// (`compiled`, an `include_str!` of the same file).
pub(crate) fn read_compiled(path: &Path, compiled: &str) -> String {
    SEEN.read_compiled(path, compiled)
}

/// Re-read every file read so far in this process and require each unchanged.
/// A scan calls this when it is done, so a tree that moved while it ran fails
/// the scan instead of reporting on a mix of two trees.
pub(crate) fn assert_unmoved() {
    SEEN.assert_unmoved();
}

#[cfg(test)]
mod tests {
    use super::Seen;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn panic_text(e: Box<dyn std::any::Any + Send>) -> String {
        e.downcast_ref::<String>().cloned().unwrap_or_default()
    }

    /// **I1321** — the binding fails loudly on a moved file, and stays green
    /// on a still one (dirty or not). A registry of its own, so a probe file
    /// it moves is never seen by a parity scan in the same process.
    #[test]
    fn i1321_a_moved_file_fails_the_scan_loudly() {
        let seen = Seen(Mutex::new(BTreeMap::new()));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("probe.rs");
        std::fs::write(&p, "fn a() {}\n").unwrap();
        assert_eq!(seen.read(&p), "fn a() {}\n");
        seen.read(&p); // a still file reads again
        seen.assert_unmoved();
        assert_eq!(seen.read_compiled(&p, "fn a() {}\n"), "fn a() {}\n");

        std::fs::write(&p, "fn b() {}\n").unwrap();
        let msg = panic_text(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| seen.assert_unmoved()))
                .unwrap_err(),
        );
        assert!(
            msg.contains("CIRISPersist#691") && msg.contains("while the scan ran"),
            "{msg}"
        );
        let msg = panic_text(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| seen.read(&p))).unwrap_err(),
        );
        assert!(msg.contains("between two reads"), "{msg}");

        let q = dir.path().join("compiled.rs");
        std::fs::write(&q, "fn disk() {}\n").unwrap();
        let msg = panic_text(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                seen.read_compiled(&q, "fn built() {}\n")
            }))
            .unwrap_err(),
        );
        assert!(msg.contains("compiled from"), "{msg}");
    }
}
