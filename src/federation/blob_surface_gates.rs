//! `FSD/BLOB_ENCRYPTION_AT_REST.md` §11.10 — **the structural blob-encryption
//! invariants: I8 (reachability), I13 (FFI error class), I14 (the storage
//! floor has no door).**
//!
//! These read source from disk, in the `store::parity` tradition, because
//! the property each asserts is about WHICH CODE CALLS WHICH — a property no
//! behavioural test can see. A behavioural test calls the function under
//! test directly, which is exactly the thing a consumer cannot do; the first
//! implementation (`fd43e74`) passed every behavioural test it had while its
//! headline gate sat on a door with no production caller.
//!
//! Like `parity.rs`, these are NOT hermetic: they read the tree as it is on
//! disk while the suite runs. Never edit `src/` under a running suite.

#[cfg(test)]
mod tests {
    fn src(rel: &str) -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// Strip `#[cfg(test)] mod tests { … }` blocks and `#[cfg(any(test,
    /// feature = "test-anchor"))]` modules so only PRODUCTION text is scanned.
    /// Crude — brace-depth from the attribute — but the alternative is a
    /// parser, and a gate that needs a parser is a gate nobody maintains.
    fn production_only(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            let t = line.trim_start();
            let is_test_attr = t.starts_with("#[cfg(test)]")
                || t.starts_with("#[cfg(any(test")
                || t.starts_with("#[tokio::test")
                || t.starts_with("#[test]");
            if is_test_attr {
                // Skip attribute lines until the item, then skip the item's
                // brace-balanced body.
                let mut depth: i64 = 0;
                let mut started = false;
                for l in std::iter::once(line).chain(lines.by_ref()) {
                    let opens = l.matches('{').count() as i64;
                    let closes = l.matches('}').count() as i64;
                    if opens > 0 {
                        started = true;
                    }
                    depth += opens - closes;
                    if started && depth <= 0 {
                        break;
                    }
                }
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    // ── I8 ───────────────────────────────────────────────────────────────
    /// **Every lifecycle operation a consumer needs is reachable from the
    /// Engine AND from Python.**
    ///
    /// The first implementation built `set_key_state` and
    /// `sweep_rotated_epochs`, tested them, and gave them 0 facades and 0
    /// bindings — while the CHANGELOG advertised "rotate, sweep … from Rust
    /// and from Python". This gate reds on that shape.
    #[test]
    fn i8_every_lifecycle_op_is_reachable_from_engine_and_ffi() {
        let engine = production_only(&src("src/engine.rs"));
        let ffi = production_only(&src("src/ffi/pyo3.rs"));
        // (orchestrate symbol, what a consumer would look for in the surface)
        let ops = [
            ("encrypt_and_cascade_community", "community"),
            ("read_for_community_viewer", "community_viewer"),
            ("encrypt_and_cascade(", "self_family"),
            ("read_for_viewer(", "for_viewer"),
            ("read_any_for_viewer", "read_blob_as"),
            ("set_key_state", "key_state"),
            ("sweep_rotated_epochs", "sweep"),
        ];
        let mut missing = Vec::new();
        for (sym, _) in ops {
            let in_engine = engine.contains(sym);
            let in_ffi = ffi.contains(sym);
            if !in_engine || !in_ffi {
                missing.push(format!("  {sym:<34} engine={in_engine:<5} ffi={in_ffi}"));
            }
        }
        assert!(
            missing.is_empty(),
            "I8: lifecycle operations with no consumer-reachable surface \
             (a tested function nobody can call is not shipped):\n{}",
            missing.join("\n")
        );
    }

    // ── I13 ──────────────────────────────────────────────────────────────
    /// **Every PyO3 blob binding preserves the `BlobError` class.**
    ///
    /// Python callers branch on the stable `blob_not_granted` /
    /// `blob_not_held` tokens `blob_err_to_py` produces. A binding that does
    /// `PyValueError::new_err(e.to_string())` collapses `NotGranted` into a
    /// permanent input error and a backend failure into the same. The first
    /// implementation did this in all five new bindings.
    #[test]
    fn i13_ffi_blob_bindings_route_errors_through_blob_err_to_py() {
        let ffi = production_only(&src("src/ffi/pyo3.rs"));
        let cascade_syms = [
            "encrypt_and_cascade_community",
            "read_for_community_viewer",
            "encrypt_and_cascade(",
            "read_for_viewer(",
            "read_any_for_viewer",
            "set_key_state",
            "sweep_rotated_epochs",
        ];
        // Split the FFI file into `fn` bodies and inspect each one that
        // touches a cascade symbol.
        let mut bad = Vec::new();
        let mut i = 0;
        while let Some(off) = ffi[i..].find("\n    fn ") {
            let start = i + off + 1;
            let end = ffi[start + 1..]
                .find("\n    fn ")
                .map(|o| start + 1 + o)
                .unwrap_or(ffi.len());
            let body = &ffi[start..end];
            let name = body
                .trim_start()
                .trim_start_matches("fn ")
                .split(['(', '<'])
                .next()
                .unwrap_or("?")
                .to_owned();
            if cascade_syms.iter().any(|s| body.contains(s)) && !body.contains("blob_err_to_py") {
                bad.push(name);
            }
            i = end;
        }
        assert!(
            bad.is_empty(),
            "I13: PyO3 blob bindings that do NOT map errors through `blob_err_to_py` \
             (Python loses blob_not_granted / blob_not_held and gets ValueError for a \
             backend failure): {bad:?}"
        );
    }

    // ── I14 ──────────────────────────────────────────────────────────────
    /// **`store_blob_local` — the storage floor — has no production caller
    /// outside the two cascades.**
    ///
    /// A floor with a public door is a bypass. The first implementation's
    /// scoped write door called the floor directly for self/family, which is
    /// precisely how plaintext ended up under a private cohort.
    #[test]
    fn i14_the_storage_floor_has_no_door() {
        let allowed = [
            "src/federation/at_rest_cascade.rs", // the self/family cascade
            "src/federation/community_dek.rs",   // the community cascade
        ];
        let mut offenders = Vec::new();
        for entry in walkdir("src") {
            let rel = entry
                .strip_prefix(&format!("{}/", env!("CARGO_MANIFEST_DIR")))
                .unwrap_or(&entry)
                .to_owned();
            if !rel.ends_with(".rs") || allowed.contains(&rel.as_str()) {
                continue;
            }
            let text = production_only(&std::fs::read_to_string(&entry).unwrap());
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                if line.contains(".store_blob_local(") || line.contains(" store_blob_local(") {
                    // the trait DECLARATION and impls are not callers
                    if line.trim_start().starts_with("fn store_blob_local")
                        || line.trim_start().starts_with("async fn store_blob_local")
                    {
                        continue;
                    }
                    // A COMMONS door may reach the floor, but only by naming a
                    // commons scope as a LITERAL CONSTANT in the call itself —
                    // never a variable, which could carry an encrypted cohort.
                    // The call spans lines; look at the argument window.
                    let window = lines[n..(n + 8).min(lines.len())].join("\n");
                    let commons_literal = window.contains("cohort_scope::FEDERATION")
                        || window.contains("cohort_scope::SPECIES")
                        || window.contains("cohort_scope::BIOSPHERE");
                    if commons_literal {
                        continue;
                    }
                    offenders.push(format!("  {rel}:{} {}", n + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "I14: production callers of the storage floor outside the two cascades — each is \
             a door that can place bytes under a cohort without sealing them:\n{}",
            offenders.join("\n")
        );
    }

    fn walkdir(rel: &str) -> Vec<String> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p.to_string_lossy().into_owned());
                }
            }
        }
        out
    }
}
