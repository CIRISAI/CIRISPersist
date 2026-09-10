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
            // C3-4 — the sweep's POLICY, not only the sweep.
            ("community_dek_set_retain_past_epochs", "retain"),
            // #832 (§12) — the chunk-DAG doors: the encrypted chunk write,
            // the scoped seal, the decrypting range read, the live handle.
            ("put_blob_chunk_scoped", "chunk_scoped"),
            ("seal_stream_scoped", "seal_scoped"),
            ("read_any_range_for_viewer", "read_blob_range_as"),
            ("stream_chunks(", "stream_chunks"),
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
            // #832
            "put_blob_chunk_scoped",
            "seal_stream_scoped",
            "read_any_range_for_viewer",
            ".stream_chunks(",
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
    /// §11.8 — **the hardware content master is resolved through the
    /// process cache by every backend.** The cache (`hardware_content_master_cached`)
    /// existed in `30fde79` with zero callers, so each encrypted read and write
    /// on a hardware-rooted node re-ran TPM + filesystem I/O (ultrareview).
    /// The sync resolver is the software arm and the error vocabulary; a
    /// backend that calls it directly bypasses the cache.
    #[test]
    fn i26_backends_resolve_the_content_master_through_the_cache() {
        for rel in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            let text = production_only(&src(rel));
            let cached = text
                .matches("resolve_persisted_content_master_cached(")
                .count();
            let direct = text.matches("resolve_persisted_content_master(").count();
            assert!(
                cached >= 1,
                "I26: {rel} never resolves the content master through the cache"
            );
            assert_eq!(
                direct, 0,
                "I26: {rel} calls the uncached resolver {direct} time(s) — every encrypted \
                 read/write on a hardware-rooted node pays TPM + filesystem I/O"
            );
        }
    }

    /// **`store_blob_local` — the storage floor — has no production caller
    /// outside the two cascades.**
    ///
    /// A floor with a public door is a bypass. The first implementation's
    /// scoped write door called the floor directly for self/family, which is
    /// precisely how plaintext ended up under a private cohort.
    /// §11.6 / I30 — **the Python sweep report carries every field the
    /// report has.** The second rebuild serialized four of five and dropped
    /// `failed`, so an operator saw a clean report over retained bytes.
    #[test]
    fn i30_python_sweep_report_carries_every_field() {
        let dek = src("src/federation/community_dek.rs");
        let ffi = production_only(&src("src/ffi/pyo3.rs"));
        let start = dek.find("pub struct SweepReport {").expect("SweepReport");
        let body = &dek[start..start + dek[start..].find("\n    }\n").expect("struct end")];
        let fields: Vec<&str> = body
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub "))
            .filter(|l| !l.starts_with("struct "))
            .filter_map(|l| l.split(':').next())
            .collect();
        assert!(fields.len() >= 5, "I30: parsed {fields:?}");
        for func in ["fn sweep_community_epochs(", "fn sweep_all_communities("] {
            let at = ffi
                .find(func)
                .unwrap_or_else(|| panic!("I30: {func} binding"));
            let end = ffi[at..]
                .find("\n    }\n")
                .map(|e| at + e)
                .unwrap_or(ffi.len());
            let body = &ffi[at..end];
            let missing: Vec<&&str> = fields
                .iter()
                .filter(|f| !body.contains(&format!("\"{f}\"")))
                .collect();
            assert!(
                missing.is_empty(),
                "I30: SweepReport fields absent from the Python serializer `{func}`: {missing:?}"
            );
        }
    }

    #[test]
    fn i14_the_storage_floor_has_no_door() {
        let allowed = [
            "src/federation/at_rest_cascade.rs",   // the self/family cascade
            "src/federation/community_dek.rs",     // the community cascade
            "src/federation/chunk_dag_cascade.rs", // #832 — the chunk cascade
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
                let floor_call = [
                    ".store_blob_local(",
                    ".put_blob_with_scope(",
                    ".put_blob_signing_at(",
                    // #832 (§12.3) — the chunk floor and the manifest floor.
                    ".put_blob_chunk_with_scope(",
                    ".seal_stream_with_scope(",
                ]
                .iter()
                .any(|m| line.contains(m));
                if floor_call {
                    // the trait DECLARATION and impls are not callers
                    if line.trim_start().starts_with("fn ")
                        || line.trim_start().starts_with("async fn ")
                    {
                        continue;
                    }
                    // blobs.rs holds the trait's own thin commons wrappers and
                    // the default `put_blob_signing_at` → `put_blob_with_scope`
                    // hop, which forwards a scope the CALLER already validated
                    // at a door. The floor itself is not a caller of itself.
                    if rel == "src/federation/blobs.rs" && !line.contains(".store_blob_local(") {
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

    // ── I36 ──────────────────────────────────────────────────────────────
    /// §12.4 — **the transfer path never decrypts.**
    ///
    /// Every `serve_blob*` facade on the Engine (the whole-blob serve, and
    /// the ranged serve #821 adds beside it) and both backends'
    /// `get_blob_range` hand out STORED bytes — ciphertext for a sealed row.
    /// A decrypt added to any of them would leak plaintext to a relay one
    /// request at a time with nothing red, so this reads the bodies from
    /// disk and reds on any decrypting call.
    #[test]
    fn i36_the_transfer_path_never_decrypts() {
        let decrypting = [
            "open(",
            "unwrap_dek",
            "read_any_for_viewer",
            "read_any_range_for_viewer",
            "read_for_viewer",
            "read_for_community_viewer",
            "aes_gcm::decrypt",
            "read_dag_for_viewer_authorized",
        ];
        let mut offenders = Vec::new();
        let mut inspected = 0usize;
        let mut check = |rel: &str, fn_prefix: &str| {
            let text = production_only(&src(rel));
            let mut i = 0;
            while let Some(off) = text[i..].find(fn_prefix) {
                let start = i + off;
                // A body ends at the next `\n    }\n` (impl-level indentation).
                let end = text[start..]
                    .find("\n    }\n")
                    .map(|e| start + e)
                    .unwrap_or(text.len());
                let body = &text[start..end];
                let name = body
                    .trim_start()
                    .trim_start_matches("pub async fn ")
                    .trim_start_matches("async fn ")
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("?")
                    .to_owned();
                inspected += 1;
                for d in decrypting {
                    if body.contains(d) {
                        offenders.push(format!("  {rel}: fn {name} contains `{d}`"));
                    }
                }
                i = end.max(start + 1);
            }
        };
        check("src/engine.rs", "pub async fn serve_blob");
        check("src/store/sqlite.rs", "async fn get_blob_range(");
        check("src/store/postgres.rs", "async fn get_blob_range(");
        assert!(
            inspected >= 3,
            "I36: expected at least serve_blob_to_peer + two get_blob_range bodies, inspected {inspected}"
        );
        assert!(
            offenders.is_empty(),
            "I36: the transfer path grew a decrypt — a relay would hand plaintext to a peer:\n{}",
            offenders.join("\n")
        );
    }

    // ── I39 ──────────────────────────────────────────────────────────────
    /// §12.7 — **every seal/open surface #832 added carries the `aad` hook
    /// for #831**, on the orchestrate doors, the Engine facades and the
    /// Python bindings, so that when CIRISVerify#279 lands, #831 flips
    /// `seal` / `open` and no surface has to be found.
    #[test]
    fn i39_every_new_door_carries_the_aad_hook() {
        let want: [(&str, &str, &str); 12] = [
            (
                "src/federation/at_rest_cascade.rs",
                "pub fn seal(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/federation/at_rest_cascade.rs",
                "pub fn open(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/federation/at_rest_cascade.rs",
                "pub async fn read_any_for_viewer<",
                "aad: Option<&[u8]>",
            ),
            (
                "src/federation/chunk_dag_cascade.rs",
                "pub async fn put_blob_chunk_scoped<",
                "aad: Option<&[u8]>",
            ),
            (
                "src/federation/chunk_dag_cascade.rs",
                "pub async fn seal_stream_scoped<",
                "aad: Option<&[u8]>",
            ),
            (
                "src/federation/chunk_dag_cascade.rs",
                "pub async fn read_any_range_for_viewer<",
                "aad: Option<&[u8]>",
            ),
            (
                "src/engine.rs",
                "pub async fn read_blob_as(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/engine.rs",
                "pub async fn read_blob_range_as(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/engine.rs",
                "pub async fn put_blob_chunk_scoped(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/engine.rs",
                "pub async fn seal_stream_scoped(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/ffi/pyo3.rs",
                "fn read_blob_range_as(",
                "aad_b64: Option<&str>",
            ),
            (
                "src/ffi/pyo3.rs",
                "fn seal_stream_scoped(",
                "aad_b64: Option<&str>",
            ),
        ];
        let mut missing = Vec::new();
        for (rel, sig, param) in want {
            let text = production_only(&src(rel));
            let Some(at) = text.find(sig) else {
                missing.push(format!("  {rel}: `{sig}` not found"));
                continue;
            };
            let end = text[at..].find(')').map(|e| at + e).unwrap_or(text.len());
            if !text[at..end].contains(param) {
                missing.push(format!("  {rel}: `{sig}` lacks `{param}`"));
            }
        }
        assert!(
            missing.is_empty(),
            "I39: surfaces without the #831 AAD hook (#831 becomes a hunt, not a flip):\n{}",
            missing.join("\n")
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
