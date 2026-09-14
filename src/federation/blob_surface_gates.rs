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
            // #838 (§12.10) — the by-position chunk read: since a sealed
            // chunk is bound to where it was written, this is the only door
            // that opens one outside its manifest.
            ("read_stream_chunk_as", "read_stream_chunk_as"),
            // #846 (BLOB_REPLICATION.md §6) — the adopt doors and the WILL
            // decision: a node that cannot store what it pulls has no
            // holder plane, and a scheduler that cannot ask before fetching
            // fetches blind.
            ("adopt_sealed_blob(", "adopt_sealed_blob"),
            ("would_hold(", "would_hold"),
            ("hold_breadth(", "hold_breadth"),
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
            // #846
            ".adopt_sealed_blob(",
            ".would_hold(",
            ".hold_breadth(",
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

    // ── I54 ──────────────────────────────────────────────────────────────
    /// §12.11 (#843) — **every Python cascade-result serializer carries the
    /// roster partition and `readable_by_nobody`.** The Rust structs carry
    /// them by type; a JSON serializer carries only what it names, and the
    /// consumer #843 was opened on reads JSON. Same shape as I30: a
    /// serializer that drops a field is a report over a fact it hides.
    #[test]
    fn i54_every_cascade_serializer_carries_the_roster_partition() {
        let ffi = production_only(&src("src/ffi/pyo3.rs"));
        let bindings = [
            "fn put_blob_encrypted_community(",
            "fn put_blob_scoped(",
            "fn put_blob_chunk_scoped(",
            "fn seal_stream_scoped(",
            "fn put_blob_encrypted_self_family(",
        ];
        let keys = [
            "\"granted\"",
            "\"excluded\"",
            "\"roster\"",
            "\"readable_by_nobody\"",
        ];
        let mut missing = Vec::new();
        for func in bindings {
            let at = ffi
                .find(func)
                .unwrap_or_else(|| panic!("I54: {func} binding"));
            let end = ffi[at..]
                .find("\n    }\n")
                .map(|e| at + e)
                .unwrap_or(ffi.len());
            let body = &ffi[at..end];
            for key in keys {
                if !body.contains(key) {
                    missing.push(format!("  {func} lacks {key}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "I54: cascade-result serializers without the roster partition — a Python caller \
             cannot learn that nobody can read what it just wrote:\n{}",
            missing.join("\n")
        );
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
        let want: [(&str, &str, &str); 15] = [
            (
                "src/federation/at_rest_cascade.rs",
                "pub fn seal(",
                "aad: Option<&[u8]>",
            ),
            // #838 — the by-position chunk read, on all three surfaces.
            (
                "src/federation/chunk_dag_cascade.rs",
                "pub async fn read_stream_chunk_as<",
                "aad: Option<&[u8]>",
            ),
            (
                "src/engine.rs",
                "pub async fn read_stream_chunk_as(",
                "aad: Option<&[u8]>",
            ),
            (
                "src/ffi/pyo3.rs",
                "fn read_stream_chunk_as(",
                "aad_b64: Option<&str>",
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

    // ── I45 ──────────────────────────────────────────────────────────────
    /// `BLOB_REPLICATION.md` §7 — **the adopt path never decrypts.** The
    /// receiver-side twin of I36: `adopt_sealed_blob`, `adopt_sealed_chunk`,
    /// the Engine facades and both backends' adopt floors hand the envelope
    /// to the row verbatim. A receiver that peeks at what it relays would be
    /// a decrypt with nothing red, so the bodies are read from disk.
    #[test]
    fn i45_the_adopt_path_never_decrypts() {
        let decrypting = [
            "open(",
            "open_aad(",
            "unwrap_dek",
            "read_any",
            "read_for_viewer",
            "read_for_community_viewer",
            "aes_gcm::decrypt",
        ];
        let mut offenders = Vec::new();
        let mut inspected = 0usize;
        let mut check = |rel: &str, fn_prefix: &str, end_marker: &str| {
            let text = production_only(&src(rel));
            let mut i = 0;
            while let Some(off) = text[i..].find(fn_prefix) {
                let start = i + off;
                let end = text[start..]
                    .find(end_marker)
                    .map(|e| start + e)
                    .unwrap_or(text.len());
                let body = &text[start..end];
                inspected += 1;
                for d in decrypting {
                    if body.contains(d) {
                        offenders.push(format!("  {rel}: `{fn_prefix}` contains `{d}`"));
                    }
                }
                i = end.max(start + 1);
            }
        };
        // The orchestration (module-level fns end at `\n}\n`).
        check(
            "src/federation/adopt_cascade.rs",
            "pub async fn adopt_sealed_blob<",
            "\n}\n",
        );
        check(
            "src/federation/adopt_cascade.rs",
            "pub async fn adopt_sealed_chunk<",
            "\n}\n",
        );
        check(
            "src/federation/adopt_cascade.rs",
            "fn resolve_adopt(",
            "\n}\n",
        );
        // The Engine facades and the floors (impl-level fns end at `\n    }\n`).
        check(
            "src/engine.rs",
            "pub async fn adopt_sealed_blob(",
            "\n    }\n",
        );
        check(
            "src/engine.rs",
            "pub async fn adopt_sealed_chunk(",
            "\n    }\n",
        );
        for rel in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            check(rel, "async fn adopt_sealed_blob_at(", "\n    }\n");
            check(rel, "async fn adopt_sealed_chunk_at(", "\n    }\n");
            check(rel, "async fn put_blob_chunk_floor(", "\n    }\n");
        }
        assert_eq!(
            inspected, 11,
            "I45: expected 3 orchestration + 2 Engine + 6 floor bodies, inspected {inspected} — \
             a door this gate cannot find is a door it cannot hold"
        );
        assert!(
            offenders.is_empty(),
            "I45: the adopt path grew a decrypt — a receiver would peek at what it relays:\n{}",
            offenders.join("\n")
        );
    }

    // ── I46 ──────────────────────────────────────────────────────────────
    /// `BLOB_REPLICATION.md` §7 — **the WILL decision runs on every
    /// consumer-reachable accept door and exists in exactly one place.**
    /// `adopt_sealed_blob`, `adopt_sealed_chunk` and `put_blob_signing` all
    /// call `would_hold`; no production site outside `hold.rs` (the
    /// decision) and `disk_pressure.rs` (the snapshot's producer) reads
    /// `refuses_proxy_writes` — a second copy of the accept rule is the
    /// door that accepts under `Stop`.
    #[test]
    fn i46_the_will_decision_has_one_home_and_every_accept_door_runs_it() {
        let fn_body = |rel: &str, sig: &str, end_marker: &str| -> String {
            let text = production_only(&src(rel));
            let at = text
                .find(sig)
                .unwrap_or_else(|| panic!("I46: `{sig}` not found in {rel}"));
            let end = text[at..]
                .find(end_marker)
                .map(|e| at + e)
                .unwrap_or(text.len());
            text[at..end].to_owned()
        };
        let mut missing = Vec::new();
        for (rel, sig, end, call) in [
            (
                "src/federation/adopt_cascade.rs",
                "pub async fn adopt_sealed_blob<",
                "\n}\n",
                "would_hold(",
            ),
            (
                "src/federation/adopt_cascade.rs",
                "pub async fn adopt_sealed_chunk<",
                "\n}\n",
                "would_hold(",
            ),
            (
                "src/engine.rs",
                "pub async fn put_blob_signing(",
                "\n    }\n",
                ".would_hold(",
            ),
        ] {
            if !fn_body(rel, sig, end).contains(call) {
                missing.push(format!("  {rel}: `{sig}` does not call `{call}`"));
            }
        }
        assert!(
            missing.is_empty(),
            "I46: accept doors that do not run the WILL decision:\n{}",
            missing.join("\n")
        );
        let allowed = [
            "src/federation/replication/hold.rs",
            "src/federation/replication/disk_pressure.rs",
            // this file: its own vocabulary
            "src/federation/blob_surface_gates.rs",
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
            for (n, line) in text.lines().enumerate() {
                let t = line.trim_start();
                // A REPORT of the snapshot (the Python `disk_pressure_state`
                // dict) is not a decision; a read in a condition is.
                if t.starts_with("//") || line.contains("set_item(") {
                    continue;
                }
                if line.contains("refuses_proxy_writes") {
                    offenders.push(format!("  {rel}:{} {}", n + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "I46: production sites reading `refuses_proxy_writes` outside the WILL decision — \
             each is a second accept rule that will drift from the first:\n{}",
            offenders.join("\n")
        );
    }

    // ── I48 (the correction) ─────────────────────────────────────────────
    /// **Serve standing never gates ACCEPT.** Role governs the BREADTH of
    /// holding (`hold_breadth`), not permission: a node that is party to
    /// content holds it whatever its serve tier, and a node that is not
    /// party to it refuses whatever its serve tier. `would_hold` and the
    /// adopt path therefore name no serve tier.
    #[test]
    fn i48_would_hold_and_the_adopt_path_consult_no_serve_tier() {
        let serve = ["resolve_serve_tier", "ServeTier"];
        let mut offenders = Vec::new();
        for (rel, sig, end) in [
            (
                "src/federation/replication/hold.rs",
                "pub async fn would_hold<",
                "\n}\n",
            ),
            (
                "src/federation/replication/hold.rs",
                "pub async fn is_audience<",
                "\n}\n",
            ),
            (
                "src/federation/adopt_cascade.rs",
                "pub async fn adopt_sealed_blob<",
                "\n}\n",
            ),
            (
                "src/federation/adopt_cascade.rs",
                "pub async fn adopt_sealed_chunk<",
                "\n}\n",
            ),
            ("src/engine.rs", "pub async fn would_hold(", "\n    }\n"),
            (
                "src/engine.rs",
                "pub async fn adopt_sealed_blob(",
                "\n    }\n",
            ),
            (
                "src/engine.rs",
                "pub async fn adopt_sealed_chunk(",
                "\n    }\n",
            ),
        ] {
            let text = production_only(&src(rel));
            let at = text
                .find(sig)
                .unwrap_or_else(|| panic!("I48: `{sig}` not found in {rel}"));
            let stop = text[at..].find(end).map(|e| at + e).unwrap_or(text.len());
            let body = &text[at..stop];
            for s in serve {
                if body.contains(s) {
                    offenders.push(format!("  {rel}: `{sig}` names `{s}`"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "I48: the accept decision consults serve standing — a role would then gate what a \
             party-to node may hold, or admit what a non-party node may not:\n{}",
            offenders.join("\n")
        );
    }

    // ── I49 ──────────────────────────────────────────────────────────────
    /// `BLOB_REPLICATION.md` §5 — **`is_proxy_content` is the one
    /// classification.** The force-evict sweep, `serve_blob_to_peer` and
    /// `would_hold` call it, and no production site outside `hold.rs` runs
    /// the local-or-family predicate for a proxy decision of its own.
    #[test]
    fn i49_is_proxy_content_is_the_one_classification() {
        let engine = production_only(&src("src/engine.rs"));
        let hold = production_only(&src("src/federation/replication/hold.rs"));
        let body = |text: &str, sig: &str, end: &str| -> String {
            let at = text
                .find(sig)
                .unwrap_or_else(|| panic!("I49: `{sig}` not found"));
            let stop = text[at..].find(end).map(|e| at + e).unwrap_or(text.len());
            text[at..stop].to_owned()
        };
        let mut missing = Vec::new();
        for (name, b) in [
            (
                "Engine::sweep_evictions_once_inner",
                body(&engine, "async fn sweep_evictions_once_inner(", "\n    }\n"),
            ),
            (
                "Engine::serve_blob_to_peer",
                body(&engine, "pub async fn serve_blob_to_peer(", "\n    }\n"),
            ),
            (
                "hold::would_hold",
                body(&hold, "pub async fn would_hold<", "\n}\n"),
            ),
        ] {
            if !b.contains("is_proxy_content(") {
                missing.push(format!("  {name} does not call is_proxy_content"));
            }
        }
        assert!(
            missing.is_empty(),
            "I49: proxy decisions not made through the one predicate:\n{}",
            missing.join("\n")
        );
        // No production site outside the decision module runs the predicate
        // for itself. The Engine's `is_local_or_family_key` and the config's
        // `is_local_or_family` are definitions; a CALL to either is a second
        // classification.
        let mut offenders = Vec::new();
        for entry in walkdir("src") {
            let rel = entry
                .strip_prefix(&format!("{}/", env!("CARGO_MANIFEST_DIR")))
                .unwrap_or(&entry)
                .to_owned();
            if !rel.ends_with(".rs")
                || rel == "src/federation/replication/hold.rs"
                || rel == "src/federation/replication/disk_pressure.rs"
                || rel == "src/federation/blob_surface_gates.rs"
            {
                continue;
            }
            let text = production_only(&std::fs::read_to_string(&entry).unwrap());
            for (n, line) in text.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || t.starts_with("pub fn ") || t.starts_with("fn ") {
                    continue;
                }
                if line.contains(".is_local_or_family(")
                    || line.contains(".is_local_or_family_key(")
                {
                    offenders.push(format!("  {rel}:{} {}", n + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "I49: sites classifying proxy content with their own predicate call — each will \
             drift from is_proxy_content:\n{}",
            offenders.join("\n")
        );
    }

    // ── I53 ──────────────────────────────────────────────────────────────
    /// `BLOB_REPLICATION.md` §2 / CC 1.13.3 — **persist claims exactly two
    /// privacy properties** — content-holding confidentiality and
    /// cohort-scoped visibility — and nothing more. No source or FSD text in
    /// the blob and replication modules claims unobservability,
    /// undiscoverability, metadata privacy or traffic-analysis resistance.
    #[test]
    fn i53_no_privacy_overclaim_in_the_blob_and_replication_text() {
        let overclaims = [
            "unobservable",
            "undiscoverable",
            "metadata privacy",
            "metadata-private",
            "metadata private",
            "traffic analysis",
            "traffic-analysis",
        ];
        let mut files: Vec<String> = walkdir("src/federation/replication");
        files.extend(
            [
                "src/federation/blobs.rs",
                "src/federation/adopt_cascade.rs",
                "src/federation/at_rest_cascade.rs",
                "src/federation/community_dek.rs",
                "src/federation/chunk_dag_cascade.rs",
                "src/federation/namespace/mod.rs",
                "src/federation/replication_policy.rs",
                "FSD/BLOB_REPLICATION.md",
                "FSD/BLOB_ENCRYPTION_AT_REST.md",
            ]
            .into_iter()
            .map(|r| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(r)
                    .to_string_lossy()
                    .into_owned()
            }),
        );
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        for path in files {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            let rel = path
                .strip_prefix(&format!("{}/", env!("CARGO_MANIFEST_DIR")))
                .unwrap_or(&path)
                .to_owned();
            for (n, line) in text.lines().enumerate() {
                let lower = line.to_ascii_lowercase();
                // The gate's own vocabulary, and the FSD sentence that names
                // the words persist must NOT use, are not claims.
                // …and one FSD sentence about WRITE ORDERING ("ordering is
                // unobservable through a door"), which is not a privacy
                // claim: it says a staged row cannot be seen mid-write.
                if lower.contains("i53")
                    || lower.contains("never \"unobservable\"")
                    || lower.contains("overclaim")
                    || lower.contains("ordering is unobservable")
                {
                    continue;
                }
                for w in overclaims {
                    if lower.contains(w) {
                        offenders.push(format!("  {rel}:{} `{w}`: {}", n + 1, line.trim()));
                    }
                }
            }
        }
        assert!(scanned >= 10, "I53: scanned only {scanned} files");
        assert!(
            offenders.is_empty(),
            "I53: text claiming a privacy property persist does not provide (CC 1.13.3 names \
             exactly two):\n{}",
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
