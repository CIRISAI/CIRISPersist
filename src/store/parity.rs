//! **The backend-parity gate** (v31.2.0, CIRISPersist#670).
//!
//! `README.md` says persist behaves the same on postgres, sqlite and memory
//! *"as an enforced invariant."* Until this module, it was not enforced — it
//! was convention plus per-case witnesses, and v31 alone found five
//! divergences of one shape: **a gate, an order, or a type that one backend
//! has and its siblings do not**. The recurring cost is always the same. The
//! memory and sqlite arms are correct, so nobody can see it, and it surfaces
//! on the one backend production runs.
//!
//! # What this module does
//!
//! It reads `src/store/{memory,sqlite,postgres}.rs` **from disk as text** and,
//! for every method of the three backend traits, extracts the **ordered
//! sequence of gate calls** the method makes. All three backends must produce
//! the same sequence. A gate present in two and absent in the third is a test
//! failure naming the backend and the missing call; so is the same set of
//! gates in a different order, because CIRISPersist#660 was an *ordering* bug
//! with all the right gates present.
//!
//! Reading from disk rather than reflecting over the compiled crate is
//! deliberate and load-bearing: it means **the postgres arm is scanned under
//! `--features sqlite`, and under no features at all**. A conformance check
//! that only runs when the backend it checks is compiled is a check that goes
//! dark exactly where this class of defect lives. It is the same idiom as
//! [`nothing_yields_anti_entropy_satisfied_today`] and
//! [`every_cited_processor_has_a_non_test_caller`], which this repo already
//! trusts.
//!
//! [`nothing_yields_anti_entropy_satisfied_today`]: crate::federation::load_bearing
//! [`every_cited_processor_has_a_non_test_caller`]: crate::federation::namespace::supersets
//!
//! # The door set is DERIVED, never listed
//!
//! There is no hand-maintained list of doors. The universe is *every method of
//! `FederationDirectory`, `BlobStorage` and `Backend` that any backend
//! implements* — read out of the impl blocks themselves. Adding a door
//! therefore enrols it in the gate on the commit that adds it, with nothing to
//! remember. A hand-maintained list someone must extend is the defect this
//! release found four times over; [`DECLARED_DIVERGENCES`] is a *subtractive*
//! manifest over a derived set, the `KNOWN_AXIS_FUSIONS` partition discipline.
//!
//! # What it cannot see
//!
//! - **Gates reached through a helper in another file.** Calls are inlined two
//!   levels deep, but only into functions defined in the *same* backend file.
//!   A gate that moved to a shared module and is called from one backend only
//!   is still visible (the call itself is the token); a gate reached through a
//!   *private helper* that also moved is not.
//! - **Semantics.** Two backends can call the same gate with different
//!   arguments. That is [`check_row_column_binding`]-shaped work, not this.
//! - **SQL.** A CHECK constraint, a column type, or a `DEFAULT` is invisible
//!   here by construction. That is where CIRISPersist#622 (postgres typed
//!   `revocation_id` as `UUID` while its siblings took any TEXT) and #656
//!   (postgres omitted `last_accessed_at` / `access_count` from blob inserts,
//!   where sqlite's DEFAULT is a 1970 epoch sentinel the eviction sweeper
//!   orders on) both lived. Those need a mechanism that reads SQL, not Rust —
//!   see `store::schema_parity`.
//!
//! [`check_row_column_binding`]: crate::federation::admission::check_row_column_binding

/// One reviewed, written-down reason a single backend's gate sequence differs
/// from its siblings'.
///
/// **An exemption is a pin, not a waiver.** It names the exact sequence that
/// backend is allowed to have, so an exemption cannot silently widen: drop
/// another gate from an exempted door and the pinned sequence stops matching.
/// It is also checked in the *other* direction — a divergence that has since
/// been fixed makes its exemption stale, and a stale exemption fails
/// [`tests::no_declared_divergence_is_stale`]. An omission is invisible; an
/// exemption someone had to write down is reviewable.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct DeclaredDivergence {
    /// The trait the method belongs to (`FederationDirectory` / `BlobStorage`
    /// / `Backend`).
    pub trait_name: &'static str,
    /// The method whose gate sequence diverges.
    pub method: &'static str,
    /// The backend that diverges. The remaining backends must still agree
    /// with each other.
    pub backend: &'static str,
    /// The exact gate sequence this backend is permitted to have. Pinned so an
    /// exemption authorises **one** shape rather than "anything goes".
    pub expected: &'static [&'static str],
    /// Why this is a substrate difference and not a hole. Reviewed prose, not
    /// a label — [`tests::every_declared_divergence_states_a_substantive_reason`]
    /// enforces a floor on it.
    pub reason: &'static str,
}

/// The reviewed divergences. Everything not listed here must be identical
/// across the three backends, gate for gate and order for order.
#[cfg(test)]
pub(crate) const DECLARED_DIVERGENCES: &[DeclaredDivergence] = &[
    DeclaredDivergence {
        trait_name: "FederationDirectory",
        method: "put_goal",
        backend: "memory",
        expected: &[],
        reason: "`canonicalize_goal_text` on the SQL backends feeds the V050 \
                 `goal_text_canonical` column, a write-only projection: nothing reads it back \
                 into a `Goal`, and the round-trip a caller observes is over `goal_text`, which \
                 is stored verbatim on all three. The memory backend has no column to project \
                 into, so running the canonicalizer here would compute a value and drop it. If \
                 `goal_text_canonical` ever acquires a reader, this exemption is wrong and the \
                 memory backend needs a projected field.",
    },
    DeclaredDivergence {
        trait_name: "FederationDirectory",
        method: "put_revocation",
        backend: "memory",
        expected: &[
            "canonicalize_in_place",
            "check_revocation_envelope_binding",
            "check_federation",
            "check_content_hash_hex",
            "verify_revocation_admission",
            "check_revocation_authority",
            "check_observed_region",
            "check_revocation_scrub_skew",
            "check_revocation_bound",
            "check_revocation_anti_rollback",
        ],
        reason: "The anti-rollback needs the newest stored `scrub_timestamp` for the subject. On \
                 sqlite and postgres that is a query the door can issue before it opens its \
                 write; on memory it is a scan under the state lock, and taking the lock is what \
                 the door does after `check_revocation_bound`. Running it under the SAME lock the \
                 insert holds is stronger than the SQL position, not weaker — the read and the \
                 write cannot race. The two gates are both refusals that mutate nothing, so their \
                 relative order is not observable in state, only in which message an operator sees \
                 when a row violates both. The RULE is the shared \
                 `check_revocation_anti_rollback`; only \"find the newest stored row\" is \
                 per-substrate.",
    },
    DeclaredDivergence {
        trait_name: "FederationDirectory",
        method: "reseal_attestation_v31",
        backend: "memory",
        expected: &[
            "check_reseal_admission",
            "check_reseal_seal_admission",
            "check_reseal_admission",
        ],
        reason: "Memory asks the pure shape gate TWICE: once before the lock, in the AV-76 tier \
                 order its siblings run, and once again on the row it actually found under the \
                 lock. The SQL backends get that second answer from their transaction — they read \
                 and update inside one — and memory's read is a separate `get_attestation` that \
                 locks and releases, so without the re-ask the door would gate one row and mutate \
                 another. An extra ask of a pure refusal is the safe direction of this difference.",
    },
];

#[cfg(test)]
mod tests {
    use super::{DeclaredDivergence, DECLARED_DIVERGENCES};
    use std::collections::{BTreeMap, BTreeSet};

    /// The three backend sources, by the name the failure message uses.
    const BACKENDS: [(&str, &str); 3] = [
        ("memory", "src/store/memory.rs"),
        ("sqlite", "src/store/sqlite.rs"),
        ("postgres", "src/store/postgres.rs"),
    ];

    /// The traits whose impls are compared, and where each trait's **default**
    /// bodies live. A backend that does not override a defaulted method runs
    /// the default, so the default's gate sequence is what it contributes —
    /// which is how "sqlite overrode this and dropped a gate the default had"
    /// becomes visible.
    const TRAITS: [(&str, &str); 3] = [
        ("FederationDirectory", "src/federation/mod.rs"),
        ("BlobStorage", "src/federation/blobs.rs"),
        ("Backend", "src/store/backend.rs"),
    ];

    /// A call is a **gate call** when its name begins with one of these and an
    /// underscore (`check_cohort_scope`), or when the name is exactly one of
    /// them and it is a method on a receiver
    /// (`hardware_attestation_policy().check`). Two rules rather than one
    /// because a bare `admits(` is a boolean predicate on a read path, while a
    /// bare `.check(` is a policy object refusing.
    const GATE_VERBS: [&str; 9] = [
        "check",
        "verify",
        "validate",
        "require",
        "admit",
        "enforce",
        "guard",
        "canonicalize",
        "refuse",
    ];

    /// Receiver-method form is accepted only for these exact names. `admits`,
    /// `validates`, and friends are predicates, not refusals, and admitting
    /// them made read paths look divergent for no behavioural reason.
    const RECEIVER_GATE_NAMES: [&str; 5] = ["check", "verify", "validate", "enforce", "admit"];

    /// Trailing substrate suffixes stripped before comparison.
    /// `check_revocation_anti_rollback_sqlite` and `..._postgres` are ONE
    /// logical gate whose "find the newest stored row" half is per-substrate;
    /// treating the names as different gates would report a divergence that is
    /// only spelling. Nothing else is normalised — in particular, no
    /// abbreviation and no case folding, so `check_x` and `check_x_v2` stay
    /// distinct.
    const SUBSTRATE_SUFFIXES: [&str; 5] = ["_memory", "_sqlite", "_postgres", "_pg", "_mem"];

    /// How deep a call into a same-file helper is followed. Two levels covers
    /// `attestation_upsert_local` → `*_write_local_attestation` → the gate
    /// block, which is where CIRISPersist#598's local-write doors live.
    const INLINE_DEPTH: usize = 2;

    fn manifest_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(rel: &str) -> String {
        let p = manifest_dir().join(rel);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    // ── lexing ──────────────────────────────────────────────────────

    /// Blank out `//` comments and string/char literal *contents* on one line,
    /// preserving byte offsets so nothing downstream has to track a shift.
    ///
    /// Block comments are not handled: this crate's backend sources use `//`
    /// and `///` exclusively, and [`no_backend_source_uses_block_comments`]
    /// keeps it that way rather than leaving the gap implicit.
    fn strip(line: &str) -> String {
        let bytes = line.as_bytes();
        let mut out = vec![b' '; bytes.len()];
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => break,
                c => {
                    out[i] = c;
                    i += 1;
                }
            }
        }
        String::from_utf8(out).unwrap_or_default()
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Tok {
        Ident(String),
        Punct(u8),
    }

    fn lex(line: &str) -> Vec<Tok> {
        let b = line.as_bytes();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < b.len() {
            let c = b[i];
            if c.is_ascii_alphanumeric() || c == b'_' {
                let s = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push(Tok::Ident(line[s..i].to_owned()));
            } else if c.is_ascii_whitespace() {
                i += 1;
            } else {
                out.push(Tok::Punct(c));
                i += 1;
            }
        }
        out
    }

    fn strip_substrate_suffix(name: &str) -> String {
        for s in SUBSTRATE_SUFFIXES {
            if let Some(base) = name.strip_suffix(s) {
                if !base.is_empty() {
                    return base.to_owned();
                }
            }
        }
        name.to_owned()
    }

    fn gate_token(name: &str, receiver: Option<&str>) -> Option<String> {
        for v in GATE_VERBS {
            if name.len() > v.len() + 1
                && name.starts_with(v)
                && name.as_bytes()[v.len()] == b'_'
                && name[v.len() + 1..].starts_with(|c: char| c.is_ascii_lowercase())
            {
                return Some(strip_substrate_suffix(name));
            }
        }
        if RECEIVER_GATE_NAMES.contains(&name) {
            if let Some(r) = receiver {
                return Some(format!("{}.{}", strip_substrate_suffix(r), name));
            }
        }
        None
    }

    /// Every `IDENT (` call on a lexed line, left to right, with the receiver
    /// (`a.NAME(`, `A::NAME(`, `a().NAME(`) when there is one.
    fn calls_on_line(toks: &[Tok]) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        for (i, t) in toks.iter().enumerate() {
            let Tok::Ident(name) = t else { continue };
            // `fn NAME(` is a definition, not a call.
            if i > 0 && matches!(&toks[i - 1], Tok::Ident(k) if k == "fn") {
                continue;
            }
            match toks.get(i + 1) {
                Some(Tok::Punct(b'(')) => {}
                // `NAME!(` is a macro; `assert_eq!` must not read as a gate.
                _ => continue,
            }
            let mut receiver = None;
            if i >= 2 {
                match (&toks[i - 1], &toks[i - 2]) {
                    (Tok::Punct(b'.'), Tok::Ident(r)) => receiver = Some(r.clone()),
                    (Tok::Punct(b':'), Tok::Punct(b':')) if i >= 3 => {
                        if let Tok::Ident(r) = &toks[i - 3] {
                            receiver = Some(r.clone());
                        }
                    }
                    (Tok::Punct(b'.'), Tok::Punct(b')')) if i >= 4 => {
                        if let (Tok::Punct(b'('), Tok::Ident(r)) = (&toks[i - 3], &toks[i - 4]) {
                            receiver = Some(r.clone());
                        }
                    }
                    _ => {}
                }
            }
            out.push((name.clone(), receiver));
        }
        out
    }

    // ── block structure ─────────────────────────────────────────────

    /// Inclusive `[start, end]` line range of the brace-matched block whose
    /// opening `{` is at or after `from`.
    fn block_end(stripped: &[String], from: usize) -> Option<usize> {
        let mut open = from;
        while open < stripped.len() && !stripped[open].contains('{') {
            open += 1;
        }
        if open >= stripped.len() {
            return None;
        }
        let mut depth = 0i32;
        for (k, line) in stripped.iter().enumerate().skip(open) {
            depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
            depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
            if depth <= 0 {
                return Some(k);
            }
        }
        None
    }

    /// Every `fn` in a file, by name, as inclusive line ranges. Used for the
    /// same-file inlining; a name with several definitions (an inherent method
    /// and a trait method of the same name) yields several ranges and all are
    /// followed, which can only ADD gate tokens — the conservative direction
    /// for a detector.
    fn index_functions(stripped: &[String]) -> BTreeMap<String, Vec<(usize, usize)>> {
        let mut out: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
        let mut i = 0usize;
        while i < stripped.len() {
            if let Some(name) = fn_name_at(&stripped[i]) {
                if let Some(end) = block_end(stripped, i) {
                    out.entry(name).or_default().push((i, end));
                    i = end;
                }
            }
            i += 1;
        }
        out
    }

    /// The most tightly-enclosing `fn` around line `i`, for failure messages.
    fn innermost_fn(index: &BTreeMap<String, Vec<(usize, usize)>>, i: usize) -> String {
        index
            .iter()
            .flat_map(|(n, rs)| rs.iter().map(move |r| (n, r)))
            .filter(|(_, &(a, b))| a <= i && i <= b)
            .max_by_key(|(_, &(a, _))| a)
            .map_or_else(|| "<file scope>".to_owned(), |(n, _)| n.clone())
    }

    fn fn_name_at(line: &str) -> Option<String> {
        let toks = lex(line);
        for (i, t) in toks.iter().enumerate() {
            if matches!(t, Tok::Ident(k) if k == "fn") {
                if let Some(Tok::Ident(n)) = toks.get(i + 1) {
                    return Some(n.clone());
                }
            }
        }
        None
    }

    /// Top-level `impl` blocks, as `(header, start, end)`.
    fn impl_blocks(stripped: &[String]) -> Vec<(String, usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < stripped.len() {
            let l = &stripped[i];
            if l.starts_with("impl ") || l.starts_with("impl<") {
                let mut hdr = String::new();
                let mut j = i;
                while j < stripped.len() && !stripped[j].contains('{') {
                    hdr.push_str(stripped[j].trim());
                    hdr.push(' ');
                    j += 1;
                }
                if j < stripped.len() {
                    hdr.push_str(stripped[j].trim());
                }
                if let Some(end) = block_end(stripped, i) {
                    out.push((hdr, i, end));
                    i = end;
                }
            }
            i += 1;
        }
        out
    }

    /// Does the signature starting at `i` open a body, or is it a `;`-
    /// terminated declaration?
    ///
    /// Load-bearing: a trait's REQUIRED methods have no body, and without this
    /// the brace matcher would run past the declaration and hand back the next
    /// *defaulted* method's body — swallowing it, so the default never enters
    /// the comparison and its overrides look unanchored.
    fn opens_a_body(stripped: &[String], i: usize) -> bool {
        for line in stripped.iter().skip(i) {
            if line.contains('{') {
                return true;
            }
            if line.trim_end().ends_with(';') {
                return false;
            }
        }
        false
    }

    /// The methods declared directly inside `[start, end]`, at one indent
    /// level (four spaces), as `(name, start, end)`.
    fn methods_in(stripped: &[String], start: usize, end: usize) -> Vec<(String, usize, usize)> {
        let mut out = Vec::new();
        let mut i = start;
        while i <= end {
            let l = &stripped[i];
            if l.starts_with("    ") && !l.starts_with("     ") && opens_a_body(stripped, i) {
                if let Some(name) = fn_name_at(l) {
                    if let Some(e) = block_end(stripped, i) {
                        if e <= end {
                            out.push((name, i, e));
                            i = e;
                        }
                    }
                }
            }
            i += 1;
        }
        out
    }

    // ── gate extraction ─────────────────────────────────────────────

    fn gate_sequence(
        stripped: &[String],
        a: usize,
        b: usize,
        index: &BTreeMap<String, Vec<(usize, usize)>>,
        depth: usize,
        seen: &BTreeSet<String>,
    ) -> Vec<String> {
        let mut seq = Vec::new();
        for i in a..=b.min(stripped.len().saturating_sub(1)) {
            for (name, receiver) in calls_on_line(&lex(&stripped[i])) {
                if let Some(tok) = gate_token(&name, receiver.as_deref()) {
                    seq.push(tok);
                    continue;
                }
                if depth == 0 || seen.contains(&name) {
                    continue;
                }
                let Some(ranges) = index.get(&name) else {
                    continue;
                };
                let mut deeper = seen.clone();
                deeper.insert(name.clone());
                for &(fa, fb) in ranges {
                    if fa <= i && i <= fb {
                        continue; // the call is inside the callee — recursion
                    }
                    seq.extend(gate_sequence(stripped, fa, fb, index, depth - 1, &deeper));
                }
            }
        }
        seq
    }

    /// `backend -> (gate sequence, 1-based line of the `fn`)`.
    type PerBackend = BTreeMap<String, (Vec<String>, usize)>;
    /// `(trait, method) -> `[`PerBackend`].
    type DoorMap = BTreeMap<(String, String), PerBackend>;

    struct Scan {
        /// Every method of every scanned trait, by trait and name.
        doors: DoorMap,
        /// Which traits each backend implements at all.
        implements: BTreeMap<String, BTreeSet<String>>,
        /// `(trait, method) -> default-body gate sequence`, for methods the
        /// trait defaults.
        defaults: BTreeMap<(String, String), Vec<String>>,
    }

    fn scan() -> Scan {
        let mut doors: DoorMap = BTreeMap::new();
        let mut implements: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut defaults: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();

        for (trait_name, rel) in TRAITS {
            let text = read(rel);
            let stripped: Vec<String> = text.lines().map(strip).collect();
            let empty = BTreeMap::new();
            let mut i = 0usize;
            while i < stripped.len() {
                let l = &stripped[i];
                if l.contains("trait ") && l.contains(trait_name) && !l.contains("impl") {
                    if let Some(end) = block_end(&stripped, i) {
                        for (name, a, b) in methods_in(&stripped, i, end) {
                            // A required method's "body" is its signature only;
                            // it has no `{`, so `methods_in` never yields it.
                            defaults.insert(
                                (trait_name.to_owned(), name),
                                gate_sequence(&stripped, a, b, &empty, 0, &BTreeSet::new()),
                            );
                        }
                        i = end;
                    }
                }
                i += 1;
            }
        }

        for (backend, rel) in BACKENDS {
            let text = read(rel);
            let stripped: Vec<String> = text.lines().map(strip).collect();
            let index = index_functions(&stripped);
            for (hdr, s, e) in impl_blocks(&stripped) {
                for (trait_name, _) in TRAITS {
                    if !hdr.contains(&format!("{trait_name} for")) {
                        continue;
                    }
                    implements
                        .entry(backend.to_owned())
                        .or_default()
                        .insert(trait_name.to_owned());
                    for (name, a, b) in methods_in(&stripped, s, e) {
                        let mut seen = BTreeSet::new();
                        seen.insert(name.clone());
                        let seq = gate_sequence(&stripped, a, b, &index, INLINE_DEPTH, &seen);
                        doors
                            .entry((trait_name.to_owned(), name))
                            .or_default()
                            .insert(backend.to_owned(), (seq, a + 1));
                    }
                }
            }
        }

        Scan {
            doors,
            implements,
            defaults,
        }
    }

    fn declared(
        trait_name: &str,
        method: &str,
        backend: &str,
    ) -> Option<&'static DeclaredDivergence> {
        DECLARED_DIVERGENCES
            .iter()
            .find(|d| d.trait_name == trait_name && d.method == method && d.backend == backend)
    }

    // ── the gates ───────────────────────────────────────────────────

    /// **CIRISPersist#670 — the invariant `README.md` claims.** Every method
    /// the three backends implement runs the same gates in the same order, or
    /// says in [`DECLARED_DIVERGENCES`] why it does not.
    #[test]
    fn every_backend_runs_the_same_gates_in_the_same_order() {
        let scan = scan();
        let mut failures: Vec<String> = Vec::new();

        for ((trait_name, method), per_backend) in &scan.doors {
            // Which backends are in scope for this trait at all? A backend
            // that does not implement the trait (MemoryBackend has no
            // `BlobStorage`) is not compared; a backend that implements the
            // trait but does not override a defaulted method contributes the
            // DEFAULT's sequence, because that is the code it runs.
            let mut seqs: BTreeMap<&str, (Vec<String>, String)> = BTreeMap::new();
            for (backend, _) in BACKENDS {
                if !scan
                    .implements
                    .get(backend)
                    .is_some_and(|t| t.contains(trait_name))
                {
                    continue;
                }
                if let Some((seq, line)) = per_backend.get(backend) {
                    seqs.insert(
                        backend,
                        (seq.clone(), format!("{backend} (own impl, line {line})")),
                    );
                } else if let Some(def) = scan.defaults.get(&(trait_name.clone(), method.clone())) {
                    seqs.insert(
                        backend,
                        (def.clone(), format!("{backend} (trait default body)")),
                    );
                } else {
                    failures.push(format!(
                        "{trait_name}::{method} — backend `{backend}` implements {trait_name} but \
                         neither overrides this method nor has a trait default to fall back on"
                    ));
                }
            }
            if seqs.len() < 2 {
                continue;
            }

            // Split into exempt and compared. The compared set must agree with
            // itself; each exempt backend must match its pinned sequence.
            let mut compared: BTreeMap<&str, (Vec<String>, String)> = BTreeMap::new();
            for (backend, entry) in seqs {
                match declared(trait_name, method, backend) {
                    Some(d) => {
                        let pinned: Vec<String> =
                            d.expected.iter().map(|s| (*s).to_owned()).collect();
                        if entry.0 != pinned {
                            failures.push(format!(
                                "{trait_name}::{method} — `{backend}` has a DECLARED divergence \
                                 whose pinned sequence no longer matches the source.\n    \
                                 pinned : {pinned:?}\n    actual : {:?}\n    An exemption pins \
                                 ONE shape. Either the change is right and the pin moves with a \
                                 revised reason, or the change dropped a gate.",
                                entry.0
                            ));
                        }
                    }
                    None => {
                        compared.insert(backend, entry);
                    }
                }
            }
            let distinct: BTreeSet<&Vec<String>> = compared.values().map(|(s, _)| s).collect();
            if distinct.len() > 1 {
                let mut detail = String::new();
                for (seq, label) in compared.values() {
                    detail.push_str(&format!("\n    {label:<34} {seq:?}"));
                }
                failures.push(format!(
                    "{trait_name}::{method} — the backends do not run the same gates in the same \
                     order.{detail}\n    Fix the backend that is missing the gate. If the \
                     difference is a real substrate difference, add a DeclaredDivergence in \
                     src/store/parity.rs saying WHY — but do not weaken a gate to make this pass."
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "backend parity (CIRISPersist#670) — {} divergence(s):\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }

    /// The manifest is checked in the **other** direction too: an exemption
    /// whose door no longer diverges is a stale note that would silently
    /// license a future divergence, so it fails until it is deleted.
    #[test]
    fn no_declared_divergence_is_stale() {
        let scan = scan();
        for d in DECLARED_DIVERGENCES {
            let key = (d.trait_name.to_owned(), d.method.to_owned());
            let per_backend = scan.doors.get(&key).unwrap_or_else(|| {
                panic!(
                    "declared divergence names {}::{}, which no backend implements — \
                     the door was renamed or removed and the exemption outlived it",
                    d.trait_name, d.method
                )
            });
            let mine = per_backend
                .get(d.backend)
                .map(|(s, _)| s.clone())
                .or_else(|| scan.defaults.get(&key).cloned())
                .unwrap_or_else(|| {
                    panic!(
                        "declared divergence names backend `{}` for {}::{}, which has no impl \
                         and no trait default",
                        d.backend, d.trait_name, d.method
                    )
                });
            let others: BTreeSet<Vec<String>> = per_backend
                .iter()
                .filter(|(b, _)| b.as_str() != d.backend)
                .map(|(_, (s, _))| s.clone())
                .collect();
            assert!(
                !others.contains(&mine),
                "{}::{} — `{}` no longer diverges from its siblings; delete the exemption in \
                 src/store/parity.rs. A live exemption over a door that agrees is a licence \
                 nobody reviewed.",
                d.trait_name,
                d.method,
                d.backend
            );
        }
    }

    /// An exemption is prose a reviewer reads. A label is not a reason.
    #[test]
    fn every_declared_divergence_states_a_substantive_reason() {
        for d in DECLARED_DIVERGENCES {
            assert!(
                d.reason.split_whitespace().count() >= 25,
                "{}::{} ({}) — the reason is {} words. An exemption has to explain what about \
                 the SUBSTRATE forces the difference, and why the divergent form is not weaker.",
                d.trait_name,
                d.method,
                d.backend,
                d.reason.split_whitespace().count()
            );
            assert!(
                BACKENDS.iter().any(|(b, _)| *b == d.backend),
                "unknown backend {:?}",
                d.backend
            );
            assert!(
                TRAITS.iter().any(|(t, _)| *t == d.trait_name),
                "unknown trait {:?}",
                d.trait_name
            );
        }
    }

    /// **The gate that stops the gate from passing vacuously.** A parser that
    /// silently stops matching turns every sequence into `[]`, every backend
    /// agrees, and the check reports green over a corpus it never read. So the
    /// scan's own yield is pinned, and the busiest door's sequence is pinned as
    /// an ordered SUBSEQUENCE — stable when gates are added, red the moment one
    /// of these stops being seen.
    #[test]
    fn the_scan_is_not_vacuous() {
        let scan = scan();
        assert!(
            scan.doors.len() > 150,
            "the impl walk collapsed ({} methods) — this gate would pass vacuously",
            scan.doors.len()
        );
        for (backend, _) in BACKENDS {
            let n = scan
                .doors
                .values()
                .filter(|m| m.contains_key(backend))
                .count();
            assert!(
                n > 60,
                "only {n} methods parsed for `{backend}` — the walk collapsed on that file"
            );
        }
        let total: usize = scan
            .doors
            .values()
            .flat_map(|m| m.values())
            .map(|(s, _)| s.len())
            .sum();
        assert!(
            total > 300,
            "only {total} gate calls found across all backends — the call lexer stopped matching"
        );

        // Assembled at runtime so this file's own text cannot satisfy the
        // scan it performs, the `nothing_yields_anti_entropy_satisfied_today`
        // discipline.
        //
        // `check_genesis_attestation_reserved` is deliberately NOT pinned:
        // CIRISPersist#665 moves it to the head of the door, and a
        // subsequence that fixed its position would fail on the merge for a
        // change that is not a regression.
        let must_contain: Vec<String> = [
            ["check", "write"],
            ["check", "federation"],
            ["check", "envelope_size_admission"],
            ["canonicalize", "in_place"],
            ["check", "content_hash_hex"],
            ["check", "instant_binding"],
            ["check", "row_column_binding"],
            ["check", "cohort_scope"],
        ]
        .iter()
        .map(|p| p.join("_"))
        .collect();
        for (backend, _) in BACKENDS {
            let seq = &scan
                .doors
                .get(&(
                    "FederationDirectory".to_owned(),
                    ["put", "attestation"].join("_"),
                ))
                .expect("put_attestation is scanned")[backend]
                .0;
            let mut it = seq.iter();
            for needle in &must_contain {
                assert!(
                    it.any(|g| g == needle),
                    "put_attestation on `{backend}` no longer shows `{needle}` in order — either \
                     the door lost a gate or the scanner stopped seeing it. Sequence: {seq:?}"
                );
            }
        }
    }

    /// [`strip`] handles `//` comments only. Rather than leave that as an
    /// unstated assumption about a 100k-line corpus, it is a checked one.
    #[test]
    fn no_backend_source_uses_block_comments() {
        for (backend, rel) in BACKENDS {
            let text = read(rel);
            for (i, line) in text.lines().enumerate() {
                let t = line.trim_start();
                assert!(
                    !t.starts_with("/*"),
                    "{backend}:{} opens a block comment; the parity scanner's `strip` only \
                     understands `//`, so a gate call inside one would be counted as live code",
                    i + 1
                );
            }
        }
    }

    /// **CIRISPersist#643, as a gate.** `pg_resign` was the only one of three
    /// sibling re-sign helpers never redirected to the shared seal, so every
    /// postgres attestation fixture signed without its instants — 34 of 46
    /// postgres reds, 14 of them matching the *wrong* refusal, which is
    /// green-adjacent noise over real typed-variant regressions.
    ///
    /// The seal recipe (canonicalize, stamp the instants, stamp the row
    /// mirror, hash, sign both halves) has exactly one home:
    /// [`seal_row_in_place`](crate::federation::tier_ingest::test_support::seal_row_in_place).
    /// A backend file that calls `sign_envelope` itself is keeping its own copy
    /// of a step the other arms centralised — which is precisely how the arm
    /// drifts, every time.
    #[test]
    fn no_backend_file_hand_rolls_the_seal() {
        // Assembled so this test's own source is not a hit.
        let needle = ["sign", "envelope"].join("_");
        // The one site that deliberately builds a seal by hand, because the
        // thing it is measuring IS a seal that does not match its claimed
        // signer. Named as `(backend, containing fn)` so a SECOND one cannot
        // appear without a reviewer seeing it.
        let sanctioned: [(&str, &str); 1] = [(
            "memory",
            // A forged REVOCATION: the envelope is signed by an attacker while
            // the row claims the revoker, so `put_revocation` must refuse it.
            // `seal_row_in_place` is Attestation-shaped and has no revocation
            // twin, and the fixture's whole point is a seal the shared helper
            // would never produce.
            "forged_revocation_wrong_signer_rejected_502e1",
        )];
        let mut offenders = Vec::new();
        for (backend, rel) in BACKENDS {
            let text = read(rel);
            let stripped: Vec<String> = text.lines().map(strip).collect();
            let index = index_functions(&stripped);
            for (i, line) in stripped.iter().enumerate() {
                if !line.contains(&needle) {
                    continue;
                }
                let owner = innermost_fn(&index, i);
                if sanctioned.contains(&(backend, owner.as_str())) {
                    continue;
                }
                offenders.push(format!("{backend}:{} in `{owner}`", i + 1));
            }
        }
        assert!(
            offenders.is_empty(),
            "a backend file is hand-rolling the attestation seal: {offenders:?}\n\
             The seal has one home — `tier_ingest::test_support::seal_row_in_place` (and the \
             `reseal*` wrappers over it). A local copy is CIRISPersist#643: it will forget the \
             instants, or the row mirror, or the canonicalization, on exactly one backend, and \
             the other two arms will keep the witnesses green while it does."
        );
        // The sanctioned list is a partition, not a floor: a site that has
        // gone away must be removed, or it silently licenses a future one.
        for (backend, owner) in sanctioned {
            let rel = BACKENDS
                .iter()
                .find(|(b, _)| *b == backend)
                .map(|(_, r)| *r)
                .expect("sanctioned backend exists");
            let text = read(rel);
            let stripped: Vec<String> = text.lines().map(strip).collect();
            let index = index_functions(&stripped);
            let ranges = index
                .get(owner)
                .unwrap_or_else(|| panic!("sanctioned seal site `{backend}::{owner}` is gone"));
            let last = stripped.len() - 1;
            assert!(
                ranges.iter().any(|&(a, b)| stripped[a..=b.min(last)]
                    .iter()
                    .any(|l| l.contains(&needle))),
                "sanctioned seal site `{backend}::{owner}` no longer hand-rolls a seal — \
                 delete it from the list"
            );
        }
    }
}
