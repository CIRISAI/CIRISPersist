//! v53.1.8 (CIRISPersist#1014) — the read-telemetry witnesses.
//!
//! - **I549** (memory, sqlite, postgres): over a seeded consent fold, the
//!   trust-root walks, the audience resolver and one admission, every
//!   `(backend, door)` counter delta equals the test probe's totals for the
//!   same calls — reads and rows exactly, bytes per the module doc's
//!   definition (sqlite / postgres: the probe's envelope bytes; memory: 0) —
//!   and each fold's delta is its one entry plus every read the probe saw
//!   while it ran.
//! - **I550** (sqlite, postgres): the snapshot, the cache counters and the
//!   admission-cache answer are reachable through `Engine`.
//! - **I551** (from disk, comments stripped): every door, fold and backend
//!   label code emits is catalogued, every catalogued one is emitted, and the
//!   snapshot's samples carry exactly the catalogued names and label values.
//! - **I552** (v53.2.0, CIRISPersist#1027, from disk): the Weaver registry's
//!   rendering (`telemetry/catalog.json`) and `TELEMETRY_CATALOG` declare the
//!   same metrics, instruments, units, label keys and label values.
//! - **I553** (v53.2.0, CIRISPersist#1027): what `emit_metrics` writes to a
//!   `metrics` recorder carries exactly the catalogued names, label keys and
//!   label values, at the counters' values — the `live-check` equivalent.
//! - **I690** (v54.1.0, CIRISPersist#1037): the snapshot lists a `(backend,
//!   door)` only once it has served a read; a fresh set lists none.
//! - **I691** (v54.1.0, CIRISPersist#1037): re-entering a fold that is
//!   already active keeps it active — every read inside the inner entry and
//!   after it is credited to the fold exactly once.
//! - **I692** (v54.1.0, CIRISPersist#1051): a read inside a fold returns
//!   within a deadline, so a mutant that never clears the fold mask fails
//!   this witness in seconds instead of hanging the run to a tool timeout.

use std::collections::{BTreeMap, BTreeSet};

use super::catalog::{self, TELEMETRY_CATALOG};
use super::{Door, DoorReads, Fold, FoldReads, LocalCounters, StoreBackend, TelemetrySnapshot};
use crate::federation::read_probe;

// ── I551 ─────────────────────────────────────────────────────────────────

/// `src` with `//` line comments and `/* */` blocks removed, so a
/// commented-out emission can neither satisfy nor defeat the gate. String,
/// raw-string and `'"'` literals are copied through untouched, so a `//` or
/// `/*` inside one (a URL, a SQL glob) strips nothing.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let copy_until = |out: &mut Vec<u8>, from: usize, end: &[u8]| -> usize {
        let mut j = from;
        while j < b.len() && !b[j..].starts_with(end) {
            if end == b"\"" && b[j] == b'\\' {
                j += 1;
            }
            j += 1;
        }
        let stop = (j + end.len()).min(b.len());
        out.extend_from_slice(&b[from..stop]);
        stop
    };
    while i < b.len() {
        let rest = &b[i..];
        if rest.starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if rest.starts_with(b"/*") {
            i += 2;
            while i < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if rest.starts_with(b"'\"'") {
            out.extend_from_slice(b"'\"'");
            i += 3;
        } else if rest.starts_with(b"r#\"") {
            out.extend_from_slice(b"r#\"");
            i = copy_until(&mut out, i + 3, b"\"#");
        } else if rest.starts_with(b"\"") {
            out.push(b'"');
            i = copy_until(&mut out, i + 1, b"\"");
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The identifiers code names as `<enum_path>Ident`.
fn idents_after(code: &str, enum_path: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = code;
    while let Some(i) = rest.find(enum_path) {
        let tail = &rest[i + enum_path.len()..];
        let ident: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() {
            found.insert(ident);
        }
        rest = tail;
    }
    found
}

/// Label values emitted from disk: every `observe::<Enum>::Ident` named
/// outside `src/observe/`, mapped to its label.
fn emitted(
    files: &[(std::path::PathBuf, String)],
    enum_path: &str,
    idents: &'static [(&'static str, &'static str)],
) -> BTreeSet<&'static str> {
    let mut labels = BTreeSet::new();
    for (path, code) in files {
        for ident in idents_after(code, enum_path) {
            let (_, label) = idents.iter().find(|(i, _)| *i == ident).unwrap_or_else(|| {
                panic!(
                    "I551 {} names {enum_path}{ident}, which the enum does not declare",
                    path.display()
                )
            });
            labels.insert(*label);
        }
    }
    labels
}

fn code_outside_observe() -> Vec<(std::path::PathBuf, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    rust_sources(&root, &mut paths);
    paths
        .into_iter()
        .filter(|p| !p.starts_with(root.join("observe")))
        .map(|p| {
            let code = strip_comments(&std::fs::read_to_string(&p).expect("read source"));
            (p, code)
        })
        .collect()
}

fn set(values: &[&'static str]) -> BTreeSet<&'static str> {
    values.iter().copied().collect()
}

#[test]
fn i551_strip_comments_strips_both_shapes() {
    let code = strip_comments("a // observe::Door::X\nb /* observe::Door::Y */ c\n");
    assert!(!code.contains("Door"), "{code}");
    assert!(code.contains('a') && code.contains('b') && code.contains('c'));
    let code = strip_comments("let u = \"https://x/*\"; observe::Door::Z; let q = '\"';\n");
    assert!(code.contains("observe::Door::Z"), "{code}");
}

#[test]
fn i551_every_emitted_label_is_catalogued_and_every_catalogued_one_emitted() {
    let files = code_outside_observe();
    for (enum_path, idents, catalogued) in [
        ("observe::Door::", Door::IDENTS, catalog::DOOR_VALUES),
        ("observe::Fold::", Fold::IDENTS, catalog::FOLD_VALUES),
        (
            "observe::StoreBackend::",
            StoreBackend::IDENTS,
            catalog::BACKEND_VALUES,
        ),
    ] {
        let emitted = emitted(&files, enum_path, idents);
        let catalogued = set(catalogued);
        let declared: BTreeSet<&str> = idents.iter().map(|(_, l)| *l).collect();
        assert_eq!(
            emitted.difference(&catalogued).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "I551 {enum_path}: emitted but not catalogued"
        );
        assert_eq!(
            catalogued.difference(&emitted).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "I551 {enum_path}: catalogued but never emitted"
        );
        assert_eq!(
            declared, catalogued,
            "I551 {enum_path}: the enum and the catalogue disagree"
        );
    }
}

/// v60.0.0 (CIRISPersist#934 step 4) — the doors recorded by ONE shared fold
/// rather than by each backend: `(Door ident, the file whose fold records it)`.
const SHARED_FOLD_DOORS: &[(&str, &str)] = &[
    ("ListLiveConsentGrantsBy", "federation/consent_admit.rs"),
    ("ListLiveConsentGrantsFor", "federation/consent_admit.rs"),
];

/// v60.0.0 — each shared-fold door is recorded in its fold's file.
#[test]
fn i551_shared_fold_doors_are_recorded_by_their_fold() {
    let files = code_outside_observe();
    for (door, file) in SHARED_FOLD_DOORS {
        let (_, code) = files
            .iter()
            .find(|(p, _)| p.ends_with(file))
            .expect("the fold's file");
        assert!(
            idents_after(code, "observe::Door::").contains(*door),
            "I551 {file} records {door}"
        );
    }
}

/// Each backend file feeds the counters under its own backend label only.
#[test]
fn i551_each_backend_records_under_its_own_label() {
    let files = code_outside_observe();
    for (file, own) in [
        ("store/memory.rs", "Memory"),
        ("store/sqlite.rs", "Sqlite"),
        ("store/postgres.rs", "Postgres"),
    ] {
        let (_, code) = files
            .iter()
            .find(|(p, _)| p.ends_with(file))
            .expect("backend file");
        let named = idents_after(code, "observe::StoreBackend::");
        assert_eq!(
            named,
            BTreeSet::from([own.to_owned()]),
            "I551 {file} records under {named:?}"
        );
        // Every door that file serves is recorded there — except the typed
        // bounded read (v56.0.0, CIRISPersist#1001), which no backend records:
        // its one wrapper does; and (v60.0.0, CIRISPersist#934 step 4) the
        // doors a shared fold records once, for every backend.
        let doors = idents_after(code, "observe::Door::");
        assert!(
            doors.len() >= Door::COUNT - 2 - SHARED_FOLD_DOORS.len(),
            "I551 {file} records {} doors",
            doors.len()
        );
        for (door, _) in SHARED_FOLD_DOORS {
            assert!(
                !doors.contains(*door),
                "I551 {file} records {door}, which its shared fold records"
            );
        }
        assert!(
            !idents_after(code, "observe::Door::").contains("AttestationQuery")
                && !code.contains("record_query_read"),
            "I904 {file} records the typed read itself; only its wrapper may"
        );
    }
    // **I904** (v56.0.0, CIRISPersist#1001) — the typed read is recorded in
    // ONE place: `record_query_read` has exactly one caller, the shared
    // wrapper `AttestationReads::query_attestations`.
    let callers: Vec<_> = files
        .iter()
        .filter_map(|(p, code)| {
            let n = code.matches("record_query_read(").count();
            (n > 0).then(|| (p.display().to_string(), n))
        })
        .collect();
    assert!(
        callers.len() == 1
            && callers[0].0.ends_with("federation/attestation_query.rs")
            && callers[0].1 == 1,
        "I904 the typed read is recorded once, in its wrapper: {callers:?}"
    );
}

#[test]
fn i551_samples_carry_exactly_the_catalogued_names_and_labels() {
    let full = TelemetrySnapshot {
        reads: StoreBackend::ALL
            .iter()
            .flat_map(|b| {
                Door::ALL.iter().map(|d| DoorReads {
                    backend: b.label(),
                    door: d.label(),
                    reads: 1,
                    rows: 1,
                    bytes: 1,
                })
            })
            .collect(),
        folds: Fold::ALL
            .iter()
            .map(|f| FoldReads {
                fold: f.label(),
                calls: 1,
                reads: 1,
                rows: 1,
                bytes: 1,
            })
            .collect(),
    };
    let samples = full.samples();
    let names: BTreeSet<&str> = samples.iter().map(|s| s.name).collect();
    let catalogued: BTreeSet<&str> = TELEMETRY_CATALOG.iter().map(|e| e.name).collect();
    assert_eq!(names, catalogued, "I551 sample names vs the catalogue");
    assert_eq!(
        catalogued.len(),
        TELEMETRY_CATALOG.len(),
        "I551 a catalogued name is listed twice"
    );
    for s in &samples {
        let entry = TELEMETRY_CATALOG
            .iter()
            .find(|e| e.name == s.name)
            .expect("catalogued");
        let keys: BTreeSet<&str> = s.labels.iter().map(|(k, _)| *k).collect();
        let specs: BTreeSet<&str> = entry.labels.iter().map(|l| l.key).collect();
        assert_eq!(keys, specs, "I551 {}: label keys", s.name);
        for (k, v) in &s.labels {
            let spec = entry.labels.iter().find(|l| l.key == *k).expect("spec");
            assert!(
                spec.values.contains(v),
                "I551 {}: {k}={v} is outside the bounded set",
                s.name
            );
        }
    }
    // Every catalogued label value appears in some sample.
    for entry in TELEMETRY_CATALOG {
        for spec in entry.labels {
            for v in spec.values {
                assert!(
                    samples.iter().any(|s| s.name == entry.name
                        && s.labels.iter().any(|(k, sv)| *k == spec.key && sv == v)),
                    "I551 {} {}={v} never sampled",
                    entry.name,
                    spec.key
                );
            }
        }
    }
}

// ── I552 ─────────────────────────────────────────────────────────────────

/// One metric as `(instrument, unit, {label key → values})`.
type MetricShape = (String, String, BTreeMap<String, BTreeSet<String>>);

/// v53.2.0 (CIRISPersist#1027) — `telemetry/catalog.json`, which
/// `scripts/weaver_check.sh` renders from the Weaver registry
/// (`telemetry/registry/*.yaml`) and fails on when the committed copy differs.
/// Read from this crate's own manifest dir, never another checkout.
fn weaver_catalog() -> BTreeMap<String, MetricShape> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("telemetry/catalog.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read telemetry/catalog.json"))
            .expect("telemetry/catalog.json is JSON");
    let mut out = BTreeMap::new();
    for m in json["metrics"].as_array().expect("metrics array") {
        let s = |v: &serde_json::Value| v.as_str().expect("string").to_owned();
        let labels = m["labels"]
            .as_array()
            .expect("labels array")
            .iter()
            .map(|l| {
                let values = l["values"]
                    .as_array()
                    .expect("values")
                    .iter()
                    .map(s)
                    .collect();
                (s(&l["key"]), values)
            })
            .collect();
        let prior = out.insert(s(&m["name"]), (s(&m["instrument"]), s(&m["unit"]), labels));
        assert!(
            prior.is_none(),
            "I552 the registry lists {} twice",
            m["name"]
        );
    }
    out
}

/// The registry and `TELEMETRY_CATALOG` declare the same metrics, units,
/// instruments, label keys and label values — compared as whole maps, so a
/// name, key or value on either side only is red.
#[test]
fn i552_the_weaver_registry_and_the_catalogue_agree() {
    let registry = weaver_catalog();
    let catalogue: BTreeMap<String, MetricShape> = TELEMETRY_CATALOG
        .iter()
        .map(|e| {
            let instrument = match e.kind {
                catalog::MetricKind::Counter => "counter",
            };
            let labels = e
                .labels
                .iter()
                .map(|l| {
                    let values = l.values.iter().map(|v| (*v).to_owned()).collect();
                    (l.key.to_owned(), values)
                })
                .collect();
            (
                e.name.to_owned(),
                (instrument.to_owned(), e.unit.to_owned(), labels),
            )
        })
        .collect();
    assert_eq!(registry.len(), 7, "I552 the registry's metric count");
    assert_eq!(
        registry, catalogue,
        "I552 telemetry/registry (via catalog.json) vs TELEMETRY_CATALOG"
    );
}

// ── I553 ─────────────────────────────────────────────────────────────────

/// Every `(backend, door)` read once (no rows, 1 byte), every fold entered
/// once around one memory `get_attestation` read: then `emit_metrics` into a
/// debugging recorder must write every catalogued name with every catalogued
/// label value and nothing else, each series at exactly the value the
/// snapshot reads for it.
#[tokio::test(flavor = "current_thread")]
async fn i553_emit_metrics_writes_exactly_the_catalogue() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    let local = LocalCounters::install();
    for backend in StoreBackend::ALL {
        for door in Door::ALL {
            super::record_read::<crate::federation::Attestation>(*backend, *door, "i553", &[], 1);
        }
    }
    for f in Fold::ALL {
        super::fold(*f, async {
            super::record_read::<crate::federation::Attestation>(
                StoreBackend::Memory,
                Door::GetAttestation,
                "i553",
                &[],
                1,
            );
        })
        .await;
    }
    // Every catalogued unit maps to a metrics::Unit: a `None` would describe
    // that counter with no unit, silently.
    for entry in TELEMETRY_CATALOG {
        let want = match entry.unit {
            "By" => metrics::Unit::Bytes,
            "{read}" | "{row}" | "{call}" => metrics::Unit::Count,
            other => panic!("I553 {}: unit {other:?} has no mapping here", entry.name),
        };
        assert_eq!(
            entry.metrics_unit(),
            Some(want),
            "I553 {}: unit {:?}",
            entry.name,
            entry.unit
        );
    }
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, super::emit_metrics);

    // (name, sorted labels) → value, on both sides.
    type Series = BTreeMap<(String, Vec<(String, String)>), u64>;
    let mut emitted = Series::new();
    for (key, unit, description, value) in snapshotter.snapshot().into_vec() {
        let key = key.key();
        let name = key.name().to_owned();
        let entry = TELEMETRY_CATALOG
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("I553 emitted {name}, which is not catalogued"));
        assert_eq!(
            description.as_ref().map(|d| d.to_string()).as_deref(),
            Some(entry.description),
            "I553 {name}: description"
        );
        // The recorder sees the catalogued unit, mapped: `By` as bytes, a
        // `{...}` annotation as a count (Codex round 2 on PR #1039).
        assert_eq!(
            unit,
            entry.metrics_unit(),
            "I553 {name}: unit (catalogue {:?})",
            entry.unit
        );
        let DebugValue::Counter(v) = value else {
            panic!("I553 {name}: not a counter: {value:?}")
        };
        let mut labels: Vec<(String, String)> = key
            .labels()
            .map(|l| (l.key().to_owned(), l.value().to_owned()))
            .collect();
        labels.sort();
        emitted.insert((name, labels), v);
    }
    let read: Series = local
        .snapshot()
        .samples()
        .into_iter()
        .map(|s| {
            let mut labels: Vec<(String, String)> = s
                .labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            labels.sort();
            ((s.name.to_owned(), labels), s.value)
        })
        .collect();
    assert_eq!(emitted, read, "I553 emitted series vs the snapshot");

    // Every catalogued (name, key, value) was emitted, and nothing else.
    let mut seen: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for (name, labels) in emitted.keys() {
        let keys = seen.entry(name.clone()).or_default();
        for (k, v) in labels {
            keys.entry(k.clone()).or_default().insert(v.clone());
        }
    }
    let catalogue: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = TELEMETRY_CATALOG
        .iter()
        .map(|e| {
            let labels = e
                .labels
                .iter()
                .map(|l| {
                    let values = l.values.iter().map(|v| (*v).to_owned()).collect();
                    (l.key.to_owned(), values)
                })
                .collect();
            (e.name.to_owned(), labels)
        })
        .collect();
    assert_eq!(
        seen, catalogue,
        "I553 emitted names/labels vs the catalogue"
    );
    assert_eq!(
        emitted[&(
            catalog::FOLD_CALLS.to_owned(),
            vec![(
                catalog::LABEL_FOLD.to_owned(),
                Fold::TrustRootValid.label().to_owned()
            )]
        )],
        1,
        "I553 fold.calls{{fold=trust_root_valid}} is the one seeded entry"
    );
}

// ── I690–I692 ────────────────────────────────────────────────────────────

/// One memory read at `door` with no rows: one read, 0 rows, 1 byte.
fn one_read(door: Door) {
    super::record_read::<crate::federation::Attestation>(
        StoreBackend::Memory,
        door,
        "i69x",
        &[],
        1,
    );
}

/// **I690** (#1037) — the snapshot's `reads` is exactly the doors that served
/// a read. Every other witness checked the rows present; none checked that a
/// never-read door is ABSENT, so `if n > 0` → `if n >= 0` (every pair listed,
/// at zeros) survived the first matrix.
#[test]
fn i690_the_snapshot_lists_only_doors_that_were_read() {
    let local = LocalCounters::install();
    assert_eq!(
        local.snapshot().reads,
        Vec::<DoorReads>::new(),
        "I690 a fresh counter set lists no door"
    );
    one_read(Door::GetAttestation);
    assert_eq!(
        local.snapshot().reads,
        vec![DoorReads {
            backend: StoreBackend::Memory.label(),
            door: Door::GetAttestation.label(),
            reads: 1,
            rows: 0,
            bytes: 1,
        }],
        "I690 one read lists exactly its (backend, door)"
    );
}

/// **I691** (#1037) — `fold(X, fold(X, read))`: the inner entry must keep X
/// active (its mask is the outer mask OR X's bit), and leaving it must leave
/// X active for the rest of the outer entry. With `|` → `^` the inner entry
/// TOGGLED X off and its read was credited to nothing.
#[tokio::test(flavor = "current_thread")]
async fn i691_reentering_an_active_fold_keeps_it_active() {
    let local = LocalCounters::install();
    let x = Fold::TrustRootValid;
    let other = Fold::OwnerGrantedScope;
    super::fold(x, async {
        one_read(Door::GetAttestation);
        super::fold(x, async {
            one_read(Door::GetAttestation);
            super::fold(other, async { one_read(Door::GetAttestation) }).await;
        })
        .await;
        one_read(Door::GetAttestation);
    })
    .await;
    let snap = local.snapshot();
    assert_eq!(
        snap.fold(x),
        (2, 4, 0, 4),
        "I691 {}: two entries, and all four reads credited once each (calls, reads, rows, bytes)",
        x.label()
    );
    assert_eq!(
        snap.fold(other),
        (1, 1, 0, 1),
        "I691 {}: only the read made inside it",
        other.label()
    );
}

/// **I692** (#1051) — `record_read` inside nested folds returns within 5 s.
/// Its credit loop clears one mask bit per pass; the first matrix's three
/// `record_read` mutants (`&=` → `|=`, `-` → `+`, `-` → `/`) never clear it,
/// and every witness hung until cargo-mutants' 300 s timeout, credited to no
/// witness. The read runs on its own thread (the counters are thread-local,
/// so it installs its own set) and this thread waits with a deadline: a hang
/// is this witness's red. A spinning thread is left behind on that red; the
/// test process exits with it.
#[test]
fn i692_a_read_inside_folds_returns_within_a_deadline() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let local = LocalCounters::install();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(super::fold(
            Fold::ResolveServeTier,
            super::fold(Fold::IsPublicGroup, async {
                one_read(Door::AttestationQuery);
            }),
        ));
        let snap = local.snapshot();
        let _ = tx.send((
            snap.fold(Fold::ResolveServeTier),
            snap.fold(Fold::IsPublicGroup),
        ));
    });
    let (outer, inner) = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("I692 a read inside two folds did not return within 5 s");
    assert_eq!(outer, (1, 1, 0, 1), "I692 the outer fold's credit");
    assert_eq!(inner, (1, 1, 0, 1), "I692 the inner fold's credit");
}

// ── I1163–I1164 (#1112) ──────────────────────────────────────────────────

/// **I1163** (#1112) — `metrics_unit` maps a UCUM annotation `{x}` to a
/// count and refuses every malformed brace form. The catalogue holds only
/// well-formed units, so I553 never reached the guard's refusing side: the
/// guard replaced with `true`, either `&&` with `||`, and `>` with `>=` all
/// survived the nightly matrix. Each malformed case below is the one input
/// a mutant answers `Count` for.
#[test]
fn i1163_metrics_unit_refuses_every_malformed_brace_form() {
    fn unit(u: &'static str) -> Option<metrics::Unit> {
        catalog::CatalogEntry {
            name: "i1163",
            kind: catalog::MetricKind::Counter,
            unit: u,
            labels: &[],
            description: "I1163",
        }
        .metrics_unit()
    }
    assert_eq!(unit("By"), Some(metrics::Unit::Bytes), "I1163 By");
    assert_eq!(unit("{x}"), Some(metrics::Unit::Count), "I1163 {{x}}");
    assert_eq!(unit("{row}"), Some(metrics::Unit::Count), "I1163 {{row}}");
    // `>` → `>=`: the empty annotation is two bytes.
    assert_eq!(unit("{}"), None, "I1163 {{}} is not an annotation");
    // the first `&&` → `||`: long enough, no opening brace.
    assert_eq!(unit("ab}"), None, "I1163 ab}} has no opening brace");
    assert_eq!(unit("abc"), None, "I1163 abc has no braces");
    // the second `&&` → `||`: a closing brace alone.
    assert_eq!(unit("}"), None, "I1163 }} alone");
    assert_eq!(unit("x}"), None, "I1163 x}} has no opening brace");
    assert_eq!(unit("{ab"), None, "I1163 {{ab has no closing brace");
    assert_eq!(unit("{x"), None, "I1163 {{x has no closing brace");
    assert_eq!(unit("{"), None, "I1163 {{ alone");
    assert_eq!(unit("x"), None, "I1163 x");
    assert_eq!(unit(""), None, "I1163 empty");
}

/// **I1164** (#1112) — a read inside three nested folds credits each of
/// them exactly once and no other fold. The three folds sit at mask bits 0,
/// 4 and 7, so a credit step that clears the wrong bit (`&=` → `|=`), or
/// none (`-` → `+`, `-` → `/`), credits fold 0 or the lowest fold twice and
/// leaves a higher one uncredited. Like I692 it runs on its own thread
/// behind a 5 s deadline, so a loop that never ends is this witness's red.
#[test]
fn i1164_a_read_credits_each_active_fold_exactly_once() {
    const ACTIVE: [Fold; 3] = [
        Fold::ResolveScopedStanceByPrincipals,
        Fold::ResolveServeTier,
        Fold::IsPublicGroup,
    ];
    assert_eq!(
        ACTIVE.map(|f| f as u32),
        [0, 4, 7],
        "I1164 the folds' mask bits"
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let local = LocalCounters::install();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(super::fold(
            ACTIVE[0],
            super::fold(
                ACTIVE[1],
                super::fold(ACTIVE[2], async {
                    one_read(Door::AttestationQuery);
                    one_read(Door::AttestationQuery);
                }),
            ),
        ));
        let snap = local.snapshot();
        let _ = tx.send(
            Fold::ALL
                .iter()
                .map(|f| (*f, snap.fold(*f)))
                .collect::<Vec<_>>(),
        );
    });
    let got = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("I1164 a read inside three folds did not return within 5 s");
    for (fold, tally) in got {
        let want = if ACTIVE.contains(&fold) {
            (1, 2, 0, 2)
        } else {
            (0, 0, 0, 0)
        };
        assert_eq!(tally, want, "I1164 {} credit", fold.label());
    }
}

// ── I549 ─────────────────────────────────────────────────────────────────

/// The probe's totals per door: (reads, rows, bytes).
fn probe_totals(log: &[read_probe::Read]) -> BTreeMap<&'static str, (u64, u64, u64)> {
    let mut out: BTreeMap<&'static str, (u64, u64, u64)> = BTreeMap::new();
    for r in log {
        let e = out.entry(r.method).or_default();
        e.0 += 1;
        e.1 += r.rows as u64;
        e.2 += r.bytes as u64;
    }
    out
}

fn delta3(a: (u64, u64, u64), b: (u64, u64, u64)) -> (u64, u64, u64) {
    (b.0 - a.0, b.1 - a.1, b.2 - a.2)
}

/// One step of I549: `before` → `after` against the probe `log` the step
/// produced. Returns the probe's (reads, rows) for the step.
fn assert_step(
    tag: &str,
    backend: StoreBackend,
    before: &TelemetrySnapshot,
    after: &TelemetrySnapshot,
    log: &[read_probe::Read],
    fold: Fold,
) -> (u64, u64) {
    let probe = probe_totals(log);
    for door in Door::ALL {
        let (reads, rows, probe_bytes) = probe.get(door.label()).copied().unwrap_or_default();
        let bytes = match backend {
            StoreBackend::Memory => 0,
            StoreBackend::Sqlite | StoreBackend::Postgres => probe_bytes,
        };
        assert_eq!(
            delta3(before.door(backend, *door), after.door(backend, *door)),
            (reads, rows, bytes),
            "I549 {tag}: {} {} counters vs the probe (reads, rows, bytes)",
            backend.label(),
            door.label()
        );
        for other in StoreBackend::ALL.iter().filter(|b| **b != backend) {
            assert_eq!(
                after.door(*other, *door),
                before.door(*other, *door),
                "I549 {tag}: a {} read moved {}'s counters",
                backend.label(),
                other.label()
            );
        }
    }
    let total = log.iter().fold((0u64, 0u64, 0u64), |acc, r| {
        (acc.0 + 1, acc.1 + r.rows as u64, acc.2 + r.bytes as u64)
    });
    let (c0, r0, w0, b0) = before.fold(fold);
    let (c1, r1, w1, b1) = after.fold(fold);
    assert!(c1 > c0, "I549 {tag}: {} was not entered", fold.label());
    let bytes = match backend {
        StoreBackend::Memory => 0,
        _ => total.2,
    };
    assert_eq!(
        (r1 - r0, w1 - w0, b1 - b0),
        (total.0, total.1, bytes),
        "I549 {tag}: {} is credited every read made while it ran (reads, rows, bytes)",
        fold.label()
    );
    (total.0, total.1)
}

pub(crate) async fn i549_counters_equal_the_probe(
    d: &dyn crate::federation::FederationDirectory,
    s: &str,
    backend: StoreBackend,
) {
    use crate::federation::audience_scan_invariants::bodies as asb;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::{
        consent_by_humans as cbh, replication_audience as ra, trust_root as tr, SignedAttestation,
    };

    let now = chrono::Utc::now();
    let local = LocalCounters::install();
    let consent = asb::seed_consent_corpus(d, s).await;
    let (t, node) = (consent.target.as_str(), consent.subjects[0].as_str());
    let (root, a, b) = (
        format!("i549-root-{s}"),
        format!("i549-a-{s}"),
        format!("i549-b-{s}"),
    );
    let (owner, dev) = (format!("i549-owner-{s}"), format!("i549-dev-{s}"));
    asb::keys(
        d,
        &[
            (&root, USER),
            (&a, USER),
            (&b, USER),
            (&owner, USER),
            (&dev, NODE),
        ],
    )
    .await;
    d.put_attestation(SignedAttestation {
        attestation: asb::charter(&format!("i549-charter-{s}"), &root, &a, &b),
    })
    .await
    .expect("I549 charter");
    crate::federation::operational::test_support::emit_trust_edge(d, &a, &root, None)
        .await
        .expect("I549 a trusts the root");
    let _ = read_probe::take();

    // The admission of one row, then the folds.
    let mut probe_reads = 0;
    let mut probe_rows = 0;
    macro_rules! step {
        ($tag:literal, $fold:expr, $call:expr) => {{
            let before = local.snapshot();
            let _ = $call;
            let log = read_probe::take();
            let (reads, rows) = assert_step($tag, backend, &before, &local.snapshot(), &log, $fold);
            probe_reads += reads;
            probe_rows += rows;
            (reads, rows)
        }};
    }
    step!(
        "admission",
        Fold::AttestationAdmission,
        d.put_attestation(SignedAttestation {
            attestation: asb::grant(&owner, Some(&dev), Some(&[("community", "r1")]), None),
        })
        .await
        .expect("I549 grant")
    );
    let (_, consent_rows) = step!(
        "consent by principals",
        Fold::ResolveScopedStanceByPrincipals,
        cbh::resolve_scoped_stance_by_principals(d, t, node, "analyze", None, now)
            .await
            .unwrap()
    );
    assert!(consent_rows > 0, "I549 the consent fold read no rows");
    step!(
        "consent",
        Fold::ResolveScopedStance,
        d.resolve_scoped_stance(t, node, "analyze", None, now)
            .await
            .unwrap()
    );
    let (_, walk_rows) = step!(
        "trust_root_valid",
        Fold::TrustRootValid,
        tr::trust_root_valid(d, &a, &root).await.unwrap()
    );
    assert!(walk_rows > 0, "I549 the trust-root walk read no rows");
    step!(
        "trusted_roots_of",
        Fold::TrustedRootsOf,
        tr::trusted_roots_of(d, &a, now).await.unwrap()
    );
    step!(
        "owner_granted_scope",
        Fold::OwnerGrantedScope,
        tr::owner_granted_scope(d, &dev, &owner, "analyze")
            .await
            .unwrap()
    );
    step!(
        "serve tier",
        Fold::ResolveServeTier,
        tr::resolve_serve_tier_over_roster(d, &dev, &owner, std::slice::from_ref(&root))
            .await
            .unwrap()
    );
    step!(
        "owner_allow_list",
        Fold::OwnerAllowList,
        ra::owner_allow_list(d, &owner, &dev).await.unwrap()
    );
    step!(
        "owner audience",
        Fold::OwnerAudience,
        ra::OwnerAudience::read(d, &owner).await.unwrap()
    );
    step!(
        "is_public_group",
        Fold::IsPublicGroup,
        ra::is_public_group(d, &root).await.unwrap()
    );
    assert!(probe_reads > 0 && probe_rows > 0);
    eprintln!(
        "I549 {}: {probe_reads} probed reads, {probe_rows} rows across the folds",
        backend.label()
    );
}

// ── I550 ─────────────────────────────────────────────────────────────────

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn i550_the_snapshot_is_reachable_through_engine(
    dispatch: crate::engine::BackendDispatch,
    d: &dyn crate::federation::FederationDirectory,
    backend: StoreBackend,
    s: &str,
) {
    use crate::federation::attestation_query::test_support::AllAttestations as _;
    use crate::federation::tier_ingest::test_support as ts;
    let local = ts::local_signer(&format!("i550-node-{s}"));
    let signer: std::sync::Arc<dyn ciris_keyring::HardwareSigner> =
        std::sync::Arc::new(crate::signing::LocalSignerHardwareAdapter::new(local));
    let engine = crate::Engine::from_shared(dispatch, signer);
    let counters = LocalCounters::install();
    let before = engine.telemetry_snapshot();
    d.all_attestations_for(&format!("i550-nobody-{s}"))
        .await
        .unwrap();
    let after = engine.telemetry_snapshot();
    assert_eq!(
        after,
        counters.snapshot(),
        "I550 the Engine reads the counters"
    );
    assert_eq!(
        delta3(
            before.door(backend, Door::AttestationQuery),
            after.door(backend, Door::AttestationQuery)
        ),
        (1, 0, 0),
        "I550 one empty read, through Engine::telemetry_snapshot"
    );
    assert_eq!(after.folds.len(), Fold::COUNT, "I550 every fold is listed");
    let caches = engine.cache_stats();
    assert_eq!(
        caches.repository_statistics.entries_resident, 0,
        "I550 a fresh backend's repository-statistics cache is empty"
    );
    assert_eq!(engine.admission_cache_stats(), None);
    let json = serde_json::to_value(&after).expect("the snapshot serializes");
    assert!(
        json["reads"].is_array() && json["folds"].is_array(),
        "{json}"
    );
}

// ── runners ──────────────────────────────────────────────────────────────

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
}

mod memory {
    use super::*;

    #[tokio::test]
    async fn i549() {
        let d = crate::store::memory::MemoryBackend::new();
        i549_counters_equal_the_probe(&d, &suffix(), StoreBackend::Memory).await;
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::store::Backend as _;

    async fn fresh() -> std::sync::Arc<crate::store::sqlite::SqliteBackend> {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        std::sync::Arc::new(b)
    }

    #[tokio::test]
    async fn i549() {
        let d = fresh().await;
        i549_counters_equal_the_probe(&*d, &suffix(), StoreBackend::Sqlite).await;
    }

    #[tokio::test]
    async fn i550() {
        let d = fresh().await;
        i550_the_snapshot_is_reachable_through_engine(
            crate::engine::BackendDispatch::Sqlite(d.clone()),
            &*d,
            StoreBackend::Sqlite,
            &suffix(),
        )
        .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::Backend as _;

    async fn fresh() -> Option<std::sync::Arc<crate::store::postgres::PostgresBackend>> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(std::sync::Arc::new(b))
    }

    #[tokio::test]
    async fn i549() {
        let Some(d) = fresh().await else { return };
        i549_counters_equal_the_probe(&*d, &suffix(), StoreBackend::Postgres).await;
    }

    #[tokio::test]
    async fn i550() {
        let Some(d) = fresh().await else { return };
        i550_the_snapshot_is_reachable_through_engine(
            crate::engine::BackendDispatch::Postgres(d.clone()),
            &*d,
            StoreBackend::Postgres,
            &suffix(),
        )
        .await;
    }
}
