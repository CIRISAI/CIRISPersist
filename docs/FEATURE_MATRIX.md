# Feature matrix — the hand legs and the depth-2 powerset (CIRISPersist#1025)

"Certify per feature SET, never a union": a cfg-gated break lives in a set
nobody built. `scripts/certify.sh` builds a hand-chosen list of sets. A hand
list only finds the breaks someone thought to build for.
`scripts/powerset.sh` derives the sets mechanically with cargo-hack's
`--feature-powerset --depth 2`: every single feature and every PAIR. NIST's
t-way result is the justification: most interaction faults involve one or two
parameters. `scripts/powerset_delta.py` compares the two.

    scripts/powerset.sh list|count       enumeration only (cargo-hack --print-command-list; no compile)
    scripts/powerset.sh check [M/N]      cargo check every set, or partition M of N
    scripts/powerset_delta.py [--verbose]

## The rule: no hand-listed leg is dropped

The powerset ADDS compile coverage. It replaces nothing in this cut. Every hand
leg stays as it is, and the test legs stay hand-derived until the powerset's
runtime is measured on CI. `powerset_delta.py` exits 1 if any hand set is not
covered at least pairwise, so a change to the exclusions that would orphan a
hand leg is caught before it lands.

## The derived set (measured 2026-10-08, depth 2)

| | count |
|---|---:|
| features declared in `Cargo.toml` | 47 |
| excluded | 4 |
| features in the powerset | 43 |
| derived sets | **929** |
| the empty set (`--no-default-features`) | 1 |
| single-feature sets | 43 |
| pairs | 885 |
| pairs cargo-hack skips as implied | 18 |

43 features give 903 pairs. cargo-hack skips the 18 where one feature already
enables the other, for example `encrypted-kv` enables `sqlite` and
`secrets-server` enables `server` (both checked in `Cargo.toml`). Note that
`default` is a feature like any other here: the derived set `default` is the
crate's default features, not the empty set.

### Exclusions

Read from `ci_feature_matrix.py`'s `NOT_TESTED` reasons:

| feature | why |
|---|---|
| `scrub-ner` | +500 MB of Candle/Tokenizers/HF-Hub codegen |
| `scrub-ort` | pulls `scrub-ner`; `ort` wants a host libonnxruntime |
| `default-pipeline-ml` | `scrub-ner` + `extract`, same reason |
| `_pyffi` | internal shared gate, never enabled directly |

All four stay compile-covered by the `--all-features` clippy pass, which the
delta does not compare because it carries the excluded set by design.

## The delta

certify.sh builds **27** hand sets: 8 LEGS, `lint`, 5 AXES × 3 backend shapes,
and the literal `run_bg` legs `pyo3sqlite`, `floortoken` and `default`.

**Hand sets the powerset builds exactly (18).** `test-anchor`, all 15 axis
legs (`axis-<a>-none|sqlite|pg` for cirisaudit, secrets, cirisnode, cirisgraph,
telemetry), `floortoken` (`sqlite`), and `default` (the empty feature list).

**Hand sets the powerset covers pairwise only (9).** Every pair of the leg's
features is built together by some derived set, but no derived set is the
whole leg. A depth-2 powerset cannot contain a 4..34-feature set. These are
why the hand legs stay:

| leg | features |
|---|---:|
| `core` | 4 |
| `cirisaudit`, `secrets`, `cirisnode`, `cirisgraph`, `telemetry` | 5 each |
| `lint` | 9 |
| `pyo3sqlite` | 11 |
| `rest` | 34 |

**Hand sets not covered even pairwise: 0.**

**Sets only the powerset builds: 911.** 37 single-feature sets (all 43 but
the five axis features and `sqlite`) and 874 pairs (all 885 but the ten axis
backend pairs and `sqlite,test-anchor`). The full list is
`scripts/powerset_delta.py --verbose`. Nothing in certify.sh
builds a single feature on its own except through the axis sweep, so single
features such as `tls`, `pyo3`, `pyo3-sqlite`, `c-abi`, `ledgers`,
`peer-replicate` and every `cirislens_*` were never compiled alone before.

## What the check found

Two partial `check` runs are on disk. Neither covered all 929 sets.

| run | sets started | wall | peak RSS | result |
|---|---:|---:|---:|---|
| `check` (all) | 34 of 929 | 598 s | not recorded | 1 red; the log ends after set 34 finished, cause not recorded |
| `check 41/80` | 12 | 274 s | 3.0 GiB | 1 red |

Both reds are real configurations that do not compile:

- **`tls` without `postgres`** (the set `test-panic,tls`; `test-panic` is an
  empty feature). `tokio-postgres-rustls` fails with
  `unresolved import tokio_postgres::tls::MakeTlsConnect` and two `E0223`.
  `tls` (`Cargo.toml:525`) enables `dep:tokio-postgres-rustls` but not
  `postgres`, so `tokio-postgres` is built without the runtime that crate
  needs.
- **`pyo3-sqlite` without `pyo3`.** 184 × `E0004` "non-exhaustive patterns:
  `&pyo3::BackendDispatch`" from `src/ffi/pyo3.rs:120`, plus never-type and
  missing-module errors. `pyo3-sqlite = ["_pyffi"]` (`Cargo.toml:43`) enables
  the shared gate but not `pyo3`. The hand leg `pyo3sqlite` always adds
  `sqlite` and nine more, so it never saw this.

Neither is fixed in this cut. Each wants a one-line feature-closure decision
(make `tls` imply `postgres`; make `pyo3-sqlite` imply `pyo3` and `sqlite`, or
gate the module on both), and that is a public feature contract change.

## Runtime and placement

The two runs measured 17.6 s and 22.8 s per set at `CARGO_BUILD_JOBS=3`.
929 sets is therefore **about 4.5 to 6 hours** serially (PROJECTED). #1025
asked for it as one leg of certify's cheap tier; at that cost it cannot be.
The proposal instead:

- **CI, weekly**, as a matrix of 8 partitions (`check 1/8` .. `8/8`), about
  35–45 min each, compile-only, `--keep-going` so one run names every broken
  set.
- **certify**, an explicit opt-in `powerset [M/N]` mode, never inside `quick`,
  `focus` or `full`.
- **Never concurrent** with another cargo in the same tree: `--no-dev-deps`
  rewrites `Cargo.toml` and `Cargo.lock` for the whole run. `check` refuses to
  start on a modified `Cargo.toml`, which is also what a killed run leaves.
- No `RUSTFLAGS=-D warnings`: a depth-2 set turns most of the crate off, and
  every resulting `dead_code` warning would be a red that says nothing about
  whether the set compiles.

The exact wiring is in `docs/CI_WIRING_53_2_0.md`.
