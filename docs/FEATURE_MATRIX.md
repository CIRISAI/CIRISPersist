# Feature matrix — the hand legs and the depth-2 powerset

A cfg-gated break lives in a feature set nobody built, so persist certifies per
feature SET, never a union. Two mechanisms build the sets:

- `scripts/certify.sh` (and CI) build a hand-chosen list of legs.
- `scripts/powerset.sh` derives sets mechanically with cargo-hack's
  `--feature-powerset --depth 2`: every single feature and every pair. Most
  interaction faults involve one or two parameters (NIST's t-way result), so
  depth 2 is the line.

`scripts/powerset_delta.py` compares the two.

    scripts/powerset.sh list|count       enumeration only (cargo-hack --print-command-list; no compile)
    scripts/powerset.sh check [M/N]      cargo check every set, or partition M of N
    scripts/powerset_delta.py [--verbose]

## The rule: no hand-listed leg is dropped

The powerset adds compile coverage and replaces nothing. Every hand leg stays,
and the test legs stay hand-derived. `powerset_delta.py` exits 1 if any hand set
is not covered at least pairwise, so a change to the exclusions that would
orphan a hand leg is caught before it merges.

## The derived set (depth 2)

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
`secrets-server` enables `server`. `default` is a feature like any other here:
the derived set `default` is the crate's default features, not the empty set.
`scripts/powerset.sh count` prints the current numbers.

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
whole leg; a depth-2 powerset cannot contain a 4..34-feature set. These are why
the hand legs stay:

| leg | features |
|---|---:|
| `core` | 4 |
| `cirisaudit`, `secrets`, `cirisnode`, `cirisgraph`, `telemetry` | 5 each |
| `lint` | 9 |
| `pyo3sqlite` | 11 |
| `rest` | 34 |

**Hand sets not covered even pairwise: 0.**

**Sets only the powerset builds: 911.** 37 single-feature sets (all 43 but the
five axis features and `sqlite`) and 874 pairs (all 885 but the ten axis
backend pairs and `sqlite,test-anchor`). `scripts/powerset_delta.py --verbose`
prints the list. These include every feature compiled on its own, such as
`tls`, `pyo3`, `pyo3-sqlite`, `c-abi`, `ledgers`, `peer-replicate` and every
`cirislens_*`.

## Each feature declares what it needs

A feature that only compiles with another feature enables it:

- **`tls = ["postgres", …]`.** All TLS code is the Postgres pool's transport
  (`src/store/postgres.rs`); there is no backend-agnostic TLS, so the feature
  declares the backend it secures.
- **`pyo3-sqlite = ["_pyffi", "sqlite"]`.** The mobile and Windows Python
  shape, kept postgres-free. Implying `pyo3` would pull `postgres` and openssl,
  the one thing it exists to drop, so it implies the backend its name says.

The gate: `ci_feature_matrix.py` keeps an `ALONE_COMPILE` table (feature →
prerequisite). `check` fails if `Cargo.toml` drops an implication, or if
`ci.yml` stops compiling each feature alone (`ci_feature_matrix.py alone`, a
`cargo check --no-default-features --features <f>` loop in the lint job).
These two implications are the fix for the two configurations the powerset
found that did not compile (CIRISPersist#1030).

## Runtime and placement

A set takes about 18–23 s to check at `CARGO_BUILD_JOBS=3`, so all 929 take
about 4.5 to 6 hours serially. The powerset therefore runs:

- **in CI, weekly** (the Sunday run of `.github/workflows/mutants.yml`), as a
  matrix of 8 partitions (`check 1/8` .. `8/8`), compile-only, `--keep-going`
  so one run names every broken set; `powerset_delta.py` runs first.
- **in certify, on request**: `certify.sh powerset [M/N]`, never inside
  `quick`, `focus` or `full`.

Two constraints:

- **Never concurrent** with another cargo in the same tree: `--no-dev-deps`
  rewrites `Cargo.toml` and `Cargo.lock` for the whole run. `check` refuses to
  start on a modified `Cargo.toml`, which is also what a killed run leaves.
- **No `RUSTFLAGS=-D warnings`**: a depth-2 set turns most of the crate off,
  and every resulting `dead_code` warning would be a red that says nothing
  about whether the set compiles.
