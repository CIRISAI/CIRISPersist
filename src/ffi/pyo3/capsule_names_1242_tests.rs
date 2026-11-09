//! v61.2.0 (CIRISPersist#1242) — **every raw-layout capsule `PyEngine` hands
//! out carries its versioned name.**
//!
//! - **I1703** opens an engine through the Python constructor, as every host
//!   does, and builds each capsule in
//!   [`RAW_LAYOUT_CAPSULES`](crate::ffi::capsule_names::RAW_LAYOUT_CAPSULES)
//!   through its real `#[pymethod]`. Each one is named exactly
//!   `ciris_persist::<base>@<CARGO_PKG_VERSION>`: `checked_pointer` with its
//!   constant accepts it; the pre-61.2 unversioned name, the same base at
//!   another version, and a sibling capsule's constant are all refused.
//!   `local_signer_capsule` and `trust_scoring_capsule` may instead raise
//!   their own `*_unavailable` `ValueError` (absent state, not a capsule);
//!   the other five must build.
//!
//! The unit legs (the name shape I1700, the refusal I1701, the exact match
//! I1702, the build-site scan I1704) are in `ffi::capsule_names`. Runs on
//! sqlite and postgres.

use super::PyEngine;
use crate::federation::tier_ingest::test_support as ts;
use crate::ffi::capsule_names::{checked_pointer, RAW_LAYOUT_CAPSULES};
use pyo3::prelude::*;
use pyo3::types::PyCapsule;
use std::ffi::CString;

/// Open `dsn` through the Python constructor, as every host does.
fn open_from_python(dsn: &str, alias: &str, dir: &std::path::Path) -> PyEngine {
    let seed = ts::seed_for(alias);
    let ed = dir.join("ed.seed");
    let pqc = dir.join("pqc.seed");
    std::fs::write(&ed, seed).unwrap();
    std::fs::write(&pqc, seed).unwrap();
    Python::initialize();
    Python::attach(|py| {
        PyEngine::new(
            py,
            dsn,
            alias,
            None,
            Some(alias.to_owned()),
            Some(ed.display().to_string()),
            Some(alias.to_owned()),
            Some(pqc.display().to_string()),
            None,
            None,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
        )
    })
    .expect("I1703: the Python open")
}

/// The capsule `method` builds, through its real `#[pymethod]`. A row added
/// to `RAW_LAYOUT_CAPSULES` without an arm here fails the witness.
fn build<'py>(engine: &PyEngine, py: Python<'py>, method: &str) -> PyResult<Bound<'py, PyCapsule>> {
    match method {
        "federation_directory_capsule" => engine.federation_directory_capsule_py(py),
        "outbound_queue_capsule" => engine.outbound_queue_capsule_py(py),
        "keyring_signer_capsule" => engine.keyring_signer_capsule_py(py),
        "runtime_handle_capsule" => engine.runtime_handle_capsule_py(py),
        "blob_storage_capsule" => engine.blob_storage_capsule_py(py),
        "local_signer_capsule" => engine.local_signer_capsule_py(py),
        "trust_scoring_capsule" => engine.trust_scoring_capsule_py(py),
        other => panic!("I1703: no build arm for `{other}`"),
    }
}

fn i1703_every_raw_layout_capsule_carries_its_versioned_name(engine: &PyEngine, who: &str) {
    Python::attach(|py| {
        let mut built = 0usize;
        for (i, &(method, name)) in RAW_LAYOUT_CAPSULES.iter().enumerate() {
            let base = method.strip_suffix("_capsule").unwrap();
            let cap = match build(engine, py, method) {
                Ok(cap) => cap,
                Err(e)
                    if matches!(method, "local_signer_capsule" | "trust_scoring_capsule")
                        && e.is_instance_of::<pyo3::exceptions::PyValueError>(py)
                        && e.value(py).to_string() == format!("{base}_unavailable") =>
                {
                    continue;
                }
                Err(e) => panic!("I1703 {who}: `{method}` failed to build: {e}"),
            };
            built += 1;
            assert!(
                checked_pointer(&cap, name).is_ok(),
                "I1703 {who}: `{method}`'s capsule must be named {name:?}"
            );
            let unversioned = CString::new(format!("ciris_persist::{base}")).unwrap();
            let other_version = CString::new(format!("ciris_persist::{base}@0.0.0")).unwrap();
            for wrong in [unversioned.as_c_str(), other_version.as_c_str()] {
                assert!(
                    !cap.is_valid_checked(Some(wrong)),
                    "I1703 {who}: `{method}`'s capsule must NOT answer to {wrong:?}"
                );
            }
            let (sibling, sibling_name) = RAW_LAYOUT_CAPSULES[(i + 1) % RAW_LAYOUT_CAPSULES.len()];
            let err = checked_pointer(&cap, sibling_name)
                .expect_err("a capsule must not unwrap as its sibling");
            assert!(
                err.value(py)
                    .to_string()
                    .starts_with(crate::ffi::capsule_names::CAPSULE_VERSION_SKEW),
                "I1703 {who}: `{method}` asked as `{sibling}` is a skew refusal: {err}"
            );
        }
        assert!(
            built >= 5,
            "I1703 {who}: only {built} raw-layout capsules built — the five with no \
             absent-state arm must always build"
        );
    });
}

#[cfg(feature = "sqlite")]
#[test]
fn i1703_raw_layout_capsules_carry_versioned_names_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
    let alias = format!("cn{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let engine = open_from_python(&dsn, &alias, dir.path());
    i1703_every_raw_layout_capsule_carries_its_versioned_name(&engine, "sqlite");
}

#[cfg(feature = "postgres")]
#[test]
fn i1703_raw_layout_capsules_carry_versioned_names_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let alias = format!("cn{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let engine = open_from_python(&dsn, &alias, dir.path());
    i1703_every_raw_layout_capsule_carries_its_versioned_name(&engine, "postgres");
    eprintln!("i1703 postgres: RAN");
}
