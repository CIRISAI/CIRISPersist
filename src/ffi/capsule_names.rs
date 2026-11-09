//! v61.2.0 (CIRISPersist#1242) — **a raw-layout capsule is named for the
//! persist build that laid it out.**
//!
//! Seven of `PyEngine`'s capsules hand the receiving cdylib a raw Rust value:
//! a concrete persist type (`engine::BackendDispatch`, `Arc<LocalSigner>`,
//! `signing::KeyringSignerHandle`), a trait object over a persist trait
//! (`Arc<dyn FederationDirectory>`, `Arc<dyn TrustScoring>`), or a foreign
//! runtime type (`tokio::runtime::Handle`). The receiver (CIRISEdge, which
//! compiles its OWN copy of ciris-persist) dereferences that pointer with ITS
//! compiled layout and vtables. When the two persist builds differ, a moved
//! private field or a reordered vtable slot is undefined behaviour that raises
//! no error: 61.1.0 changed `PostgresBackend`'s fields (#1231), which a 61.0
//! consumer reading a 61.1 `BackendDispatch` would read at the wrong offsets.
//!
//! So each of those capsules is named `ciris_persist::<capsule>@<version>`,
//! with `<version>` this crate's `CARGO_PKG_VERSION`, and
//! [`checked_pointer`] is the consumer's unwrap. Both sides read the name from
//! the ONE constant here, so they cannot drift inside one build; across two
//! builds the consumer's copy of [`checked_pointer`] carries the consumer's
//! version, and a skewed pair is refused at the name check, before any
//! dereference, with a `capsule_version_skew` error naming both names.
//!
//! **The guard holds only if the consumer asks with its compiled constant.**
//! `pointer_checked(cap.name())` (passing the capsule's own name back) checks
//! nothing. A consumer must call [`checked_pointer`] with the constant for the
//! capsule it expects, or `pointer_checked(Some(<that constant>))`.
//!
//! **What the version binds, and what it does not.** Persist pins exactly one
//! CIRISVerify tag, so a persist version implies one `ciris-keyring` source
//! (whose `HardwareSigner` / `PqcSigner` trait objects ride inside
//! `KeyringSignerHandle`). It does NOT imply the consumer's `tokio` (persist
//! depends on `tokio = "1"`; each binary resolves its own) or its `rustc`, and
//! Rust guarantees no struct layout across compilers. The versioned name is a
//! necessary guard, not a sufficient one; the sound surfaces are the
//! ABI-versioned `*_ops` / `executor` capsules (a `#[repr(C)]` vtable checked
//! against its `*_ABI_VERSION`, ops dispatched inside persist's `.so`), whose
//! `_v1` names are NOT versioned by this module.

use std::ffi::CStr;

/// `"ciris_persist::<base>@<CARGO_PKG_VERSION>"` as a `&'static CStr`, built
/// at compile time.
macro_rules! versioned_capsule_name {
    ($base:literal) => {
        match CStr::from_bytes_with_nul(
            concat!(
                "ciris_persist::",
                $base,
                "@",
                env!("CARGO_PKG_VERSION"),
                "\0"
            )
            .as_bytes(),
        ) {
            Ok(name) => name,
            Err(_) => panic!("a capsule name carries an interior NUL"),
        }
    };
}

/// This build's crate version, the suffix every raw-layout capsule name
/// carries after `@`.
pub const PERSIST_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `federation_directory_capsule`: an `Arc<dyn FederationDirectory>` (a trait
/// object over a persist trait; its vtable order is persist's build's).
pub const FEDERATION_DIRECTORY: &CStr = versioned_capsule_name!("federation_directory");

/// `outbound_queue_capsule`: a concrete `engine::BackendDispatch`
/// (`Arc<SqliteBackend>` / `Arc<PostgresBackend>`).
pub const OUTBOUND_QUEUE: &CStr = versioned_capsule_name!("outbound_queue");

/// `keyring_signer_capsule`: a concrete `signing::KeyringSignerHandle`
/// holding `ciris-keyring` trait objects.
pub const KEYRING_SIGNER: &CStr = versioned_capsule_name!("keyring_signer");

/// `runtime_handle_capsule`: a `tokio::runtime::Handle` (tokio's layout; see
/// the module note on what the persist version does not bind).
pub const RUNTIME_HANDLE: &CStr = versioned_capsule_name!("runtime_handle");

/// `blob_storage_capsule`: a concrete `engine::BackendDispatch`.
pub const BLOB_STORAGE: &CStr = versioned_capsule_name!("blob_storage");

/// `local_signer_capsule`: a concrete `Arc<signing::LocalSigner>`.
pub const LOCAL_SIGNER: &CStr = versioned_capsule_name!("local_signer");

/// `trust_scoring_capsule`: an `Arc<dyn TrustScoring>` (a trait object over a
/// persist trait).
pub const TRUST_SCORING: &CStr = versioned_capsule_name!("trust_scoring");

/// Every raw-layout capsule, as `(PyEngine method, versioned name)`. A
/// consumer that looks a capsule up by its method name finds the name it must
/// ask for here.
pub const RAW_LAYOUT_CAPSULES: [(&str, &CStr); 7] = [
    ("federation_directory_capsule", FEDERATION_DIRECTORY),
    ("outbound_queue_capsule", OUTBOUND_QUEUE),
    ("keyring_signer_capsule", KEYRING_SIGNER),
    ("runtime_handle_capsule", RUNTIME_HANDLE),
    ("blob_storage_capsule", BLOB_STORAGE),
    ("local_signer_capsule", LOCAL_SIGNER),
    ("trust_scoring_capsule", TRUST_SCORING),
];

/// The versioned name a raw-layout capsule method's capsule carries, or
/// `None` for a method that hands out no raw-layout capsule.
pub fn name_for_method(method: &str) -> Option<&'static CStr> {
    RAW_LAYOUT_CAPSULES
        .iter()
        .find(|(m, _)| *m == method)
        .map(|(_, name)| *name)
}

/// The stable token that leads a skew refusal's message.
pub const CAPSULE_VERSION_SKEW: &str = "capsule_version_skew";

/// The consumer's unwrap of a raw-layout capsule: the payload pointer when
/// `capsule` is named exactly `expected` (one of this module's constants, as
/// the CONSUMER's copy of persist compiled it), else a `TypeError` led by
/// [`CAPSULE_VERSION_SKEW`] naming the expected name, this build's version,
/// and the name the capsule carries. Nothing is dereferenced on either path;
/// casting the pointer to the payload type remains the caller's `unsafe`.
pub fn checked_pointer(
    capsule: &pyo3::Bound<'_, pyo3::types::PyCapsule>,
    expected: &'static CStr,
) -> pyo3::PyResult<std::ptr::NonNull<std::ffi::c_void>> {
    use pyo3::types::{PyAnyMethods, PyCapsuleMethods};
    // `PyCapsule_IsValid` does not fail and sets no exception: a wrong name
    // or a NULL pointer is `false`.
    if !capsule.is_valid_checked(Some(expected)) {
        let held = capsule
            .repr()
            .map(|r| held_name_from_repr(&r.to_string()))
            .unwrap_or_else(|_| "<unreadable>".to_owned());
        let held_version = held
            .rsplit_once('@')
            .map(|(_, v)| v.to_owned())
            .unwrap_or_else(|| "a pre-61.2 build (unversioned name)".to_owned());
        return Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "{CAPSULE_VERSION_SKEW}: this consumer compiled ciris-persist {PERSIST_VERSION} and \
             asks for a capsule named \"{}\", but the engine handed one named \"{held}\" \
             (persist {held_version}). A raw-layout capsule is sound only between identical \
             persist builds (CIRISPersist#1242): build the consumer against the persist version \
             of the wheel it runs with, or use the ABI-versioned *_ops capsule.",
            expected.to_string_lossy(),
        )));
    }
    capsule.pointer_checked(Some(expected))
}

/// The name inside CPython's `<capsule object "NAME" at 0x…>` repr, or the
/// whole repr when it carries no quoted name (`<capsule object NULL at …>`).
fn held_name_from_repr(repr: &str) -> String {
    match (repr.find('"'), repr.rfind('"')) {
        (Some(a), Some(b)) if b > a => repr[a + 1..b].to_owned(),
        _ => repr.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyCapsule;
    use pyo3::Python;

    /// I1700 — every raw-layout capsule name is
    /// `ciris_persist::<base>@<CARGO_PKG_VERSION>`, the seven are distinct,
    /// and `name_for_method` maps each method to its own.
    ///
    /// Red under: dropping the `@`/version from `versioned_capsule_name!`
    /// (the pre-61.2 names), pointing two constants at one base, or a
    /// `RAW_LAYOUT_CAPSULES` row whose method and name disagree.
    #[test]
    fn i1700_every_raw_layout_capsule_name_carries_the_crate_version() {
        let suffix = format!("@{}", env!("CARGO_PKG_VERSION"));
        let mut seen = std::collections::BTreeSet::new();
        for (method, name) in RAW_LAYOUT_CAPSULES {
            let name = name.to_str().expect("a capsule name is UTF-8");
            let base = method
                .strip_suffix("_capsule")
                .expect("every raw-layout method ends `_capsule`");
            assert_eq!(
                name,
                format!("ciris_persist::{base}{suffix}"),
                "I1700: `{method}`'s capsule name must carry this build's version"
            );
            assert!(seen.insert(name), "I1700: `{name}` is used twice");
            assert_eq!(
                name_for_method(method).map(|n| n.to_str().unwrap()),
                Some(name),
                "I1700: name_for_method(`{method}`)"
            );
        }
        assert_eq!(seen.len(), 7);
        assert_eq!(PERSIST_VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(name_for_method("directory_ops_capsule"), None);
        assert_eq!(name_for_method("executor_capsule"), None);
    }

    /// I1701 — `checked_pointer` REFUSES a capsule laid out by another persist
    /// build: one named for another version, one with the pre-61.2
    /// unversioned name, and one that names a different raw-layout capsule. Each is a `TypeError` led by
    /// `capsule_version_skew` that names the expected name, this build's
    /// version and the name the capsule carries. The refused capsules wrap a
    /// value of the WRONG type (a `u64`), so a helper that reached a
    /// dereference here would be reading foreign memory; the refusal path
    /// returns before `pointer_checked`, which is the only call that yields a
    /// pointer.
    ///
    /// Red under: `checked_pointer` passing the capsule's own name back
    /// (`pointer_checked(cap.name())`, Edge's pre-#1242 shape, which accepts
    /// every name), or comparing only the `ciris_persist::<base>` prefix.
    #[test]
    fn i1701_a_capsule_from_another_persist_build_is_refused_before_any_dereference() {
        Python::initialize();
        Python::attach(|py| {
            let skewed: [(&'static CStr, &str); 3] = [
                (c"ciris_persist::outbound_queue@0.0.0", "0.0.0"),
                (
                    c"ciris_persist::outbound_queue",
                    "a pre-61.2 build (unversioned name)",
                ),
                (
                    // A name for this version, but the wrong capsule.
                    BLOB_STORAGE,
                    PERSIST_VERSION,
                ),
            ];
            for (name, held_version) in skewed {
                let cap = PyCapsule::new_with_value(py, 0xDEAD_BEEF_u64, name).unwrap();
                let err = checked_pointer(&cap, OUTBOUND_QUEUE)
                    .expect_err("I1701: a skewed capsule name must be refused");
                assert!(
                    err.is_instance_of::<pyo3::exceptions::PyTypeError>(py),
                    "I1701: a skew refusal is a TypeError: {err}"
                );
                let msg = err.value(py).to_string();
                let held = name.to_str().unwrap();
                for needle in [
                    CAPSULE_VERSION_SKEW,
                    OUTBOUND_QUEUE.to_str().unwrap(),
                    PERSIST_VERSION,
                    held,
                    held_version,
                ] {
                    assert!(
                        msg.contains(needle),
                        "I1701: the refusal of `{held}` must name `{needle}`: {msg}"
                    );
                }
                assert!(
                    msg.starts_with(CAPSULE_VERSION_SKEW),
                    "I1701: the token leads: {msg}"
                );
            }

            // An unnamed capsule cannot be built through the safe
            // `new_with_value` (it takes a `&'static CStr`), so the NULL-name
            // arm of the message is pinned at the repr parser.
            assert_eq!(
                held_name_from_repr("<capsule object NULL at 0x7f00>"),
                "<capsule object NULL at 0x7f00>"
            );
        });
    }

    /// I1702 — `checked_pointer` ACCEPTS a capsule named exactly the expected
    /// constant: the guard refuses skew, not every capsule.
    ///
    /// Red under: a `checked_pointer` that always refuses, or one that asks
    /// `pointer_checked` for a name other than `expected`.
    #[test]
    fn i1702_the_exact_versioned_name_is_accepted() {
        Python::initialize();
        Python::attach(|py| {
            for (method, name) in RAW_LAYOUT_CAPSULES {
                let cap = PyCapsule::new_with_value(py, 7_u64, name).unwrap();
                assert!(
                    checked_pointer(&cap, name).is_ok(),
                    "I1702: `{method}`'s own name must be accepted"
                );
            }
        });
    }

    /// I1704 — no capsule build site in `ffi/pyo3.rs` spells a
    /// `c"ciris_persist::…"` name literal except the ABI-versioned `_v1`
    /// ones: every raw-layout build site reads this module's constants, so a
    /// new raw capsule cannot ship an unversioned name. Comment lines are
    /// stripped (the doc examples quote the old names).
    ///
    /// Red under: reverting any of the seven build sites to its literal.
    #[test]
    fn i1704_no_raw_layout_build_site_spells_an_unversioned_literal() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ffi/pyo3.rs");
        let text = std::fs::read_to_string(&path).expect("read src/ffi/pyo3.rs");
        let mut offenders = Vec::new();
        let mut uses = 0usize;
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("capsule_names::") {
                uses += 1;
            }
            let mut rest = code;
            while let Some(at) = rest.find("c\"ciris_persist::") {
                let lit = &rest[at + 2..];
                let end = lit.find('"').unwrap_or(lit.len());
                if !lit[..end].ends_with("_v1") {
                    offenders.push(format!("pyo3.rs:{}: {}", i + 1, &lit[..end]));
                }
                rest = &lit[end..];
            }
        }
        assert!(
            uses >= RAW_LAYOUT_CAPSULES.len(),
            "I1704: only {uses} `capsule_names::` uses in pyo3.rs — the seven raw-layout \
             build sites must each read their constant (or the scan is broken)"
        );
        assert!(
            offenders.is_empty(),
            "I1704: an unversioned capsule name literal at a build site (CIRISPersist#1242): \
             {offenders:?}"
        );
    }
}
