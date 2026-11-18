//! v59.0.0 (sealed-transport floor, operator ruling 2026-10-19; CC 5.3.3.5 E1
//! option (i)) — **I1144–I1147: the framed key plane is retired.**
//!
//! v58 restored the framed outbound key-plane listings for pre-v58 peers
//! (compat reads). Every RNS byte now rides a per-link hybrid seal with no
//! classical fallback, so an unsealed old peer is unreachable, and v59 drops
//! the compat reads: the key plane replicates only as rows.
//!
//! - **I1144 (one-way migration at first open, sqlite + postgres)** — a store
//!   migrated only through V195 (the v57 schema) holding a key record, a key
//!   revocation, two signed occurrences, a route and a FRAMED occurrence
//!   revocation is migrated forward: with no write in between, every key, key
//!   revocation and occurrence has its key-plane row (the v58 lazy rehome,
//!   eager), no identity loses a key or a route, the framed revocation is kept
//!   as a legacy projection row (V200) and the occurrence it names stays
//!   revoked, and the rehome reports what it counted. Memory holds no v57
//!   store, so this leg is SQL only.
//! - **I1145 (inbound framed objects are refused, every backend)** — the
//!   framed occurrence-revocation record read and every framed wire-index
//!   reload refuse or resolve nothing, typed `federation_envelope_kind_retired`
//!   where a door answers.
//! - **I1146 (the capsule's framed inbound ops are refused)** —
//!   `ApplyReplicatedKeyRecord` and `PutIdentityOccurrenceRevocation` answer
//!   `federation_envelope_kind_retired: key` /
//!   `…: identity_occurrence_revocation` (in `ffi::directory_capsule`'s tests,
//!   which own the capsule fixture).
//! - **I1148 (a pre-door revocation evicts no genesis key, sqlite +
//!   postgres)** — a V195 store holding another key's framed revocation of
//!   the self pair `(F, F)` migrates forward with `F` still on the roster and
//!   acting as the self; the same act through the two-path door evicts it.
//! - **I1150 (the replication path takes in no framed object, every
//!   backend)** — a peer's advertisement of a hash of each retired kind is
//!   refused at the wire-index ingest (`insert_known_wire_hash`); the
//!   authoring doors `put_identity_occurrence` / `put_revocation` still land
//!   rows. (The capsule's `ApplyReplicatedKeyRecord` and
//!   `PutIdentityOccurrenceRevocation` are I1146's.)
//! - **I1147 (the compat reads stay gone, from disk)** — no trait method,
//!   backend impl, capsule op, Python method or stub carries a retired listing
//!   or the framed revocation door (comments stripped); the v58 I1123 gate
//!   (no hybrid-pending revocation path) rides along.
//!
//! v62.0.0 (the JSON cut, lead's ruling on earlier serving surfaces): I1145
//! and I1150 are deleted. They witness the framed reads, the content-hash
//! wire-index reloads and the known-hash ingest of the earlier form, which
//! slice F deletes. I1147 (from disk) stays; `seed_raw_framed_*` stay for
//! their other caller.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    /// **I1147** — the compat reads and the framed revocation door stay gone
    /// (from disk, comments stripped); and (v58 I1123) no hybrid-pending
    /// revocation path came back.
    #[test]
    fn i1147_the_compat_reads_stay_gone() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for file in [
            "src/federation/mod.rs",
            "src/store/sqlite.rs",
            "src/store/postgres.rs",
            "src/ffi/directory_capsule.rs",
            "src/ffi/pyo3.rs",
            "src/federation/directory_double.rs",
            "python/ciris_persist/ciris_persist.pyi",
        ] {
            let code: String = std::fs::read_to_string(root.join(file))
                .unwrap()
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !t.starts_with("//") && !t.starts_with('#') && !t.starts_with("\"\"\"")
                })
                .collect::<Vec<_>>()
                .join("\n");
            for gone in [
                "fn list_signed_key_records_since",
                "fn list_signed_revocations_since",
                "fn list_signed_identity_occurrences_since",
                "fn list_signed_identity_occurrence_revocations_since",
                "fn list_signed_identity_occurrence_revocations_for",
                "fn put_identity_occurrence_revocation(",
                "def list_signed_key_records_since",
                "def list_signed_revocations_since",
                "def list_signed_identity_occurrences_since",
                "def list_signed_identity_occurrence_revocations_since",
                "ListSignedKeyRecordsSince",
                "ListSignedRevocationsSince",
                "ListSignedIdentityOccurrencesSince",
                "ListSignedIdentityOccurrenceRevocationsSince",
                "SignedIdentityOccurrenceRevocation {",
                "ServedIdentityOccurrenceRevocation",
                // v58 I1123
                "fn attach_revocation_pqc_signature",
                "def attach_revocation_pqc_signature",
                "fn list_hybrid_pending_revocations",
                "fn sweep_revocations",
                "AttachRevocationPqcSignature",
                // v62.0.0 — the whole PQC cold path (a composite is atomic).
                "fn attach_key_pqc_signature",
                "fn attach_attestation_pqc_signature",
                "def attach_key_pqc_signature",
                "def attach_attestation_pqc_signature",
                "fn list_hybrid_pending_keys",
                "fn list_hybrid_pending_attestations",
                "fn run_pqc_sweep",
                "def run_pqc_sweep",
                "pqc_sweep_on_init",
                "fn cold_path_pqc_sign",
                "HybridPendingRow",
            ] {
                assert!(
                    !code.contains(gone),
                    "I1147: {file} carries `{gone}` — a retired framed key-plane path is back"
                );
            }
        }
    }
}
