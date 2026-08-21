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
//! `nothing_yields_anti_entropy_satisfied_today` and
//! `every_cited_processor_has_a_non_test_caller`, which this repo already
//! trusts.
//!
//! # Nothing here is recognised by a name pattern
//!
//! **The first version of this gate matched call names against a list of
//! verbs** — `check_`, `verify_`, `validate_`. It was wrong in exactly the way
//! this module exists to catch: `authorize_family_growth`,
//! `authorize_community_growth` and `reject_future_dated_community_revocation`
//! are live production gates on all three backends, and the sweep that
//! reported "six divergences, none blocking" had been run by a detector that
//! could not see any of them. A second attempt keyed on the call's *module
//! path* instead, and immediately produced a false finding — `grant_trust`
//! looked like a gate missing on two backends, when in fact all three call
//! `validate_trust_grant` and two of them reach it through
//! `crate::store::memory::`. **A path-prefix rule is exactly as much a guess
//! as a name-prefix rule.**
//!
//! So the alphabet is a **partition, not a pattern**. The universe is derived:
//! every call in a scanned door whose failure propagates out of it — `f(..)?`,
//! `f(..).await?`, `f(..).map_err(..)?`, `if let Err(..) = f(..)`. Every name
//! in that universe must appear in [`CALL_CLASSES`], and **a name that does
//! not reds the build**. There is no silent skip, so the question "what does
//! this make invisible?" has one answer: nothing, because nothing may go
//! unclassified.
//!
//! A call whose failure does *not* propagate cannot refuse the write, so it
//! cannot be a gate. That is a structural exclusion, not a guess.
//!
//! # The door set is DERIVED, never listed
//!
//! There is no hand-maintained list of doors either. The universe is *every
//! method of `FederationDirectory`, `BlobStorage` and `Backend` that any
//! backend implements* — read out of the impl blocks themselves. Adding a door
//! enrols it in the gate on the commit that adds it.
//! [`DECLARED_DIVERGENCES`] is a *subtractive* manifest over a derived set,
//! the `KNOWN_AXIS_FUSIONS` partition discipline.
//!
//! # What it cannot see
//!
//! - **Argument semantics.** Two backends can call the same gate with
//!   different arguments. That is `check_row_column_binding`-shaped work.
//! - **SQL.** A CHECK constraint, a column type, or a `DEFAULT` is invisible
//!   here by construction. That is where CIRISPersist#622 and #656 lived, and
//!   it is why `store::schema_parity` is a separate mechanism.
//! - **Gates reached through a helper in a *third* file.** Delegation is
//!   followed into same-file helpers ([`Class::Delegates`]); a helper that
//!   moved to a shared module is visible as the call itself, but its contents
//!   are not.

/// What a propagated call *is*, for the purpose of comparing doors.
///
/// The fail-open direction is [`Self::Plumbing`]: a real gate misfiled there
/// becomes invisible. Every `Plumbing` row in [`CALL_CLASSES`] was reviewed
/// against that question specifically, and the rule applied was **"can this
/// refuse something about the caller's input?"** — not "does its name look
/// like a gate", which is the mistake that produced the first version.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// A refusal. Contributes its name to the compared sequence.
    Gate,
    /// Storage, serialization, driver, row-mapping, locking, derivation. It
    /// can fail, but only on the substrate's own terms — never on a policy
    /// question about the row. Contributes nothing.
    Plumbing,
    /// Another door or a same-file helper that itself runs gates. Contributes
    /// the callee's own sequence, inlined.
    Delegates,
}

/// **The alphabet, as a partition over a derived universe.**
///
/// Every call in a scanned door whose failure propagates must appear here.
/// [`tests::every_propagated_call_in_a_door_is_classified`] fails, naming the
/// backend and the line, on anything that does not — and
/// [`tests::no_call_class_is_stale`] fails on an entry the corpus no longer
/// contains, so this is a partition in both directions rather than a floor.
///
/// Notable judgements, recorded because they are the ones a reviewer should
/// argue with:
///
/// - `compute_persist_row_hash` is **Plumbing**. It is a derivation, not a
///   refusal: it fails only on a non-finite weight, which
///   `check_row_column_binding` has already refused. Its *absence* would be a
///   real defect, but the row-hash witnesses catch that directly, and treating
///   it as a gate would flag the memory backend's second call (it re-derives
///   the stored row's hash for a conflict check where the SQL backends SELECT
///   it) as a divergence it is not.
/// - `check` is **Gate**, and is the receiver-qualified form —
///   `hardware_attestation_policy.check`, `DimensionAdmissionPolicy::default().check`.
///   A policy object refusing is a gate whatever the method is called.
/// - `prepare_proposal` / `prepare_decision` / `parse_stream_id` are **Gate**
///   despite their names, because each validates caller-supplied shape before
///   anything is stored. Classified by what they do, not what they are called.
#[cfg(test)]
pub(crate) const CALL_CLASSES: &[(&str, Class)] = &[
    ("accord_nonce_issued", Class::Delegates),
    ("acquire_migration_lock", Class::Delegates),
    ("add", Class::Plumbing),
    ("admission_gate", Class::Plumbing),
    ("admit_witness", Class::Gate),
    ("aggregation_record_from_row", Class::Delegates),
    ("all_kind_hash_keys", Class::Plumbing),
    ("apply_migration_lock_timeout", Class::Delegates),
    ("as_array", Class::Plumbing),
    ("assemble_chunk_dag_range", Class::Plumbing),
    ("assemble_fountain_content", Class::Delegates),
    ("authorize_community_growth", Class::Gate),
    ("authorize_family_growth", Class::Gate),
    ("backfill_trace_dedup_shard_keys", Class::Delegates),
    ("bytes", Class::Plumbing),
    ("caller_scope_from_directory", Class::Gate),
    ("canonicalize_in_place", Class::Gate),
    ("check", Class::Gate),
    ("check_admin_action_attribution", Class::Gate),
    ("check_admissible", Class::Gate),
    ("check_admission_via_envelope", Class::Gate),
    ("check_attested_subject_admission", Class::Gate),
    ("check_blob", Class::Gate),
    ("check_canonical_role_admission", Class::Gate),
    ("check_capacity_consent_admission", Class::Gate),
    ("check_capacity_never_local", Class::Gate),
    ("check_co_steward_role_admission", Class::Gate),
    ("check_cohort_scope", Class::Gate),
    ("check_community_membership_steward_binding", Class::Gate),
    ("check_consensus_protocol_form", Class::Gate),
    ("check_content_hash_hex", Class::Gate),
    ("check_delegated_duty_scores_admission", Class::Gate),
    ("check_delivery_mode_vocabulary", Class::Gate),
    ("check_device_class", Class::Gate),
    ("check_encryption_pubkeys", Class::Gate),
    ("check_envelope_size_admission", Class::Gate),
    ("check_family_charter_admission", Class::Gate),
    ("check_federation", Class::Gate),
    ("check_genesis_attestation_reserved", Class::Gate),
    ("check_genesis_rebake_purge_admission_under", Class::Gate),
    ("check_geographic_community_admission", Class::Gate),
    ("check_infra_attest_role_admission", Class::Gate),
    ("check_instant_binding", Class::Gate),
    ("check_key_pqc_attachment", Class::Gate),
    ("check_no_moderator_federate_apply", Class::Gate),
    ("check_node_agency_admission", Class::Gate),
    ("check_observed_region", Class::Gate),
    ("check_partner_revision_monotonic", Class::Gate),
    ("check_partner_set_and_quorum", Class::Gate),
    ("check_peer_deadmission", Class::Gate),
    ("check_peer_record_admission", Class::Gate),
    ("check_privileged_identity_type_admission", Class::Gate),
    ("check_promotion_admission", Class::Gate),
    ("check_promotion_cohort_standing", Class::Gate),
    ("check_purge_admission", Class::Gate),
    ("check_put_blob_admission", Class::Gate),
    ("check_reseal_admission", Class::Gate),
    ("check_reseal_seal_admission", Class::Gate),
    ("check_reserved_prefix_admission", Class::Gate),
    ("check_revocation_anti_rollback", Class::Gate),
    ("check_revocation_authority", Class::Gate),
    ("check_revocation_bound", Class::Gate),
    ("check_revocation_envelope_binding", Class::Gate),
    ("check_revocation_scrub_skew", Class::Gate),
    ("check_role_authority", Class::Gate),
    ("check_row_column_binding", Class::Gate),
    ("check_single_node_owner_admission", Class::Gate),
    ("check_skew_and_payment", Class::Gate),
    ("check_trace_dimension_admission", Class::Gate),
    ("check_trust_charter_admission", Class::Gate),
    ("check_user_target_steward_binding_admission", Class::Gate),
    ("check_withdraws_admission", Class::Gate),
    ("check_write", Class::Gate),
    ("check_write_cohort_scope_for", Class::Gate),
    ("cloned", Class::Plumbing),
    ("commit", Class::Plumbing),
    ("compute_persist_row_hash", Class::Plumbing),
    ("connect", Class::Plumbing),
    ("decode", Class::Plumbing),
    ("dedicated_connect", Class::Delegates),
    ("delete_blob", Class::Delegates),
    ("deserialize_signature", Class::Plumbing),
    ("deserialize_witness_signatures", Class::Plumbing),
    ("entry_as_stored", Class::Plumbing),
    ("envelope_dimension", Class::Plumbing),
    ("execute", Class::Plumbing),
    ("filter", Class::Plumbing),
    ("filter_withheld_rows", Class::Gate),
    ("find", Class::Plumbing),
    ("fountain_manifest_row", Class::Delegates),
    ("from_bytes", Class::Plumbing),
    ("from_manifest_bytes", Class::Plumbing),
    ("from_run", Class::Plumbing),
    ("from_str", Class::Plumbing),
    ("from_value", Class::Plumbing),
    ("from_wire_str", Class::Plumbing),
    ("get", Class::Plumbing),
    ("get_accord_proposal", Class::Delegates),
    ("get_attestation", Class::Delegates),
    ("get_client", Class::Delegates),
    ("get_mut", Class::Plumbing),
    ("index_stored_key_row", Class::Delegates),
    ("index_stored_record", Class::Delegates),
    ("insert_trace_events_batch", Class::Delegates),
    ("insert_trace_llm_calls_batch", Class::Delegates),
    ("iter", Class::Plumbing),
    ("list_attestations_by", Class::Delegates),
    ("list_org_memberships_for", Class::Delegates),
    ("list_partner_records_for", Class::Delegates),
    ("load_or_init_content_master", Class::Delegates),
    ("lookup_community", Class::Delegates),
    ("lookup_family", Class::Delegates),
    ("lookup_identity_for_occurrence", Class::Delegates),
    ("lookup_public_key", Class::Delegates),
    ("map_err", Class::Plumbing),
    ("memory_idempotent_insert", Class::Delegates),
    // v36.0.0 (CIRISPersist#668) — visible because the cursor family's row
    // mappers are now direct calls (see the `pg_row_to_*` note): these are
    // the mappers' own decode helpers. Plumbing — they fail only on the
    // substrate's own stored bytes (a corrupt column), never on caller input.
    ("decode_witness_set", Class::Plumbing),
    ("pg_witness_set", Class::Plumbing),
    ("strict_ts", Class::Plumbing),
    ("mint_content_kem_keypair", Class::Plumbing),
    // v31.4.0 (CIRISPersist#682). Plumbing, deliberately: it allocates THIS
    // node's next `federation_keys.admitted_at` and fails only when the `MAX`
    // read fails — a substrate error. It asks nothing about the caller's row
    // and can refuse no input, so it cannot be a gate. Its ABSENCE from a door
    // is a real defect, but the #682 witnesses catch that directly (mutating
    // the call out reds the late-replication witness on that backend), which is
    // where that belongs.
    ("next_key_admission_position", Class::Plumbing),
    // v36.0.0 (CIRISPersist#707) — the postgres spelling of the same
    // allocator after the serve-position widening (`GREATEST(admitted_at,
    // mutated_at)`). Plumbing for the identical #682 reason: it allocates and
    // refuses nothing; its ABSENCE from a door is what the re-serve/late-
    // admit witnesses red on.
    ("next_key_serve_position", Class::Plumbing),
    // v36.0.0 (CIRISPersist#668) — the V130 per-plane allocator (postgres +
    // memory spelling). Plumbing: reads a MAX and fails only on substrate
    // error; the per-plane #668 witnesses catch a door that skips it.
    ("next_plane_position", Class::Plumbing),
    ("ok_or_else", Class::Plumbing),
    ("optional", Class::Plumbing),
    ("parse_from_rfc3339", Class::Plumbing),
    ("parse_stream_id", Class::Gate),
    ("parse_ts", Class::Plumbing),
    ("pg_envelope_text", Class::Delegates),
    ("pg_envelope_value", Class::Delegates),
    ("pg_load_stream_chunk_hashes", Class::Delegates),
    ("pg_project_attestation_subjects", Class::Delegates),
    ("pg_project_consent_peer_set", Class::Delegates),
    // v36.0.0 (CIRISPersist#668) — newly VISIBLE rather than newly written,
    // the whole cursor family this time: every `list_*_since` used to pass
    // its row mapper as a bare function reference to `query`/`query_map`;
    // the pair cursor reads `admitted_at`/`_pos` alongside the row, so the
    // mappers are now called explicitly inside the closure and propagate.
    // Same class as every previously-listed `*_row_to_*` sibling.
    ("pg_row_to_attestation", Class::Delegates),
    ("pg_row_to_community", Class::Delegates),
    (
        "pg_row_to_community_membership_revocation",
        Class::Delegates,
    ),
    ("pg_row_to_family", Class::Delegates),
    ("pg_row_to_family_membership_revocation", Class::Delegates),
    ("pg_row_to_identity_occurrence", Class::Delegates),
    ("pg_row_to_identity_occurrence_revocation", Class::Delegates),
    ("pg_row_to_location_proof", Class::Delegates),
    ("pg_row_to_transport_destination", Class::Delegates),
    ("pg_row_to_key_record", Class::Delegates),
    ("pg_row_to_org_membership", Class::Delegates),
    ("pg_row_to_organization", Class::Delegates),
    ("pg_row_to_partner_record", Class::Delegates),
    ("pg_row_to_peer_metadata_for_hash", Class::Delegates),
    ("pg_row_to_revocation", Class::Delegates),
    ("pg_row_to_signed_community", Class::Delegates),
    (
        "pg_row_to_signed_community_membership_revocation",
        Class::Delegates,
    ),
    ("pg_row_to_signed_family", Class::Delegates),
    (
        "pg_row_to_signed_family_membership_revocation",
        Class::Delegates,
    ),
    ("pg_row_to_signed_identity_occurrence", Class::Delegates),
    (
        "pg_row_to_signed_identity_occurrence_revocation",
        Class::Delegates,
    ),
    ("pg_row_to_signed_location_proof", Class::Delegates),
    ("pg_row_to_signed_partner_record", Class::Delegates),
    ("pg_row_to_signed_transport_destination", Class::Delegates),
    ("pg_row_to_stored_proposal", Class::Delegates),
    ("pg_upsert_wire_index", Class::Delegates),
    ("prepare", Class::Plumbing),
    ("prepare_chunk_rows", Class::Plumbing),
    ("prepare_decision", Class::Gate),
    ("prepare_proposal", Class::Gate),
    ("prepare_sealed_manifest_row", Class::Plumbing),
    ("prepare_stream_chunk_row", Class::Plumbing),
    ("project_route", Class::Plumbing),
    ("put_family_local", Class::Delegates),
    ("put_transport_destination", Class::Delegates),
    ("query", Class::Plumbing),
    ("query_map", Class::Plumbing),
    ("query_one", Class::Plumbing),
    ("query_opt", Class::Plumbing),
    ("query_row", Class::Plumbing),
    ("recompute_and_assert_root", Class::Gate),
    ("record_hard_case", Class::Delegates),
    ("references_attestation_id_from_envelope", Class::Plumbing),
    ("reject_future_dated_community_revocation", Class::Gate),
    ("reload_record_bytes", Class::Plumbing),
    ("resolve", Class::Plumbing),
    ("resolve_steward_roster", Class::Gate),
    ("revocation_fold_target", Class::Plumbing),
    ("root_hash_from_bytes", Class::Plumbing),
    ("safe_get_with", Class::Plumbing),
    ("scope_blob_symbol_from_pg_row", Class::Delegates),
    ("seal_content_kem_private", Class::Plumbing),
    ("self_key_id", Class::Plumbing),
    ("serialize_signature", Class::Plumbing),
    ("serialize_witness_signatures", Class::Plumbing),
    ("spawn_blocking", Class::Plumbing),
    ("sqlite_load_stream_chunk_hashes", Class::Delegates),
    // v36.0.0 (CIRISPersist#707/#668) — the sqlite allocator spellings.
    // Plumbing, same rationale as `next_key_admission_position` above.
    ("sqlite_next_key_serve_position", Class::Plumbing),
    ("sqlite_next_plane_position", Class::Plumbing),
    ("sqlite_project_attestation_subjects", Class::Delegates),
    ("sqlite_project_consent_peer_set", Class::Delegates),
    // v36.0.0 (CIRISPersist#668) — newly VISIBLE for the whole cursor
    // family; see the `pg_row_to_*` block's note.
    ("sqlite_row_to_attestation", Class::Delegates),
    ("sqlite_row_to_community", Class::Delegates),
    (
        "sqlite_row_to_community_membership_revocation",
        Class::Delegates,
    ),
    ("sqlite_row_to_family", Class::Delegates),
    (
        "sqlite_row_to_family_membership_revocation",
        Class::Delegates,
    ),
    ("sqlite_row_to_identity_occurrence", Class::Delegates),
    (
        "sqlite_row_to_identity_occurrence_revocation",
        Class::Delegates,
    ),
    ("sqlite_row_to_location_proof", Class::Delegates),
    ("sqlite_row_to_transport_destination", Class::Delegates),
    ("sqlite_row_to_org_membership", Class::Delegates),
    ("sqlite_row_to_organization", Class::Delegates),
    ("sqlite_row_to_partner_record", Class::Delegates),
    ("sqlite_row_to_signed_community", Class::Delegates),
    (
        "sqlite_row_to_signed_community_membership_revocation",
        Class::Delegates,
    ),
    ("sqlite_row_to_signed_family", Class::Delegates),
    (
        "sqlite_row_to_signed_family_membership_revocation",
        Class::Delegates,
    ),
    ("sqlite_row_to_signed_identity_occurrence", Class::Delegates),
    (
        "sqlite_row_to_signed_identity_occurrence_revocation",
        Class::Delegates,
    ),
    ("sqlite_row_to_signed_location_proof", Class::Delegates),
    ("sqlite_row_to_signed_partner_record", Class::Delegates),
    (
        "sqlite_row_to_signed_transport_destination",
        Class::Delegates,
    ),
    // v31.4.0 (CIRISPersist#682) — newly VISIBLE rather than newly written.
    // `list_signed_key_records_since` used to pass this as a bare function
    // reference to `query_map`; the pair cursor reads `_pos` alongside the row,
    // so it is now called explicitly and propagates. Same class as every other
    // `sqlite_row_to_*` sibling.
    ("sqlite_row_to_key_record", Class::Delegates),
    ("sqlite_row_to_revocation", Class::Delegates),
    ("sqlite_row_to_stored_proposal", Class::Delegates),
    ("sqlite_row_tuple_to_peer_metadata", Class::Delegates),
    ("sqlite_upsert_wire_index", Class::Delegates),
    ("to_string", Class::Plumbing),
    ("to_value", Class::Plumbing),
    ("transaction", Class::Plumbing),
    ("transpose", Class::Plumbing),
    ("try_from", Class::Plumbing),
    ("try_get", Class::Plumbing),
    ("try_into", Class::Plumbing),
    ("validate_envelope_against_schema", Class::Gate),
    ("validate_family_members", Class::Gate),
    ("validate_grant_admission", Class::Gate),
    ("validate_location_cell", Class::Gate),
    ("validate_registration_pubkey", Class::Gate),
    // v38.0.0 (CIRISPersist#721) — validate_trust_grant is SHAPE validation
    // (malformed input), not authority: classifying it Gate was the parity
    // table reporting the trust doors as gated while they were open. The
    // authority gates are the two below.
    ("validate_trust_grant", Class::Plumbing),
    ("check_trust_grant_authority", Class::Gate),
    ("check_trust_revocation_authority", Class::Gate),
    ("verify_and_prepare_participation", Class::Gate),
    ("verify_bundle_quorum", Class::Gate),
    ("verify_community_admission", Class::Gate),
    (
        "verify_community_membership_revocation_admission",
        Class::Gate,
    ),
    ("verify_consent_record_transit_ingest", Class::Gate),
    ("verify_family_admission", Class::Gate),
    ("verify_family_membership_revocation_admission", Class::Gate),
    ("verify_federation_tier_ingest", Class::Gate),
    ("verify_for_admission", Class::Gate),
    ("verify_inline_hash", Class::Gate),
    ("verify_location_proof_admission", Class::Gate),
    ("verify_org_membership_admission", Class::Gate),
    ("verify_organization_admission", Class::Gate),
    ("verify_receipt_signature", Class::Gate),
    ("verify_revocation_admission", Class::Gate),
    ("verify_signed_identity_occurrence", Class::Gate),
    ("verify_signed_identity_occurrence_revocation", Class::Gate),
    ("verify_signed_touch_claim", Class::Gate),
    ("verify_signed_transport_destination", Class::Gate),
    ("verify_stream_sth_signature", Class::Gate),
    ("verify_stream_sth_witnesses", Class::Gate),
    ("verify_touch_claim_admission", Class::Gate),
];

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
    /// The trait the method belongs to.
    pub trait_name: &'static str,
    /// The method whose gate sequence diverges.
    pub method: &'static str,
    /// The backend that diverges. The rest must still agree with each other.
    pub backend: &'static str,
    /// The exact gate sequence this backend is permitted to have.
    pub expected: &'static [&'static str],
    /// Why this is a substrate difference and not a hole.
    pub reason: &'static str,
}

/// The reviewed divergences. Everything not listed here must be identical
/// across the three backends, gate for gate and order for order.
#[cfg(test)]
pub(crate) const DECLARED_DIVERGENCES: &[DeclaredDivergence] = &[
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
                 sqlite and postgres that is a query the door issues before it opens its write; \
                 on memory it is a scan under the state lock, and taking the lock is what the \
                 door does after `check_revocation_bound`. Running it under the SAME lock the \
                 insert holds is STRONGER than the SQL position, not weaker — the read and the \
                 write cannot race. Both gates are refusals that mutate nothing, so their \
                 relative order is not observable in state, only in which message an operator \
                 sees when a row violates both.",
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
                 order its siblings run, and again on the row it actually found under the lock. \
                 The SQL backends get that second answer from their transaction — they read and \
                 update inside one — and memory's read is a separate `get_attestation` that locks \
                 and releases, so without the re-ask the door would gate one row and mutate \
                 another. An extra ask of a pure refusal is the safe direction of this difference.",
    },
];

#[cfg(test)]
mod tests {
    use super::{Class, DeclaredDivergence, CALL_CLASSES, DECLARED_DIVERGENCES};
    use std::collections::{BTreeMap, BTreeSet};

    /// The three backend sources, by the name the failure message uses.
    const BACKENDS: [(&str, &str); 3] = [
        ("memory", "src/store/memory.rs"),
        ("sqlite", "src/store/sqlite.rs"),
        ("postgres", "src/store/postgres.rs"),
    ];

    /// The traits whose impls are compared, and where each trait's **default**
    /// bodies live. A backend that does not override a defaulted method runs
    /// the default, so the default's gate sequence is what it contributes.
    const TRAITS: [(&str, &str); 3] = [
        ("FederationDirectory", "src/federation/mod.rs"),
        ("BlobStorage", "src/federation/blobs.rs"),
        ("Backend", "src/store/backend.rs"),
    ];

    /// Combinators that pass their receiver's failure through unchanged. The
    /// token is the RECEIVER's name, not the combinator's — otherwise `map_err`
    /// (840 occurrences) would be the only thing this gate ever saw.
    const TRANSPARENT: [&str; 6] = [
        "map_err",
        "ok_or_else",
        "ok_or",
        "and_then",
        "context",
        "with_context",
    ];

    /// Trailing substrate suffixes stripped before comparison.
    /// `check_revocation_anti_rollback_sqlite` and `..._postgres` are ONE
    /// logical gate whose "find the newest stored row" half is per-substrate.
    const SUBSTRATE_SUFFIXES: [&str; 5] = ["_memory", "_sqlite", "_postgres", "_pg", "_mem"];

    /// How deep a [`Class::Delegates`] call is followed.
    const INLINE_DEPTH: usize = 2;

    fn manifest_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(rel: &str) -> String {
        let p = manifest_dir().join(rel);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    // ── lexing ──────────────────────────────────────────────────────

    /// Length- and line-preserving blank of comments and string/char literal
    /// contents, over a WHOLE FILE.
    ///
    /// Two things here are load-bearing and both were bugs first:
    ///
    /// 1. **`/* … */` is recognised anywhere, not only at the start of a
    ///    trimmed line, and it spans lines.** The first version only looked at
    ///    line starts, so `some_call(); /* check_a_gate(&row)?; */` counted the
    ///    commented-out gate as live — a gate someone had *deleted* still read
    ///    as present, which is the exact failure this module exists to catch,
    ///    inside the module itself. `postgres.rs` contains a real instance.
    /// 2. **String contents are blanked.** A gate name inside a SQL literal or
    ///    an error message is not a call.
    fn strip_file(text: &str) -> Vec<String> {
        let b = text.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        let mut i = 0usize;
        while i < b.len() {
            let c = b[i];
            match c {
                b'"' => {
                    out.push(b' ');
                    i += 1;
                    while i < b.len() && b[i] != b'"' {
                        if b[i] == b'\\' {
                            out.push(b' ');
                            i += 1;
                            if i < b.len() {
                                out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                                i += 1;
                            }
                            continue;
                        }
                        out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                        i += 1;
                    }
                    if i < b.len() {
                        out.push(b' ');
                        i += 1;
                    }
                }
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        out.push(b' ');
                        i += 1;
                    }
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    let end = text[i + 2..].find("*/").map_or(b.len(), |p| i + 2 + p + 2);
                    for &ch in &b[i..end] {
                        out.push(if ch == b'\n' { b'\n' } else { b' ' });
                    }
                    i = end;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out)
            .split('\n')
            .map(str::to_owned)
            .collect()
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

    fn classify(name: &str) -> Option<Class> {
        CALL_CLASSES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, c)| *c)
    }

    // ── call extraction ─────────────────────────────────────────────

    /// A call site inside a door body.
    #[derive(Debug, Clone)]
    struct Call {
        /// Bare callee name, substrate suffix stripped.
        name: String,
        /// Receiver, when the call was `a.NAME(`, `A::NAME(` or `a().NAME(`.
        receiver: Option<String>,
        /// Byte offset of the name within the body text.
        at: usize,
        /// Line within the file, 1-based, for failure messages.
        line: usize,
    }

    fn ident_end(b: &[u8], mut i: usize) -> usize {
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        i
    }

    fn match_paren(b: &[u8], open: usize) -> Option<usize> {
        let mut depth = 0i32;
        for (k, &c) in b.iter().enumerate().skip(open) {
            if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
        }
        None
    }

    /// Every `IDENT (` in `text`, with its matched close paren and receiver.
    fn raw_calls(text: &str, first_line: usize) -> Vec<(Call, usize)> {
        let b = text.as_bytes();
        let mut out = Vec::new();
        let mut line = first_line;
        let mut i = 0usize;
        while i < b.len() {
            if b[i] == b'\n' {
                line += 1;
                i += 1;
                continue;
            }
            if !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
                i += 1;
                continue;
            }
            if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
                i += 1;
                continue;
            }
            let s = i;
            let e = ident_end(b, i);
            i = e;
            let name = &text[s..e];
            // skip whitespace to the next significant byte
            let mut j = e;
            while j < b.len() && (b[j] == b' ' || b[j] == b'\t' || b[j] == b'\n') {
                j += 1;
            }
            // `NAME!(` is a macro, never a gate.
            if b.get(j) != Some(&b'(') {
                continue;
            }
            // `fn NAME(` is a definition.
            let before = text[..s].trim_end();
            if before.ends_with(" fn") || before.ends_with("\nfn") || before == "fn" {
                continue;
            }
            let Some(close) = match_paren(b, j) else {
                continue;
            };
            // receiver: `a.NAME`, `A::NAME`, `a().NAME`
            let mut receiver = None;
            let pre = text[..s].trim_end();
            if let Some(head) = pre.strip_suffix('.').or_else(|| pre.strip_suffix("::")) {
                let head = head.trim_end();
                let head = head.strip_suffix("()").unwrap_or(head);
                let head = head.trim_end();
                let bytes = head.as_bytes();
                let mut k = bytes.len();
                while k > 0 && (bytes[k - 1].is_ascii_alphanumeric() || bytes[k - 1] == b'_') {
                    k -= 1;
                }
                if k < bytes.len() {
                    receiver = Some(head[k..].to_owned());
                }
            }
            out.push((
                Call {
                    name: strip_substrate_suffix(name),
                    receiver,
                    at: s,
                    line,
                },
                close,
            ));
        }
        out
    }

    /// The calls in `text` whose failure **propagates out of the door**, in
    /// source order.
    ///
    /// A call whose failure does not propagate cannot refuse the write, so it
    /// cannot be a gate. That is the structural reduction that keeps the
    /// classification manifest small enough to be reviewed — it is not a guess
    /// about names.
    ///
    /// Four propagating forms are recognised: `f(..)?`, `f(..).await?`,
    /// `f(..)<transparent combinator>?` (the token is `f`, not the
    /// combinator), and `if let Err(..) = f(..)`.
    fn propagated_calls(text: &str, first_line: usize) -> Vec<Call> {
        let raw = raw_calls(text, first_line);
        let by_close: BTreeMap<usize, usize> = raw
            .iter()
            .enumerate()
            .map(|(idx, (_, c))| (*c, idx))
            .collect();
        let b = text.as_bytes();

        // Offsets of every `if let Err(..) =` / `if let Ok(..) =` scrutinee.
        let mut errlet_targets: BTreeSet<usize> = BTreeSet::new();
        let mut search = 0usize;
        while let Some(p) = text[search..].find("if let ") {
            let start = search + p;
            search = start + 7;
            if let Some(eq) = text[start..].find('=') {
                let mut k = start + eq + 1;
                while k < b.len() && (b[k] as char).is_whitespace() {
                    k += 1;
                }
                errlet_targets.insert(k);
            }
        }

        let mut out = Vec::new();
        for (call, close) in &raw {
            let mut propagates = false;
            let tail = text[close + 1..].trim_start();
            if tail.starts_with('?') {
                propagates = true;
            } else if let Some(rest) = tail.strip_prefix('.') {
                let rest = rest.trim_start();
                if let Some(after_await) = rest.strip_prefix("await") {
                    propagates = after_await.trim_start().starts_with('?');
                }
            }
            if !propagates {
                // `if let Err(..) = <path>::NAME(..)` — the scrutinee starts at
                // the head of the path, so walk from the recorded offset over
                // path characters and see whether this call is the head call.
                for &t in &errlet_targets {
                    if t > call.at {
                        continue;
                    }
                    let seg = &text[t..call.at];
                    if seg
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.')
                    {
                        propagates = true;
                        break;
                    }
                }
            }
            if !propagates {
                continue;
            }
            // Walk transparent combinators back to the real callee.
            let mut c = call.clone();
            let mut guard = 0;
            while TRANSPARENT.contains(&c.name.as_str()) && guard < 8 {
                guard += 1;
                let Some(recv_close) = receiver_close(text, &c) else {
                    break;
                };
                let Some(&idx) = by_close.get(&recv_close) else {
                    break;
                };
                c = raw[idx].0.clone();
            }
            out.push(c);
        }
        out.sort_by_key(|c| c.at);
        out
    }

    /// For `EXPR.combinator(..)`, the close paren of `EXPR`'s own call, if it
    /// had one.
    fn receiver_close(text: &str, call: &Call) -> Option<usize> {
        let pre = text[..call.at].trim_end();
        let head = pre.strip_suffix('.')?.trim_end();
        let head = head.strip_suffix("await").map_or(head, |h| {
            h.trim_end().strip_suffix('.').unwrap_or(h).trim_end()
        });
        head.ends_with(')').then(|| head.len() - 1)
    }

    // ── block structure ─────────────────────────────────────────────

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

    fn fn_name_at(line: &str) -> Option<String> {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let p = toks.iter().position(|t| *t == "fn")?;
        let raw = toks.get(p + 1)?;
        let name: String = raw
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

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

    fn index_functions(stripped: &[String]) -> BTreeMap<String, Vec<(usize, usize)>> {
        let mut out: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
        let mut i = 0usize;
        while i < stripped.len() {
            if fn_name_at(&stripped[i]).is_some() && opens_a_body(stripped, i) {
                if let Some(name) = fn_name_at(&stripped[i]) {
                    if let Some(end) = block_end(stripped, i) {
                        out.entry(name).or_default().push((i, end));
                        i = end;
                    }
                }
            }
            i += 1;
        }
        out
    }

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

    /// The ordered gate sequence of the body at `[a, b]`, and every call it
    /// made that [`CALL_CLASSES`] does not classify.
    /// What a walk collects besides the sequence itself: every propagated
    /// call the partition does not classify, and every classified name it did
    /// see (for the staleness half). Bundled so the walk keeps one out-param
    /// rather than three.
    #[derive(Default)]
    struct Collected {
        unclassified: Vec<(String, usize)>,
        used: BTreeSet<String>,
    }

    fn gate_sequence(
        stripped: &[String],
        a: usize,
        b: usize,
        index: &BTreeMap<String, Vec<(usize, usize)>>,
        depth: usize,
        seen: &BTreeSet<String>,
        out: &mut Collected,
    ) -> Vec<String> {
        let body = stripped[a..=b.min(stripped.len() - 1)].join("\n");
        let mut seq = Vec::new();
        for call in propagated_calls(&body, a + 1) {
            if classify(&call.name).is_some() {
                out.used.insert(call.name.clone());
            }
            match classify(&call.name) {
                Some(Class::Gate) => {
                    // Short generic names carry their receiver, so
                    // `hardware_attestation_policy.check` is not just `check`.
                    let tok = match (&call.receiver, call.name.as_str()) {
                        (Some(r), "check") => {
                            format!("{}.{}", strip_substrate_suffix(r), call.name)
                        }
                        _ => call.name.clone(),
                    };
                    seq.push(tok);
                }
                Some(Class::Plumbing) => {}
                Some(Class::Delegates) => {
                    if depth == 0 || seen.contains(&call.name) {
                        continue;
                    }
                    let Some(ranges) = index.get(&call.name) else {
                        continue; // defined in another file — the call is the token we have
                    };
                    let mut deeper = seen.clone();
                    deeper.insert(call.name.clone());
                    for &(fa, fb) in ranges {
                        if fa <= a && b <= fb {
                            continue; // this IS the callee — recursion
                        }
                        seq.extend(gate_sequence(
                            stripped,
                            fa,
                            fb,
                            index,
                            depth - 1,
                            &deeper,
                            out,
                        ));
                    }
                }
                None => out.unclassified.push((call.name.clone(), call.line)),
            }
        }
        seq
    }

    /// `backend -> (gate sequence, 1-based line of the `fn`)`.
    type PerBackend = BTreeMap<String, (Vec<String>, usize)>;
    /// `(trait, method) -> `[`PerBackend`].
    type DoorMap = BTreeMap<(String, String), PerBackend>;

    struct Scan {
        doors: DoorMap,
        implements: BTreeMap<String, BTreeSet<String>>,
        defaults: BTreeMap<(String, String), Vec<String>>,
        /// `(backend, call name, line)` for every unclassified propagated call.
        unclassified: Vec<(String, String, usize)>,
        /// Every classified name actually seen, for the staleness half.
        seen_classes: BTreeSet<String>,
    }

    fn scan() -> Scan {
        let mut doors: DoorMap = BTreeMap::new();
        let mut implements: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut defaults: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        let mut unclassified: Vec<(String, String, usize)> = Vec::new();
        let mut seen_classes: BTreeSet<String> = BTreeSet::new();

        for (trait_name, rel) in TRAITS {
            let stripped = strip_file(&read(rel));
            let empty = BTreeMap::new();
            let mut i = 0usize;
            while i < stripped.len() {
                let l = &stripped[i];
                if l.contains("trait ") && l.contains(trait_name) && !l.contains("impl") {
                    if let Some(end) = block_end(&stripped, i) {
                        for (name, a, b) in methods_in(&stripped, i, end) {
                            let seq = gate_sequence(
                                &stripped,
                                a,
                                b,
                                &empty,
                                0,
                                &BTreeSet::new(),
                                &mut Collected::default(),
                            );
                            // A trait default's own calls are NOT held to the
                            // partition: the manifest is derived from the
                            // backend files, and widening it to three more
                            // modules buys nothing this gate compares.
                            defaults.insert((trait_name.to_owned(), name), seq);
                        }
                        i = end;
                    }
                }
                i += 1;
            }
        }

        for (backend, rel) in BACKENDS {
            let stripped = strip_file(&read(rel));
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
                        let mut collected = Collected::default();
                        let seq = gate_sequence(
                            &stripped,
                            a,
                            b,
                            &index,
                            INLINE_DEPTH,
                            &seen,
                            &mut collected,
                        );
                        for (n, line) in collected.unclassified {
                            unclassified.push((backend.to_owned(), n, line));
                        }
                        seen_classes.extend(collected.used);
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
            unclassified,
            seen_classes,
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

    /// **The alphabet is a partition, and this is the half that makes it one.**
    ///
    /// A call whose failure propagates out of a door, and which
    /// [`CALL_CLASSES`] does not classify, **fails the build**. It is not
    /// skipped, not defaulted to plumbing, not matched against a verb list.
    ///
    /// This exists because the first version of this module used a verb
    /// whitelist and was blind to every `authorize_*` and `reject_*` gate in
    /// the tree — including the forward-secrecy guard
    /// `reject_future_dated_community_revocation`, live on all three backends.
    /// A detector that silently skips what it does not recognise converts an
    /// unknown into a false assurance, which is worse than no detector.
    #[test]
    fn every_propagated_call_in_a_door_is_classified() {
        let scan = scan();
        let mut lines: Vec<String> = scan
            .unclassified
            .iter()
            .map(|(be, n, line)| format!("  {be}:{line}  `{n}`"))
            .collect();
        lines.sort();
        lines.dedup();
        assert!(
            lines.is_empty(),
            "{} propagated call(s) in a backend door are not classified in CALL_CLASSES:\n{}\n\n\
             Classify each as Gate (it refuses something about the caller's input), Plumbing (it \
             fails only on the substrate's own terms), or Delegates (it is another door or a \
             same-file helper that runs gates). The fail-open direction is Plumbing, so say why \
             if you choose it. Do NOT widen a pattern to make this pass — a pattern is what this \
             replaced.",
            lines.len(),
            lines.join("\n")
        );
    }

    /// The other direction: a classified name the corpus no longer contains is
    /// a stale row, and a stale row is a licence nobody reviewed.
    #[test]
    fn no_call_class_is_stale() {
        let scan = scan();
        let stale: Vec<&str> = CALL_CLASSES
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !scan.seen_classes.contains(*n))
            .collect();
        assert!(
            stale.is_empty(),
            "CALL_CLASSES rows no longer appear in any scanned door — delete them: {stale:?}"
        );
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for (n, _) in CALL_CLASSES {
            assert!(names.insert(n), "duplicate CALL_CLASSES row {n:?}");
        }
    }

    /// **CIRISPersist#670 — the invariant `README.md` claims.** Every method
    /// the three backends implement runs the same gates in the same order, or
    /// says in [`DECLARED_DIVERGENCES`] why it does not.
    #[test]
    fn every_backend_runs_the_same_gates_in_the_same_order() {
        let scan = scan();
        let mut failures: Vec<String> = Vec::new();

        for ((trait_name, method), per_backend) in &scan.doors {
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

    /// An exemption whose door no longer diverges is a stale note that would
    /// silently license a future divergence.
    #[test]
    fn no_declared_divergence_is_stale() {
        let scan = scan();
        for d in DECLARED_DIVERGENCES {
            let key = (d.trait_name.to_owned(), d.method.to_owned());
            let per_backend = scan.doors.get(&key).unwrap_or_else(|| {
                panic!(
                    "declared divergence names {}::{}, which no backend implements",
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

    /// **The gate that stops the gate from passing vacuously.**
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

        // Assembled at runtime so this file's own text cannot satisfy the scan
        // it performs. `check_genesis_attestation_reserved` is deliberately NOT
        // pinned: CIRISPersist#665 moves it to the head of the door, and a
        // subsequence fixing its position would fail on that merge for a change
        // that is not a regression.
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

    /// The dye test for [`strip_file`]'s two fail-open bugs, both real.
    #[test]
    fn a_commented_out_gate_does_not_read_as_live() {
        // 1. A block comment that does NOT start the line. The first version
        //    only looked at line starts and counted this gate as present.
        let planted =
            "    fn d(&self) -> R {\n        let x = 1; /* check_a_gate(&row)?; */\n        \
                       check_b_gate(&row)?;\n    }\n";
        let stripped = strip_file(planted);
        let body = stripped.join("\n");
        let names: Vec<String> = propagated_calls(&body, 1)
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert!(
            !names.iter().any(|n| n == "check_a_gate"),
            "a commented-out gate read as LIVE: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "check_b_gate"),
            "the live gate beside it was lost: {names:?}"
        );

        // 2. A gate name inside a string literal is not a call.
        let in_string =
            "    fn d(&self) -> R {\n        err(\"check_c_gate(x)? failed\")?;\n    }\n";
        let names2: Vec<String> = propagated_calls(&strip_file(in_string).join("\n"), 1)
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert!(
            !names2.iter().any(|n| n == "check_c_gate"),
            "a gate name inside a string literal read as a call: {names2:?}"
        );

        // 3. A multi-line block comment.
        let multi = "    fn d(&self) -> R {\n        /* check_d_gate(&row)?;\n           still \
                     commented */\n        check_e_gate(&row)?;\n    }\n";
        let names3: Vec<String> = propagated_calls(&strip_file(multi).join("\n"), 1)
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert!(
            !names3.iter().any(|n| n == "check_d_gate")
                && names3.iter().any(|n| n == "check_e_gate"),
            "multi-line block comment mishandled: {names3:?}"
        );
    }

    /// The dye test for the propagation rule, including the `map_err` unwrap
    /// that keeps 840 combinator calls from being the only thing this sees.
    #[test]
    fn only_a_propagating_call_counts_and_combinators_are_transparent() {
        let planted = "    fn d(&self) -> R {\n        \
                       let a = check_ignored(&row);\n        \
                       check_direct(&row)?;\n        \
                       check_awaited(&row).await?;\n        \
                       check_mapped(&row).map_err(|e| E(e))?;\n        \
                       if let Err(x) = check_iflet(&row) { return Err(x); }\n    }\n";
        let names: Vec<String> = propagated_calls(&strip_file(planted).join("\n"), 1)
            .into_iter()
            .map(|c| c.name)
            .collect();
        for want in [
            "check_direct",
            "check_awaited",
            "check_mapped",
            "check_iflet",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} missed: {names:?}");
        }
        assert!(
            !names.iter().any(|n| n == "check_ignored"),
            "a call whose failure does not propagate cannot refuse the write, so it must not \
             count: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "map_err"),
            "the combinator must be unwrapped to its receiver: {names:?}"
        );
    }

    /// [`strip_file`] handles `//` and `/* */`. That is checked, not assumed.
    #[test]
    fn no_backend_source_uses_raw_strings() {
        // Raw strings (`r"..."`, `r#"..."#`) are NOT understood by `strip_file`
        // — the escape handling would mis-track the closing quote. None exist
        // today; this keeps it that way rather than leaving it implicit.
        let needle = ["r", "#\""].join("");
        for (backend, rel) in BACKENDS {
            let text = read(rel);
            assert!(
                !text.contains(&needle),
                "{backend} uses a raw string literal; `strip_file` does not understand them, so \
                 a gate call inside one would be counted as live code"
            );
        }
    }

    /// **CIRISPersist#643, as a gate.** `pg_resign` was the only one of three
    /// sibling re-sign helpers never redirected to the shared seal, so every
    /// postgres attestation fixture signed without its instants — 34 of 46
    /// postgres reds, 14 of them matching the *wrong* refusal.
    ///
    /// The sanctioned list pins the **occurrence count**, not just the
    /// containing function. Scoping an exemption to a whole function made it an
    /// upper bound: a second hand-rolled seal added to the same function would
    /// have been silently skipped, and the staleness half only required that
    /// *at least one* remain.
    #[test]
    fn no_backend_file_hand_rolls_the_seal() {
        // Assembled so this test's own source is not a hit.
        let needle = ["sign", "envelope"].join("_");
        // `(backend, containing fn, exact occurrences)`.
        let sanctioned: [(&str, &str, usize); 1] = [(
            "memory",
            // A forged REVOCATION: the envelope is signed by an attacker while
            // the row claims the revoker, so `put_revocation` must refuse it.
            // `seal_row_in_place` is Attestation-shaped and has no revocation
            // twin, and the fixture's whole point is a seal the shared helper
            // would never produce.
            "forged_revocation_wrong_signer_rejected_502e1",
            1,
        )];
        let mut counted: BTreeMap<(&str, String), usize> = BTreeMap::new();
        let mut offenders = Vec::new();
        for (backend, rel) in BACKENDS {
            let stripped = strip_file(&read(rel));
            let index = index_functions(&stripped);
            for (i, line) in stripped.iter().enumerate() {
                if !line.contains(&needle) {
                    continue;
                }
                let owner = index
                    .iter()
                    .flat_map(|(n, rs)| rs.iter().map(move |r| (n, r)))
                    .filter(|(_, &(a, b))| a <= i && i <= b)
                    .max_by_key(|(_, &(a, _))| a)
                    .map_or_else(|| "<file scope>".to_owned(), |(n, _)| n.clone());
                *counted.entry((backend, owner.clone())).or_default() += 1;
                if !sanctioned
                    .iter()
                    .any(|(b, f, _)| *b == backend && *f == owner)
                {
                    offenders.push(format!("{backend}:{} in `{owner}`", i + 1));
                }
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
        // EXACT counts, both directions: a second occurrence inside a
        // sanctioned function fails, and a sanctioned site that has gone away
        // fails rather than silently licensing a future one.
        for (backend, owner, want) in sanctioned {
            let got = counted
                .get(&(backend, owner.to_owned()))
                .copied()
                .unwrap_or(0);
            assert_eq!(
                got, want,
                "sanctioned seal site `{backend}::{owner}` has {got} hand-rolled seal(s), pinned \
                 at {want}. An exemption scoped to a whole function is an upper bound, not a \
                 partition — pin the count or the second copy is invisible."
            );
        }
    }
}
