# v62 JSON cut: shutting the earlier-form doors (plan)

Read-only survey, 2026-11-16. Nothing was built or run. Every count is a `git grep` count, so it is a line count and not a semantic count.

**Anchors**
- `v62-int` is at `6a9e88eb` (slices B, D and E1 merged).
- `v62-wire` is at `943d3433`, with E2a work in progress uncommitted in the working tree (10 modified files). All the E2a facts below are read from that working tree.
- `v62-baseline` is at `3cdcc0f2` (E2b, with uncommitted edits in `edition_baseline.rs` and `edition_upgrade.rs`).
- CC is on the `rc20` branch at `ae09856`.
- Verify is the `v23.1.3` checkout at `05976a2`.

Claims are marked **TESTED** (read in code or data) or **BELIEVED** (inferred).

---

## 0. What is already in place, and what is not

| piece | state | where |
|---|---|---|
| The edition-2 door: form, edition-1 refs, Verify verdict, node-computed row id, key-record end rule | built (E2a) | `src/federation/edition2/door.rs::admit_row` |
| One entry for a statement: key plane, a further voice, or a row through the attestation gates | built | `edition2/ingest.rs::put_statement`, `Engine::put_edition2_statement` (`engine.rs:9996`) |
| The only caller of `put_statement` | **Engine only.** Replication, tier ingest, PyO3 and the capsule do **not** call it (TESTED: `git grep put_statement\|put_edition2_statement`). The CHANGELOG line "Replication and tier ingest deliver statements through this one entry" is not true of the code. tier_ingest only calls `verify_carried` for a JSON row that already carries `ceg_statement`. | — |
| Statement store | built, sqlite + pg: `put_row/statements_about/rows_naming/voices_of/put_object/objects_of` | `edition2/store.rs` |
| A **cursor listing** of statements (to serve peers) | **missing** | — |
| Mapping an edition-2 row onto a typed table | **only `Attestation`** (`ingest::attestation_of`). A `key:record` and a `key:revocation` go to `ceg_statements` alone. Nothing projects onto `federation_families`, `federation_communities`, the membership revocation/widening tables, occurrences, `transport_destinations`, location proofs, `federation_revocations`, trust grants, accord tables or lineage cosigns. | — |
| Genesis bundle/2 | generic rules only. `put_genesis_bundle` **always** refuses `genesis_bundle_reader_unavailable` and stores nothing (TODO(verify-bundle-reader) ×6) | `edition2/genesis.rs` |
| Producer primitive (sign an edition-2 row with persist's signer) | **missing**. Verify has `sign_row_statement` (in-memory `CompositeSigningKey` only) and `sig_structure`. Persist has `LocalSigner::sign_composite` (`signing/mod.rs:546`). Neither side has an object-statement minter; the test minters live in `edition2/genesis_invariants.rs::{bundle_voice,voice_over}`. | — |
| Fixture switch | `emit_edition2`, `with_edition2` and `FLIP` (37 builders, I1912) exist, but **no builder reads the switch yet** (TESTED: zero callers outside `fixture_switch.rs`) | `edition2/fixture_switch.rs` |
| PyO3 / capsule edition-2 surface | **none** ("No pyo3 surface is added in this slice") | — |
| Composites-only for STH, sig19, aggregation_meta, storage_contention and witness | done in slice D (`691798ea`) | — |

**Markers:**
- `TODO(json-cut)` ×7: CHANGELOG ×4, `admission.rs:5030` (licensure count at the signed instant), `admission.rs:15486` (co-scrub canonical conferral for earlier-form key ids), `cosign.rs:54` (`quorum_key`).
- `TODO(baseline-merge)` ×7, all in `edition2/{ingest,genesis_store}_invariants.rs`.
- Also `TODO(verify-bundle-reader)` ×6, `TODO(archive-ruling)` ×8 and `TODO(key_end)` ×3.

### 0.1 A conflict between E2a and E2b that the cut cannot skip (TESTED)
- **E2a** keeps an edition-2 key **only** in `ceg_statements` ("`federation_keys` is the earlier store, and an edition-2 key is never written to it"). Its store witnesses therefore **turn the signer FKs off**: `PRAGMA foreign_keys=OFF` on sqlite and `EDITION2_SIGNER_FKS_DROPPED_PG` on pg. The comment says "the E2b baseline drops the earlier store's signer FKs".
- **E2b** does the opposite. Its V300 keeps every signer FK and adds `federation_keys.{edition, record_row_id, kid}` with `CHECK (edition <> 2 OR (record_row_id IS NOT NULL AND kid IS NOT NULL))`. That is "the edition-2 projection of a verified key:record into federation_keys".
- So on the merged baseline, `put_statement` → `put_attestation` for an edition-2 row hits an FK violation on `attesting_key_id`/`scrub_key_id`, because the identity-ref is not in `federation_keys`. **Ruling needed (recommend E2b's):** `put_statement` writes the `key:record` projection into `federation_keys` (edition 2) in the same transaction as the `ceg_statements` row. Tier 2 keeps reading the identity set from the live record. The `TODO(baseline-merge)` FK hacks are then deleted.

### 0.2 CC moved after E2a was written (TESTED)
CC `rc20@ae09856` ("The genesis bundle's payload, its count and its anchor", 07:38 today) now defines the `ceg-genesis-bundle/2` payload as a closed map:
- refs, version, asserted_at, the accord's name, holders, serve_nodes, and the charter with each holder's `recovery_commitments`;
- key records and bindings are named by row id, never copied;
- the anchor is either the holders' thumbprints or the bundle's object id;
- an unheld named row makes the bundle **wait**.

`edition2/genesis.rs` still says "the proposal has not landed, and persist builds no payload member from it". Slice C must adopt the landed payload. CC `manifests/signed_object_v2.cddl:237` also closes the object-typ list to three: `ceg-genesis-bundle/2`, `ceg-revocation-snapshot/2` and `ceg-boot-manifest/2`. **Everything else is a row of a family.**

---

## 1. Earlier-form INBOUND entry points

"E2 counterpart" means a path on `v62-wire` that admits the same fact as an edition-2 statement.
- **Row:** yes, through `put_statement`, mapped onto `Attestation`.
- **None:** there is no edition-2 path; the "missing" column says what is needed.

### 1a. Rust doors (`FederationDirectory`, `src/federation/mod.rs` trait from l.3598; impls in `store/{sqlite,postgres}.rs` and `federation/directory_double.rs`)

| door (file::fn) | earlier-form shape decoded / verified | E2 counterpart | missing |
|---|---|---|---|
| `put_attestation`, `put_attestation_with_origin`, `put_attestation_authored`, `put_attestation_synced` → `attestation_admit.rs` `plan_put_attestation` + `tier_ingest::verify_row_hybrid_signature` | `SignedAttestation` JSON. Ed25519 over `JCS(attestation_envelope)` + ML-DSA over `JCS‖ed_sig` (bound hybrid); `original_content_hash = sha256(JCS)` | **Row** (`put_statement` → same gates) | The refusal itself. Every arm of `verify_row_hybrid_signature` except `verify_carried` must refuse `earlier_form_object`; the arms are `key_plane::verify_plane_row`, `group_plane::verify_plane_row`, `self_roster::verify_proposal_row`, the cosign row and the generic bound-hybrid. |
| `apply_replicated_attestation` (trait l.~4368; `attestation_apply.rs`; `Engine::apply_replicated_attestation` engine.rs:10028) | `SignedAttestation` from a peer | **None as bytes.** Today an edition-2 row can only arrive as a JSON row that carries `ceg_statement`, which is itself an earlier-form object on the wire. | `apply_replicated_statement(bytes, offered_row_id)` → `put_statement(tier=federation)`, plus its cursor/dedup semantics (the `StoreConflict` advance) |
| `put_public_key`, `register_federation_key` (`Engine` 9878), `rebind` (`register.rs::verify_key_registration`, `check_key_id_fingerprint`, `verify_proof_of_possession`) | `SignedKeyRecord`: `registration_envelope`, hybrid scrub, key_id `alias-<fp>` where `fp` is derived from the Ed25519 pubkey (`register::key_id_fingerprint`) | **Row** (`key:record` via `put_statement` → KeyPlane) | The `federation_keys` projection (§0.1); refuse by name at `put_public_key` |
| `apply_replicated_key_record` (trait l.~3798; `Engine` 9969) | `SignedKeyRecord` replicated as a `key:record:v1` JSON row | key:record statement | Bytes entry (as above) |
| `adopt_scrub_upgrade`, `adopt_genesis_reanchor`, `store_rebound_key_record`, `store_invalid_replaced_key_record` | legacy re-scrub / re-anchor of v1 JSON records | none needed | Delete (§5) |
| `put_revocation` (`SignedRevocation`); key revocation via `register::check_revocation_bound*` | JSON revocation + scrub | `key:revocation` statement → KeyPlane | Key revocation is covered. `revocation:{entity_type}:{reason}` for non-key entities maps to `Attestation` only; `federation_revocations` gets no projection. |
| `put_family`, `put_family_local`, `put_community`, `apply_replicated_community` (`family_admit.rs`, `community_admit.rs`, `group_plane.rs::plan_group_row`) | `SignedFamily`/`SignedCommunity` JSON with roster co-signatures (group plane "minted from the signed object it carries") | **None** (a `group:roster` statement maps to `Attestation` but never reaches `federation_families`/`federation_communities` or `federation_group_versions`) | `group:roster` → typed group projection, counted voices (CC 2.6.1.9) |
| `put_{family,community}_membership_{revocation,widening}` (trait l.~6544–6575) | `Signed*MembershipRevocation/Widening` (consensus scrub sets) | **None** | `membership:{stage}` → the four membership tables |
| `put_identity_occurrence(_local)`, `put_identity_occurrence_revocation_local` (`occurrence_admit.rs`) | `SignedIdentityOccurrence` | **None** | `identity:occurrence` / `identity:occurrence_revocation` → occurrence tables |
| `put_transport_destination`, `put_signed_transport_destination` (`self_at_login.rs::SignedTransportDestination`) | JSON signed over `ceg_produce_canonicalize`, X-Wing members (E1) | **None** | `transport:{kind}` → `transport_destinations`; `transport:canonical_rebind` already reads the carried row |
| `put_location_proof` (`SignedLocationProof`) | JSON hybrid | **None** | **No CC family** (see §8, blocker) |
| `put_touch_claim` (`SignedTouchClaim`) | JSON hybrid | **None** | **No CC family** (blocker) |
| `apply_replicated_accord_evidence`, `Engine::apply_replicated_accord_quorum_evidence` (`accord_carriage.rs::admit_replicated_accord_evidence`) | JSON envelope + `ciris_verify_core::threshold::ThresholdSignature` set over `JCS(envelope)` (`accord_family_signing_bytes`) | **None** | Counted `accord:*` rows (voices fold) |
| `put_accord_proposal`, `put_accord_participation`, `put_accord_decision` | JSON payloads (PyO3 `*_json`) | **None** | Map to `accord:invoke:*` / `accord:lifecycle:*` families, or rule them node-local |
| `put_lineage_head_cosign`, `store_lineage_head_cosign` | JSON cosign over the lineage head | partial: `cosign::edition2_voices` folds by `event_row_id` | A `cosign:{state}` statement door to `federation_lineage_head_cosigns` |
| `Engine::apply_replicated_key_grant`, `key_grant.rs::check_key_grant_row_admission` | `SignedKeyGrantRow` (JSON attestation row) | **Row** (`key_grant:{axis}` → `Attestation`) | Its typed effects (`federation_blob_key_grants`, `federation_stream_dek_grants`) are not reached from `put_statement`. Verify that the attestation path drives them (BELIEVED partly). |
| `federation_grant_trust` / `revoke_trust` (`SignedTrustGrant/Revocation`, `emit.rs::grant_trust`) | JSON hybrid over `trust_grant_signing_bytes` | **None** | `trust:{job}:{version}` fits only loosely; ruling needed: operator-local or a row |
| `apply_replicated_purge`, `steward_purge.rs` (`StewardPurgeNotice`: JSON `takedown_notice` + threshold cosigs over `JCS`) | JSON | digest only (E2a I1900) | A counted `takedown_notice:{basis}` statement |
| `put_custody_ack`, `holding_claim.rs` (`custody:ack:v1` JSON rows) | JSON | **Row** (`custody:{kind}`) if routed | Entry routing |
| `put_delivery_receipt`, `stream_receipt.rs:217` (`verify_hybrid_via_directory`) | JSON hybrid | **None** | `delivery_receipt:{stream_id}` statement |
| `insert_known_wire_hash`, `list_*wire_hashes*`, `rebuild_signed_wire_index`, `lookup_signed_record_by_content_hash` (`wire_index.rs`) | sha256 of the JCS image is the replication dedup key | — | Re-key on `statement_id` / row id |
| tier ingest `tier_ingest.rs::verify_federation_tier_ingest`, `verify_row_hybrid_signature` | the bound-hybrid core | `verify_carried` arm | Make it the only arm |

### 1b. PyO3 (`src/ffi/pyo3.rs`, 39,356 lines, 659 fns)

There are about 30 federation inbound doors that take a signed JSON string. None has an edition-2 twin. **Missing: `put_edition2_statement(bytes, offered_row_id=None)` and `apply_replicated_statement(bytes, peer)`.** Errors map as `ValueError(federation_malformed_row)` and the retryable `federation_attester_key_unknown`.

The doors, by line:
- keys: `put_public_key` 6158, `register_federation_key` 6339, `adopt_scrub_upgrade` 6416, `apply_replicated_key_record` 6502, `rebind_key_record` 6527;
- rows: `apply_replicated_attestation` 6652, `apply_replicated_key_grant` 6720, `put_attestation` 7705, `put_revocation` 8556, `deregister_federation_key` 8607;
- evidence and PQC attach: `apply_replicated_accord_evidence` 8725, `attach_key_pqc_signature` 9124, `attach_attestation_pqc_signature` 9166;
- typed planes: `put_identity_occurrence_json` 10512, `put_wholeness_witness_json` 10753, `put_family_json` 11115, `put_community_json` 11183, `put_lineage_head_cosign_json` 11264;
- accord: `put_accord_{proposal,participation,decision}_json` 11357/11441/11502;
- genesis: `pin_trust_from_bundle_response_json` 11871, `install_genesis_bundle_roster_json` 5556, `bake_assembled_genesis` 5519;
- purge: `apply_replicated_purge_json` 13509, `purge_rows_json` 13407;
- trust: `federation_grant_trust` 16049, `federation_revoke_trust` 16093;
- custody and receipts: `put_custody_ack` 14069, `put_delivery_receipt` 10322.

Adjacent signed-JSON doors, whose scope needs a ruling (§8): `cirisnode_put_*` ×7 (21968–22313), `put_detection_event` 18523, `put_edge_detection_event` 18633, `put_calibration_bundle` 18815, the trace receive/verify paths (17396, 17593–17818).

### 1c. Capsule (`src/ffi/directory_capsule.rs`, the `DirectoryOp` enum, 115 variants)
- Inbound JSON ops (17): `PutPublicKey`, `PutAttestation`, `PutAttestationAuthored`, `PutAttestationSynced`, `ApplyReplicatedAttestation`, `ApplyReplicatedAttestationSynced`, `ApplyReplicatedKeyRecord`, `PutRevocation`, `PutLocationProof`, `PutIdentityOccurrence`, `PutIdentityOccurrenceRevocation`, `PutFamily`, `PutCommunity`, `PutTransportDestination`, `PutSignedTransportDestination`, `ApplyReplicatedAccordEvidence` and `PutLineageHeadCosign`.
- `VerifyHybridViaDirectory` verifies earlier-form signatures.
- Missing: an append-only `PutEdition2Statement` op and `ApplyReplicatedStatement` op. The enum is append-only, so the old variants must stay as **refusing** arms and never be removed.

### 1d. HTTP (`src/server/`)
- `GET /v1/trust-root/bundle` and `/v1/steward-key` (`server/mod.rs:141–142` → `canonical_community::trust_root_bundle_response(canonical_genesis_bundle())`) serve **bundle/1 JSON**. Under CC 5.3.4 the body is `{"statements": [hex…], …}` plus the rows the bundle names.
- `POST /api/v1/pipeline/ingest` (`server/pipeline.rs:208`) verifies the edge's `PipelineEnvelope` with `verify_hybrid_via_directory`. It **looks up earlier-form pubkeys in `federation_keys`**, so it stops verifying once peers hold edition-2 keys only.
- `POST /api/v1/accord/events` takes Agent trace batches (trace wire, §8).
- `server/secrets.rs:353` is request auth (`verify_hybrid_via_directory`). It is not a CEG row, but it shares the key lookup.

---

## 2. Earlier-form OUTBOUND / producer paths (each needs an edition-2 producer)

**The shared primitive comes first (missing):** `edition2::produce::sign_row(signer: &dyn HardwareSigner|LocalSigner, iss, sub, row_type, family, payload: cde::Value) -> Vec<u8>`. It builds the protected header the way Verify's `sign_row_statement` does, signs `ciris_verify_core::edition2::sig_structure(prot, payload)` with `LocalSigner::sign_composite`, and returns the tag-18 bytes. `sign_object(typ, payload)` does the same for bundle/2.

The witness for the primitive: its output equals `sign_row_statement` byte for byte under a seeded `CompositeSigningKey`, and `admit_row` accepts it.

| producer (file::fn) | what it builds today | edition-2 producer |
|---|---|---|
| `Engine::register_self_federation_key` (engine.rs:2729/2950), `rebind_self_federation_key` (3175) | self-signed `SignedKeyRecord` + hybrid scrub; returns `alias-<fp>` | a `key:record` statement; returns the identity-ref (**the Agent stores the returned id**) |
| `Engine::put_community_self_signed` (3232), `put_family_self_signed` (3272) | `SignedCommunity`/`SignedFamily` | `group:roster` statement |
| `Engine::emit_attestation`, `emit_attestation_self`, `assemble_attestation_self` (4138–4255); `attestation_emit.rs::emit_with_local_signer`, `canonicalize` | JSON envelope → JCS → hybrid | `sign_row` (Server's ~14 `emit_*` sites stay insulated if the `EmitAttestationInput` shape survives) |
| `Engine::widen_audience` (3683), `custody_for` (3739) | re-signed rows | `sign_row` |
| `Engine::emit_key_grant`, `emit_pending_key_grants` (6321/6470); `key_grant.rs::emit_*_with_local_signer` (2004–2228) | `SignedKeyGrantRow` | `key_grant:{axis}` statement |
| `emit.rs::grant_trust` (252), `operational.rs::emit_trust_edge` (3710) | `SignedTrustGrant` | per the §8 ruling |
| `holding_claim.rs::sign_holding_claim` (256), `emit_holding_claim` (584) | `custody:ack` JSON | `custody:{kind}` |
| `blobs.rs::emit_withdraws_attestation_helper` (5054; the eviction sweeper) | `withdraws` attestation | `sign_row` |
| `accord_recovery.rs::draft_accord_recovery` (104) | JSON draft for holders to sign | a CBOR payload draft (`Sig_structure` bytes to sign) |
| `ownership_reclaim.rs::build_{reclaim_petition,wa_finding,reclaim_withdraws}_envelope` (713–772) | JSON envelopes for external signing | payload drafts |
| `cohort` / PyO3 `cohort_build_membership_change_envelope` (24021), `purge_notice_signing_payload_json` (13428) | JSON signing payloads | CBOR payload + `Sig_structure` |
| `maintenance/vocabulary.rs::tighten_body` (1104) | re-signs rows during vocabulary tightening | `sign_row`, or delete the re-sign |
| `migration.rs::sign_canonical` (1703) | v1→hybrid re-scrub | delete |
| PyO3 `local_sign` (5010), `local_sign_hybrid` (5499), `cold_path_pqc_sign` (34651), `sweep_keys`/`sweep_attestations` (34764/34825), the PQC cold-path in `put_public_key`/`put_attestation`/`put_revocation` | separate Ed25519 / ML-DSA signatures; the PQC half filled in later | add `sign_composite`/`sign_row` PyO3. The cold-path PQC fill-in and sweeps are dead (a composite is atomic). `local_sign*` are used by the Agent for non-row signing (§6), so keep them or rule. |
| genesis seed (`genesis/mod.rs::seed_family_and_canonical` 3276, `seed_canonical_servers` 1080, `seed_delegation_plane` 3684, `seed_canonical_community` 3406, `seed_serve_transport_destinations` 3337, `SqliteBackend/Postgres::seed_genesis_accord_holders`, called from Engine boot at engine.rs:11227/11288) | bakes the bundle/1 JSON rows into the earlier store | slice C |
| served rows: `list_attestations_since(_by_prefixes)`, `list_owner_bindings_since`, `list_signed_{families,communities,*membership*,location_proofs,transport_destinations}_since`, `list_signed_identity_occurrences_for`, `list_signed_records`, `lookup_signed_record_by_content_hash`, `list_signed_accord_quorum_evidence_since`, `list_purge_executions_since` (+ PyO3 8664/8811/8857/9056, capsule `List*`) | JSON `Signed*` to peers (Edge's Summary/Deliver serialises these with serde_json) | **missing:** `edition2_statements_since(cursor, families?)` on both backends; statement bytes are served as received (CC 2.6.1.2) |
| `trust_root_bundle_response(_json)` (`canonical_community.rs:3595`, PyO3 11826) | bundle/1 + rooted row | bundle/2 statements + named rows |

---

## 3. Test fixtures

All of this is TESTED by grep over `src/`, `tests/` and `benches/`.

**Size of the suite:** about 5,244 test fns in 497 files (5,085 in `src` and 159 in `tests/`).

**The FLIP list:** 37 builders with **1,228 call sites**. The top builders by call sites (and files):

| builder | call sites (files) |
|---|---|
| `tier_ingest::sign_community` | 160 (38) |
| `consent_peer_set::grant` | 141 (36) |
| `tier_ingest::bare_attestation` | 139 (50) |
| `reverse_quorum::signed_row` | 92 (15) |
| `sign_family` | 79 (27) |
| `bootstrap_admission::scores_row` | 79 (11) |
| `owner_binding_attestation` | 77 (29) |
| `sign_community_membership_revocation` | 63 (23) |
| `replicated_key_record` | 60 (16) |
| `operational::signed_canonical_record` | 48 (6) |
| `seal_row` | 43 (16) |
| `signed_trust_attestation` | 40 (6) |

Two builders have 0 callers (`sign_widening_by_consensus`, `sign_family_widening_by_consensus`), and 11 have only one.

**Hand-built earlier-form construction outside the builders:**

| construct | sites (files) |
|---|---|
| `SignedAttestation {` | 978 (130). Of these, 355 in 92 files are the trivial `SignedAttestation { attestation: x }` wrapper, which is mechanical. |
| `Attestation {` literals | 446 (113) |
| `SignedKeyRecord {` | 585 (55) |
| `KeyRecord {` | 153 (45) |
| `attestation_envelope:` | 202 (79) |
| `registration_envelope:` | 94 (42) |
| `scrub_signature_classical` | 1,171 (179) |
| `sign_envelope(_with)(` | 133 (56) |
| `ceg_produce_canonicalize(` | 140 (49) |

**Split by file** (files with tests):

| class | files | tests |
|---|---|---|
| builders only | 15 | 118 |
| literals only | 74 | 734 |
| both | 122 | 2,421 |
| no earlier-form row | 286 | 1,813 |

**About 3,270 tests in 211 files touch earlier-form rows.**

**Genesis dependence across the whole suite:** Engine constructors (`with_signer*`, `from_shared`, `with_hardware_signer*`) appear 335 times in 52 files, and every one of them seeds the baked JSON genesis at boot. `canonical_genesis_bundle()` has 80 sites in 23 files. The `seed_*` / `install_test_ceremony_outputs` helpers have 129 sites in 22 files.

**What flips mechanically:**
1. **The switch (37 builders).** Each builder, when `emit_edition2()` is set, derives a `CompositeSigningKey` from its string key id (seed = the first 32 bytes, as today's test signers do), builds a **CBOR** payload, signs it with `sign_row_statement` and returns `attestation_of(admit_row(...))`. The callers of these 1,228 sites need no edit **unless they assert a literal id** (next point).
2. **A test codec for literal rows (new, recommended):** `edition2::fixture_switch::statement_of(&Attestation /*earlier-form shaped*/, seed_key) -> Vec<u8>` and `row_of(...) -> Attestation`. It is the inverse of `ingest::json_of`/`attestation_of`: instants (`INSTANT_MEMBERS`) go to POSIX ms, the scaled members (`SCALED_MEMBERS`) go to ×10⁶, and the hex members listed in a `BYTES_MEMBERS` table go to bstr. `seal_row` (43 sites) and `sign_envelope` (133) re-implemented on it, plus the 355 trivial wrappers, cover a large share of the literal sites.
   - Its witness is a round-trip: `attestation_of(admit(statement_of(a))).envelope == a.envelope` minus `ceg_statement`/`row`. It is checked for every family the suite uses.

**What needs hand rewrites:**
- **Ids.**
  - An edition-2 row id is computed, and an edition-2 key id is an identity-ref. Every test that picks an id (`"att-1"`) and later reads or asserts it breaks: there are 117 `attestation_id: "…"` literal sites in 28 files, 18 `get_attestation("…")` in 6 files and 10 `lookup_public_key("…")` in 7 files.
  - Key-id string comparisons (`"k1"`, `"A1"`) are not countable by grep and are pervasive.
  - Remedy: test helpers `kid("k1") -> identity-ref` and `rid(&row) -> hex`. The rewrite is mechanical per line but needs hand care.
- `SignedKeyRecord`/`KeyRecord` literals (738 sites) become `key:record` statements: a different shape, with no `registration_envelope`.
- Typed-plane literals (`SignedFamily`/`Community`/`Revocation`/Occurrence/…) wait on §1a's missing typed projections.
- Tests that **assert earlier-form behaviour** (hybrid-pending, `attach_*_pqc`, scrub upgrade, fingerprint, JCS hash checks, `*_v1_pinned`) are deleted, not rewritten.

**Estimated share** (BELIEVED, ±10 points):
- about **35–40%** of the touched tests turn green through the switch plus the codec with no per-test edit;
- about **45%** need line-level id/assertion edits;
- about **15–20%** are deleted or rewritten by hand (earlier-form behaviour, key-record literals, typed planes).
- The 1,813 non-row tests are affected only through the Engine-boot genesis (slice C's fixture makes that mechanical).

---

## 4. The baked earlier-form genesis

- **Embedded:**
  - `src/federation/genesis/canonical_seed.json` (537 lines, the v4 amend, `ceg-genesis-bundle/1`; `CANONICAL_SEED_JSON` at `genesis/mod.rs:716`, parsed at 795);
  - `accord_holder_seed.json` (172), behind `accord_holder_genesis_records()` and `effective_accord_holder_records()`;
  - `prior_ceremony_delegation_rows.json` (95);
  - the vectors in `tests/vectors/genesis_bundle/{v2_registry_live,v3_persist_c45a1519,v4_persist_v59_1_0,v4_variant_*}.json` (7 files).
- **The module:** `src/federation/genesis/` is 12,447 lines, including `mod.rs` (5,668), `bundle.rs` (1,467), `ceremony.rs`, `ceremony_verify.rs`, `amend.rs`, `posture.rs`, `roster_install.rs`, `test_ceremony.rs` and `test_anchor_block.rs`.
- **What boots from it:**
  - Engine construction, which seeds the accord holders, the family, the canonical servers, the delegation plane, the canonical community and the serve transport destinations;
  - `genesis_posture` and the `ROOT_REQUIRING_GATES`;
  - `verify_*_seeded`;
  - `trust_root_bundle_response` (HTTP + PyO3);
  - `pin_trust_from_bundle_response_json`;
  - `install_genesis_bundle_roster(_json)`;
  - `bake_assembled_genesis`;
  - `is_pinned_bundle_row` and `check_genesis_attestation_reserved` (the id-squat reserve);
  - `admission::holds_canonical_conferral` (the earlier co-scrub);
  - `row_type_invariants.rs:542–550` (`include_str!` ×3);
  - the replication trust-root predicate.
- **Outside persist:** Edge (4 sites) and Server (10 sites) read `canonical_genesis_bundle().serve_nodes[].record.key_id`. Server's `final_genesis.rs` *writes* `canonical_seed.json` for persist to bake.
- **Replacement:**
  - (i) Production: **no baked bundle** until the ceremony. A v62 node boots **pre-genesis** (`GenesisPosture::Absent`), roots nothing and waits for a bundle/2 at the import door. A release may carry a **default anchor** (the holders' thumbprints, CC 5.3.4) once the holders mint keys.
  - (ii) Tests: a **bundle/2 test ceremony fixture** (`genesis::test_ceremony_v2`, `cfg(any(test, feature="test-anchor"))`). It works in four steps:
    1. derive three holder `CompositeSigningKey`s and N serve-seat keys from fixed seeds;
    2. mint their `key:record` statements and the seat bindings (X-Wing, `seat_xwing_from_binding`);
    3. mint one `ceg-genesis-bundle/2` payload per CC `ae09856` (holders, serve_nodes, charter with `recovery_commitments`, refs to the record/binding row ids);
    4. have every holder sign it.

    The fixture exposes `install()`, so Engine-boot tests get the same rooting the v4 seed gives them today, plus `anchor()` (the thumbprint set).
  - The `install` path must go through the real `put_genesis_bundle`. That path **cannot place a bundle until Verify ships its bundle reader** (§8). Until then the only honest options are:
    - (a) wait;
    - (b) an Eric-ruled `cfg(test)` placement that runs persist's generic rules and says so by name. Memory rule: never synthesize evidence to satisfy your own gate, so (b) must be ruled, not assumed.

---

## 5. Code that becomes dead when the doors shut

**Delete at the cut (S = safe):**

| item | where | safe? |
|---|---|---|
| Earlier-form genesis: bundle/1 parse, bake, amend, ceremony, ceremony_verify, roster_install (JSON), `adopt_genesis_reanchor`, the three JSON seeds, the `tests/vectors/genesis_bundle/*` vectors | `federation/genesis/*` (~12k lines) | **S only after slice C lands** |
| PQC cold-path fill-in: `cold_path_pqc_sign`, `sweep_keys`, `sweep_attestations`, `attach_{key,attestation}_pqc_signature` (trait, both backends, double, capsule, PyO3) | pyo3.rs 34651–34825, 9124/9166; `mod.rs`; `wire_index.rs` | **S** (composite is atomic) |
| Scrub upgrade v1→hybrid: `adopt_scrub_upgrade`, `migration.rs::sign_canonical`, `store_invalid_replaced_key_record` | engine 9911, `mod.rs`, `migration.rs`, `register.rs` | **S** |
| Earlier-form key fingerprint: `register::key_id_fingerprint`, `check_key_id_fingerprint` (+ `key_id_fingerprint_invariants.rs`) | `register.rs` | **S** for persist. Edge calls it (`verify.rs:827`), which is a clean-break adoption note. |
| Non-statement arms of `verify_row_hybrid_signature`: the key-plane, group-plane, self-roster and cosign "minted from the signed object it carries" proofs | `tier_ingest.rs`, `key_plane.rs`, `group_plane.rs`, `self_roster.rs`, `cosign.rs` | **S for the proof arms only.** Their *rules* stay (one rule set, two codecs). |
| `register::verify_key_registration`, `verify_proof_of_possession`, `verify_record_signed_by` | `register.rs` | **S** after `put_public_key` refuses by name |
| Earlier co-scrub canonical conferral (`presents_canonical_conferral`, `holds_canonical_conferral`, `canonical_conferral_coscrub`, `is_canonical_over_roster`) and the E1 "earlier form" reading | `admission.rs` (`TODO(json-cut)` 15486) | **S** after C (canonical = `serve_nodes` of the bundle in force) |
| The licensure signed-instant count (`community_quorum_cosigned_at`) | `admission.rs:5030` | **S** |
| `quorum_key` (cosign earlier name) + V214 column use | `cosign.rs` | **S** in code; the column stays in V300 (unused) |
| `transit_kex_pubkeys` (the earlier pair) reading | `self_at_login.rs`, `admission.rs` | **S** with transport rows |
| JCS wire-hash index keyed on `sha256(JCS)` | `wire_index.rs`, `insert_known_wire_hash` … | **Not S:** re-key it on `statement_id` (it is replication dedup) |
| `attestation_admit` V211 form-refused ledger (`federation_attestations_form_refused`) | `attestation_admit.rs:282` | BELIEVED dead with JSON instants; check |
| Capsule `VerifyHybridViaDirectory` op | `directory_capsule.rs:2453` | Keep the variant (append-only) as a refusing arm |
| `canonicalize_envelope_for_signing_v1_pinned`, `PythonJsonDumpsCanonicalizer` | `verify/canonical.rs`, `audit/verify.rs`, `types.rs` | **Not S:** the audit chain and the trace wire use them |

**Do not delete (still load-bearing after the cut):**
- **The JCS canonicaliser** (`ceg_produce_canonicalize`, `serde_jcs`):
  - `ingest::attestation_of` computes the mapped row's `original_content_hash` over `JCS(envelope)`;
  - it is also used by `blobs::to_jcs_bytes`, `crossing`, `canonical_at_rest`, the audit chain and the trace ingest.
  - It becomes **dead for signing** but not for hashing. Removing it would need `original_content_hash` redefined as the row id or the statement id. That is a follow-up, not the cut.
- **`verify::hybrid::verify_hybrid` / `verify_hybrid_via_directory`** (the bound hybrid) is still called by:
  - the trace ingest (`ingest.rs:3363`, `server/pipeline.rs`);
  - fountain admit (`fountain/admit.rs:178`);
  - cirisnode (sqlite/pg);
  - derived detection and calibration (pyo3 18545–18871);
  - `stream_receipt.rs`;
  - the secrets server;
  - the PyO3 `verify_hybrid` the Agent calls.

  It is dead only if §8's scope ruling also closes those planes. Note also that `verify_hybrid_via_directory` resolves pubkeys from `federation_keys`, so after the cut it only works for keys that the edition-2 projection (§0.1) writes with component pubkeys. Whether a composite key's components may be used as standalone signers is a CC question (§8).

---

## 6. The adopters' surface (adoption notes)

Read-only grep. Edge is `<checkout CIRISEdge-adopt614>@15947fe` (pins persist 61.4.1). Server is `<checkout CIRISServer-wasm0>@97b7f409` (pins 61.4.1); `CIRISServer-wasmfsd` is older (`50368fda`, pins 59.1.2). The Agent is `<checkout CIRISAgent-aspdma>@bbc432957`.

**CIRISEdge**
- **Producers:**
  - 20 production sites call persist's `ceg_produce_canonicalize` and fill `scrub_signature_classical/_pqc` by hand. They are in `chat.rs`, `files.rs`, `membership.rs`, `community_roster.rs`, `group_content/store.rs`, `touch_claim.rs`, `replication/attestation_bind.rs`, `transport/self_route.rs`, `transport/realtime_av_alm/delivered.rs` and `bin/edge_node.rs`.
  - `identity.rs:395` and `verify.rs:1655` use `canonicalize_envelope_for_signing` for Edge's own transport envelope, which is not a persist row.
  - **Change:** sign edition-2 rows with persist's new `sign_row`, or with Verify's minter and a composite key. Keep a local JCS for Edge's own transport envelope if the CC ruling keeps it.
- **Doors:**
  - `put_attestation_authored` ×9, `put_attestation` ×3, `put_attestation_synced` (`replication/bridge.rs:15247`), `put_public_key` (`edge_node.rs:1145`) and `put_signed_transport_destination` ×2 move to `put_edition2_statement` / `apply_replicated_statement`.
  - The wrappers in `ffi/kept_directory.rs` and `replication/counting_directory_930.rs` (14 sites) move to the new capsule ops.
  - `attach_*_pqc_signature` (4 sites) is removed.
- **Replication wire:** Summary/Deliver serialise `Signed*` JSON and key on `envelope_hash` (`replication/protocol.rs:863–869`). They must carry statement bytes, keyed by statement id / row id.
- **Fingerprint:** `verify.rs:827` uses `register::key_id_fingerprint`, which is removed. Key ids become identity-refs (`identity_ref(thumbprint)`).
- **Genesis:** `edge.rs:1816,1906`, `peer_obligation.rs:163` and `reticulum.rs:3695` read bundle/1 `serve_nodes[].record.key_id`. They need a bundle/2 accessor: `bundles_in_force` → `serve_nodes` identity-refs.

**CIRISServer**
- **Producers:**
  - 16 `ceg_produce_canonicalize` sites (accord_duty, add_device, admin_ops, attest, auth/ownership, commons_surface, equivocation, family_api ×3, location, mesh_config_surface, peer, sign_object ×2);
  - the lens-core `canonicalize_envelope_for_signing` ×2 (lens batches, the trace wire);
  - `auth/ownership.rs:1065–1108` builds a `KeyRecord` with `original_content_hash = sha256(JCS)`, which becomes a `key:record` statement.
- **Doors:** `put_attestation_authored` ×6, `put_attestation` ×3 (including the allegiance import, `mesh_genesis.rs:1301–1838`), `put_public_key` ×3, `put_revocation` and `put_signed_transport_destination`.
- **Insulated if persist re-targets `emit_attestation*`:** the `emit_attestation(_self)` sites (~14) and `attestation_upsert_local`.
- **Genesis:**
  - `final_genesis.rs` (`/v1/accord/final-genesis{,/plan,/sign}`) must produce **`ceg-genesis-bundle/2` voices** (holders sign the CBOR payload), no longer `canonical_seed.json`;
  - `/v1/trust-root/bundle` and `/v1/trust-root/import`, `/v1/federation/test-genesis-bundle` and `CIRIS_TEST_GENESIS_BUNDLE` change to bundle/2;
  - `mesh_genesis.rs` and `trust_root_api.rs` read `canonical_genesis_bundle()` / `effective_accord_holder_records()`, and both are removed.
- **Cosign routes:** `/v1/accord/duty/cosign` and `/v1/families/{id}/changes/cosign` accept JCS scrubs. They become a further voice over the same payload (CC 2.6.1.9).
- **Harness:** `agent_boot.py:616` calls `register_federation_key(json.dumps(rec))`.
- **Key ids:** `fedcode::derive_key_id` is the earlier-form key id.

**CIRISAgent** (light)
- `register_self_federation_key(...)` (`edge_runtime.py:610`). The returned id becomes an identity-ref; the Agent overwrites `_actor_key_id` from it, which is fine if it treats the id as opaque.
- `lookup_public_key` reads `pubkey_ed25519_base64`, `pubkey_ml_dsa_65_base64` and `identity_type` in 3 places. Keep the JSON shape for edition-2 projections (fill the component pubkeys), or document the new shape.
- `local_sign` / `signer()` / `verify_hybrid` are used for separate signatures in `substrate_signing.py` (non-row). Keep them, or rule them out.
- `attestation_upsert_local` (unsigned local tier): unaffected if the local tier survives.
- The Agent's trace JCS comes from CIRISVerify, not from persist.

---

## 7. Slice plan

**The rule that makes the slices parallel:** build each edition-2 counterpart *beside* its JSON door, so the suite stays green. Shut the doors in one final, mechanical commit (F) after the fixtures have flipped (E).

**Memory rule:** at most 2 cargo-building agents at once (parallel cargo agents OOM-killed the session).

### J0: the merge (sequential, must merge first; size M)
- Merge E2a (`v62-wire`, once committed) and E2b (`v62-baseline`) into `v62-int`.
- Resolve §0.1: `put_statement` writes the edition-2 `key:record` projection into `federation_keys` (`edition=2`, `record_row_id`, `kid`, component pubkeys), FKs ON.
- Delete the 7 `TODO(baseline-merge)` hacks (`SQLITE_DDL`/`POSTGRES_DDL` self-creation, `foreign_keys=OFF`, `EDITION2_SIGNER_FKS_DROPPED_PG`).
- **Shared-file additions made here, so A–D do not collide:**
  - new trait methods on `FederationDirectory` (`edition2_statements_since`, the typed-projection writers below as stubs returning `Unsupported`), implemented on sqlite, pg and `directory_double`;
  - the producer primitive `edition2::produce::{sign_row, sign_object}`;
  - the test codec `statement_of` / `row_of` and the id helpers `kid()` / `rid()`.
- **Files:** `edition2/{ingest,store,produce(new),fixture_switch}.rs`, `federation/mod.rs` (trait), `store/{sqlite,postgres}.rs`, `federation/directory_double.rs`, `store/parity.rs`, `sqlite_conn_model.rs`.
- **Witnesses:**
  - I1906/I1909 green on the V300 baseline with FKs on, on sqlite + pg;
  - `sign_row` equals `sign_row_statement` byte for byte and `admit_row` admits it;
  - the codec round-trip for every family `FLIP` emits.

### A: inbound doors + typed projections (parallel after J0; L)
- Route every Rust inbound door through `put_statement`.
- Add `apply_replicated_statement` (bytes, offered id, tier `federation`, typed `StoreConflict` cursor advance).
- Add the edition-2 → typed-table projections:
  - `group:roster` → families/communities/group_versions;
  - `membership:{stage}` → the 4 membership tables;
  - `identity:occurrence(_revocation)` → occurrences;
  - `transport:{kind}` → `transport_destinations`;
  - `revocation:*` → `federation_revocations`;
  - `cosign:{state}` → lineage-head cosigns;
  - `key_grant:{axis}` effects;
  - counted `accord:*` evidence, `takedown_notice:{basis}`, `custody:{kind}`, `delivery_receipt:{stream_id}`.
- Each JSON door gets a **named-refusal path ready but not yet active**: one shared primitive, `edition2::door::refuse_earlier_form(plane)`, so F is a one-line flip per door.
- **Files:**
  - `federation/{attestation_admit,attestation_apply,tier_ingest,register,key_plane,group_plane,family_admit,community_admit,occurrence_admit,consent_admit,accord_carriage,steward_purge,cosign,self_roster,key_grant,holding_claim,stream_receipt,wire_index}.rs`;
  - the projection SQL in `store/{sqlite,postgres}.rs` (functions only; J0 owns the signatures).
- **Depends on:** J0; §8 rulings for location proof, touch claim and trust grant (leave those doors JSON-refusing with **no** E2 counterpart if CC defines no family).
- **Witnesses**, per door, on sqlite+pg:
  - the edition-2 statement is admitted and lands in the typed table;
  - the same fact as an earlier-form object is refused `earlier_form_object` **by name** once the refusal is active (asserted in F);
  - a replicated statement under a wrong offered id is `row_id_mismatch`;
  - the key-unknown error is retryable and does not advance the cursor.

### B: producers + serving (parallel after J0; M–L)
- Re-target every §2 producer to `sign_row`.
- Serve statement bytes:
  - `edition2_statements_since` behind `list_*_since`;
  - `lookup_signed_record_by_content_hash` becomes a lookup by row id / statement id;
  - the wire index is re-keyed on `statement_id`.
- Drafts (`draft_accord_recovery`, `ownership_reclaim` builders, `purge_notice_signing_payload`, `cohort_build_membership_change_envelope`) return CBOR payload + `Sig_structure` bytes.
- Delete the PQC cold-path and the scrub upgrade.
- **Files:**
  - `engine.rs` (producer fns only);
  - `federation/{attestation_emit,emit,key_grant (emit half),holding_claim (sign half),blobs (withdraws helper),accord_recovery,ownership_reclaim,operational (emit_trust_edge),migration}.rs`;
  - `maintenance/vocabulary.rs`.
- **Overlap with A:** `key_grant.rs` and `holding_claim.rs`. Split them by function (A takes admission, B takes emission), or serialise those two files.
- **Witnesses:**
  - each producer's output is admitted by `put_statement` on a second node (two-node witness: **deliver through the planes**, not just the same directory);
  - `register_self_federation_key` returns an identity-ref;
  - a served statement equals the received bytes.

### C: genesis bundle/2 + boot (parallel after J0; L; **production placement blocked on Verify**)
- Adopt CC `ae09856`'s payload in `edition2/genesis.rs`.
- Add the `test_ceremony_v2` fixture (§4).
- Engine boot: pre-genesis when no bundle is held, and the test fixture installs under test-anchor.
- Re-derive everything from `bundles_in_force`: holders → accord roster, serve_nodes → canonical (ruling C), charter → family, bindings → serve transport.
- `trust_root_bundle_response` serves bundle/2 voices and named rows.
- The import door takes bundle/2 (`pin_trust_from_bundle_response`).
- Then delete `federation/genesis/*` bundle/1 and the JSON seeds.
- **Files:** `federation/genesis/*`, `edition2/genesis.rs`, `engine.rs` (boot fns only, l.~11145–11310), `canonical_community.rs` (bundle response), `server/mod.rs`, `admission.rs` (canonical by bundle; the `TODO(json-cut)` co-scrub), `row_type_invariants.rs`, `replication` trust-root predicate.
- **Overlap with B in `engine.rs`:** disjoint fn ranges; merge B first.
- **Depends on:** J0; Verify bundle reader (or an Eric-ruled test placement).
- **Witnesses:**
  - a fresh node is pre-genesis and roots nothing;
  - the test ceremony bundle installs and the canonical = `serve_nodes`;
  - a bundle/1 JSON at the import door and at `put_genesis_bundle` is `earlier_form_object`;
  - a later bundle short of a strict majority is `count_unmet` (concludes nothing);
  - the HTTP route serves `{"statements":[hex…]}`;
  - all on sqlite + pg.

### D: host surfaces (parallel after J0; M)
- **PyO3:** `put_edition2_statement`, `apply_replicated_statement`, `sign_row`/`sign_composite`, `bundles_in_force_json`, `edition2_statements_since`.
- Every §1b earlier-form PyO3 door raises `ValueError(federation_malformed_row: earlier_form_object)` (behind the same F flip).
- Python stubs/typing.
- **Capsule:** append `PutEdition2Statement` and `ApplyReplicatedStatement`; the old variants become refusing arms.
- **HTTP pipeline ingest:** a ruling (§8) to verify via edition-2 keys or to refuse.
- **Files:** `ffi/pyo3.rs`, `ffi/pyo3/*`, `ffi/directory_capsule.rs`, `python/` stubs, `server/pipeline.rs`.
- **Depends on:** J0 for the signatures; A/B/C for behaviour. D can land the surface against J0 stubs and gain behaviour on merge.
- **Witnesses:**
  - a Python round-trip: the statement is admitted and the JSON is refused by name with `ValueError`;
  - error-type parity (memory: a new error arm keeps the Python type of the arm it replaces);
  - the capsule op numbering is unchanged (append-only gate).

### E: the fixture flip (after A–D; L, the largest; parallelisable by file partition, 2 agents max)
- Make the 37 builders read `emit_edition2()` (default on), and re-implement `seal_row`/`sign_envelope` on `statement_of`.
- Then rewrite the literal sites file by file (§3: about 211 files and ~3,270 tests), using `kid()` / `rid()` for ids.
- Delete the tests of earlier-form behaviour.
- Partition by directory: `federation/*_invariants.rs` A–M, N–Z, `store/`, `ffi/`, `tests/`.

### F: shut the doors + delete (sequential, last; S–M)
- Activate `refuse_earlier_form` on every door (Rust, PyO3, capsule, HTTP).
- Remove the switch (`FLIP` stays as history, or is deleted with I1912).
- Delete §5's S items.
- Clear all `TODO(json-cut)`.
- Write the CHANGELOG Removed and Adoption sections.
- **Witness, gating the property and not the fix:** a from-disk gate enumerating every `FederationDirectory` write method, PyO3 door and capsule `Put*/Apply*` op, asserting that each refuses an earlier-form object by name on sqlite + pg. A new door that forgets the refusal turns the gate red.

**Order:** J0 → (A ∥ B ∥ C ∥ D; at most 2 building at once, with B before C on `engine.rs`) → E → F. **J0 must merge first.** C's production path stays blocked until Verify ships its reader. A, B, D and E do not depend on that, provided C's test fixture placement is ruled.

**Rough size:** J0 M (≈1.5–2k lines), A L (≈5–7k), B M–L (≈3k), C L (≈4k added, ≈12k deleted), D M (≈2k), E L (touches ~211 files), F S–M (≈15–25k lines deleted net, BELIEVED).

---

## 8. What blocks on Verify or CC, and the rulings needed

1. **Verify: the genesis bundle reader** (`TODO(verify-bundle-reader)` ×6). `put_genesis_bundle` stores nothing until it ships. That blocks the production genesis, and the test-fixture install too unless a `cfg(test)` placement is ruled. **Ask Verify:** a `verify_genesis_bundle(voices, anchor, held_rows) -> Placement`.
2. **Verify: an object-statement minter** (only `sign_row_statement` exists, and only for an in-memory key). Persist can build its own from `sig_structure` and a header (J0), but a Verify KAT for `ceg-genesis-bundle/2` statements would keep the producer honest.
3. **Verify divergences E2a already reported:** `names_earlier_form`, `after_valid_until` (retryable at persist), and `second_voice`/`counted_with_refs` under the test family model.
4. **CC: typed planes with no rc20 family** (TESTED against `manifests/family_model.json`, 184 families):
   - **location proof**;
   - **touch claim**;
   - **trust grant / trust revocation** (`trust:{job}:{version}` is not the same thing);
   - **wholeness witness** (slice D made it composite, but it is not a row of a family);
   - **accord proposal / participation / decision** as persist stores them;
   - **stream epoch DEK registration**, sealed-blob manifests (`file:{version}`?).

   CC `signed_object_v2.cddl` admits only three object typs, so each of these is either a row of a named family or node-local. **Each needs a CC ruling before A can give it an edition-2 door.** Until then the door refuses earlier-form with nothing admitted, which is a feature loss to announce.
5. **Scope ruling (Eric/CC): the non-directory signed-JSON planes.** None of these is a federation-directory row, but each is an earlier-form signed JSON object:
   - Agent traces (`/api/v1/accord/events`, `receive_and_persist`, `verify_trace`; CC has `trace:{form}:{version}`);
   - the Lens `PipelineEnvelope`;
   - cirisnode contributions, votes and attestations;
   - derived detection events and calibration bundles (`detection:*`);
   - fountain manifests (`fountain/admit.rs`);
   - stream delivery receipts;
   - the secrets API request auth;
   - the audit chain.

   Does v62.0 shut them too ("a v62 node reads only edition-2 objects"), or do they follow? This decides whether `verify_hybrid`, the bound-hybrid and `local_sign*` die in F.
6. **CC: composite components as standalone keys.** If `lookup_public_key` keeps serving component pubkeys of an edition-2 key, so that `verify_hybrid_via_directory` users and the Agent's `lookup_public_key` keep working, are separate-signature uses of a composite's components allowed? (CC 2.6.1.7 domain separation.)
7. **`original_content_hash` under edition 2:** keep `sha256(JCS(projection))` (so JCS stays), or redefine it as the row id. This is a persist decision, but adopters read the column.
8. **The ordering ruling for C's test placement** (§4 (a)/(b)).
