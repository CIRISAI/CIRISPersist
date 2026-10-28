# FSD — CC 2.3 at the bytes plane (CIRISPersist#853, #862)

**Surface:** `BlobError::Withdrawn`, the `blob_tombstone::binding_state` fold, `Engine::evict_blob`, and a resolver that sees both reference shapes.
**Constraint (#853):** `check_withdraws_admission` admits a `withdraws` whose target is not local with `rule = None` ("authority is a read-side concern"). Anything that acts on a `withdraws` at the bytes plane must recompute the rule when it acts, or an unauthorized replicated `withdraws` becomes a deletion vector.

## 1. The problem

CC 2.3 holds at the row plane: a subject's `withdraws` tombstones the referencing attestation, and readers of the row see it retracted (`precedence::retired_ids`, one fold; the CC 2.3.2.1 reject vectors; the `key_grant` refusal). The bytes plane needs the same guarantee. Without it, `read_blob_as`, `read_blob_range_as` and `serve_blob_to_peer` would return bytes whose referencing row is withdrawn — on the author node and on every holder that adopted them — through the FFI, a Python consumer, CIRISServer's `resolve_content`, and the swarm serve door.

CIRISEdge holds the edge half (CIRISEdge#614): a `RevocationRegister` re-derives the rule against the local target when a `withdraws` lands, marks the sha `Revoked`, refuses the chunk with `Withdrawn`, and routes to `EjectHardDelete`. Persist holds three things:

1. **The read door** consults the referencing row's tombstone before returning bytes.
2. **The serve door** answers `Withdrawn` — which Edge's `MissReason::Withdrawn` / `ChunkSourceRefusal::Withdrawn` carry and `blob_swarm` aborts on — instead of `NotHeld`, which means "ask another holder" and would walk the fetcher around the mesh.
3. **A per-sha eviction** that retracts this node's own holding claims and then deletes, in the sweep's order and under I18's contract (#862 part 1).

The binding resolver must find every row that references the bytes, including a chat row. A `BlobPointer` row carries the sha as a typed pointer member, never as an `evidence_ref`, so the resolver folds both shapes (#862 part 2, §3.1).

## 2. The rule

A blob's bytes are readable and servable iff **at least one** row that binds them is **live**. A row is live iff it is not retired by `precedence::retired_ids` over the composers naming it. A `withdraws` that retires a row at the bytes plane must be one this node **re-derives authority for now**, against the target it holds now: `check_withdraws_admission(directory, &withdraws)` returns `Ok(Some(rule))`. The stored `withdraws_admission_rule` is never read. `Ok(None)` (the target was not local at admission, or the target is a carrier row) and `Err(WithdrawsNotAdmitted)` both mean *this withdraws does not retire the bytes*.

Why "at least one live binding" and not "no withdrawn binding": the same blob may be legitimately referenced by several rows (a re-share, a quote). CC 2.3 is the subject's right to pull *their* row; it does not let one withdrawn reference delete bytes another live row still establishes. This also keeps the fold from being a deletion vector: retiring the bytes requires every binding to be retired, each by an authority re-derived now.

Why "re-derive, never the stored rule": `retraction_entitled`'s arm 3 trusts `withdraws_admission_rule.is_some()`, which is correct for the row-plane fold (the write door set it against a locally present target). At the bytes plane the `withdraws` may have been admitted with `None` because the target arrived later, and nothing rechecks a deferred row when its target lands. The read is the moment persist holds both rows, so the read is where the rule is computed. A fold that treated `None` as anything but "not retired" would let anyone who can get a `withdraws` admitted erase content they had no authority over.

## 3. The structure

### 3.1 `attestations_binding_content` sees both reference shapes (#862 part 2)

`admission::envelope_binds_content(envelope, sha)` holds when `evidence_refs` contains the sha **or** `blob_pointer::pointer_for(envelope, sha)` is `Ok(Some(_))`. A pointer-shaped member that is *unreadable* (`Err(PointerError)`) counts as **binding**: the row plainly references these bytes, and a malformed key-plane member must not make it invisible to the tombstone fold ("malformed is a refusal, not absence", in the direction that fails closed for the subject).

The SQL prefilters narrow on `attestation_envelope LIKE '%sha%'` (sqlite) and `(evidence_refs @> $1 OR attestation_envelope::text LIKE $2)` (postgres); the exact check runs in Rust. The `attestation_type = 'scores' AND tier = 'federation'` narrowing holds: a `withdraws` targets a content-establishing row, and local-tier rows are producer-only authority.

### 3.2 The fold: `blob_tombstone::binding_state(directory, sha) -> BindingState`

```rust
pub enum BindingState {
    /// No row binds these bytes (also a blob whose rows are on another node).
    /// The read proceeds.
    Unbound,
    /// ≥1 binding row is live. The read proceeds.
    Live,
    /// Every binding row is retired by a withdraws whose authority this node
    /// re-derived NOW. Names the retiring composer of the last live binding.
    Withdrawn { attestation_id: String, withdraws_id: String },
}
```

Per binding row `r` (from 3.1): gather the structural composers naming `r.attestation_id` **by reference** — `FederationDirectory::list_attestations_referencing(target_id)`. (A subject's `withdraws` is attested to the *issuer*, so neither the target's by-slice nor its for-slice reaches it; I149 witnesses this.) For each `withdraws`/`recants` among them, **replace** the stored entitlement with the re-derived one — `check_withdraws_admission(directory, g)` must be `Ok(Some(_))`, else the composer is dropped before precedence. The re-derivation is the fold's *only* authority; there is no second predicate beside it. Then `retired_ids` decides `r`'s fate under §6.1 precedence. `Unbound` is distinct from `Live` so a witness can tell "no row" from "a live row"; both read.

A sha that no row binds directly but that a sealed DAG relation names (a chunk, or a v3 child) is judged by the manifests it belongs to (`FederationDirectory::dag_manifests_of_chunk`, #979): `Withdrawn` only when every such manifest is withdrawn, `Live` when any is live, `Unbound` otherwise. The relation is persist's own (written at the seal and the promote), so no author-asserted row can tie a chunk to a live manifest.

A custody report (a device's `here` claim) is not a binding: it does not keep withdrawn bytes live and does not make the device a subject of the content (I149b).

### 3.3 Where it sits on the read paths

After authorization, before the body — the same slot as the AAD-at-plaintext refusal (§11.3 (5)), in `read_any_for_viewer` and `read_any_range_for_viewer` (step 2½). A stranger is still `NotGranted` first and learns nothing (I4b); an authorized viewer of withdrawn bytes gets `BlobError::Withdrawn`. The chunk-DAG dispatch runs after this check, so a DAG's chunks inherit the manifest row's verdict.

### 3.4 The serve door

`check_serve_disposition` has a third gate after pressure and quarantine: `binding_state(sha)` is `Withdrawn` ⇒ `BlobError::Withdrawn`. The serve door has no viewer to authorize, and the refusal names only the sha and the withdraws id — both of which a peer holding the row already sees on the wire.

### 3.5 `BlobError::Withdrawn`

```rust
/// CC 2.3 at the bytes plane (#853): every row binding these bytes is
/// retired by a `withdraws` whose authority this node re-derived at read
/// time. Distinct from `NotHeld` ("ask another holder") — trying another
/// peer will not help, which is what edge's `MissReason::Withdrawn` says.
Withdrawn { sha256_hex: String, attestation_id: String, withdraws_id: String },
```
kind `blob_withdrawn`; Python `RuntimeError("blob_withdrawn: <sha>")` — a refusal after authorization raises `RuntimeError`, as `SealDidNotOpen` does. The wire token edge maps to is `MissReason::Withdrawn` (serde `"withdrawn"`); persist's serve-door refusal carries `kind()`, and the Server/edge bridge maps `blob_withdrawn` → `Withdrawn` exactly as it maps `blob_not_held` → `NotHeld`.

### 3.6 `Engine::evict_blob(sha, now) -> EvictBlobReport` (#862 part 1)

The sweep's own sequence for one sha, public. First retract **this node's** own non-retired holding claims about the sha (`custody:ack:v1`), each by a hybrid-signed `withdraws` at the claim's scope (CC 3.1.3.3 rule 4, #989); **only then** `delete_blob`. I18's contract holds verbatim: a retraction that cannot be admitted **aborts** (bytes and binding stay, the error propagates); a retry after a partial failure never double-retracts (the directory's retraction fold at write, #502 E7). It requires a `LocalSigner` (federation-tier withdraws are hybrid-signed), as `evict_actor` does. A sha this node never claimed has nothing to retract and is deleted directly; the report says which happened. When the sha is a manifest whose fold is `Withdrawn`, the DAG chunks this node holds whose own fold is also `Withdrawn` are evicted the same way and counted in the report.

**What `evict_blob` does not do:** decide *whether* to evict. That is the caller's (edge's converger on `Revoked`, an operator, the retention sweep). The authority question for a *withdraws-driven* eviction is answered by 3.2; a caller that wants "evict because withdrawn" asks `binding_state` first. `evict_blob` on a `Live` blob is a policy choice the caller makes in its own name, exactly as `delete_blob` is.

## 4. Invariants

Witnesses live in `src/federation/bytes_plane_tombstone_invariants.rs` and run on sqlite and postgres.

- **I149 — a withdrawn reference stops the bytes, everywhere they are read.** A subject-bearing content row binds a blob by **pointer** (the chat shape) on node A; the row is A's own. A subject (rule 2, not the author — the case CC 2.3 exists for) emits `withdraws`. Then, for an authorized viewer: `read_blob_as` → `Withdrawn`; `read_blob_range_as` → `Withdrawn`; `serve_blob_to_peer` → `Withdrawn`, not `NotHeld`. A stranger is still `NotGranted`. Before the withdraws, all three read. `kind()` is `blob_withdrawn`.
- **I149b — a custody report is not a binding** (CC 2.3 + CC 3.1.3.3). A device that filed `here` for a file: once the file row is withdrawn the bytes are `Withdrawn` and every door refuses; the report does not make the device a subject or duty holder of the content; a genuine second referencing row still keeps the bytes `Live`.
- **I150 — the stored rule is not consulted.** The same row and blob, but the `withdraws` is **admitted out of order** (target absent at admission ⇒ stored `rule = None`) and is **unentitled** (a third party). After the target lands the bytes still read: `Live`. Then an *entitled* out-of-order withdraws (stored `None` too) lands: `Withdrawn`. Same stored value, opposite verdicts — the verdict comes from the re-derivation.
- **I151 — one live binding keeps the bytes.** Two rows bind one blob; one is withdrawn by its subject; the bytes read (`Live`); the second is withdrawn; `Withdrawn`.
- **I152 — the resolver sees the pointer shape.** `attestations_binding_content(sha)` returns a row whose only reference is a `BlobPointer` member (no `evidence_refs`) on both backends, and still returns the `evidence_refs` shape; an unreadable pointer member at that sha counts as binding.
- **I153 — `evict_blob` retracts before it deletes, and aborts on a refused retraction.** After `evict_blob`: exactly one `withdraws` by this node naming its holding claim, the bytes gone, the holder list no longer naming this node. With the withdraws made inadmissible (a `now` outside the admission skew, I18(b)'s shape): bytes and claim stay, `Err`. A second `evict_blob` after success: no second withdraws, `Ok`, the report says nothing was held.

### 5.1 Mutation table

Run under `scripts/pg_test_db.sh`.

| # | Mutant | Verdict |
|---|--------|---------|
| M1 | the fold trusts the STORED `withdraws_admission_rule` | KILLED — I150 |
| M2 | a re-derived `Ok(None)` is treated as retiring | **equivalent** — see below |
| M3 | `Unbound` is treated as `Withdrawn` (every unbound read refused) | KILLED — I149, I40, I42 |
| M4 | one withdrawn binding retires the bytes (`Live` requires all live) | KILLED — I149, I150, I151 |
| M5 | the serve door answers `NotHeld` for withdrawn bytes | KILLED — I149 |
| M6 | the tombstone is checked BEFORE authorization | KILLED — I149 (a stranger saw `Withdrawn`) |
| M7 | the resolver drops the pointer shape | KILLED — I150, I152 |
| M8 | an unreadable pointer counts as not binding | KILLED — I152 |
| M9 | `evict_blob` deletes before it retracts | KILLED — I153's abort leg |
| M10 | `evict_blob` retracts retired claims again on a retry | KILLED — I153 |
| M11 | the Python message drops the blob | KILLED — the boundary pin |

**M1** is killed only because I150 lands both withdraws *before* their targets (stored `None`), and because the fold has no predicate beside the re-derivation. A withdraws that lands after its target is stored with its rule, and a stored-rule fold would agree with the real one; a second predicate that re-spelled rules 1 and 2 from the target's own fields would entitle a subject's withdraws either way. Either would hide the mutant.

**M2** is equivalent: it changes the `Ok(None)` arm of the re-derivation, but at read time the binding row *is* the target, so the target is local by construction and never a carrier row — the re-derivation returns `Ok(Some(_))` or `Err(WithdrawsNotAdmitted)`, never `Ok(None)`. The hazard the mutant describes (a deferred `None` read as retired) is what I150's second leg measures, through the `Err` arm.

## 5. Not in scope

- Deciding *when* to evict withdrawn bytes on a holder (edge's converger does this on `Revoked`; the retention sweep has its own policy). Persist stops **serving and reading** them and gives the caller `evict_blob` to act with.
- The non-author-subject case at the **edge** bytes plane (edge produces no subject-bearing federation-tier dimensions); I149 exercises it on persist's own doors.
- `supersedes` at the bytes plane: a superseded row's bytes are still that row's bytes; ranking below both retraction forms in §6.1, a supersedes never flips a binding dead.
