# FSD — CC 2.3 at the bytes plane (CIRISPersist#853, #862)

**Release:** v47.2.0 (MINOR: a new `BlobError` arm, a new Engine door, a widened resolver).
**Operator constraint (verbatim, #853):** *`check_withdraws_admission` admits a withdraws whose target isn't local with `rule = None` ("authority is a read-side concern"). An eviction hook must recompute the rule when it acts, or an unauthorized replicated withdraws becomes a deletion vector.*

## 1. The gap

CC 2.3 holds at the row plane: a subject's `withdraws` tombstones the referencing attestation and readers of the row see it retracted (`precedence::retired_ids`, one fold since #686; the CC 2.3.2.1 reject vectors and the `key_grant` refusal since v44.4.0/#851). It does **not** hold at the bytes plane. `read_blob_as`, `read_blob_range_as` and `serve_blob_to_peer` never ask whether the row that references a blob is withdrawn. The bytes stay readable on the author node and on every holder that adopted them, indefinitely: through the FFI, a Python consumer, CIRISServer's `resolve_content`, and the swarm serve door.

Edge's half shipped (CIRISEdge#614): a `RevocationRegister` re-derives the rule against the local target when a `withdraws` lands, marks the sha `Revoked`, refuses the chunk with `Withdrawn`, and routes to `EjectHardDelete`. Three things remain that only persist can close:

1. **The read door** consults the referencing row's tombstone before returning bytes.
2. **The serve door** answers `Withdrawn`, which Edge's `MissReason::Withdrawn` / `ChunkSourceRefusal::Withdrawn` already carry and `blob_swarm` aborts on, instead of `NotHeld`, which means "ask another holder" and walks the fetcher around the mesh.
3. **A per-sha eviction** that retracts this node's `holds_bytes` claim and then deletes, in the sweep's order and under I18's contract (#862 part 1).

And the prerequisite: **the binding resolver cannot find a chat row.** `attestations_binding_content` / `envelope_binds_content` fold `evidence_refs` only. A `BlobPointer` row (edge's chat rows, every v46.1.0+ producer) carries the sha as a typed pointer member and never as an `evidence_ref`, so a tombstone fold that starts from the sha cannot reach the row whose tombstone matters (#862 part 2).

## 2. The rule

A blob's bytes are readable and servable iff **at least one** row that binds them is **live**. A row is live iff it is not retired by `precedence::retired_ids` over the composers naming it. A `withdraws` that retires a row at the bytes plane must be one this node **re-derives authority for now**, against the target it holds now: `check_withdraws_admission(directory, &withdraws)` returns `Ok(Some(rule))`. The stored `withdraws_admission_rule` is never read. `Ok(None)` (the target was not local at admission, or the target is a `holds_bytes` directory row) and `Err(WithdrawsNotAdmitted)` both mean *this withdraws does not retire the bytes*.

Why "at least one live binding" and not "no withdrawn binding": the same blob may be legitimately referenced by several rows (a re-share, a quote). CC 2.3 is the subject's right to pull *their* row; it does not let one withdrawn reference delete bytes another live row still establishes. This is also what keeps the fold from being a deletion vector: retiring the bytes requires every binding to be retired, each by an authority re-derived now.

Why "re-derive, never the stored rule": `retraction_entitled`'s arm 3 trusts `withdraws_admission_rule.is_some()`, which is correct for the row-plane fold (the write door set it against a locally-present target). At the bytes plane the withdraws may have been admitted with `None` because the target arrived later, and nothing rechecks a deferred row when its target lands. The read is the moment persist finally holds both rows, so the read is where the rule is computed. A fold that treated `None` as anything but "not retired" would let anyone who can get a `withdraws` admitted erase content they had no authority over.

## 3. The structure

### 3.1 `attestations_binding_content` sees both reference shapes (#862 part 2)

`admission::envelope_binds_content(envelope, sha)` becomes: `evidence_refs` contains the sha **or** `blob_pointer::pointer_for(envelope, sha)` is `Ok(Some(_))`. A pointer-shaped member that is *unreadable* (`Err(PointerError)`) counts as **binding**: the row plainly references these bytes and a malformed key-plane member must not make it invisible to the tombstone fold (v46.1.0's "malformed is a refusal, not absence" rule, here in the direction that fails closed for the subject).

Both SQL prefilters already narrow on `attestation_envelope LIKE '%sha%'` (sqlite) / `evidence_refs @> [sha]` (postgres); the postgres one is widened to `(evidence_refs @> $1 OR attestation_envelope::text LIKE $2)` and the exact check stays in Rust. The `attestation_type = 'scores' AND tier = 'federation'` narrowing stays: a `withdraws` targets a content-establishing row, and local-tier rows are producer-only authority.

### 3.2 The fold: `blob_tombstone::binding_state(directory, sha) -> BindingState`

```rust
pub enum BindingState {
    /// No row binds these bytes (the pre-#853 answer for every blob; also a
    /// blob whose rows are on another node). The read proceeds as today.
    Unbound,
    /// ≥1 binding row is live. The read proceeds.
    Live,
    /// Every binding row is retired by a withdraws whose authority this node
    /// re-derived NOW. Names the retiring composer of the last live binding.
    Withdrawn { attestation_id: String, withdraws_id: String },
}
```

Per binding row `r` (from 3.1): gather the structural composers naming `r.attestation_id` **by reference** — the new `FederationDirectory::list_attestations_referencing(target_id)` on all three backends, discriminated by the three composer ops. (The first cut used `list_attestations_for(r.attested_key_id)`, the slice every `retired_ids` caller folds over; a subject's `withdraws` is attested to the *issuer*, so that slice never reached it — I149 caught it.) For each `withdraws`/`recants` among them **replace** the stored entitlement with the re-derived one — `check_withdraws_admission(directory, g)` must be `Ok(Some(_))`, else the composer is dropped before precedence; the re-derivation is the fold's *only* authority (a rule-1/2 pre-filter beside it was a second predicate and hid the stored-rule mutant, §5.1). Then `retired_ids` decides `r`'s fate under §6.1 precedence. `Unbound` is deliberately distinct from `Live` so a witness can tell "no row" from "a live row"; both read.

### 3.3 Where it sits on the read paths

After authorization, before the body — the same slot as the AAD-at-plaintext refusal (§11.3 (5)), in `read_any_for_viewer` and `read_any_range_for_viewer` (step 2½). A stranger is still `NotGranted` first and learns nothing (I4b); an authorized viewer of withdrawn bytes gets `BlobError::Withdrawn`. The chunk-DAG dispatch runs after this check, so a DAG's chunks inherit the manifest row's verdict.

### 3.4 The serve door

`check_serve_disposition` gains a third gate after pressure and quarantine: `binding_state(sha)` is `Withdrawn` ⇒ `BlobError::Withdrawn`. The serve door has no viewer to authorize, and the refusal names only the sha and the withdraws id — both of which a peer holding the row already sees on the wire.

### 3.5 `BlobError::Withdrawn`

```rust
/// CC 2.3 at the bytes plane (#853): every row binding these bytes is
/// retired by a `withdraws` whose authority this node re-derived at read
/// time. Distinct from `NotHeld` ("ask another holder") — trying another
/// peer will not help, which is what edge's `MissReason::Withdrawn` says.
Withdrawn { sha256_hex: String, attestation_id: String, withdraws_id: String },
```
kind `blob_withdrawn`; Python `RuntimeError("blob_withdrawn: <sha>")` — a refusal after authorization keeps `RuntimeError`, as `SealDidNotOpen` does (v47.1.0). The wire token edge maps to is `MissReason::Withdrawn` (serde `"withdrawn"`); persist's serve-door refusal carries `kind()` and the Server/edge bridge maps `blob_withdrawn` → `Withdrawn` exactly as it maps `blob_not_held` → `NotHeld` today.

### 3.6 `Engine::evict_blob(sha) -> EvictBlobReport` (#862 part 1)

The sweep's own sequence for one sha, public: for each of **this node's** live `holds_bytes:sha256:<sha>` rows (`list_local_holders` filtered to our key), emit the `withdraws` through `emit_withdraws_attestation_helper`; **only then** `delete_blob`. I18's contract holds verbatim: a withdraws that cannot be admitted **aborts** (bytes and binding stay, error propagates); a retry after a partial failure never double-retracts (the directory's retraction fold at write, #502 E7). Requires a `LocalSigner` (federation-tier withdraws are hybrid-signed), as `evict_actor` does. A sha this node never announced has nothing to retract and is deleted directly; the report says which happened.

**What `evict_blob` does NOT do:** it does not decide *whether* to evict. That is the caller's (edge's converger on `Revoked`, an operator, the retention sweep). The authority question for a *withdraws-driven* eviction is answered by 3.2, and a caller that wants "evict because withdrawn" asks `binding_state` first; `evict_blob` on a `Live` blob is a policy choice the caller is making in its own name, exactly as `delete_blob` is today.

## 4. Invariants

- **I149 — a withdrawn reference stops the bytes, everywhere they are read** (sqlite + postgres; memory has no blob storage). A subject-bearing content row binds a blob by **pointer** (the chat shape) on node A; A adopts nothing, the row is A's own. A subject (rule 2, not the author — the case CC 2.3 exists for and the one edge's witness could not exercise) emits `withdraws`. Then, for an authorized viewer: `read_blob_as` → `Withdrawn`; `read_blob_range_as` → `Withdrawn`; `serve_blob_to_peer` → `Withdrawn`, not `NotHeld`. A stranger is still `NotGranted`. Before the withdraws, all three read. `kind()` is `blob_withdrawn`.
- **I150 — the stored rule is not consulted.** The same row and blob, but the `withdraws` is **admitted out of order** (target absent at admission ⇒ stored `rule = None`) and is **unentitled** (a third party). After the target lands the bytes still read: `Live`. Then an *entitled* out-of-order withdraws (stored `None` too) lands: `Withdrawn`. Same stored value, opposite verdicts — the verdict came from the re-derivation. *The mutation that trusts the stored rule (or treats `None` as retired) deletes on the unauthorized row and fails here.*
- **I151 — one live binding keeps the bytes.** Two rows bind one blob; one is withdrawn by its subject; the bytes read (`Live`); the second is withdrawn; `Withdrawn`.
- **I152 — the resolver sees the pointer shape.** `attestations_binding_content(sha)` returns a row whose only reference is a `BlobPointer` member (no `evidence_refs`), on all three backends, and still returns the `evidence_refs` shape; an unreadable pointer member at that sha counts as binding.
- **I153 — `evict_blob` retracts before it deletes, and aborts on a refused retraction.** After `evict_blob`: exactly one `withdraws` by this node naming its `holds_bytes` row, the bytes gone, `list_holders` no longer naming this node. With the withdraws made inadmissible (the I18 shape): bytes and binding stay, `Err`. A second `evict_blob` after success: no second withdraws, `Ok`, report says nothing was held.

Mutants planned (outcomes in §5.1): the fold reads the stored rule instead of re-deriving (I150 red); `Unbound` treated as `Withdrawn` (every pre-#853 read red); the serve door answers `NotHeld` (I149 serve leg red); `evict_blob` deletes before the withdraws (I153's abort leg red); the resolver drops the pointer shape (I152 red, and I149 cannot find its row); an unreadable pointer counts as not binding (I152 red); the read-path check moved before authorization (I149's stranger leg red: `Withdrawn` leaks to a stranger).

### 5.1 Mutation round — 11 mutants: 9 killed, 1 killed on the third round after a code correction, 1 equivalent

Run under `scripts/pg_test_db.sh`.

| # | Mutant | Verdict |
|---|--------|---------|
| M1 | the fold trusts the STORED `withdraws_admission_rule` | **survived rounds one and two**, then KILLED — see below |
| M2 | a re-derived `Ok(None)` is treated as retiring | **equivalent** — see below |
| M3 | `Unbound` is treated as `Withdrawn` (every pre-#853 read refused) | KILLED — I149, I40, I42 |
| M4 | one withdrawn binding retires the bytes (`Live` requires all live) | KILLED — I149, I150, I151 |
| M5 | the serve door answers `NotHeld` for withdrawn bytes | KILLED — I149 |
| M6 | the tombstone is checked BEFORE authorization | KILLED — I149 (a stranger saw `Withdrawn`) |
| M7 | the resolver drops the pointer shape | KILLED — I150, I152 |
| M8 | an unreadable pointer counts as not binding | KILLED — I152 |
| M9 | `evict_blob` deletes before it retracts | **survived round one**, then KILLED — I153's abort leg |
| M10 | `evict_blob` retracts retired claims again on a retry | KILLED — I153 |
| M11 | the Python message drops the blob | KILLED — the boundary pin |

**M1** survived twice, and the second survival was the useful one. Round one: I150's entitled withdraws had landed *after* its target, so it was stored with rule 2 and the stored-rule fold agreed with the real one; the witness was corrected to land both withdraws before their targets (stored `None`). Round two: it still survived, because the fold's pre-filter re-spelled rules 1 and 2 from the target's own fields *beside* the re-derivation, so a subject's withdraws was entitled either way and the stored rule was never asked. That pre-filter was a second predicate for the same fact — the class #893 and #897 were about — and it was hiding the mutant. It is gone: `check_withdraws_admission` is the fold's only authority. Round three killed M1′ through I150/A.

**M2** is equivalent: it changes the `Ok(None)` arm of the re-derivation, but at read time the binding row *is* the target, so the target is local by construction and never a `holds_bytes` row — the re-derivation returns `Ok(Some(_))` or `Err(WithdrawsNotAdmitted)`, never `Ok(None)`. The hazard the mutant was written for (a deferred `None` read as retired) is what I150/B measures, through the `Err` arm. Recorded rather than chased.

**M9** survived round one because I153 had no refused-retraction leg; it now evicts with a `now` outside the admission skew (I18(b)'s shape) and asserts `Err`, bytes kept, claim kept.

## 5. Not in scope

- Deciding *when* to evict withdrawn bytes on a holder (edge's converger does this on `Revoked`; the retention sweep has its own policy). Persist stops **serving and reading** them and gives the caller `evict_blob` to act with.
- The non-author-subject case at the **edge** bytes plane (edge produces no subject-bearing federation-tier dimensions today); I149 exercises it on persist's own doors.
- `supersedes` at the bytes plane: a superseded row's bytes are still that row's bytes; ranking below both retraction forms in §6.1, a supersedes never flips a binding dead.
