# Persist kinds and planes against rc20 (origin/rc20 ae09856; persist v61.4.1)

## Q1

| Kind | persist (v61.4.1) | rc20 basis | Answer |
|---|---|---|---|
| location proof | federation/mod.rs:6543, :6646; replication_policy.rs:76 (`LocationProof`); types.rs:3668 | CC 3.3.3 subject_kind; CC 4.5.9 subject-only; CC 3.3.2 says every row needs a registered dimension, and none exists | ROW, proposed `location_proof:{version}` (CC 3.1.3, wire `location_proof:v1`, positive-only, subject-only, placement `federation` or `community`) |
| touch claim | mod.rs:9786; types.rs:4554; freshness.rs (V112); not a replicated kind | CC 3.2 owner-binding: the floor is the owner's latest owner-signed row; there is no `fresh_as_of` member anywhere | NODE-LOCAL fold (CC 2.4.1 "node-local derived state"); witness_touch and n_of_m forms have no basis: GONE |
| trust grant / revocation | mod.rs:9245, :9261; types.rs:4701 (columns on `federation_keys`, Key kind already retired) | CC 3.2 T3, CC 4.4.3.34 | ROW `delegates_to` with `trust:accepts:v1` or `trust:confers:v1` (`trust_classes`, `trust_depth`); revocation = signer's `withdraws`; `expires_at` = the row's own end |
| wholeness witness | mod.rs:9888, :9916; witness/admit.rs:207 | CC 6.1.1, 6.1.3: a composite raw signature over a binary preimage, no COSE | TRANSPORT (substrate object). Composite at the cut; not a row |
| accord proposal / participation / decision | mod.rs:10569, :10640, :10659; replication_policy.rs:115 (`AccordQuorumEvidence`) | CC 5.3.4 amend: a later bundle counted at a strict majority of the predecessor's holders | GONE as separate objects. A roster change is an amend of the `ceg-genesis-bundle/2` OBJECT (proposal = payload, participation = a holder's statement, decision = the count) |
| stream DEK row | blobs.rs:1366 (`self_retention_wrap`); blob_admit.rs:170, :178 | CC 5.1; CC 3.3.2 | Split: the record is NODE-LOCAL; the wraps are ROWs of `key_grant:{axis}` (stream), CC 3.1.3 |
| sealed manifest | blobs.rs:5358 (JCS `ChunkManifest` as a `chunk_dag` blob) | CC 2.6.1.4 size rule; CC 6.1.5: payload bytes, named by digest | Not signed. Blob-plane bytes named from the owner's row (`file:v1` and the like) |

## Q2

| Plane | rc20 basis | Answer |
|---|---|---|
| agent traces | CC 3.1.5 `trace:{form}:{version}`, CC 5.3.2.8 | SPLIT. The replicated trace is MESH (`trace:complete:v1` row); a node's own working copy is LOCAL |
| Lens BatchEnvelope | none: agent-to-node HTTP body | LOCAL only if no mesh party verifies it. The traces inside it are rows when replicated |
| cirisnode | CC 3.1.9: already rows | MESH (CC 3.1.9 families); ledgers and bookkeeping are LOCAL |
| detection events | CC 3.1.8.2, 3.4.8 `detection:*` | MESH, as rows |
| fountain aggregation | CC 6.1.2.1 AggregationMetaV1; CC 6.1: no storage codec | SPLIT. The aggregation meta is MESH (a CC 6.1.3 composite); the fountain content manifest and its symbols are GONE |
| stream receipts | CC 2.6.1.11 COSE receipts (RFC 9942); `delivery_receipt:{stream_id}` | MESH: STH receipts as COSE receipts, delivery receipts as rows |
| secrets API | none | LOCAL: node-internal; nothing of the mesh verifies it |
| audit chain | CC 3.1.3 `audit_chain:hash_continuity`; CC 4.5.9.3 tombstones | SPLIT. The chain is LOCAL (its Ed25519-only form may stay); any continuity claim served is a row |

## Text gaps (diff: proposal.diff)
1. Location proof has no family. Fix: the registry row above, plus "a row of `location_proof:v1`" in CC 3.3.3.
2. CC 2.6.1.11 says the media trailer is "the one exception", but CC 6.1.3's objects are also raw composites. Fix: "…and the substrate objects of CC 6.1.3 are the exceptions."
3. CC 3.2 "carried as `fresh_as_of`" names no member. Fix: "the `asserted_at` of the owner's most recent owner-signed row that the node holds, a fold the node computes and no row of its own."
4. CC 4.2.6 says no roster change or recovery can be signed. Fix: "In this form the three are one amend of the genesis bundle…"; "A recovery is a later bundle that changes only the rotating holder's seat." CC 2.6.1.11 gains "A recovery counts under the rotating holder's recovery key alone." The accord row leaves the open-encodings table.
5. Open, not in the diff:
   - The amend has no window `W` and no proposer nonce, but CC 4.2.6's table and lame-duck rule still read `W`. The owner or the verifier must settle this.
   - `location_proof` has no family-model card or derivation rows yet.
