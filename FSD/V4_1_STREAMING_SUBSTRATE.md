# FSD: CIRISPersist — Streaming substrate (CEG §10.5)

**Status:** Implemented — ranged reads (`get_blob_range`), `ChunkDag` blobs (V061), live stream chunks (`federation_stream_chunks`, V062), per-stream STHs (V063) and stream/epoch-addressed `key_grant` rows (V064), on both backends. Not implemented: an HTTP `206` tier, IPFS interop, and the accountable (witness-cosign) STH tier (CIRISRegistry#34).
**Upstream issues:** CIRISPersist#142 (substrate proposal), #144 (library survey), #145 (swarm fetch, downstream), CIRISRegistry#34 (STH consistency-proof enforcement, accountable tier), CIRISVerify#47 (hybrid KEM).
**Spec of record (protocol):** `CIRISRegistry/FSD/CEG/10_endpoints.md` §10.5 (V1/V2/V3 locks), §7.9 (`delivery_receipt:{stream_id}`), §0.9 (JCS canonical). This FSD is the **substrate mapping** of that protocol; where the two differ, CEG §10.5 is normative.

---

## 0. Summary

CEG §10.5 defines the **delivery axis** (visibility + revocability + *delivery*), including media multicast. This substrate implements its three primitives — ranged reads, `BlobBody::ChunkDag`, and live `put_blob_chunk` / `seal_stream` — over **SHA-256** (BLAKE3/iroh would force a wire migration across every repo, not justified by keyframe-aligned seek). It reuses the in-tree `SignedTreeHead` / transparency machinery, `aes-gcm`, `hkdf` and the hybrid KEM.

What CEG §10.5 requires of the substrate:
1. **Per-stream transparency log** — each stream is its own RFC 6962 log (`log_id = stream:<id>`), reusing the `SignedTreeHead` shape, not a `scores`-attestation dimension. Media chunks stay out of the global provenance tree (§10.5.0).
2. **PQC wrap mandatory** — streaming epoch DEKs wrap with `wrap_algorithm: v2 = x25519+ml-kem-768` (§10.5.3).
3. **STREAM nonce layout** (§10.5.2 V2 lock) — `prefix[7] ‖ counter_be[4] ‖ last_flag[1]`.
4. **Epoch axis** — `key_grant` rows addressed by `(stream_id, epoch)`, which needs a parallel CHECK arm beside the content-addressed one (§4.4).
5. **Delivery receipts** (§10.5.4 V3 lock) — `delivery_receipt:{stream_id}` reserved prefix; verification is a JOIN against the published root, not a signature check.

---

## 1. Why — mission + the CEG dependency

CEG's streaming-multicast half (`CIRISRegistry/FSD/CEG/` §10.5) needs a substrate that stores, serves and verifies live, chunked, encrypted content. This is that substrate.

Mission grounding (MISSION.md):
- **§1.2 N_eff / evidence** — a live stream is signed evidence like any trace; the per-stream transparency log (§10.5.1) makes a stream's chunk sequence tamper-evident under the same RFC 6962 algorithm persist already runs for audit chains. Streams don't get a weaker integrity story.
- **§1.4 apophatic bound — substrate stays format-blind.** Persist does NOT parse fMP4/WebM/HLS/DASH. Seek intelligence lives at the consumer (every container encodes its own time→byte index). Substrate serves opaque octet ranges over content-addressed bytes. This is the same "not an analytics engine" discipline applied to media.
- **§1.5 parity** — `get_range`, `ChunkDag`, and the stream tables all ship on BOTH Postgres and SQLite. A Raspberry-Pi peer hosting a community's stream is a first-class peer.
- **§1.6 fail-honest** — a catch-up request against an evicted epoch returns `ContentMiss`, never a silent gap (§10.5.3 P4). At-rest auth happens per-chunk so a truncated/torn stream is *detected*, not coerced.
- **§3 canonical bytes** — the STREAM nonce, the STH `signing_bytes`, and the delivery-receipt `receipt_signing_bytes` are all domain-separated + length-prefixed per the CEG-locked layouts; persist re-emits byte-exact.

---

## 2. Scope

### 2.1 In scope

| Primitive | CEG §10.5 anchor | Part |
|---|---|---|
| `get_blob_range(sha, start, end_inclusive)` (byte-range read, both backends + External proxy) | — (substrate primitive; enables §10.5 chunk fetch) | A |
| `BlobBody::ChunkDag { manifest_sha }` + manifest format + `put_blob_chunks` atomic upload | §10.1.1 Merkle-over-chunks | B |
| `federation_stream_chunks (stream_id, seq) → chunk_sha` index table | §10.5.3 table | C |
| `put_blob_chunk(stream_id, seq, …)` + `seal_stream(stream_id)` live append | §10.5.0/.1 | C |
| Per-stream transparency log (reuse `SignedTreeHead`/`TransparencyStore`, `log_id = stream_id`) | §10.5.1 V1 | C |
| Per-segment AES-256-GCM + STREAM nonce sealing | §10.5.2 V2 | C |
| Epoch-DEK `key_grant` cascade w/ `wrap_algorithm: v2` (PQC) + the RC1-1c CHECK migration | §10.5.3 D2/D3 | C |
| `delivery_receipt:{stream_id}` ingest/read (reserved prefix) | §10.5.4 V3 | C |

### 2.2 Out of scope

- **Container parsing** — substrate is format-blind (§1.4). `symphonia`/`mp4parse`/`webm-iterable` live at edge/consumer (#144 track-don't-adopt).
- **Multi-peer swarm fetch** — CIRISPersist#145; consumes the ranged-read and `ChunkDag` primitives.
- **MoQ / QUIC live transport** — lives at CIRISEdge; the substrate exposes bytes through PyO3, CIRISEdge does the wire. `quinn`/`h3`/`wtransport` are edge deps (#144).
- **HTTP `206` range tier** — not implemented; ranged reads are served through PyO3 (§4.1).
- **BLAKE3 / Bao-tree verified streaming** — refused (§3.1); substrate stays SHA-256.
- **MLS-style O(log N) rekey tree** — CEG §10.5.3 marks it "1.x, additive" (rides the opaque key_grant payload); not implemented.

---

## 3. Adopt/roll decisions (CIRISPersist#144)

The load-bearing calls:

### 3.1 Strategic: SHA-256, not BLAKE3 (LOCKED)

CEG §10.1.1 fixes the substrate hash as SHA-256 — every `federation_key`, every `evidence_refs[]`, every Contribution lineage walk depends on it. Adopting `iroh-blobs`/Bao-tree (BLAKE3) would mean either a multi-month 7-repo BLAKE3 wire migration or a fork-every-consumer hybrid. The streaming win it buys — byte-aligned sub-chunk verified streaming — is wasted on video, whose seek granularity is **keyframe-aligned (1–5s), not byte-aligned**. Merkle-over-chunks (manifest SHA + per-chunk SHA, §10.1.1) gives the integrity property at chunk granularity using SHA-256 already in stack. **Substrate stays SHA-256.**

### 3.2 Adopt (all already in-tree or transitively present)

| Concern | Crate | Note |
|---|---|---|
| BLOB-substr reads | `rusqlite` incremental `Blob` I/O; PG `substring(bytea,…)` | both backends native partial reads |
| Per-segment AEAD | `aes-gcm` (RustCrypto) | in stack via ciris-keyring |
| Per-chunk nonce/key HKDF | `hkdf` (RustCrypto) | in stack |
| Epoch-DEK hybrid wrap | `ciris-crypto` `hybrid_kex` + `ml_kem` (CIRISVerify#47) | the §10.5.3 `wrap_algorithm: v2` |
| `(stream_id, seq)` monotonicity | DB `UNIQUE` constraint | substrate primitive, not a lib |
| Manifest compression (sidecar only) | `zstd` | in stack; manifests/playlists only — NEVER video bytes |
| Per-stream RFC 6962 log | **in-tree** `SignedTreeHead`/`TransparencyStore` (CIRISVerify 2.3.0 transparency) | instantiate per `stream_id` |

### 3.3 Roll our own (small, scoped)

| Concern | ~lines | Why |
|---|---|---|
| ChunkDag manifest (flat Merkle list) | ~100 | flat one-level DAG; `rs_merkle` over-delivers; two serde structs + JCS |
| STREAM-nonce AES-GCM-HKDF framing | ~150 | tight loop over chunks; `tink-rs` incomplete/unmaintained |
| Per-backend BLOB-substr facade | ~50/backend | backend-specific SQL; no lib abstracts both |
| Manifest verify (SHA-of-manifest + per-chunk SHA) | ~50 | linear walk; `sha2` in stack |

### 3.4 Explicitly NOT adopting (with reasons, from #144)

`tink-rs` (incomplete/unmaintained), `iroh-blobs` (BLAKE3, §3.1), zstd seekable format (v0.1.0 since 2017), IPFS UnixFS wire (CID v1 + dag-pb commitment — defer until a real IPFS consumer), `actix-web` (stack is axum/tokio). Track-don't-adopt: `moq-rs` (when IETF MoQ → RFC; forward bet), `libp2p-bitswap` (#145 design ref), `iroh-blobs` (if federation ever rides iroh gossip).

---

## 4. Substrate mapping — the three primitives

### 4.1 `get_blob_range` — ranged read

```rust
// BlobStore trait + Engine + PyO3
fn get_blob_range(&self, sha256: &[u8; 32], range_start: u64, range_end_inclusive: u64)
    -> impl Future<Output = Result<Option<BlobRange>, BlobError>> + Send;
```

- **`BlobBody::Inline`** — server-side substring, no full-buffer load: SQLite `rusqlite` incremental `Blob` read at `(offset, len)`; Postgres `SELECT substring(bytes_inline FROM $start+1 FOR $len)`.
- **`BlobBody::External(ExternalRef)`** — proxy `Range: bytes=start-end` to the upstream object store; honor `206`/`Content-Range`.
- **`BlobBody::ChunkDag`** — walk the manifest prefix-sum, fetch covering chunk(s), slice at the boundaries.
- **Bounds** — reject `start > end`, `end ≥ total_size` clamped per RFC 9110 §14.4 semantics; typed `BlobError::RangeNotSatisfiable`.
- **Surface:** **PyO3** (cohabitation callers — lens-core, sovereign agent — want in-process bytes). Remote viewers use CIRISEdge's transport. The decrypting range read for sealed content is `read_blob_range_as` (§8.1); `get_blob_range` serves stored bytes to relays.

### 4.2 `BlobBody::ChunkDag`

`federation_blobs.bytes_inline` stores the **manifest** (JCS-canonical JSON per CEG §0.9), `content_sha256` = SHA(manifest bytes):

```json
{ "v": 1, "total_size": <u64>, "chunks": [ {"sha":"<hex32>","size":<u32>}, … ] }
```

- Each chunk is its own `federation_blobs` row (`Inline` or `External`). One-level DAG only (UnixFS flat-leaves; no nested DAGs).
- **CEG §10.1.1 satisfaction**: consumer verifies manifest SHA (= row `content_sha256`) before consumption, then each chunk's SHA on read. Full-SHA-before-consumption holds at both levels; no prefix short-circuit.
- `put_blob_chunks(manifest, chunks…)` — atomic multi-row insert (manifest + N chunk rows in one txn).
- Adds one `storage_kind`/`BlobBody` variant; the chunk relation rides CEG open-vocab `topical_relation:has_chunk` (no grammar change).
- **Chunk size: 1 MiB** (§8) — IPFS UnixFS 2025 profile; below fMP4 2–6s segment sizes; 16-byte GCM tag overhead < 0.002%.

#### 4.2.1 V061 migration — not pure-additive at the CHECK layer

`federation_blobs.storage_kind` (V047) carries `CHECK (storage_kind IN ('inline','s3','external_url'))` **plus a cross-column CHECK** tying storage_kind → which body column is present (inline→`bytes_inline`, s3/external_url→`external_ref`). Admitting `'chunk_dag'` (manifest stored in `bytes_inline`) extends **both** CHECKs on **both** backends:
- **Postgres** — `DROP CONSTRAINT` + `ADD CONSTRAINT` for the storage_kind enum + the cross-column rule, adding the `(chunk_dag → bytes_inline present)` arm. Bounded.
- **SQLite** — table-level CHECKs are baked into `CREATE TABLE` and cannot be `ALTER`ed, so this is the **12-step table rebuild** (create the new table with the extended CHECKs, copy rows, drop old, rename, recreate indexes/triggers and the holds_bytes linkage), preserving every column and index.

It is the smaller sibling of the stream/epoch CHECK migration (§4.4).

### 4.3 Live append + per-stream log

```rust
async fn put_blob_chunk(&self, stream_id: &str, seq: u64, body: Bytes, epoch: u64, …)
    -> Result<ChunkReceipt, StreamError>;
async fn seal_stream(&self, stream_id: &str) -> Result<SealedStream, StreamError>;
```

- Table `federation_stream_chunks (stream_id TEXT, seq BIGINT, chunk_sha TEXT, epoch BIGINT, …, PRIMARY KEY (stream_id, seq))` (V062) — the `UNIQUE(stream_id, seq)` is the monotonicity guarantee. Each chunk also lands as a normal `federation_blobs` row.
- **Per-stream transparency log (§10.5.1 V1)** — a stream is its own RFC 6962 log (`log_id = stream:<id>`) whose leaves are the chunk hashes in `seq` order. The **producer** signs the STH (hybrid Ed25519 + ML-DSA-65, §10.3 `signing_bytes`; mint with `stream_sth::produce_stream_sth`, PyO3 `sign_stream_sth_json`) every **K=64 chunks OR T=2s, always at an epoch boundary and at `sealed_at`**. Persist does not sign stream STHs. `put_stream_sth` (V063) gates them in order: parse the stream id from `log_id`; load the first `tree_size` chunk hashes (fewer → refused); recompute the root with CIRISVerify's transparency store; refuse a mismatch; verify the producer's hybrid signature; insert — a `(stream_id, tree_size)` conflict with a different root is refused as equivocation, an identical re-put is idempotent. Witness cosignatures are stored as provided and not enforced (best-effort tier); the accountable tier (§10.3.1 consistency proof) waits on CIRISRegistry#34. **A live stream never appends into the global provenance log** (§10.5.0).
- `seal_stream` builds the `ChunkDag` manifest from the index, computes its SHA, writes the final `federation_blobs` row + final STH with `last_flag` chunk.
- **Subscribe-while-live** rides the existing CEG attestation-subscribe path; no new `attestation_type` (1+4 lockdown).

### 4.4 The stream/epoch `key_grant` CHECK migration (V064)

CEG §10.5.3: the V054 cross-column CHECK requires `key_grant` rows be **content-addressed** (`media_content_sha256 IS NOT NULL`). The streaming epoch-key axis is **stream/epoch-addressed** (`(stream_id, epoch[, recipient])`, NULL `media_content_sha256`) → rejected by that CHECK alone. V064 adds a **parallel CHECK arm**: `(content-addressed) OR (stream/epoch-addressed)` — a bounded constraint migration on both backends (PG `DROP/ADD CONSTRAINT`, SQLite trigger rewrite per V054/V056 discipline).

---

## 5. Encryption posture (§10.5.2 / §10.5.3)

Full PQC envelope for streaming, per CEG §10.5.3:

| Layer | Algorithm | Source |
|---|---|---|
| Content (bulk) | AES-256-GCM per-chunk, **STREAM nonce** | `aes-gcm` (in stack) |
| Chunk nonce | `prefix[7]=HKDF-SHA256(epoch_dek; "ciris-stream-nonce/v1"‖stream_id‖epoch)[0..7]` ‖ `counter_be[4]` ‖ `last_flag[1]` | `hkdf` (in stack); mirrors `KEY_GRANT_V1_INFO` versioned-context pattern |
| DEK wrap (per epoch) | **`wrap_algorithm: v2 = X25519 + ML-KEM-768` (hybrid, FIPS 203) — MANDATORY** | `ciris-crypto` `hybrid_kex`/`ml_kem` (shipped) |
| Authenticity (STH, receipts) | Ed25519 + ML-DSA-65 | `ciris-crypto` (in stack) |
| Hashes | SHA-256 | `sha2` (in stack) |

Key invariants:
- **Per-segment AEAD, never whole-object** — whole-object GCM buffers the entire blob to validate one tag (AWS S3 EC v3) → incompatible with seek. Each 1 MiB chunk seals independently → random access works.
- **STREAM nonce safety** — within an epoch the 32-bit `counter_be` is strictly monotonic and MUST NOT wrap; substrate forces an epoch roll before `2³²−1` (operational cap `MAX_CHUNKS_PER_EPOCH = 2²⁴`). Across epochs the DEK changes, so a reset counter is a distinct `(key, nonce)` pair — cross-epoch reset is nonce-safe. `last_flag=0x01` on the final chunk gives truncation+append resistance.
- **Epoch triggers** — **member removal ⇒ MANDATORY rotation** (forward-only unsubscribe); member addition ⇒ no rotation + Option-A catch-up bounded by `history_on_join`; time/bytes ⇒ optional hygiene. Forward-only, NO PCS (consistent with CEG 0.7 §11.7.1 Option A).
- **Consumer MUST reject** a streaming epoch grant carrying `wrap_algorithm: v1`.
- **Catch-up bound (P4)** — `min(operator depth cap, chunk-eviction horizon)`; an evicted-epoch request returns `ContentMiss` (fail-honest). Operators MUST set the P4 cap with the cascade (otherwise the worst case is 10⁶ grants per rekey).

No per-segment `key_grant` rows — HKDF derives per-chunk keys from one epoch DEK (§142 anti-recommendation; §10.5.3).

---

## 6. Integration with the cohort_scope machinery

A stream is scoped content. A `live_stream` delivered to a community rides the **same target-membership gate**: the stream's `cohort_scope`/`cohort_target_id` names the audience (a `community_key_id`), and the epoch-DEK `key_grant` cascade is the Policy-L cascade over **that community's roster** (§10.5.3) against the rotating epoch key. The read-side §4.3 predicate and write-side §4.6 AV-58 gate apply to stream chunks exactly as to traces — no new scope machinery; streaming reuses `CallerScope`/`CallerAdmission` + `cohort_scope_sql_predicate` (`FSD/V4_0_DATA_ACCESS_SURFACE.md`). Member removal triggering epoch rotation (§5) is the cryptographic enforcement of the same forward-only-unsubscribe the revocation substrate (#161) enforces at the membership-row layer.

---

## 7. Parts and migrations

| Part | Deliverable | CEG | Migration |
|---|---|---|---|
| **A** | `get_blob_range` over `Inline` + `External` (PyO3) | none | none |
| **B** | `BlobBody::ChunkDag` + manifest + `put_blob_chunks` + ranged reads over ChunkDag | §10.1.1 | V061 (`storage_kind` CHECK) |
| **C** | `federation_stream_chunks` + `put_blob_chunk` / `seal_stream` + per-stream STH + STREAM-nonce AEAD + epoch-DEK v2 cascade + `delivery_receipt:{stream_id}` | §10.5.1–.4 | V062, V063, V064 |

The accountable witness-cosign tier additionally waits on CIRISRegistry#34; the best-effort tier (producer-signed STH only) is what runs.

---

## 8. Decisions

| Question | Decision |
|---|---|
| Chunk size | **1 MiB** (IPFS 2025 profile; below fMP4 segment sizes; tag overhead negligible). Per-content-class tuning would be an operator knob, not a substrate constant. |
| Live latency target | **CMAF/LL-HLS; MoQ is the forward bet.** The substrate exposes bytes; transport choice lives at CIRISEdge. `moq-rs` is tracked, not adopted, until IETF moq-transport is an RFC. |
| Ranged-read surface | **PyO3** (cohabitation callers). An HTTP `206` tier is not implemented. |
| IPFS interop | **Not implemented**; worth doing only for a real IPFS consumer (CID v1 + dag-pb is a non-trivial commitment). |
| Encryption at-rest seek | **Resolved by CEG §10.5.2** — per-segment AES-256-GCM + STREAM nonce; whole-object GCM refused. |
| DEK wrap algorithm | **Set by CEG §10.5.3** — `wrap_algorithm: v2` hybrid PQC, mandatory. |

---

## 8.1 Encryption at rest — crossed with `BLOB_ENCRYPTION_AT_REST.md` §12 (#832)

This document's §5 sealing posture (per-segment AES-256-GCM, STREAM nonce) is
the CEG §10.5.2 interop format; the SUBSTRATE's own at-rest seal for a chunk
DAG is specified in `FSD/BLOB_ENCRYPTION_AT_REST.md` §12 and differs on
purpose: each chunk is its own `CRBLOB` `AtRestEnvelope` with a random nonce
(the epoch DEK is shared by every writer in a community, so a counter nonce is
not safe for the substrate to mint), content-addressed by its ciphertext; the
manifest is `ChunkManifest` **v2** — ciphertext shas, PLAINTEXT sizes,
`chunk_tier` — sealed under the same DEK; the seal door checks the chunk ROWS'
recorded tier; the decrypting range read is `read_blob_range_as` beside
`read_blob_as`, while `get_blob_range` keeps serving stored bytes to relays;
and `stream_chunks` is the live-stream handle (reads before seal). The v1
manifest is unchanged for plaintext DAGs.

## 9. Cross-references

- **CEG** `CIRISRegistry/FSD/CEG/10_endpoints.md` §10.5 (.0 framing, .1 per-stream STH V1, .2 STREAM nonce V2, .3 epoch cascade D2/D3 + PQC wrap, .4 delivery receipts V3); §7.9 reserved prefix; §0.9 JCS; §10.1.1 full-SHA MUST; §10.3 SignedTreeHead reuse.
- **CIRISPersist#142** — the substrate proposal.
- **CIRISPersist#144** — adopt/roll survey (§3).
- **CIRISPersist#145** — multi-peer swarm fetch (consumes the A/B primitives).
- **CIRISPersist#161** — revocation substrate (the membership-row layer the epoch rotation enforces cryptographically).
- **CIRISVerify#47** — hybrid X25519+ML-KEM-768 KEX (the §10.5.3 `wrap_algorithm: v2`).
- **CIRISRegistry#34** — STH consistency-proof enforcement (accountable-tier gate).
- **MISSION.md** §1.4 (format-blind), §1.5 (parity), §1.6 (fail-honest), §3 (canonical bytes).
- In-tree reuse: `ciris_verify_core::transparency` (`SignedTreeHead`/`TransparencyStore`), `ciris-crypto` (`hybrid_kex`/`ml_kem`/`aes_gcm`/`hkdf`), `federation_blobs`, V054 `key_grant` constraint.
