# FSD: Blob Encryption at Rest — CIRISPersist

> **Renamed 2026-09-09** from `ENCRYPTED_AT_REST.md` / "Content Encryption
> at Rest". The document now leads with **blob encryption at rest** — the
> cohort-keyed DEK cascade that is actually being implemented (§10).
>
> §3's boundary map for the other substrates (`trace_events`, `cirisgraph`,
> `audit_log`, the agent runtime tables, …) is **retained unchanged** as the
> forward plan; it is not superseded by the rename, and §9's sequencing
> still governs it. The attestation question specifically is tracked as
> **JC-10** and remains undecided.

**Status:** Proposed (locked design — this document formalizes a settled
exploration; it is the spec, not a re-exploration)
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-05-22
**Repo:** `~/CIRISPersist`
**Risk:** Architectural, on-disk format. Multi-release, phased. The
on-disk format change sits entirely behind the `Engine` API; post-2.9.0
persist is the sole DB opener, so the change is **unilateral** — no
downstream coordination, gated only on absorption completeness.

---

## 1. Why this exists

Every CIRISPersist substrate stores, at rest, the *reasoning content* of
CIRIS agents — the raw payloads of trace events, the attributes of
memory-graph nodes, the context of audit entries. Today the at-rest
confidentiality of that content is **delegated to deployment full-disk
encryption** (`docs/THREAT_MODEL.md:738` — "software-backed deployments
have no key isolation beyond OS keyring file permissions … mitigations
are deployment-level (full-disk encryption …)"). That is the right
posture for a row's *structural metadata* and the wrong posture for its
*content*: it makes confidentiality a property of how the operator
provisioned the disk, not a property persist guarantees.

A solar-LoRa Raspberry Pi, a federation relay host run by a peer you
have rated but do not control, a phone in a pocket, a leaked Postgres
backup tarball — these are the deployments the federation is *for*, and
on every one of them "we assumed the operator turned on FDE" is a hope,
not a guarantee.

This FSD specifies **content encryption at rest**: persist itself
encrypts the reasoning content of every substrate, application-layer,
**100% backend-agnostic**, while keeping a plaintext queryable
projection of each record's structural skeleton. The ciphertext is the
authoritative form; the plaintext projection is a reconcilable cache.

The capability this buys: **a federation that measures reasoning quality
without reading reasoning content.** The Coherence Ratchet and the N_eff
measurement (MISSION.md §1.2 — "N_eff is k_eff") score the *derived
signals* on the projection; they never need the content. A peer relay
can host another agent's evidence corpus, serve scoreable queries over
it, and be cryptographically unable to read what the agent reasoned
about. Evidence that is *scoreable-but-not-readable*.

### 1.1 Why this is uniquely possible for CIRIS data

Application-layer "encrypt the content, keep a queryable projection"
fails for general-purpose databases — you cannot know in advance which
columns a future query needs, so either you encrypt nothing queryable or
you encrypt nothing useful. CIRIS data escapes that trap for four
structural reasons:

**(a) The query set is closed and typed → the projection is *knowably
complete*.** The `ReadEngine` analytics surface is a fixed set of ~21
methods (`migrations/.../V042__trace_events_analytics_indexes.sql`
header: "The ReadEngine analytics query set is FIXED (~21 methods)").
V042 already *enumerated* every scalar those queries extract. When the
query set is closed, the set of columns that must stay plaintext is
finite, knowable, and auditable — not a guess about the future.

**(b) The federation scores derived signals, not content → the privacy
boundary equals the queryability boundary, by design.** The
Coherence Ratchet, capacity scoring, and manifold-conformity paths
cluster on cohort-identity labels and operate on *scored scalars*
(`csdma_plausibility_score`, `dsdma_domain_alignment`, `idma_k_eff`,
`idma_correlation_risk` — V042 Group A). They never read the prose of a
thought. So the columns a query needs *are exactly* the columns that are
non-sensitive by design. There is no tension to resolve: the line
between "queryable" and "private" is one line, drawn once.

**(c) Every record is agent-signed → the plaintext projection is
plaintext-but-unforgeable.** Every persist row carries a scrub/audit
envelope: an Ed25519 (cold-path ML-DSA-65) signature over the canonical
bytes (`src/ingest.rs::sign_scrub_envelopes`; the
`signature`/`scrub_signature*`/`original_content_hash`/`persist_row_hash`
columns on every substrate table). Confidentiality and integrity are
therefore **orthogonal layers**: the signature already makes the
projection *tamper-evident* without encrypting it. Plaintext-here is
plaintext-but-unforgeable, not plaintext-and-unprotected. Encryption
adds the one property the signature does not — confidentiality — and
adds it only where it is needed.

**(d) The scrubber already located the content/signal boundary.** The
post-ingest pipeline already cleaves content from signal: trace *levels*
(`trace_level` column) gate how much content a deployment ships at all,
and the scrub envelope's `original_content_hash`
(`src/ingest.rs::compute_pre_scrub_hashes`) is precisely the hash of
"the content, before scrub" — persist already names, hashes, and signs
the content/signal seam. Content encryption at rest does not *invent*
that boundary; it *enforces* the boundary the scrubber already drew.

The conclusion: the skeleton/content cleavage is not an imposition on
CIRIS data — it is a property CIRIS data already has, made load-bearing.

---

## 2. The boundary principle

Every persist substrate is a **signed, structured record** with two
parts. Content encryption at rest splits the record along the seam that
already exists between them.

### 2.1 Skeleton / queryable projection — stays PLAINTEXT

The structural columns the `ReadEngine` and indexes need stay plaintext:

- The cohort/identity/time axes: `agent_id_hash`, `ts`, `event_type`,
  `trace_id`, `thought_id`, `deployment_domain`, `deployment_type`,
  `agent_role`, the cost columns (`cost_usd`, `cost_llm_calls`,
  `cost_tokens`).
- The **V042-shredded scored scalars** — `csdma_plausibility_score`,
  `dsdma_domain_alignment`, `idma_k_eff`, `idma_correlation_risk` —
  promoted to real typed columns (see §5).
- The audit machinery: hash-chain fields (`sequence_number`,
  `prev_hash`, `entry_hash`), Merkle fields (`leaf_hash`, `root_hash`,
  `leaf_index`), the per-identity `next_value` sequence counter, and
  every signature/envelope column
  (`signature`, `signing_key_id`, `signature_verified`,
  `original_content_hash`, `scrub_signature_classical`,
  `scrub_signature_pqc`, `scrub_key_id`, `scrub_timestamp`,
  `pqc_completed_at`, `persist_row_hash`).

**Rationale.** (i) This is the *intended federation-transparency
surface*: the Coherence Ratchet / N_eff measurement score *on* these
columns, so they are non-sensitive by design (§1.1b). (ii) The columns
are covered by the agent's signature over the canonical bytes — plaintext
here is *plaintext-but-tamper-evident* (§1.1c), not unprotected. The
projection is a queryable cache, and a *signed* one.

### 2.2 Content — gets ENCRYPTED

The raw reasoning content gets encrypted: `trace_events.payload`,
`cirisgraph.nodes.attributes`, `cirislens.audit_log.payload`, the
free-text fields of agent runtime substrates (`thoughts.content`,
`tasks.description`, …), and the consensus-envelope payloads.

The authoritative form of a content column becomes
`AES-GCM(signed_canonical_content)`. On read, persist decrypts, then
**re-verifies the signature** against the decrypted plaintext, then
returns it. The plaintext projection (the shredded scalars, the
skeleton) is a queryable cache reconcilable against that signed
authority: if the cache and the decrypted-and-verified content disagree,
the signed content wins and the divergence is a typed error
(`docs/THREAT_MODEL.md` discipline — fail honest, MISSION.md §1.6).

---

## 3. The boundary map — per-substrate classification

This is the core deliverable. Each substrate's main table(s) is walked
column by column. `P` = projection (stays plaintext); `E` = content
(encrypted); `⚑` = **judgment call flagged for the user** — see §3.12.

Schema sources are cited per substrate; every cited path exists in
`migrations/postgres/lens/` (SQLite parity files mirror them).

### 3.1 `cirislens.trace_events` — `V001` + `V003` + `V006` + `V009`

The flagship substrate. One row per `ReasoningEvent` broadcast.

| Column | Class | Why |
|---|---|---|
| `event_id`, `ts` | P | PK; time axis — every analytics query seeks on `ts`. |
| `trace_id`, `thought_id`, `task_id` | P | Journey/dedup keys; `trace_events_dedup` / `trace_events_journey` indexes. |
| `step_point`, `event_type`, `attempt_index` | P | Closed-enum structural discriminators; V042 partials filter on `event_type`. |
| `agent_id_hash` | P | Hashed cohort identity; the federation-transparency surface (§1.1b). |
| `agent_name` | ⚑ | Hashed-vs-named — see §3.12. Plaintext today; flagged. |
| `cognitive_state`, `trace_level`, `schema_version` | P | Structural labels; `trace_level` gates content shipment (§1.1d). |
| `deployment_domain` | ⚑ | Cohort axis the Ratchet clusters on, BUT may reveal operational specifics — see §3.12. |
| `deployment_type`, `agent_role`, `agent_template`, `deployment_region`, `deployment_trust_mode` | ⚑ | Cohort axes (V006); `deployment_region` in particular can be operationally revealing — see §3.12. |
| `cost_usd`, `cost_llm_calls`, `cost_tokens` | P | Scored scalars; cost-analytics queries aggregate them. |
| **`payload`** | **E** | **The raw reasoning content.** The authoritative form becomes `AES-GCM(signed_canonical_payload)`. |
| `extracted_features`, `classifications`, `pipeline_metadata` | ⚑ | V009 pipeline side-channels. `extracted_features` is *derived signal* (projection-like); `classifications` can name detected content classes (PII categories) — see §3.12. |
| `signature`, `signing_key_id`, `signature_verified` | P | Integrity envelope (§2.1). |
| `original_content_hash`, `scrub_signature`, `scrub_key_id`, `scrub_timestamp` | P | Scrub envelope (`V003`); the integrity layer. |
| `audit_sequence_number`, `audit_entry_hash`, `audit_signature` | P | Audit-chain anchor; `trace_events_audit_seq` indexes it. |
| `pii_scrubbed` | P | Structural flag. |

**Fit:** clean. The V042-shredded scalars currently live *inside*
`payload`; §5 promotes them out so `payload` can be fully encrypted.

### 3.2 `cirislens.trace_llm_calls` — `V001`

| Column | Class | Why |
|---|---|---|
| `call_id`, `ts`, `trace_id`, `thought_id`, `task_id` | P | Keys + time axis. |
| `parent_event_id`, `parent_event_type`, `parent_attempt_index`, `attempt_index` | P | Structural linkage. |
| `duration_ms`, `prompt_tokens`, `completion_tokens`, `prompt_bytes`, `completion_bytes`, `cost_usd`, `attempt_count`, `retry_count` | P | Scored scalars. |
| `handler_name`, `service_name`, `model`, `base_url`, `response_model`, `status`, `error_class` | ⚑ | Operational labels; `base_url` can reveal a private LLM endpoint — see §3.12. |
| `prompt_hash` | P | Hash, not content. |
| **`prompt`, `response_text`** | **E** | **Raw LLM prompt and completion — the most sensitive content in the corpus.** |

**Fit:** clean. `trace_llm_calls` has no V042 indexes; no shredding
needed. Note this table carries **no per-row signature envelope** — its
integrity rides on the parent `trace_events` row. Encrypting `prompt` /
`response_text` here means the re-verify-on-read step (§4.2) must verify
against the parent event's signature, not a local one. See §8 unresolved.

### 3.3 `cirisgraph.nodes` / `cirisgraph.edges` — `V013`

| `nodes` column | Class | Why |
|---|---|---|
| `node_id`, `scope`, `node_type` | P | PK + closed-enum structural type; `nodes_type_scope` index. |
| `version`, `updated_by`, `updated_at`, `created_at` | P | Lifecycle / optimistic-concurrency. |
| **`attributes`** | **E** | **The node's content payload.** `AES-GCM(signed_canonical_attributes)`. |
| `signature`, `signing_key_id`, `signature_verified`, `original_content_hash`, `persist_row_hash` | P | Integrity envelope. |

| `edges` column | Class | Why |
|---|---|---|
| `edge_id`, `source_node_id`, `target_node_id`, `scope`, `relationship` | P | Graph topology — k-hop CTE traversal needs all of it plaintext. |
| `weight` | P | Scored scalar. |
| `attributes` | ⚑ | Per-edge attributes (timestamp windows, direction). Small, structural — but free-form. See §3.12. |
| `created_at` | P | Lifecycle. |

**Fit, with one caveat — the GIN index.** `V013` builds
`nodes_attributes_gin ... USING GIN (attributes)` for `@>` containment /
`?` key-existence predicate push-down. **A GIN index over encrypted
ciphertext extracts nothing** — this is the V042 problem (§5) again, in a
different substrate. The boundary map flags it: encrypting
`attributes` forces either (a) dropping `nodes_attributes_gin` and
accepting that attribute-predicate reads become full scans, or (b) a
`cirisgraph`-side shredding migration analogous to V042-final. Verified
against `V013`'s own header: the agent's actual graph workload is "point
lookup + time-window scan + bounded procedural k-hop" — *not*
attribute-predicate-heavy — so (a) is likely acceptable, but it is a
**flagged decision**, see §3.12.

### 3.4 `cirislens.audit_log` — `V014`

| Column | Class | Why |
|---|---|---|
| `entry_id`, `sequence_number`, `tenant_id` | P | PK + per-tenant monotonic chain key; `UNIQUE(tenant_id, sequence_number)` enforces order. |
| `actor_id`, `action_type`, `subject_kind`, `subject_id` | P | Self-signed identity + closed-token discriminators; `audit_log_subject` / `audit_log_actor` / `audit_log_action_type` indexes. |
| **`payload`** | **E** | **Free-form per-action content.** |
| `prev_hash`, `entry_hash` | P | **Hash chain — MUST stay plaintext (§2.1).** Critical: see fit note. |
| `recorded_at` | P | Time axis. |
| `signature`, `signing_key_id`, `signature_verified`, `persist_row_hash` | P | Integrity envelope. |

**Fit — RESOLVED: the chain commits to ciphertext (§8.1).** `V014`'s
header notes the canonical bytes for `prev_hash`/`entry_hash` "include
this payload byte-for-byte." Under content encryption that payload is
the stored ciphertext: **the hash chain commits to the encrypted form.**
Encrypt-on-write runs first — `ct = AES-GCM(canonical(payload))` — then
`prev_hash`/`entry_hash` are computed over the canonical entry carrying
`ct`. The chain therefore commits to exactly what is stored and
replicated, so any peer holding the (encrypted) corpus re-hashes and
verifies the chain **without the decryption key** — the audit log stays
a federation transparency substrate (MISSION.md §9) even when its
content is encrypted. Content authenticity for a key-holder is a
*separate* layer: the actor's self-signature (`actor_id` IS the pubkey)
is computed over *plaintext* before encryption and travels inside the
blob — the actor never holds persist's content key, never signs
ciphertext. Three orthogonal layers: confidentiality (AES-GCM),
content-authenticity (actor signature over plaintext), transparency
(chain/Merkle over ciphertext). This must be a tested invariant (§6).
The same form applies to `merkle_leaves.canonical_bytes` /
`leaf_serialized` (§3.7).

### 3.5 `cirisgraph.telemetry_metrics` — `V015`

| Column | Class | Why |
|---|---|---|
| `metric_id`, `metric_name`, `tenant_id` | P | Keys; `telemetry_window` index. |
| `value` | P | Scored scalar — the measurement itself. |
| `labels` | ⚑ | Free-form label set (4 KiB cap). Mostly structural; can carry operational specifics. See §3.12. |
| `observed_at`, `expires_at`, `created_at` | P | Time / TTL axes; `telemetry_expires` reaping index. |

**Fit — does NOT fit the cleavage cleanly; flagged as honest exception.**
`telemetry_metrics` has **no content column and no per-row signature**
(`V015` header: "Audit envelope is intentionally OMITTED on raw
metrics … they're ephemeral (24h)"). It is pure projection — there is no
"content" to encrypt. The spec's honest position: **`telemetry_metrics`
is exempt from content encryption** (no content; 24h-lived; FDE remains
the at-rest posture for it). If `labels` is judged sensitive (§3.12),
that is a *labels-only* encryption decision, not a skeleton/content
split. Rolled-up `tsdb_summary` nodes land in `cirisgraph.nodes` and are
covered by §3.3.

### 3.6 `cirislens.federation_keys` / `_attestations` / `_revocations` — `V004`

| Representative columns (`federation_keys`) | Class | Why |
|---|---|---|
| `key_id`, `identity_type`, `identity_ref`, `algorithm` | P | The directory's lookup keys; `federation_keys_identity` index. |
| `pubkey_ed25519_base64`, `pubkey_ml_dsa_65_base64` | P | **Public** keys — public by definition. |
| `valid_from`, `valid_until` | P | Validity window. |
| `registration_envelope` (`_attestations.attestation_envelope`, `_revocations.revocation_envelope`) | ⚑ | "Canonical bytes signed at registration … stored verbatim for forensic reconstruction." It is envelope/provenance, not reasoning content — leans P, but it is a JSONB blob. See §3.12. |
| `original_content_hash`, `scrub_signature_classical`, `scrub_signature_pqc`, `scrub_key_id`, `scrub_timestamp`, `pqc_completed_at`, `persist_row_hash` | P | Integrity envelope. |
| `reason` (`_revocations`) | ⚑ | Free-form revocation reason — could name a person/incident. See §3.12. |

**Fit — does NOT fit the cleavage cleanly; flagged as honest exception.**
The federation directory is, by purpose, a **transparency substrate**:
it exists so peers can walk a trust chain (`V004` header — "the
'registry DB compromise → arbitrary trust anchor' attack disappears
because consumers walk the FK chain"). It is the *least* content-bearing
substrate in persist. The spec's default: **federation directory tables
are projection-only — exempt from content encryption** — with `reason`
and the `*_envelope` blobs raised as flagged calls (§3.12). The
`AV-` entry (§5b of THREAT_MODEL, §7 here) must say this plainly: a
stolen federation directory reveals the trust graph, and that is
*intended* — it is a public ledger.

### 3.7 `cirislens.merkle_leaves` / `merkle_sth_log` — `V021`

| Column | Class | Why |
|---|---|---|
| `tenant_id`, `leaf_index`, `chain_event_id`, `tree_size` | P | Tree coordinates. |
| `leaf_hash`, `root_hash` | P | Merkle hashes — MUST stay plaintext (§2.1). |
| `canonical_bytes`, `leaf_serialized` | P | RFC 6962 hashing-form bytes — see fit note. |
| `signature_blob`, `signer_key_id`, `witness_signatures` | P | Signed-tree-head signatures. |
| `appended_at`, `signed_at` | P | Time axes. |

**Fit — projection-only by construction; commits to ciphertext.** The
Merkle layer is a *transparency* layer (RFC 6962). `canonical_bytes` and
`leaf_serialized` embed the audit entry — and per §3.4 (RESOLVED) the
entry's `payload` is the stored ciphertext. `leaf_serialized` is built
from the *encrypted* `payload`, so the tree commits to ciphertext: the
transparency proofs verify against the bytes every peer already holds —
RFC 6962 auditability is preserved without ever exposing plaintext.
§3.4 and §3.7 are therefore one consistent rule: **the hash chain and
the Merkle tree both commit to the encrypted form.**

### 3.8 `cirislens_secrets.*` — `V010`

**Fit — already encrypted; this feature does not touch it.**
`cirislens_secrets.secrets.encrypted_value` is already
`AES-256-GCM(secret)` via `src/secrets/crypto.rs`. The secrets substrate
is the *pattern* this FSD generalizes, not a target of it. `access_log`,
`master_key_meta`, `filter_config`, `cirislens_pseudonyms` are
projection/metadata and stay as-is. One genuine note: `access_log.purpose`
and `access_log.error` are free-form — but the secrets module is
out of scope for this FSD; no change.

### 3.9 `cirisnode.*` — `V011` / `V012`

Eight federation-consensus tables (`contributions`, `votes`,
`credits_ledger`, `expertise_ledger`, `moderation_events`,
`slashing_attestations`, `reconsideration_requests`,
`reconsideration_attestations`, `promotion_attestations`).

| Representative columns | Class | Why |
|---|---|---|
| `*_id`, `contribution_type`, `domain`, `language`, `subject_kind` | P | PK + closed-enum cell discriminators; `contributions_cell` etc. indexes. |
| `author_id`, `voter_id`, `accuser_id`, `adjudicator_id`, `target_contributor`, `contributor_id` | P | Self-signed identities (Ed25519 pubkeys). |
| `submitted_at` / `cast_at` / `filed_at` / `attested_at` / `requested_at` | P | Time axes. |
| `is_canonical`, `canonicalized_at` | P | Pending-vs-canonical gate. |
| `balance`, `expertise`, `is_active` | P | Derived ledger scalars (scored). |
| **`payload`** | **E** | **The consensus content** — deferral text, proposal body, accusation evidence, adjudication rationale. |
| `witness_set` | ⚑ | Witness set for high-stakes contributions — names witnessing keys; structural-ish but free-form. See §3.12. |
| `aggregate_evidence` (`V012`) | ⚑ | Evidence blob backing a promotion attestation. See §3.12. |
| `registration_envelope`-style envelopes, all `signature*`/`scrub_*`/`persist_row_hash` | P | Integrity envelope. |

**Fit:** clean for `payload`. The derived `credits_ledger` /
`expertise_ledger` are pure projection (no content column) — exempt,
like `telemetry_metrics`.

### 3.10 Agent runtime substrates — `V024`–`V035`

`tasks`, `thoughts`, `service_correlations`, `scheduled_tasks`,
`tickets`, `deferral_reports`, `creation_ceremonies`,
`continuity_awareness`, `feedback_mappings`, `wa_cert`. These are Phase 3
absorption tables (FSD `CIRIS_PERSIST.md` §2) — mutable relational state.

Representative classification (`thoughts`, `V025`):

| Column | Class | Why |
|---|---|---|
| `thought_id`, `source_task_id`, `channel_id`, `thought_type`, `status` | P | Keys + closed-enum state. |
| `created_at`, `updated_at`, `round_number`, `thought_depth`, `parent_thought_id`, `agent_occurrence_id` | P | Structural / lifecycle. |
| **`content`** | **E** | **The thought's reasoning prose.** |
| `context_json`, `ponder_notes_json`, `final_action_json` | **E** | Reasoning content — JSONB, but content, not skeleton. |

`tasks` (`V024`): `description`, `context_json`, `outcome_json`,
`updated_info_content`, `images_json` → **E**; everything else → P.
`creation_ceremonies` (`V031`): `new_agent_purpose`,
`new_agent_description`, `creation_justification`,
`ethical_considerations`, `expected_capabilities` → **E**; IDs,
timestamps, `ceremony_status` → P.
`continuity_awareness` (`V032`): `final_thoughts`,
`reactivation_instructions`, `unfinished_tasks`, `deferred_goals` → **E**;
the rest → P.

**Fit — two genuine problems, flagged.** (i) `tickets` (`V028`) carries
`email` (`NOT NULL`) and `user_identifier` — **direct PII columns that
are also lookup keys**. This is the one place the skeleton/content
cleavage genuinely fights itself: the column is both PII (wants
encryption) and a query key (wants plaintext). See §3.12 and §8.
(ii) `wa_cert` (`V034`) carries `password_hash`, `api_key_hash`,
`oauth_external_id`, `oauth_links` — credential material. `password_hash`
/ `api_key_hash` are *already hashes* (not reversible content); but
`oauth_external_id` and `oauth_links` are identifying. See §3.12.

### 3.11 Primitives with no content — `V030`, `V037`, `V038`, `V039`

`maintenance_locks` (`V030`), `revoked_service_tokens` (`V037`),
`identity_sequences` (`V038`), `occurrence_registry` (`V039`).

**Fit — projection-only by construction; exempt.** These are
coordination primitives: a lock row, a revocation tombstone, a monotonic
counter (`identity_sequences.next_value` — MUST stay plaintext, it is
the sequence authority), an occurrence heartbeat. The single nuance:
`occurrence_registry.metadata` is a free-form JSONB blob — flagged in
§3.12. Nothing else here has content; FDE remains the at-rest posture.

### 3.12 Judgment calls — flagged for the user to decide

The boundary map does **not** silently decide these. Each is a genuine
"projection convenience vs. confidentiality" trade. The user picks.

| # | Column(s) | The tension |
|---|---|---|
| **JC-1** | `trace_events.deployment_domain` (and `cirisnode` `domain`) | The *known* hard call. The Ratchet clusters cohorts on it, so plaintext makes cross-agent analytics cheap — but for some deployments the domain string ("crisis-intervention", a named customer) *is* an operational disclosure. **Options:** (a) plaintext always; (b) content-encrypted always (analytics then query a per-deployment opaque cohort token instead); (c) per-deployment policy flag — domain is plaintext where the deployment declares it non-sensitive, encrypted otherwise, with a stable hashed cohort token kept plaintext for the Ratchet either way. |
| **JC-2** | `trace_events.agent_name` vs `agent_id_hash` | `agent_id_hash` is already a hash and unambiguously projection. `agent_name` is a human-readable label and may name a real deployment/person. Recommend: encrypt `agent_name`, keep `agent_id_hash` plaintext (V042 indexes already cover `agent_name` — it would need to move to a content column, which is fine: no analytics *groups* on the name, only displays it). User confirms. |
| **JC-3** | `deployment_type`, `agent_role`, `agent_template`, `deployment_region`, `deployment_trust_mode` | Cohort axes (V006). Most are low-cardinality closed enums (safe plaintext). `deployment_region` and `agent_template` are higher-cardinality and can be operationally revealing. User: are all six plaintext, or do `region`/`template` move to content? |
| **JC-4** | `trace_events.classifications` (V009) | `extracted_features` is derived signal → projection. But `classifications` names *which content classes* (PII categories — UserId, ChannelId, …) were detected. Knowing "this trace contained 3 UserId matches" is itself a small leak. User: projection or content? |
| **JC-5** | `trace_llm_calls` `base_url`, `model`, `service_name`, `handler_name` | `base_url` can be a private/internal LLM endpoint URL. User: plaintext operational labels, or encrypt `base_url` (and possibly `model`)? |
| **JC-6** | `cirisgraph.nodes` GIN index | Encrypting `attributes` kills `nodes_attributes_gin`. User: (a) drop the GIN index and accept full-scan attribute reads (V013 says the real workload doesn't need it), or (b) commission a `cirisgraph` shredding migration analogous to V042-final. |
| **JC-7** | `cirisgraph.edges.attributes`, `telemetry_metrics.labels`, `occurrence_registry.metadata`, `cirisnode` `witness_set` / `aggregate_evidence`, `federation_keys` `registration_envelope` / `*_envelope`, `federation_revocations.reason` | Free-form JSONB/text blobs on otherwise projection-only substrates. Each *leans* projection (structural/provenance, not reasoning content) but none is a closed type. User: blanket "free-form blobs on projection-only tables stay plaintext", or encrypt case-by-case? |
| **JC-10** | `cirislens.federation_attestations.attestation_envelope`, **scoped by cohort** | **REOPENED 2026-09-09 at the operator's request.** Distinct from JC-7, which asks whether free-form blobs on projection-only tables stay plaintext as a *class*. This asks something JC-7 does not contemplate: should the attestation envelope be **encrypted under the cohort's DEK** for `family` / `community` / `affiliations` (and possibly `self`), leaving commons plaintext — i.e. the envelope joins the §2.2 content side, keyed by `cohort_scope` rather than by column. §8(4) currently exempts this substrate as "a transparency substrate by purpose"; that exemption is what is being reconsidered. **Measured cost, if adopted:** (i) the generated `dimension` column (sqlite V106/V114/V117, postgres V106/V122) cannot be derived from ciphertext, which also voids V137's seek index; (ii) 14 SQL sites read inside the envelope — 12 postgres, 2 sqlite — over `references_attestation_id` (×4), `dimension` (×3), `evidence_refs` (×1); (iii) the postgres GIN on `evidence_refs` dies, making citation lookup a scan-plus-decrypt; (iv) **the sharpest one — the retraction folds are `NOT EXISTS` subqueries matching `w.attestation_envelope->>'references_attestation_id'` against another row's id, 23 sites per backend. Encrypt the withdrawing row and the match yields NULL, `NOT EXISTS` becomes true, and a retracted row reads as LIVE. That fails toward disclosure, silently.** **Prerequisite either way:** hoist the join keys (`references_attestation_id`, `dimension`, `evidence_refs`) into maintained plaintext columns first, with a gate asserting no SQL reads inside the envelope; after that the scope choice is policy, not correctness. **Note on scoping to family/community/affiliations while excluding `self`:** that excludes the *cheapest* scope — `self` never federates (`suppresses_holds_bytes`) and is never peer-verified — and encrypts the three that do reach peers. It is defensible on volume (self is the hot internal path) but it is not the cheap subset, and a mixed-encryption table makes the negative predicates in (iv) worse, not better. **User decides:** (a) keep the §8(4) exemption — the directory is the transparency surface, per the same argument that made the audit log commit to ciphertext in §8(1); (b) adopt cohort-scoped envelope encryption, after the join-key hoist; (c) adopt it only for `self`/`family`, which is where the peer-verification cost is lowest. |
| **JC-8** | `tickets.email` / `tickets.user_identifier` (V028) | The genuine conflict (§3.10): PII that is also a lookup key. **Options:** (a) plaintext (FDE-only protection for ticket PII); (b) encrypt the value, keep a separate `email_hash` plaintext column for lookup (a deterministic-hash sidecar — equality lookup works, no range/substring); (c) encrypt and accept that ticket lookup-by-email becomes a decrypt-and-scan. |
| **JC-9** | `wa_cert` `oauth_external_id`, `oauth_links` (V034) | `password_hash` / `api_key_hash` are already non-reversible hashes (leave plaintext). `oauth_external_id` / `oauth_links` are identifying. User: encrypt the OAuth identity columns? |

---

## 4. Mechanism

### 4.1 Encrypt-on-write — the ingest path

Encryption hooks into the ingest path **after verify, after scrub,
before backend insert** — i.e. between step 5 (sign scrub envelopes) and
step 6 (decompose / insert) of
`src/ingest.rs::IngestPipeline::receive_and_persist`. Ordering is
load-bearing and must not change: verify-before-persist (MISSION.md §1.6)
runs over the *agent-shipped plaintext*; scrub mutates plaintext;
encryption is the *last* transform before bytes hit the backend.

For each content column of each decomposed row:

1. Take the **canonical bytes** of the content (`canonicalize_value` —
   the same canonicalizer the signature was computed over).
2. Derive a per-row content key (§4.3).
3. `ct = crypto::encrypt(content_key, fresh_nonce, canonical_content)`
   — AES-256-GCM via the existing `src/secrets/crypto.rs` facade.
4. The row's content column is written as `ct`; the per-row
   `salt` + `nonce` + `encryption_key_ref` are written to sidecar
   columns (§4.4). The plaintext skeleton/projection columns (including
   the V042-shredded scalars, §5) are written plaintext as today.

The shredded scalars are extracted from the *plaintext* content
**before** step 3 — encryption is strictly downstream of shredding.

Substrates with their own write paths (graph upsert, audit append,
cirisnode ingest) get the identical transform at their respective
`insert_*` boundaries; the encrypt step is a shared helper, not
re-implemented per backend (mirrors how `crypto.rs` is the sole
`ciris_crypto` import site).

### 4.2 Decrypt + re-verify on read

On every read that returns a content column:

1. Read `ct` + sidecar `salt`/`nonce`/`encryption_key_ref`.
2. Derive the content key (§4.3) and
   `pt = crypto::decrypt(content_key, nonce, ct)` — GCM auth-tag
   failure is a typed `Crypto` error (corruption or master-key
   mismatch).
3. **Re-verify the row signature** against `pt` using the existing
   `src/verify/` path (`verify_trace` / the audit-chain verifier). The
   decrypted content must match what the agent signed. A signature
   failure here is *not* a soft warning — it is a typed error, and the
   read fails honest (MISSION.md §1.6: "no third state").
4. Decrypted plaintext is held in `Zeroizing<Vec<u8>>` (§4.5) and
   returned; if the read also touched the plaintext projection cache,
   persist may reconcile (§4.6).

GCM is authenticated encryption — step 2 already detects ciphertext
tampering. Step 3 is the *additional* guarantee: it proves the plaintext
is the *agent's* content, not merely *some* content that decrypts
cleanly under persist's key. Confidentiality (GCM) and authenticity
(Ed25519/ML-DSA) stay orthogonal layers end to end (§1.1c).

### 4.3 Key structure — per-row content keys under the master key

Mirror `src/secrets/` exactly. The master key is **the secrets master
key path persist already owns**: hardware-rooted, derived by
`ciris_verify_core::derive_symmetric_key` over a TPM / Android Keystore /
Secure-Enclave-sealed seed (`src/secrets/hardware.rs`), with a software
fallback that is *honest about being software*
(`SecretsError::HardwareKeyUnavailable` — MISSION.md §1.6). Content
encryption introduces **no new master-key root**; it reuses this one,
under a distinct HKDF context string (a new stable wire constant
analogous to `SECRETS_MASTER_CONTEXT`, e.g. `content-at-rest-master-v1`,
so content keys and secret-store keys are domain-separated).

Per row: a fresh 32-byte `salt` and a fresh 12-byte `nonce`, exactly as
`src/secrets/crypto.rs` (`SALT_LEN = 32`, `NONCE_LEN = 12`). The per-row
content key is `derive_secret_key(content_master, salt)` —
PBKDF2-HMAC-SHA-256, 600k iters. Each row's content is encrypted under
its own derived key with its own nonce: no nonce reuse across rows, and
a single leaked per-row key never compromises any other row.

**Open performance question (see §8):** `secrets/` uses PBKDF2 at ~100 ms
per key because secrets are low-volume. Trace ingest is high-volume.
Per-row PBKDF2 at ingest rate is almost certainly too slow; the
implementation phase must choose a per-row KDF appropriate to the volume
— most likely **HKDF-SHA-256** (microseconds, the same primitive
`hardware.rs` already uses for master derivation) keyed by
`(content_master, row-unique salt)`. This FSD records HKDF-per-row as the
*intended* mechanism and PBKDF2-per-row as explicitly rejected on
performance grounds; the implementation phase confirms.

### 4.4 Per-row sidecar columns

Each content-bearing table gains, per encrypted column (or one shared
set where a table has a single content column), the sidecar columns the
secrets schema already models (`V010` `secrets`): `salt BYTEA`,
`nonce BYTEA`, `encryption_key_ref TEXT` (FK into a content-key-meta
table mirroring `master_key_meta`, so master-key rotation has one
surface). A `content_enc_version` small-int per row records the
encryption-format version so future format changes are
detectable/migratable. These sidecar columns are themselves
projection/metadata — plaintext.

### 4.5 Zeroization

Decrypted content is sensitive material in process memory. As
`src/secrets/` already does (`hardware.rs` wraps the raw seed in
`Zeroizing`), every decrypted plaintext buffer and every derived per-row
key is held in `zeroize::Zeroizing` so it is scrubbed on drop. The
re-verify step (§4.2) operates on the `Zeroizing` buffer in place. No
decrypted content is logged, ever (the AV-15 sanitization discipline —
`SecretsError::kind()` tokens, never payload bytes — extends here).

### 4.6 Reconciliation

The plaintext projection (shredded scalars, skeleton) is a *cache* of
facts derivable from the signed authoritative content. The authoritative
form is `AES-GCM(signed_canonical_content)`. Where a read both decrypts
content and consults the projection, persist may reconcile: if a shredded
scalar in the plaintext column disagrees with the value re-extracted
from the decrypted-and-verified content, the **signed content wins** and
the divergence is surfaced as a typed error (a corruption signal —
fail-honest, MISSION.md §1.6). Routine reads trust the cache for speed;
reconciliation is the audit/repair path.

---

## 5. The V042 consequence — full shredding ("V042-final")

V042 built **expression indexes** on `payload->>'csdma_plausibility_score'`
etc. — `migrations/{postgres,sqlite}/lens/V042__trace_events_analytics_indexes.sql`.
The index key carries `(payload->>'<field>')::float8` (Postgres) /
`json_extract(payload, '$.<field>')` (SQLite) as a trailing covering
column, and the partial predicate filters `payload ? '<field>'`.

**Once `payload` is AES-GCM ciphertext, every one of those expression
indexes extracts nothing.** `payload->>'x'` over ciphertext is not a
score; it is garbage or NULL. The four V042 Group A indexes
(`trace_events_an_csdma`, `_an_dsdma`, `_an_idma_keff`, `_an_idma_corr`)
and the `payload`-derived FILTER columns of Group B (`trace_events_an_trace_summary`)
silently stop working.

Content encryption therefore **forces** completing V042's design —
promoting the shredded scalars from expression-index targets to **real,
plaintext, typed columns.** This is *part of this work*, not separate;
it is the first migration phase (§9.1). Call it **V042-final / full
shredding.** It comprises:

1. **Promote the four scalars to real columns** on `trace_events`:
   `csdma_plausibility_score`, `dsdma_domain_alignment`, `idma_k_eff`,
   `idma_correlation_risk` — typed `DOUBLE PRECISION`, NULLABLE. Either
   persist-populated columns written by the ingest decompose pass (the
   recommended shape — works identically on both backends; generated
   columns over an encrypted blob are impossible), or, if a deployment
   keeps `payload` plaintext during transition, generated columns
   bridging the gap. The locked choice: **persist-populated real
   columns**, written by decompose from the plaintext content *before*
   encryption (§4.1).
2. **Rebuild V042's indexes on the real columns.** The Group A indexes
   become plain composite/partial indexes `(deployment_domain, ts,
   agent_id_hash, <real scalar column>)` — no expression, no
   `payload ?` predicate; the partial predicate becomes
   `WHERE event_type = '<EVENT>' AND <scalar> IS NOT NULL`. Simpler and
   faster than the V042 expression indexes, and **identical on Postgres
   and SQLite** (the dialect divergence in V042 existed *only* because
   JSON-extraction syntax differs — real columns erase it).
3. **Rewrite the `ReadEngine` SQL** (`src/store/postgres.rs`,
   `src/store/sqlite.rs` — `cross_agent_divergence`,
   `list_trace_summaries`, and the rest of the ~21-method set) to query
   the real columns instead of `payload->>'…'` / `json_extract(...)`.
   The "exact-expression-match constraint" V042 documents disappears:
   no expression to match.

Net: V042-final is strictly better engineering *independent of
encryption* (real typed columns beat expression indexes), and it is the
*precondition* that makes `payload` encryptable at all. The boundary map
(§3.1) lists the four shredded scalars as projection columns precisely
because this phase makes them real.

---

## 6. Backend-agnostic guarantee

This is non-negotiable (`MEMORY`: no PG-only declarations).

- **One mechanism.** Application-layer AES-256-GCM via
  `src/secrets/crypto.rs` → `ciris_crypto::aes_gcm`. Not SQLCipher
  (SQLite-only — would make SQLite and Postgres structurally different).
  Not Postgres TDE / `pgcrypto` (Postgres-only). Not filesystem/FDE
  (deployment-managed, not persist-managed — the posture this FSD
  *replaces* for content). The ciphertext is computed in Rust, identically,
  before it reaches either backend.
- **One column type.** Encrypted content lands in `BYTEA` on Postgres
  and `BLOB` on SQLite — the *identical* logical column, the same
  `Vec<u8>` round-trip. This is the same shape `cirislens_secrets.secrets.encrypted_value`
  already uses on both backends (`V010`). No backend sees anything the
  other does not.
- **One test suite.** Every encryption test runs against *both*
  backends — encrypt-on-write, decrypt-on-read, re-verify, GCM-tamper
  rejection, master-key-mismatch rejection, the §4.6 reconciliation
  path, and the §3.4 / §3.7 "hash chain commits to plaintext / Merkle
  commits consistently" invariants. A test that passes on one backend
  and not the other is a release blocker. The V042-final indexes
  (§5) are likewise verified identical on both.

---

## 7. Threat model

**Adversary.** Anyone who obtains the database **at rest** — the DB file
or a backup of it — *without* the running persist process and its
in-memory key cache. Concretely: a stolen solar-LoRa Pi or phone; a
malicious or compromised federation relay host that stores another
agent's corpus; a leaked Postgres backup tarball; a discarded disk.

**What is defended.** The **reasoning content** — `trace_events.payload`,
`trace_llm_calls.prompt` / `response_text`, `cirisgraph.nodes.attributes`,
`audit_log.payload`, `cirisnode` `payload`, agent-runtime
`content`/`description`/`*_json` — is AES-256-GCM ciphertext under a
key the adversary does not have (the key is HKDF-derived from a
TPM/Keystore/Secure-Enclave-sealed seed; on a software-fallback host the
key derives from an OS-keyring seed the adversary would *also* need —
the same residual `docs/THREAT_MODEL.md` AV-25 already names for the
software-signer fallback). An adversary with the DB file alone cannot
read what any agent reasoned about.

**What the projection still reveals — stated honestly.** A stolen DB
file still exposes the plaintext skeleton: hashed agent IDs
(`agent_id_hash`), timestamps (`ts`), event types, trace/thought IDs,
cost scalars, the V042-final scored scalars, the cohort axes (subject to
the JC-1/JC-3 decisions), the audit hash-chain and Merkle structure, and
the federation directory's trust graph (§3.6). **This is not a leak —
it is the intended federation-transparency surface** (§1.1b, §2.1). The
Coherence Ratchet and N_eff measurement are *designed* to operate on
exactly this data; a peer is *supposed* to be able to score it. The
honest framing for operators: content encryption at rest protects *what
the agent reasoned about*, not *that the agent reasoned, when, at what
cost, and how well it scored*. The latter is public-by-design evidence.

**Residual.** (i) The running process holds derived keys and decrypted
buffers in memory — an adversary with live process memory access (root
on the running host, a debugger) is outside this threat model, exactly
as for `src/secrets/`. (ii) Software-fallback hosts inherit the
AV-25-class residual: no hardware key isolation; mitigation is
operational (prefer hardware-attested deployments). (iii) The metadata
projection is unencrypted by design — FDE remains *recommended* for
defense-in-depth over the projection, but is no longer the *only* thing
standing between an adversary and the content.

**Proposed new THREAT_MODEL.md entry — `AV-<next>`: at-rest content
confidentiality.** A new `AV-` entry stating: persist encrypts substrate
*content* at rest under the hardware-rooted secrets master key;
substrate *projection/skeleton* stays plaintext as the intended
transparency surface and is signed (tamper-evident); the federation
directory and coordination primitives are projection-only and exempt;
software-fallback hosts inherit the AV-25 residual.

**Posture change at `docs/THREAT_MODEL.md:738`.** That paragraph
currently delegates *all* at-rest confidentiality to deployment FDE. It
must be revised: at-rest confidentiality **of content** becomes
persist-managed (this feature); FDE remains *recommended* for the
plaintext projection metadata as defense-in-depth, but is downgraded
from "the mitigation" to "a complementary mitigation." The line that FDE
is the mitigation for *content* is deleted — content is now encrypted by
persist.

---

## 8. Honest assessment — what is hard or unresolved

The skeleton/content cleavage is real and most substrates fit it
cleanly. The genuinely hard parts:

1. **Audit-leaf canonical form — RESOLVED (2026-05-22): the chain and
   Merkle tree both commit to ciphertext (§3.4, §3.7).** The open
   question was whether the audit hash chain and Merkle tree commit to
   plaintext `canonical(payload)` or to the encrypted form. Resolved
   against **MISSION.md §9**: the audit log is a *federation
   transparency substrate*, and a transparency log's defining property
   (RFC 6962) is **key-independent auditability**. If the tree committed
   to plaintext, a peer holding an *encrypted* corpus could verify only
   tree structure, not leaf contents — the log would silently stop being
   a transparency log the moment its content was encrypted. Committing
   to ciphertext keeps it one: every peer holds the ciphertext, so every
   peer can re-hash and fully audit the chain/tree **without the key**.
   This does *not* weaken content-authenticity — the worry that "the
   agent would have to sign ciphertext" was incorrect: the actor's
   self-signature is over *plaintext*, computed before encryption, a
   separate layer inside the blob; the actor never holds persist's
   content key. Three orthogonal layers, cleanly (§3.4). Plaintext-
   commitment would additionally have been *redundant* — the actor
   signature already gives a key-holder content integrity — and a
   marginal known-plaintext oracle. No longer open.

2. **`trace_llm_calls` has no per-row signature (§3.2).** Its integrity
   rides on the parent `trace_events` row. Encrypting `prompt` /
   `response_text` means decrypt-on-read cannot re-verify against a
   *local* signature — it must verify against the parent event. The
   read path must therefore join to the parent, or the decompose pass
   must propagate a per-call integrity hash. Tractable, but it makes the
   §4.2 re-verify step non-uniform across substrates.

3. **Per-row KDF performance (§4.3).** `secrets/` uses PBKDF2 at ~100 ms
   per key. At trace-ingest volume that is fatal. The FSD records HKDF-
   per-row as the intended mechanism but the implementation phase must
   confirm the throughput and the domain-separation argument.

4. **Substrates that do not fit the cleavage** — stated plainly rather
   than forced: `telemetry_metrics` (§3.5) has *no content column* and
   no signature — exempt; the federation directory (§3.6) is a
   *transparency substrate* by purpose — projection-only, exempt **(this
   exemption is REOPENED as JC-10, 2026-09-09: the operator has asked
   whether the attestation envelope should be encrypted under the cohort
   DEK for the encrypted cohorts. The exemption stands until JC-10 is
   decided — it is not silently overridden by the blob work)**; the
   coordination primitives (§3.11) have no content — exempt;
   `credits_ledger` / `expertise_ledger` (§3.9) are pure derived
   projection — exempt. "Exempt" is an honest classification, not a gap:
   these substrates have nothing confidential to encrypt.

5. **`tickets.email` (§3.10, JC-8)** is the one column where the
   cleavage genuinely self-contradicts — PII that is also a query key.
   No option is free; the user picks among plaintext / hash-sidecar /
   decrypt-and-scan.

7. **The §4.3 master-key root was DECLARED and never IMPLEMENTED —
   found 2026-09-09, unresolved.** Corrected from a first reading that
   called this a deliberate second root; the truth is less deliberate and
   more concerning.

   `at_rest_cascade.rs` documents the §4.3 design exactly — *"the persist
   content master key (`content_master_key`) … Hardware-rooted HKDF over
   the secrets-store sealed seed under a distinct context, with a
   software fallback honest about being software"* — and defines the
   constant §4.3 calls for:

   ```rust
   pub const CONTENT_MASTER_CONTEXT: &str = "content-at-rest-master-v1";
   ```

   **Neither is wired.** `content_master_key` does not exist: the module
   header links to it and no such function is defined anywhere in the
   tree. `CONTENT_MASTER_CONTEXT` has **zero call sites** — a "stable
   wire constant" nothing derives from.

   What runs instead is `load_or_init_content_master()`, the backend
   table path, which generates a random software key into
   `federation_content_master` with the descriptor *"software
   content-at-rest master (no hardware seed wired)"*. So the software
   fallback is not a fallback — it is the only path, reached by default
   rather than by decision, while the constant and the doc assert
   otherwise. A reader of this module would conclude the hardware root is
   in place.

   Consequences, all of which compound with corpus size:
   - **No rotation surface on the blob key material.** §4.4 specifies
     `encryption_key_ref` FK'ing into a content-key-meta table mirroring
     `master_key_meta` "so master-key rotation has one surface." Secrets
     rows carry that column; `federation_community_dek`,
     `federation_community_dek_member_grants` and
     `federation_blob_key_grants` carry no equivalent, and there is no
     content-key-meta table. There is also no content-master rotation
     code anywhere in the tree.
   - **`federation_community_dek.wrap_algorithm` admits exactly one
     value**, `aes256_gcm_content_master`, so every community DEK wrap
     hangs off that single software root. Losing or rotating it leaves
     the per-member hybrid wraps
     (`federation_community_dek_member_grants`) as the only recovery
     path.
   - Each blob sealed before this is reconciled is a blob that must be
     re-wrapped afterwards. The fix is O(1) now and O(corpus) later.

   **Decision needed before blob storage extends to more cohorts:**
   (a) adopt the §4.3 root — derive the content master from the secrets
   master under a `content-at-rest-master-v1` HKDF context, migrating the
   existing single row; or (b) amend §4.3 to sanction a separate
   federation content root, and say why. Either way §4.4's rotation
   surface (`encryption_key_ref` + content-key-meta) should land *before*
   the corpus grows, because it is a schema change over sealed rows once
   it does.

8. **The GIN index on `cirisgraph.nodes.attributes` (§3.3, JC-6)** is a
   second, smaller V042 — encrypting `attributes` kills predicate
   push-down. V013's own header argues the real workload doesn't need
   it, so dropping the index is probably fine — but it is a decision,
   not an assumption.

---

## 9. Sequenced implementation plan

Honest, phased, multi-release. Each phase is its own release and stands
on its own. No phase ships content encryption until the one before it
has landed.

### 9.1 Phase 1 — boundary map + V042-final shredding migration

Land §3 (this document) as the committed boundary map. Resolve the
§3.12 judgment calls (JC-1..JC-9) and the §8(1) audit-leaf fork. Ship
the **V042-final** schema migration (§5): promote the four shredded
scalars to real `DOUBLE PRECISION` columns on `trace_events`,
backfill them from existing plaintext `payload`, on both backends.
*No encryption yet* — `payload` is still plaintext; this phase is pure
schema/shredding and is independently valuable.

### 9.2 Phase 2 — `ReadEngine` SQL rewrite + V042-final index rebuild

Rewrite the ~21 `ReadEngine` methods (`src/store/postgres.rs`,
`src/store/sqlite.rs`) to query the real scalar columns. Drop the V042
expression indexes; create the V042-final plain composite/partial
indexes (§5.2). Verify identical query plans and results on both
backends. Still no encryption — but the read path no longer depends on
`payload` being plaintext-JSON.

### 9.3 Phase 3 — ingest-path encrypt-on-write

Add the content-key-meta table and the per-row sidecar columns (§4.4).
Implement the shared encrypt helper (§4.1) and the per-row HKDF key
derivation under the content master (§4.3). Wire encrypt-on-write into
the ingest decompose boundary and the graph/audit/cirisnode write paths
for the substrates classified `E` in §3. New writes land encrypted; old
rows are still plaintext (read path handles both via
`content_enc_version`).

### 9.4 Phase 4 — read-path decrypt + signature re-verify + reconcile

Implement decrypt-on-read, the §4.2 signature re-verification, the
`Zeroizing` discipline (§4.5), and the §4.6 reconciliation path.
Resolve §8(1) and §8(2) here in code. This is the phase that delivers
the actual confidentiality guarantee end to end.

### 9.5 Phase 5 — transparent migration of existing plaintext data

A versioned data migration walks every pre-encryption row, encrypts its
content columns in place, and bumps `content_enc_version`. **Unilateral**
— post-2.9.0 persist is the sole DB opener, the format change is entirely
behind the `Engine` API, and no downstream consumer coordinates on it
(gated only on absorption completeness, FSD `CIRIS_PERSIST.md` §2).
Batched and lock-considerate, mirroring `secrets`'
`reencrypt_all` chunking (`REENCRYPT_CHUNK_SIZE`).

### 9.6 Phase 6 — documentation

Update `docs/THREAT_MODEL.md`: add the `AV-` entry (§7) and revise the
`:738` at-rest posture. Update `MISSION.md` §1.6 — content encryption at
rest is a *fail-honest* feature (decrypt-then-re-verify, no third state;
reconciliation surfaces divergence as a typed error) and belongs in the
"fail-honest is a mission stance" section. Update
`FSD/CIRIS_PERSIST.md` to reference this substrate property.

---

## 10. Blob encryption at rest — the cohort-keyed DEK cascade (LOCKED 2026-09-09)

This section is the **committed design** for blob encryption across all
four encrypted cohorts. It supersedes nothing in §3 (the other substrates'
boundary map stands); it makes the blob half implementable.

### 10.1 Scope — four cohorts, three tiers, one cascade

`cohort_scope::crypto_tier` resolves seven cohorts into three tiers. Four
cohorts are encrypted:

| cohort | tier | delivery set |
|---|---|---|
| `self` | `InvisibleEncrypted` | every **active occurrence** of the identity |
| `family` | `InvisibleEncrypted` | every member's active occurrences |
| `community` | `CommunityDek` | every active member, per epoch |
| `affiliations` | `CommunityDek` | every active member, per epoch |

`species` / `biosphere` / `federation` are `Plaintext` — commons, and the
correct answer, not a gap. The **CC 4.4.3.2.1 infrastructure opt-out**
stands unchanged: an *authorized* `cohort_subkind: infrastructure`
community (own key is the `substrate_persist` authority) takes Commons
plaintext, no DEK. A self-labeled one that is *not* authorized gets the
full cascade — an unauthorized label can never force plaintext.

### 10.2 The root — `content_master_key` MUST be implemented before minting

§4.3 specifies **no new master-key root**: derive from the secrets sealed
seed under a distinct HKDF context. `at_rest_cascade.rs` already declares
the constant —

```rust
pub const CONTENT_MASTER_CONTEXT: &str = "content-at-rest-master-v1";
```

— and documents `content_master_key` as *"Hardware-rooted HKDF over the
secrets-store sealed seed under a distinct context, with a software
fallback honest about being software."* **Neither is wired** (§8(7)):
`content_master_key` does not exist, the constant has zero call sites, and
`load_or_init_content_master()` generates a random software key instead.

**Locked:** implement `content_master_key` as specified and make it the
sole supplier to `wrap_dek_for_persist`. `load_or_init_content_master`
becomes the *software fallback path only*, and must be honest about it
(`SecretsError::HardwareKeyUnavailable` discipline, MISSION §1.6).

**This lands FIRST.** There are no communities and no sealed blobs today,
so there is nothing to migrate. Every blob sealed before this is one that
must be re-wrapped after: O(1) now, O(corpus) later.

### 10.3 HKDF derives; it cannot deliver

A recurring question, settled here. **HKDF covers all four cohorts for
derivation and none of them for delivery**, because delivery targets a
party holding a *different* secret:

| job | primitive | cohorts |
|---|---|---|
| content master ← secrets seed | HKDF-SHA-256 under `CONTENT_MASTER_CONTEXT` | all four |
| per-object DEK | fresh RNG (self/family) / per-epoch (community) | all four |
| persist self-retention wrap | AES-256-GCM under the content master | all four |
| **delivery to occurrences / members** | **X25519 + ML-KEM-768 hybrid** (`x25519_mlkem768_aes256_gcm_hkdf_sha256`) | all four |

HKDF appears *inside* the hybrid wrap as its KDF step — that is where it
belongs. `self` is not an exception: an identity has multiple occurrences,
so even self content is delivered, not merely derived.

v1 wraps remain unrepresentable (V087 CHECK) — CC 4.4.3.4.1 / CC 5.2 HNDL.


#### 10.3.1 Delivery is SETTLED — one pipeline, four cohorts

Delivery is not an open question. Every cohort resolves to the **same
terminal**, and only the first step differs:

```
cohort  →  recipient set  →  active occurrences  →  encryption_pubkeys  →  hybrid wrap
```

| cohort | recipient enumeration |
|---|---|
| `self` | `list_identity_occurrences_active(owner)` |
| `family` | members → `list_identity_occurrences_active(member)` each |
| `community` / `affiliations` | `resolve_community_members` → `list_identity_occurrences_active(member)` each |

Everything downstream of the enumeration is **identical across all four**:
each active occurrence carries `encryption_pubkeys`, and the DEK is wrapped
to them with

```rust
ciris_crypto::key_grant::wrap_dek_for_recipient_v2(&x_pub, &ml_kem_pub, dek)
```

**Persist does no key exchange.** The occurrence is signed and its
`encryption_pubkeys` are bound by that signature (#418); admission
validates them structurally (`check_encryption_pubkeys` — base64, exact
raw byte length per half). So persist *reads verified key material* and
wraps to it. KEX is the transport layer's; the substrate's job begins at
"here is a verified recipient pubkey pair."

**Fail-secure exclusion, never downgrade.** An occurrence carrying no
valid `encryption_pubkeys` is **excluded from the fan-out** and a
`hard_case:recipient_excluded` is emitted. There is no plaintext fallback
and no v1 fallback — CEG §10.1.4, and V087's CHECK makes a v1 wrap
unrepresentable at the schema level (CC 4.4.3.4.1 / CC 5.2, HNDL). A
recipient we cannot wrap to is a recipient who does not receive, and that
is recorded rather than silently tolerated.

**What this settles for §10.** The delivery half needs no new design and no
new primitive for any cohort — including `self`, whose multiple
occurrences make it a delivery problem like the others rather than a
derivation-only one. The work in §10.10 is therefore confined to the
ROOT (§10.2), the KEYSET STATE (§10.5), and the SWEEP (§10.7). Minting a
community DEK reuses this pipeline unchanged, per epoch, over
`resolve_community_members` at the bumped epoch.

### 10.4 The keyset model — Tink semantics, not the Tink crate

We adopt [Tink's keyset design](https://developers.google.com/tink/design/keysets):
a set of keys, exactly one **primary**, old keys retained **decrypt-only**,
and a key identifier carried with the ciphertext so decryption never scans.

**We do not take the dependency.** `project-oak/tink-rust` is explicitly
*"not an official port … not supported by Google's cryptography teams"*,
is *"under construction"* with an API subject to change without warning,
and implements no cryptography itself — it is an API layer over the same
RustCrypto primitives `ciris_crypto` already provides. Adding it would
insert an unofficial, self-disclaimed layer between us and primitives we
already use correctly, in exchange for a table shape. MISSION §1.4 stands:
all crypto routes through `ciris_crypto`.

Our schema is already three-quarters of a keyset:

| Tink | ours |
|---|---|
| keyset | `federation_community_dek (community_key_id, epoch)` |
| primary pointer | `federation_community_dek_epoch.epoch` |
| key id in ciphertext | `federation_scope_blobs.group_dek_epoch` (inline) / `federation_community_blob_epoch` (side table) |
| **per-key state** | **NEW — §10.5** |

### 10.5 Key state — and the AV-70 amendment

**AV-70 today ratifies "forward-only (old-epoch blobs keep grants)"** —
Option-A's *"once shared, always shared."* A removed member keeps read
access to pre-rotation blobs they were already a grantee on. That is the
same posture MLS and Tink both take: forward secrecy protects *future*
content, not past.

**This design moves past it**, at the operator's direction. Adding a
destroy path makes the property "shared until the epoch is destroyed",
which is **stronger than either MLS or Tink offers** and therefore ours to
own. AV-70 is amended accordingly, and the cost is stated below rather
than discovered later.

Every DEK row gains a state:

| state | new seals | decrypts | meaning |
|---|---|---|---|
| `enabled` | yes | yes | the primary |
| `disabled` | no | yes | rotated past; AV-70's original behaviour, now one state among three |
| `destroyed` | no | **no** | key material gone |

**The DESTROY precondition — non-negotiable.** An epoch may move to
`destroyed` only when **every object sealed under it has been either
re-sealed under a live epoch or evicted from every holder**. Destroying a
DEK whose content still exists does not erase the content; it orphans it,
converting a confidentiality operation into unrecoverable data loss.

The precondition is *checkable*, and cheaply — which is why §10.7's reverse
index is load-bearing rather than a perf nicety. **A destroy that cannot
prove its precondition must refuse, not proceed.**

### 10.6 Distributed copies, and why the tombstone ceiling is the mechanism

Neither MLS nor Tink solves recall: MLS assumes a delivery service and
guarantees only forward secrecy; Tink assumes you control the storage. We
assume neither — blobs are fountained to peers.

The substrate already has the one primitive that reaches every holder.
`LifetimeClass::Tombstone` and `MonotonicSupersede` **project at their
plane's `tombstone_ceiling` regardless of scope**, precisely so a
retraction can never be out-run by the record it retracts — *anywhere a
copy could have travelled*. Eviction-on-rotate rides that plane.

**Consequence, and it needs a gate:** the blob/shard plane's
`tombstone_ceiling` must be **at least as wide as shards can travel**. A
ceiling narrower than the copy set starves holders and silently
un-revokes — the exact failure #713's per-plane ceiling was introduced to
reason about. This is a gate, not a convention.

### 10.7 Triggers — and why they are background by default

Two triggers, deliberately different in kind:

1. **Revocation-driven (immediate, synchronous).**
   `put_community_membership_revocation` already bumps the epoch
   transactionally, and future-dated `effective_at` is rejected at write
   time (SecReview F4). Exposure window for *new* content is zero. This
   stays exactly as-is.

2. **Sweep-driven (background, asynchronous).** Re-seal and eviction are
   O(objects at the epoch) and must **never run inline with a membership
   change** — a community rotation would otherwise stall on its own
   corpus. The sweep is a background job in the shape of the existing
   `evict_fountain_content_by_consent` /
   `evict_fountain_content_for_disk_pressure` paths, with an
   operator-callable synchronous variant for "do it now".

The sweep is **time-driven, not event-driven**: `removed_key_ids_at`
deliberately excludes future-dated revocations, so deletion must fire at
`effective_at`, which is a schedule rather than a reaction to arrival.

**Retention policy.** OpenMLS ships a configurable *past-epoch deletion
policy* because a delivery service cannot guarantee epoch-N content
arrives before epoch N+1 begins. Same problem here. Retaining every epoch
forever is unbounded; destroying eagerly orphans in-flight content. The
policy is a declared knob — `retain_past_epochs` — not an implicit
"keep forever".

### 10.8 Ordering constraint — encrypt, then fountain. Never the reverse.

A blob is sealed **before** it is fountained. Fountaining plaintext and
encrypting afterwards leaves plaintext shards on peers that no subsequent
rotation can recall, and the tombstone plane cannot un-see them.

**Reach, stated honestly (2026-09-10, from the Edge adoption thread #826).**
Even for sealed shards, "rotation is not recall" reaches only as far as the
shard plane's tombstone ceiling — and a ceiling wide enough helps only if
shards stay under it. Edge's shard plane today has a serve gate and no
STORE gate: the fountain converger pushes shards toward `target_holders`
without asking who may hold, so a shard can land on a node outside the
cohort, and a `Cohort`-ceiling tombstone will not reach it. Until
CIRISEdge#581 lands, the recall this section relies on is an INTENDED reach,
not an enforced one; Edge will return with a bound it can defend and it will
be pinned here as the shard plane's number. CIRISEdge#582 is the mirror —
what the converger deletes on an unverified holder count.

This is a **gate**, not a convention: the fountain path must refuse a
plaintext body whose `cohort_scope` resolves to an encrypted tier.

### 10.9 Schema deltas

1. `key_state TEXT NOT NULL DEFAULT 'enabled' CHECK (key_state IN ('enabled','disabled','destroyed'))` on `federation_community_dek`.
2. `CREATE INDEX … ON federation_community_blob_epoch (community_key_id, epoch)` — the reverse lookup the DESTROY precondition and the sweep both need. Today the PK is `at_rest_sha256` alone, so enumerating an epoch's objects full-scans. Self/family already has the analogous seek (`federation_blob_key_grants_by_recipient`, `(cohort_scope, recipient_key_id)`); this closes the asymmetry.
3. `encryption_key_ref` + a content-key-meta table mirroring `master_key_meta` (§4.4), so master-key rotation has one surface. Secrets rows carry this; blob key material does not.
4. `retain_past_epochs` on the community DEK epoch record.

### 10.10 Implementation order

Each step stands alone and is separately witnessed.

1. **`content_master_key`** (§10.2) — the real root. Nothing else is safe to mint on.
2. **Schema deltas** (§10.9) — cheap now, a migration over sealed rows later.
3. **Community DEK mint/rotate** on the real root, with key state.
4. **The encrypt-then-fountain gate** (§10.8).
5. **The background sweep** (§10.6/§10.7) — re-seal, evict, then destroy.

Steps 1–2 are prerequisites in the strong sense: they are O(1) today and
O(corpus) once content exists.

**Delivery is absent from this list on purpose** (§10.3.1). The
cohort → occurrences → `encryption_pubkeys` → hybrid-wrap pipeline is
built, wired and identical for all four cohorts, and persist performs no
key exchange — it wraps to signature-bound material admission has already
validated. Nothing in §10 requires a new delivery primitive; minting a
community DEK reuses that pipeline per epoch.

---

## 11. The shape that §10 should have had — REBUILT 2026-09-09 after three reviews

§10 locked the *design*. The first implementation of it (`fd43e74`, PR #827) was
reviewed three ways — a local code review (15 findings), Codex (8), and a cloud
ultrareview (4) — and ~17 verified issues clustered into ten root causes. None
of them was a typo. They were the same mistake in ten places: **each guarantee
was implemented as a check at one site, and nothing made the check the only
way through.** A gate on a door nobody calls; authorization on two of three
branches; "sealed" tested by an 8-byte prefix; "destroyed" as a text column;
a precondition the sweep satisfied by zeroing the thing it then read.

This section states the shape those guarantees need in order to be true **by
construction**, so that a test can falsify them through the surface a consumer
holds. §10's decisions stand; §11 is how they are made unbypassable.

### 11.1 The blob row is the authority on its own tier

`federation_blobs` gains two columns (V139, both dialects, each CHECKed
against its closed set): `cohort_scope` — the cohort the write named, kept as
provenance — and **`crypto_tier`** (`plaintext` / `invisible_encrypted` /
`community_dek`) — **the tier the write door RESOLVED**, which is what reads
dispatch on. Both are written by the door in §11.2; only `crypto_tier` is read
by the door in §11.3. **Nothing sniffs bytes to decide a tier, and nothing
re-derives a tier from a label.**

Two columns because they are two facts. The first rebuild stored only the
scope and had reads recompute the tier from it with `crypto_tier(scope, None)`
— the exact call §11.2(2) says the write door must not make, because it drops
the directory axis. So an authorized infrastructure community's write resolved
`Plaintext`, was stored under the literal scope `community`, and every read
then classified that same row `CommunityDek`, looked for a binding a plaintext
row correctly does not have, and failed. The write-time resolution was
discarded on the way to disk. Recording the resolved tier is what "the row is
the authority" has to mean; recording the input to the resolution is not.

This is the single change that removes two root causes at once. The first
implementation had reads inspecting the body for the envelope magic to decide
whether a blob was sealed — so a commons payload that happened to begin with
`CRBLOB\x01\x00` was routed down the encrypted path, and a plaintext body in a
private cohort was returned as public. When the row says what it is, the
question "is this sealed?" becomes "does this row's tier require sealing, and
does its body parse as an envelope?" — a structural check, not a guess.

**Backfill — corrected.** The first rebuild wrote "blob storage had not
shipped, so there is no encrypted legacy" and defaulted every pre-V139 row to
commons. That premise was false: `Engine::put_blob_encrypted_self_family`
shipped in v42, and the community cascade has bound blobs to epochs since V087.
Under that default, every ciphertext row an upgraded node already held would
have read back through §11.3's plaintext arm — grant check skipped, envelope
bytes returned to any viewer. A migration default is a security decision.

V139 classifies each existing row from the row's OWN evidence, in this order:
a row with a `federation_community_blob_epoch` binding is `community_dek` /
`community`; a row with a `federation_blob_key_grants` row is
`invisible_encrypted` under that grant's recorded `cohort_scope`; what remains
is commons. It also deletes bindings and grants whose blob row no longer exists
(earlier eviction paths deleted the blob and left them — §11.5). I16 seeds
rows of each kind through V138, runs V139, and reads them back.

### 11.2 One write door, and the storage floor is not a door

`Engine::put_blob_scoped(cohort_scope, community_key_id, plaintext, media_type)` is
the **only** consumer-facing write that accepts an encrypted cohort, in Rust and
in Python (named `_scoped` to keep it distinct from the raw `BlobStorage::put_blob`
storage method). It:

1. validates `cohort_scope` against the closed set;
2. **resolves the tier from the directory, never from the caller.** For
   `community` / `affiliations` it looks the community up and applies
   `is_authorized_infrastructure_community` — CC 4.4.3.2.1's carve-out is a
   property of the community record and its authority, which is exactly why
   the first implementation's `crypto_tier(scope, None)` was wrong: it dropped
   the one axis a caller must not be allowed to assert;
3. dispatches: **Plaintext** → store + announce `holds_bytes`;
   **InvisibleEncrypted** → the self/family cascade (fresh DEK, per-occurrence
   wraps, no `holds_bytes`); **CommunityDek** → the community cascade (epoch
   DEK, per-member wraps) **and** announce `holds_bytes`, because community
   content federates with cleartext provenance and the cascade never emitted
   the announcement it documented as the caller's job;
4. records `cohort_scope` **and the resolved `crypto_tier`** on the row;
5. **screens the PLAINTEXT with the perceptual-hash matcher, exactly once,
   before anything is sealed.** The first rebuild reached the matcher only
   through the announce step, which for a community write receives the
   randomized ciphertext envelope — a matcher configured to refuse known-bad
   images was handed bytes it could never match, after the cascade had already
   persisted them — and the self/family cascade never reached it at all. The
   screening is one shared function; the encrypted tiers call it at this door,
   and the commons tier is screened by the floor it lands on, so every path is
   screened once and no path twice;
6. **derives the attesting key id from the signer it was given**, by the same
   recipe as `Engine::local_derived_key_id` (#275: `derive_key_id(alias,
   Ed25519 pubkey)`, refusing a non-Ed25519 signer). The door takes no key-id
   argument. The first rebuild took one, and the Python binding passed the
   scrub alias it holds — a `holds_bytes` row that either FK-fails or names a
   key the sweep does not search under, so the announcement could never be
   retracted (§11.5). A parameter that has exactly one correct value is not a
   parameter.
7. **takes caller-supplied associated data and binds it into the seal, never
   into the row** (#831, from #830). `aad: Option<&[u8]>` (Python `aad_b64`)
   is folded into the AES-GCM tag through `ciris_crypto::aes_gcm::encrypt_aad`
   at both encrypted tiers — the self/family cascade and the community
   cascade's `seal_store_bind_at` — and is **not stored**: not on the row, not
   in the `AtRestEnvelope` (whose on-disk layout is unchanged), not in any
   grant. The reader supplies it again at the read door, so what it binds is
   whatever the caller holds elsewhere — for a chat message, the referencing
   row's author, signed instant and epoch. Under a per-epoch community DEK a
   ciphertext lifted from Alice's row onto an attacker's own validly-signed
   row opens for every member; a row-side commitment to `(sha, author,
   asserted_at)` does not stop that, because the attacker signs a
   self-consistent tuple. Only the seal can refuse it, and it does so without
   the blob layer learning what a row is. `Some(aad)` at a **plaintext** tier
   — commons, or the authorized-infrastructure carve-out — is refused
   (`InvalidArgument`): there is no seal to bind it to, and dropping it
   silently would leave the caller believing in a binding that does not
   exist. Transfers are unchanged: the ciphertext ships verbatim, and a peer
   that holds the referencing row also holds what it needs to open it.

The pre-existing commons doors (`put_blob_signing`, `put_blob_json`) remain and
are **commons-only by construction**: they record `federation`. There is no
consumer-reachable path that stores bytes at an encrypted cohort without
sealing them, because the only function that accepts an encrypted cohort is
the one that seals.

`store_blob_local`, `put_blob_with_scope` and `put_blob_signing_at` are the
storage floor: they take a body and a scope and persist without resolving a
tier. In-crate, the two cascades call them, and the commons doors may reach
them **only by naming a commons scope as a literal constant in the call**
(`cohort_scope::FEDERATION`), never through a variable that could carry a
private cohort; a from-disk gate (I14) reds on any other production caller.

**Out-of-crate, the floor is unconstructible.** `BlobStorage` is a `pub` trait
and CIRISServer consumes this crate from Rust, so every `pub` method on it is a
door for a Rust consumer; the first rebuild's I14 read the in-crate text and
called the floor sealed. Each floor method now requires a `StorageFloor`
token — a type with a private field and a `pub(crate)` constructor. An
external caller cannot name one, so `put_blob_with_scope(…, "self", plaintext)`
from outside the crate is a compile error, not a policy. I22 is a
`compile_fail` doctest — the one witness that runs as an external crate.

### 11.3 One read door, and it authorizes before it dispatches

`Engine::read_blob_as(sha, viewer)` — Rust and Python — is the read a server or
agent holds. Its order is fixed and the order **is** the guarantee:

1. load the row; absent ⇒ `NotHeld`;
2. **authorize by the row's tier, before touching the body:**
   Plaintext ⇒ public by construction, proceed;
   InvisibleEncrypted ⇒ the viewer holds an at-rest grant on this sha;
   CommunityDek ⇒ the viewer holds a member grant on **this blob's epoch**;
   otherwise ⇒ `NotGranted`, naming only the sha and the viewer;
3. only then read the body, and for an encrypted tier **require it to parse as
   an `AtRestEnvelope`** — a row that claims an encrypted tier and carries an
   unparseable body is corruption (`Backend`), never a plaintext return;
4. decrypt and return —
5. **under the associated data the reader presented, if any** (#831):
   `read_blob_as(sha, viewer, aad)` hands `aad` to
   `ciris_crypto::aes_gcm::decrypt_aad`; the same bytes, or the open fails.
   That failure is reachable only **after** step 2 — a non-member presenting
   the right data is still `NotGranted` — and it is a crypto-class error
   (`Backend`), never `NotGranted`: the viewer was authorized; the bytes did
   not belong to the row they arrived on. The message says exactly that and
   names neither the data nor the binding. By the verify pair's contract a
   wrong AAD is indistinguishable from a tampered body, and the door does not
   try to distinguish them. `Some(aad)` against a plaintext row is refused as
   at the write door, for the same reason: nothing bound it.

The first implementation authorized inside two of three branches and let the
third return bytes to anyone. Authorization that lives inside a branch is
authorization the next branch forgets. Here it lives above the dispatch, so
adding a fourth tier cannot skip it.

A destroyed-epoch refusal is reachable only **after** step 2 passes. The first
implementation checked destruction first and named the community and epoch in
the error, disclosing a blob's binding to a non-grantee.

### 11.4 Key state is cryptographic, atomic, and honest about its reach

**Destroy deletes key material.** Moving an epoch to `destroyed` deletes the
persist self-retention wrap **and every member-grant row for that epoch**, in
the same transaction as the state change. A text column that says "destroyed"
while every wrap survives is a read-door refusal, not destruction; the first
implementation shipped exactly that.

**Bind requires the CURRENT epoch, not merely an enabled one.** Rotation bumps
the pointer; the sweep that disables the old epoch runs later, in the
background. In that window the old epoch is still `enabled`, so an emission
that read epoch N before a revocation bumped it to N+1 would — under the first
rebuild's predicate — seal under N's DEK and bind to N, and the member just
removed, who keeps N's wrap by AV-70, could read content written AFTER their
removal. Forward secrecy would hold for every write except the one racing the
revocation. The bind is therefore conditional on `epoch = current pointer AND
key_state = 'enabled'`, in one statement; a refused bind is the cascade's cue
that the world moved, so it deletes the ciphertext row it just stored (no
orphan) and re-seals under the new current epoch, bounded to a few attempts.
`disabled` keeps its meaning (no new seals, reads still open) as the sweep's
belt to this predicate's braces.

**The primary cannot be retired by the key-state door.** Disabling or
destroying the current epoch is refused, at the door and in the backend's
conditional UPDATE (`epoch <> current pointer`). Otherwise an empty current
epoch — a failed first emission mints a DEK and stores nothing — could be
destroyed, the pointer would keep naming it, and every later write would fail
in `ensure_epoch_dek` with nothing but an unrelated membership revocation able
to advance it. Rotation retires an epoch; the key-state door only ever acts on
epochs rotation has already left behind.

**One serialization boundary per community.** "Mutually exclusive by
statement" is true on sqlite, where every call holds the one connection
mutex, and was FALSE on postgres: under READ COMMITTED a bind's `EXISTS
(enabled)` and a destroy's `NOT EXISTS (binding)` are non-locking snapshot
reads, so a seal that read *enabled* and a destroy that read *no binding*
can both commit, leaving a blob bound to a destroyed epoch — the exact
interleaving §11.4 claimed impossible. Every operation that reads or moves a
community's epoch state on postgres — bind, key-state change, rotation
(`bump_epoch`), eviction, and the holder announcement of a community blob —
now runs in a transaction that first takes
`pg_advisory_xact_lock(hashtext('community_dek:' ‖ community_key_id))`. The
lock is per community, transaction-scoped, released at commit or rollback,
and cheap; it makes the statement predicates below sufficient rather than
merely necessary. I27 witnesses occupancy: with the lock held from another
session, each of those operations does not complete until it is released.

**Bind and destroy are mutually exclusive by statement.** Binding a blob to an
epoch is a conditional insert that succeeds only while the epoch is current and
`enabled`.
Destroying is a conditional update that succeeds only while zero objects are
bound. Each is one statement, so the interleaving that stranded a freshly
sealed blob on a destroyed epoch cannot occur: one side sees the other's
write, or neither commits. No lock is taken across check-seal-bind because
the check *is* the write.

**The precondition is local, and says so.** "No object is sealed under this
epoch" means **no object on this node**. Persist cannot know what peers hold;
the first implementation's precondition said "evicted from every holder",
which it then satisfied by zeroing a node-local count — a precondition that
cannot be checked is one that gets asserted. Recall of fountained copies is the
tombstone plane's job (§10.6), and destroy does not claim it.

**What destroyed cannot undo.** A recipient who already recovered the DEK
from a delivered wrap holds it. That is AV-70's forward-only guarantee stated
from the other side, and it remains true. `destroyed` means *persist's* copies
of the key material are gone and *persist* will never serve that content
again. It does not mean the ciphertext is unreadable by a party who already
had the key — no key-management scheme can offer that, and the FSD stops
implying it.

### 11.5 Eviction retracts what it announced

Community content is announced (`holds_bytes`). The sweep's eviction therefore
follows the established `evict_actor` discipline: emit `withdraws` for the
local holder attestation, **then** delete. This requires a signer, which is why
the sweep is an **Engine** operation (§11.6) and not a backend one.

**A failed withdraws aborts the eviction.** The first rebuild wrote "deletion
proceeds even if the withdraws fails (an orphan withdraws is better than a
missing one)" and called it fail-honest. Read again, it is the opposite: on
failure there is no withdraws at all, the bytes are deleted anyway, and
`list_holders` advertises this node for content it cannot serve until the
holder TTL expires — the precise defect I9 exists to catch, reintroduced on the
error path. Now a withdraws that cannot be signed or stored propagates, the
bytes stay, and the sweep reports the epoch as blocked; the next run retries.
Retry is safe because announcements this node has already retracted are
skipped (the withdraws this node signed name their targets), so a partial
failure never double-retracts.

**A blob's satellite rows die with it.** `delete_blob` — the floor every
eviction path ends at — removes the epoch binding and the at-rest grants in the
same transaction as the blob row, on both backends. The first rebuild deleted
only the blob row from the pre-existing finite-budget sweeper's path, so an
evicted community blob left its binding behind, the epoch object count stayed
non-zero forever, and that epoch's DEK could never be destroyed even though the
bytes were gone. A count is only a precondition if every deletion maintains it.

**An announcement never stores.** The community arm of the write door seals,
stores and binds in the cascade, then announces `holds_bytes`. The second
rebuild announced through the signing floor, whose row insert is
`ON CONFLICT DO NOTHING`: if a rotation and a retention sweep evicted the
blob between the bind and the announcement, the announcement RE-INSERTED the
ciphertext row — without its binding — and returned success for a row
`read_blob_as` then reported as corrupt. The announcement is now its own
floor operation that emits the holder attestation **only for a row that
exists**, and for a community-tier row only while its binding exists, in one
transaction under the community's serialization boundary. Evicted under the
writer's feet ⇒ the writer is told (`NotHeld`), never handed a success for
bytes that are gone (I28). The other order — announce first, sweep second —
is the ordinary case: the sweep finds the announcement and retracts it.

**Scope of the retraction, stated plainly.** The sweep retracts announcements
this node made **under its own signing key** — the derived federation key its
`LocalSigner` holds, which is what `put_blob_scoped` announces under. An
announcement made under some other attesting key (the FFI's `put_blob_signing`
lets a caller name one, resolved through `select_signer`) is that key's holder's
to retract; this node cannot sign a `withdraws` for it and does not pretend to.
Invariant I9 asserts the own-key case, which is the production shape.

**Eviction is a fact a reader is told; deletion is not (#833).** After a
retention sweep the first v43 shape reported an evicted community blob as
"carries no community-DEK binding" — indistinguishable from a sha that was
never ours, because I19 deletes a blob's satellites with it. The binding was
deleted for a good reason (a binding that outlives its blob held the epoch's
object count above zero and made its DEK undestroyable), and a per-blob
tombstone is unbounded growth, which is what eviction exists to prevent.
The bounded shape: **the sweep's eviction deletes the blob row and its
at-rest grants but KEEPS `federation_community_blob_epoch`, stamping
`evicted_at` (V140, nullable, both dialects)** with the instant the sweep
was given. `community_dek_epoch_object_count` counts only bindings with
`evicted_at IS NULL`, so the destroy precondition and I19 are unchanged —
`delete_blob`, the generic floor, still removes the binding, because only
the sweep is a *policy* action a reader should be told about. The
announcement floor (I28) treats an evicted binding as absent. A second
sweep of the same epoch finds nothing live and evicts nothing, so the
stamp is written once. Cost: one small row per blob that once existed
under a community epoch — bounded by the corpus that was.

The read door then has a third answer for a row-less sha, and its position
in §11.3's order is the guarantee: **after** authorization. A row-less sha
with a binding is authorized exactly as a live community blob would be —
by the viewer's grant on the binding's `(community, epoch)` — **or** by the
viewer being an active occurrence of a member on the community's current
roster (the set the next emission would wrap to). The second leg is
load-bearing, not a convenience: the sweep destroys an epoch in the same
pass that evicts it, and destroy deletes every member-grant row (I5), so
by the time a member asks, the epoch's own grants are gone; a door that
authorized by the epoch grant alone would refuse every member `NotGranted`
and the feature would be reachable only from a test that evicts without
destroying. A viewer that passes neither leg — a stranger, or a removed
member whose old grants the destroy erased — gets `NotGranted`, naming only
the sha and the viewer (I4b holds: the refusal class to a non-grantee does
not disclose the binding, and it is the same class a stranger gets on a
live blob). Only an authorized viewer reaches
`BlobError::Evicted { community_key_id, epoch, evicted_at }`, which names
the epoch's retention as the reason. A row-less sha with a live binding
(`evicted_at` NULL) is the state I19 forbids and is reported as `NotHeld`,
never as evicted; a row-less sha with no binding is `NotHeld` as before —
"never ours" and "swept" are now different answers.

### 11.6 The lifecycle is on every consumer surface

`Engine::community_dek_set_key_state`, `Engine::sweep_community_epochs`,
`Engine::sweep_all_communities` (the shape a scheduler calls), and
`Engine::community_dek_set_retain_past_epochs` — the retention policy the
sweep enforces — with PyO3 bindings. The second rebuild exposed the sweep and
not the policy, so a Python-only deployment could run a sweep that was
structurally unable to evict anything: `retain_past_epochs` defaults to
retain-indefinitely and nothing on the surface could change it. A sweep
report also carries `failed` (epochs whose retraction could not be admitted,
§11.5), and the Python serializer carries every field the report has (I30);
the second rebuild dropped `failed`, so an operator saw a clean report over
retained bytes. The first implementation built the state machine and the sweep with
zero facades and zero bindings — the CHANGELOG advertised "rotate, sweep …
from Rust and from Python" over a lifecycle that was inert outside the test
binary. The same defect this cut had just found three times in older code.

### 11.7 The root never re-mints

`derive_hardware_master_for_context(context, create_seed_if_absent)`. The
secrets store's first migration legitimately creates the seed. The content
path, once a `hardware` row exists, passes `false`: an absent seed is a hard
error naming the consequence. The first implementation claimed this and did
the opposite — the shared derivation sealed a fresh seed on absence, so a lost
keyring directory silently produced a different master, every prior blob and
every sealed content-KEM private half failed to unwrap with an opaque AEAD
error, and new writes succeeded under the new root.

### 11.8 Cost discipline

- The derived content master is resolved **once per process** on the blocking
  pool and cached; the async hot path never performs TPM or filesystem I/O.
- Epoch eviction is one `DELETE … WHERE sha256 IN (SELECT …)` plus one binding
  delete, not one round trip per object, and on SQLite the connection mutex is
  not held across a per-row loop.
- The read door loads the body once.

**The cache remembers only success.** The hardware-master cache stored
whatever the first derivation returned — including `None` from a transient
TPM or filesystem error or a failed join — in a process-wide `OnceLock`, so
one bad moment at boot made the entire encrypted corpus unavailable until
restart. Only a successfully derived key is cached; a failed derivation
returns the error and the next call derives again (I29).

### 11.9 Every backend, every surface, every error

- The cross-backend lifecycle harness covers the sweep — disable, evict-with-
  withdraws, destroy — on sqlite **and** postgres. The first implementation's
  sweep had zero postgres coverage across three backend methods that differ
  materially in implementation.
- Every PyO3 blob binding maps `BlobError` through `blob_err_to_py`, so Python
  keeps the stable `blob_not_granted` / `blob_not_held` tokens it branches on
  and backend failures arrive as `RuntimeError`, not as permanent input errors.

### 11.10 Invariants — each falsifiable through a consumer-held door

| # | invariant | falsified by | catches |
|---|---|---|---|
| I1 | No consumer-reachable write stores an unsealed body at an encrypted cohort. | `Engine::put_blob_scoped("self", …, plaintext)` stores plaintext | A1 |
| I2 | The blob row records its RESOLVED tier; reads dispatch on that column, never on bytes and never on a re-derivation from the scope. | commons body beginning with the magic is refused/misrouted; a private plaintext row is served; an infra community's plaintext row is unreadable | B1, C1, C2-1 |
| I3 | In an encrypted tier the stored body parses as an `AtRestEnvelope`. | magic + garbage accepted | C1 |
| I4 | Every read door authorizes by tier **before** any dispatch, and a refusal names only sha + viewer. | stranger reads a self blob; destroyed-epoch error names the community | B1, B2 |
| I5 | `destroyed` ⇒ zero persist key material for that epoch. | a wrap row survives destroy | D1 |
| I6 | Bind requires `enabled`; destroy requires zero bound; both atomic. | a blob bound to a destroyed epoch | D3 |
| I7 | The precondition destroy checks is the precondition destroy states. | doc says "every holder", code counts local | D2 |
| I8 | Rotate/sweep/key-state are reachable from Engine and FFI. | 0 facades | A2 |
| I9 | Eviction of announced content emits `withdraws` before delete. | `list_holders` still names this node after eviction | G1 |
| I10 | The tier of a community blob is resolved from the directory, including the infra carve-out. | authorized infra community cannot store by any route | E1 |
| I11 | A hardware root never re-mints. | absent seed ⇒ new master | F1 |
| I12 | The lifecycle harness, sweep included, runs on every backend from one function. | a sqlite-only sweep test | H1 |
| I13 | FFI preserves `BlobError` class. | `NotGranted` arrives as `ValueError` | I1 |
| I14 | `store_blob_local` is reached only by the two cascades, or with a literal commons scope. | a floor call carrying a variable scope | A3 |
| I15 | An authorized infrastructure community's write resolves `Plaintext`, stores that tier, and reads back through `read_blob_as`. | write succeeds, read reports "no binding" | C2-1 |
| I16 | V139 classifies pre-existing rows from their grants and bindings; a pre-V139 self/family/community ciphertext row is NOT served as commons after upgrade. | upgraded node serves envelope bytes to a stranger | C2-4 |
| I17 | Bind requires the CURRENT epoch; a bind against a rotated-past `enabled` epoch is refused, and the cascade re-seals under the current epoch leaving no orphan row. | post-revocation content sealed under the old DEK | C2-2 |
| I18 | A withdraws failure aborts the eviction: bytes intact, error propagated, already-retracted announcements skipped on retry. | bytes gone, `list_holders` still names this node | C2-3 |
| I19 | `delete_blob` removes the epoch binding and the at-rest grants transactionally; a deleted blob cannot hold an epoch's object count above zero. | destroy blocked forever by a binding whose blob is gone | C2-9 |
| I20 | The current epoch cannot be disabled or destroyed through the key-state door. | pointer names a destroyed epoch; every write fails | C2-8 |
| I21 | The matcher screens the plaintext, once, before sealing, on every tier. | matcher sees ciphertext; self/family never screened | C2-6 |
| I22 | The storage floor is unconstructible outside the crate (`compile_fail`). | external Rust caller stores plaintext at `self` | C2-7 |
| I23 | The write door derives the attesting key id from its signer; no surface passes an alias. | Python announces under the scrub alias; sweep cannot retract | C2-5 |
| I24 | The row records the cohort the write NAMED; an `affiliations` write is not collapsed to `community`. | `blob_cohort_scope` reports `community` for an affiliations write | U4 |
| I25 | The floor refuses a self-contradicting row: `self`/`family` at `plaintext`, commons at a sealed tier. | a token-holding in-crate caller records a private plaintext row | — |
| I26 | Every backend resolves a hardware content master through the process cache; the uncached resolver has no backend caller. | the cache has zero callers; TPM I/O per read | U2 |
| I27 | On postgres, bind / key-state / rotation / eviction / community announcement each take the community's transaction lock: none completes while another session holds it. | a blob bound to a destroyed epoch under READ COMMITTED | C3-1 |
| I28 | The community announcement emits only for an existing, bound row; evicted between bind and announce ⇒ `NotHeld`, no row re-inserted. | a bindingless ciphertext row after a raced sweep | C3-2 |
| I29 | The hardware-master cache stores only a successful derivation; a transient failure is retried on the next call. | one failed derivation at boot ⇒ corpus unavailable until restart | C3-3 |
| I30 | The retention policy is settable from the Engine and Python, and the Python sweep report carries every `SweepReport` field. | a Python sweep that can never evict; `failed` dropped | C3-4, C3-5 |
| I31 | The retention sweep keeps the epoch binding and stamps `evicted_at`; the object count ignores evicted bindings; an authorized viewer (epoch grantee or current roster occurrence) reading an evicted sha — through the whole-blob door, the range door, or as a DAG's covering chunk — gets `Evicted{community, epoch, evicted_at}`, a stranger gets `NotGranted`, an unknown sha gets `NotHeld`, and destroy after the sweep still succeeds. | a member's read after a sweep is `NotHeld` ("never ours"); a stranger's read names the epoch; an evicted binding blocks destroy | #833 |
| I32 | Every seal door checks the chunk ROWS: a `chunk_dag` row is written only over chunks whose recorded `crypto_tier` (and, for a community, whose epoch binding's community) is the DAG's own; the commons `seal_stream` refuses a sealed chunk row and the scoped seal refuses a plaintext one. | a public manifest over community-sealed chunks; a "sealed" manifest over a plaintext chunk | #832 |
| I33 | A sealed DAG's manifest row is content-addressed by its CIPHERTEXT, recorded at the DAG's tier, and the storage layer (`get_blob`, `get_blob_range`) hands out only its opaque bytes; the read door refuses a stranger before touching manifest or chunk. | `get_blob` parses (or fails to parse) a sealed manifest; a stranger reads a chunk or the manifest | #832 |
| I34 | The decrypting range read authorizes at the manifest before dispatch, maps a PLAINTEXT range to the covering chunk set, opens each chunk independently, and returns exactly `[start, end]` of the plaintext; `start ≥ total` is `RangeNotSatisfiable` naming the plaintext size. | a ciphertext substring; an off-by-one at a chunk boundary; bytes for a non-grantee | #832 |
| I35 | The whole read of a DAG (`read_any_for_viewer`) returns the concatenated content when `total_size ≤ DAG_WHOLE_READ_CAP_BYTES` and refuses above it with `InvalidArgument` naming the cap and the range door; a commons DAG reads the same way. | a `chunk_dag` row refused to every reader; an unbounded allocation | #832 |
| I36 | The transfer path never decrypts: every `serve_blob*` Engine facade and both backends' `get_blob_range` contain no `open(`, `unwrap_dek`, `read_any` or `read_for_viewer` call (from-disk gate). | a relay that hands plaintext to a peer | #832, #821 |
| I37 | `stream_chunks(stream_id)` lists a LIVE stream's chunks in `seq` order with each chunk's sha, recorded tier and plaintext size before any seal, together with the latest STH's `tree_size`, read in one transaction. | DVR/catch-up has no handle on an unsealed stream; a listing that disagrees with the STH it reports | #832 |
| I38 | A chunk keeps the epoch it was sealed under: after a rotation the reader recovers each chunk's DEK from the CHUNK's own binding, and a viewer holding no grant on that chunk's epoch is refused `NotGranted` (AV-70 per chunk). | the manifest's epoch used for every chunk; a post-rotation joiner reads pre-join segments | #832 |
| I39 | Every seal/open call site this cut adds carries `aad: Option<&[u8]>` down to `seal` / `open`, and until CIRISVerify#279 lands those two IGNORE it — pinned by a test, so #831 is a flip of two lines and not a hunt for surfaces. | a new door without the parameter; `seal` silently binding AAD before the primitive exists | #832, #831 |
| I40 | Caller-supplied associated data is bound into the seal and never stored: a seal under `A` opens under `A` and fails under `A'` — after authorization (a non-member presenting `A` is `NotGranted`), as a crypto-class error, at both encrypted tiers; `Some(aad)` at a plaintext tier is refused at EVERY seal/open door — whole-blob, chunk write, stream seal, range read. | the `A'` open succeeds; a mismatch surfaces as `NotGranted`; a commons write accepts and drops the data | #830 |

Every one of these is written **before** the corresponding fix and confirmed
red — I1–I14 on `fd43e74`, I15–I23 on `30fde79` — and each turns red again
under mutation of the logic it guards. I24–I26 (the ultrareview's nits and
the floor's self-contradiction refusal) were written alongside their fixes,
so their evidence is the mutation alone: each turns red when its guard is
removed, and that is stated here rather than implied. Two honest exceptions, recorded
rather than hidden: I18(a) (no double retraction) is held by the directory's
retraction fold at write (#502 E7), so a second filter in the evict loop was
mutation-tested, found to guard nothing, and removed; and the key-state
door's "current epoch" check (I20) is a friendlier message in front of the
backend statement that is the real guard — removing the message alone leaves
I20 green, removing the statement's predicate turns it red. I22 is a
`compile_fail` doctest, which `cargo nextest` never runs; it has its own
certify gate and CI step so the witness executes. On postgres the community
announcement (I28) refuses an evicted row at two points — the binding lookup
that names the community to lock, and the existence check under that lock —
and each alone refuses the evicted case, so removing either survives; the
pair removed together turns I28 red, which is the evidence recorded. I40 (#831)
was written before the binding existed and confirmed red on the re-pinned
tree with `aad` threaded through every seal and open but unused — the
self-tier `A'` open returned Alice's plaintext; it reds again when either
twin drops the data (the seal, or the open), when the community cascade stops
passing it, and when the plaintext-tier refusal is removed at either door. A test that is green on
the code it was written to catch is a report.

**I31 (#833)** was written first and confirmed red on v43.0.0 (`170cc89`),
failing at its first structural assertion: the sweep deleted the binding.
Mutation evidence, every restore `cmp`-verified: removing `evicted_at IS
NULL` from the object count turns I31, I5 and I6 red (sqlite) and I31 and
I5 red (postgres); removing it from the destroy statement's own `NOT
EXISTS` predicate turns I31, I5, I6 and I9 red (sqlite) and I31 and I5 red
(postgres) — that third site was found by the EXISTING witnesses when the
first two were changed alone, which is what they are for; making the sweep
delete the binding instead of stamping it turns I31 red on both backends;
removing the read door's authorization hands a stranger `Evicted` naming the
community and epoch (I31 red); removing the roster leg refuses a current
member `NotGranted` after the production sweep (I31 red); removing the grant
leg refuses a removed member who still holds the epoch grant (I31 red). Two
edits survive and are recorded rather than dressed up as guards: the
`evicted_at IS NULL` filter on the sweep's object SELECT (the UPDATE's own
predicate is the guard; the filter only spares the retraction scan) and the
same filter on the announcement's binding check (the row-existence check
refuses an evicted sha alone; the filter is belt to those braces). A
row-less sha with a LIVE binding — the `None => NotHeld` arm — is the state
I19 forbids and cannot be constructed through a door, so that arm is
untested and said so here.

**C2 = the second Codex review (2026-09-09, of `30fde79`).** Nine findings,
all verified real, six root causes: the row stored the tier's INPUT not the
tier (C2-1, C2-4); "enabled" was not "current" (C2-2, C2-8); the error path
of eviction undid what the happy path guaranteed (C2-3, C2-9); a screen ran on
the wrong bytes (C2-6); an in-crate text gate was mistaken for an API boundary
(C2-7); and a parameter with one correct value was left as a parameter (C2-5).
The common thread with §11's own diagnosis of `fd43e74`: each was a guarantee
established at one site and not carried to the next — into the row, across the
race window, down the error path, past the crate boundary.

**U = the cloud ultrareview of `30fde79`**, five findings. U1 is C2-1 (the
infra read). U2: the §11.8 hardware-master cache existed with zero callers —
the perf fix its docstring described was never applied; both backends now
resolve through it, and I26 reds if either stops. U3: the Python
`store_blob_local_json` still documented itself as the self/family privacy
primitive while writing a commons plaintext row that `read_blob_as` serves
to anyone; its contract now says what it is — unannounced is not private —
and points private content at `put_blob_scoped`. U4: the community cascade
hard-coded `community` on the row for an `affiliations` write (I24). U5: the
V139 sqlite header claimed the final-name rebuild shape while the DDL used
`__v139` + RENAME; the header now says that shape is safe for THIS table and
why it is not a template.

**I32–I39 (#832)** are the chunked-content rows (§12). Two of them were
confirmed RED on `170cc89` (v43.0.0) through doors that already existed: the
commons half of I32 (`seal_stream` wrote a plaintext manifest over a chunk row
the community cascade had sealed) and the commons half of I35
(`read_any_for_viewer` refused every `chunk_dag` row). The rest exercise doors
this cut adds, so their evidence is the mutation alone, recorded in §12.8.

**C3 = Codex's third review, of `45bd9b4`**, five findings, all real. Two
are the same root cause — a serialization boundary that existed on sqlite by
accident of its single connection mutex and did not exist on postgres at
all: the bind/destroy race under READ COMMITTED (C3-1) and the
announce-after-cascade window that could re-insert an evicted row (C3-2).
One is a cache that remembered failure (C3-3). Two are the same shape as
§11.6's own finding about the first implementation — a surface that
exposes the operation and not its policy or its report (C3-4, C3-5).

---

## 12. Chunked content under the envelope — LOCKED 2026-09-09 (#832)

§10 sealed a **whole body** under one envelope; `FSD/V4_1_STREAMING_SUBSTRATE.md`
made a body **many rows** — chunks under a `chunk_dag` manifest, appended live
by `put_blob_chunk`, frozen by `seal_stream`, served by `get_blob_range`. The
two documents never crossed, and the seam showed at the write door:
`body_is_sealed(ChunkDag)` answered *Unverifiable* because the door saw only
the manifest, and in an encrypted cohort cannot-verify is a refusal. Correct
for that door, and it meant **community-scope video was unwritable** —
chunking is what makes seek and range possible, and chunking is exactly what
the encrypted door refused. On the read side `get_blob_range` over a sealed
whole blob returned a ciphertext substring, which is not a plaintext range.

This section is the crossing. Everything in §11 stands; §12 states how a DAG
lives under the same tier column, the same doors, the same read order.

### 12.1 The shape — each chunk is a whole blob

**A chunk is sealed exactly as a whole blob is.** Each chunk is its own
`AtRestEnvelope` (`CRBLOB` magic ‖ 12-byte nonce ‖ AES-256-GCM ciphertext+tag),
a fresh random nonce per chunk, and its `federation_blobs` row is
content-addressed by the SHA-256 of its **ciphertext**. Consequences, each
deliberate:

- **Transfer, dedup and the swarm's hash verifier are unchanged.** A relay
  fetches `(manifest_sha, chunk_sha)`, verifies the chunk's sha over the bytes
  it received, and stores what it cannot read. Chunks ship as opaque bytes
  exactly like whole blobs (§10.6, the transfer model).
- **Every chunk row records its tier.** The chunk write goes through the
  storage floor with a `StorageFloor` token, so `cohort_scope` and
  `crypto_tier` are written on the chunk row by the door that resolved them
  (§11.1). That is what makes "is this DAG sealed?" **verifiable**: the seal
  door asks the chunk ROWS, not the manifest's word (§12.3).
- **The CEG §10.5.2 STREAM nonce is not used here.** `stream_seal.rs` (Cut C2,
  the `prefix[7] ‖ counter_be[4] ‖ last_flag[1]` layout) remains the
  consumer-side/interop format it was. The substrate's own seal is the
  `CRBLOB` envelope with a random nonce because the epoch DEK is **shared by
  every writer in the community** — a counter nonce is only safe with one
  writer per `(key, prefix)`, and persist does not police writer count; a
  96-bit random nonce at the `MAX_CHUNKS_PER_EPOCH = 2²⁴` cap has a collision
  bound of ~2⁻⁴⁹ per epoch. One format for whole blobs and chunks also means
  one `open`, one `AtRestEnvelope::from_bytes`, one overhead constant.

### 12.2 The manifest — plaintext sizes, sealed under the same DEK

The manifest lists the **ciphertext chunk shas** alongside **PLAINTEXT
sizes**, so a plaintext byte range maps to a chunk set by prefix sum. It is a
`ChunkManifest` at schema version **2**:

```json
{"chunk_tier":"community_dek","chunks":[{"sha":"<hex32 of CIPHERTEXT>","size":<plaintext u32>},…],"total_size":<plaintext u64>,"v":2}
```

- `v: 2` and `chunk_tier` appear **only for a sealed DAG**. A plaintext DAG —
  the commons `seal_stream`, `put_blob_chunks`, or the scoped seal resolving
  `Plaintext` — keeps emitting `v: 1` byte-for-byte as before, so every
  build-manifest and commons-video address a consumer already holds is
  unchanged.
- **This is the MAJOR for manifest consumers.** A parser that rejects an
  unknown `v` or an unknown key breaks on a v2 manifest; a consumer that
  checks `sum(size) == Σ chunk row size_bytes` breaks, because a sealed
  chunk's stored length is `size + 36`. `chunk_tier` is self-description for
  the party that has opened the manifest; the door and the reader dispatch on
  the ROW's `crypto_tier` column, never on it (I2).
- **The manifest bytes are sealed under the same DEK as the chunks**, as an
  inline `AtRestEnvelope`. The `chunk_dag` row therefore carries
  `crypto_tier` like any other row (V139), is content-addressed by the sha of
  the sealed manifest bytes, and its `size_bytes` is the **stored** (envelope)
  length — the number `get_blob_range` bounds on — not the plaintext total,
  which lives inside the manifest. For a v1 plaintext DAG `size_bytes` stays
  `total_size`, as Cut B specified.
- **At the storage layer a sealed manifest is opaque.** `get_blob` on a
  `chunk_dag` row whose tier column is not `plaintext` returns
  `BlobBody::Inline(envelope_bytes)` — a relay receives bytes it can forward
  and cannot parse; `get_blob_range` serves a substring of those bytes, the
  storage contract it has always had. Neither reads the tier from the bytes:
  the dispatch is `(storage_kind, crypto_tier)`, both columns (I33).

### 12.3 The write doors — and the seal door checks the rows

Two doors, both free functions in `chunk_dag_cascade::orchestrate` shared by
the Engine and the PyO3 surface, both resolving the tier from the DIRECTORY
(`resolve_write_tier`, §11.2 (2)) and never from the caller:

**`put_blob_chunk_scoped(cohort_scope, community_key_id, stream_id, seq,
plaintext, epoch, media_type, aad)`** — screens the plaintext with the
matcher once (I21), then per tier:

| tier | what happens |
|---|---|
| `Plaintext` (commons, or an authorized infra community) | the bytes as given, through the chunk floor with a `Plaintext` token; `cohort_scope` recorded |
| `InvisibleEncrypted` (`self` / `family`) | a **fresh per-chunk DEK**, `seal`, the envelope through the chunk floor, then persist's self-retention wrap and a v2 wrap to every active occurrence — the same grant rows a whole blob gets, keyed on the chunk's ciphertext sha |
| `CommunityDek` | `ensure_epoch_dek` at the CURRENT epoch (idempotent past the first chunk), `seal`, the envelope through the chunk floor **with the epoch binding in the same transaction** — bind-if-still-current (I17), so a rotation racing the append refuses the whole append and the door re-seals under the new epoch; nothing is left behind, not even an index row |

`epoch` is the producer's stream epoch label (the nonce-cap axis, V062) and is
recorded on the index row as given; **which DEK sealed a community chunk is
the chunk row's epoch binding**, a separate fact in a separate table. Two
axes, two columns — the label is never read back as a key.

**`seal_stream_scoped(signer, cohort_scope, community_key_id, stream_id,
media_type, aad)`** — resolves the tier, lists the stream's rows through
`stream_chunks`, and **refuses unless every chunk row's recorded tier is the
DAG's tier** (and, for a community, every chunk's binding names the community
being sealed). Only then does it build the manifest (v2 with plaintext sizes,
or v1 for `Plaintext`), seal it under the DAG's DEK, and store the `chunk_dag`
row through the manifest floor — with the epoch binding in-transaction for a
community, with the self-retention and occurrence grants for `self`/`family`.
The floor additionally refuses if the stream's chunk count changed between
the listing and the write (a seal over a moving stream is refused, not
truncated). A `Plaintext` or `CommunityDek` seal announces `holds_bytes` for
the manifest sha under the signer's derived key, as `put_blob_scoped` does;
`InvisibleEncrypted` announces nothing.

**The commons `seal_stream` is a seal door too**, and I32 binds it: it now
refuses a stream any of whose chunk rows is not at `plaintext`. Before #832 it
wrote a public manifest over community-sealed rows the community cascade had
stored (staged through `put_blob_chunk`'s `ON CONFLICT DO NOTHING`), which is
the exact "self-contradicting DAG" the row-check exists to make unrepresentable.

**The floor.** `put_blob_chunk_with_scope` and `seal_stream_with_scope` are
storage-floor methods on `BlobStorage`: each takes a `StorageFloor` token, so
they are unconstructible outside the crate (I22) and I14's from-disk gate
lists them beside `store_blob_local` with `chunk_dag_cascade.rs` as the only
permitted caller. The commons `put_blob_chunk` is the trait's own commons
wrapper over the chunk floor with `cohort_scope::FEDERATION` as a literal. Each
floor also refuses a self-contradicting row (I25): a sealed-tier token whose
body does not parse as an envelope, or whose declared plaintext size is not
`stored − 36`; a plaintext token whose declared size is not the body length.

### 12.4 Reads — one door, authorize first, then per chunk

**`read_any_for_viewer(sha, viewer, aad)`** keeps §11.3's order and gains the
DAG arm: after the row-tier authorization it reads the row HEAD (`storage_kind`,
`crypto_tier`, `size_bytes`); for a `chunk_dag` it opens the manifest (sealed
tiers) or parses it (plaintext), and returns the **concatenated content** when
`total_size ≤ DAG_WHOLE_READ_CAP_BYTES` (64 MiB). Above the cap it refuses
with `InvalidArgument` naming the total, the cap and the range door — a video
is read by range, never materialized whole by a facade a server calls in a
request handler. The cap is a judgement recorded here: 64 chunks at the 1 MiB
inline cap is the largest allocation the whole-read door will ever make.

**`read_any_range_for_viewer(sha, viewer, start, end_inclusive, aad)`** is the
door beside it — the decrypting range read the issue asked for. Order:

1. row head; absent ⇒ `NotHeld`;
2. **authorize by the row's tier, before touching any body** (§11.3, I4);
3. bounds against the PLAINTEXT total: `start > end` ⇒ `InvalidArgument`,
   `start ≥ total` ⇒ `RangeNotSatisfiable { range_start, size: total }`, `end`
   clamped to `total − 1`;
4. dispatch on `(storage_kind, crypto_tier)`: a plaintext inline row or DAG is
   `get_blob_range`; a sealed inline row is opened whole and sliced (a whole
   blob has no seek — that is what a DAG is for); a sealed DAG maps the range
   to the covering chunk set by prefix sum and opens **only those chunks**, so
   seek is O(segment);
5. for each chunk it reads, the reader checks the CHUNK ROW: its recorded tier
   must be the DAG's, its sha is re-verified over the stored bytes (CEG
   §10.1.1), the DEK is recovered from the **chunk's own** binding (community)
   or self-retention grant (`self`/`family`), and the opened length must equal
   the manifest's size for that chunk.

**Authorization is per epoch, not per manifest alone (I38).** A stream that
crossed a rotation has chunks bound to epoch N and epoch N+1. The manifest
binds to the epoch current at seal. A member who joined at N+1 holds a grant on
the manifest and none on N; under AV-70's ratified forward-only rule they
cannot read what was sealed before they arrived, and the read door says so —
`NotGranted`, naming only sha and viewer — for a range that touches an
epoch-N chunk. The check is memoized per `(community, epoch)` within one call,
so it costs one grant lookup per distinct epoch in the range, not one per
chunk. `self`/`family` chunks are authorized by the viewer's grant on each
chunk row, which `rekey_for_newcomers` keeps aligned with the manifest's
because it walks every blob a cohort holds grants on — chunk rows included,
which is the correctness argument for per-chunk grants over a stream-level DEK.

**The transfer path never decrypts (I36).** `serve_blob_to_peer`, the ranged
serve #821 adds beside it, and both backends' `get_blob_range` contain no
`open(` / `unwrap_dek` / `read_any` / `read_for_viewer` call — a from-disk gate
in `blob_surface_gates.rs`, so a decrypt cannot be added to the relay path
without turning a test red.

### 12.5 `stream_chunks` — the handle a live stream has (#832 Q3, Q4)

A blob is addressable only once immutable, because the address IS the content;
that rule does not move. A growing stream is addressed by
`(stream_id, tree_size)` on the STH plane, and each chunk by its own sha from
the moment `put_blob_chunk*` returns. What was missing was the join:

**`stream_chunks(stream_id) → StreamChunks { chunks: [(seq, chunk_sha,
epoch, size_bytes, plaintext_size, crypto_tier, cohort_scope)], sth_tree_size }`**
— the stream's chunks so far in `seq` order, each with the tier its row
records and its plaintext size, plus the latest producer-signed STH's
`tree_size`, read in ONE transaction so the listing and the STH it reports are
the same snapshot. A DVR consumer reads the prefix `[0, tree_size)` as
tamper-evident and the tail as best-effort; it then fetches each chunk by sha
(`read_any_range_for_viewer` on a chunk sha, or the relay's `get_blob_range`
for opaque transfer). Reachable from the Engine and from Python (I8).

**Handoff (Q4): stream into persist as produced.** `put_blob_chunk_scoped`
each segment as it is finalized — sealed at write under the epoch DEK the
first chunk already needed — `put_stream_sth` as the tree grows,
`seal_stream_scoped` at the end. Chunk rows are immutable and content-
addressed, so persist is a correct place to buffer and there is no re-encode
at seal: the seal writes a manifest over rows that already exist.

### 12.6 Schema — V142

`federation_stream_chunks.plaintext_size_bytes` (both dialects, `NOT NULL`,
backfilled `= size_bytes` for every pre-V142 row, which were all plaintext).
`size_bytes` keeps meaning the stored length; the manifest and `stream_chunks`
report the plaintext length from this column, never from `stored − 36`
arithmetic at read time (every preimage field is persisted). The chunk row's
tier and cohort live on `federation_blobs` (V139) — one fact, one table.

### 12.7 AAD per chunk lands with #831 — the hook points

#831 (blocked on CIRISVerify#279, `aes_gcm::{encrypt_aad, decrypt_aad}`) binds
a ciphertext to its referencing row through the GCM tag. For a DAG the binding
the issue named is `(manifest sha, index)` per chunk, so a chunk lifted into
another DAG does not open. This cut does **not** implement AAD — crypto routes
through `ciris_crypto`, and the primitive is not there yet — but it threads the
parameter through every new surface so #831 is a flip, not a hunt:

| hook | today |
|---|---|
| `at_rest_cascade::seal(dek, plaintext, aad)` / `open(dek, envelope, aad)` | `aad` accepted and **ignored** — `// #831` — pinned by a test that `seal(Some(A))` opens under `None` and under `A'` |
| `chunk_dag_cascade::orchestrate::put_blob_chunk_scoped(…, aad)` | passed to `seal` |
| `chunk_dag_cascade::orchestrate::seal_stream_scoped(…, aad)` | passed to `seal` for the manifest |
| `at_rest_cascade::orchestrate::read_any_for_viewer(…, aad)` and `read_any_range_for_viewer(…, aad)` | passed to `open` for the manifest and every chunk |
| `Engine::{put_blob_chunk_scoped, seal_stream_scoped, read_blob_as, read_blob_range_as}` | `aad: Option<&[u8]>` |
| `PyEngine.{put_blob_chunk_scoped, seal_stream_scoped, read_blob_as, read_blob_range_as}` | `aad_b64=None` |

What #831 will do at those points: `seal`/`open` call the `_aad` primitives;
`put_blob_scoped` and the whole-blob community cascade gain the parameter they
do not carry today (their `None` sites are marked `// #831`); and a refusal
of `Some(aad)` at a plaintext tier lands at the doors. Per-chunk AAD derived
from `(manifest sha, index)` cannot be computed at chunk-write time — the
manifest sha does not exist until seal — so #831's chunk binding is
`(stream_id, seq)` at write with the manifest committing to both, or a re-seal
at seal time; that decision is #831's and is not pre-empted here.

### 12.8 What this cut does not do

- No `External` chunks under an encrypted tier (the floor cannot see the
  bytes; §10.8's cannot-verify-is-a-refusal stands for them).
- No nested DAGs (Cut B's one-level rule).
- No stream-level DEK for `self`/`family`: per-chunk fresh DEKs cost
  O(chunks × occurrences) grant rows and buy per-blob semantics that every
  existing grant walker (`rekey_for_newcomers`, `list_at_rest_blobs_for_recipients`,
  `delete_blob`'s satellite removal) already gets right. Recorded as the
  judgement; a stream DEK keyed off the manifest is a later optimization that
  must not change any door.
- `put_blob_chunks` (Cut B's atomic multi-row upload) stays commons-only; the
  encrypted path is the live-append one, which is what video needs.

**Mutation record (§11.10 discipline).** Fourteen mutations, each applied,
the named witnesses run, the file restored from the committed baseline; all
fourteen KILLED. Three needed a second pass, and each of the three was the
class §11.10 warns about — the right outcome through a neighbouring gate:
the dropped chunk-row tier check (I32) was caught by the cohort check because
the witness's plaintext chunk was a commons row; the dropped range-read
authorization (I34) was masked by the community open's defense-in-depth
re-check and by the per-chunk grant; the dropped per-chunk grant check (I34b)
was masked by the manifest authorization. The witnesses now stage a plaintext
row at the SAME cohort, read a sealed self WHOLE blob by range as a stranger,
and read as an occurrence granted on the manifest but not on the chunk row.
The full table is in the CHANGELOG entry for this cut. (The `seal_ignores_aad_until_831` pin was deleted when #831 landed in the same release; I40
is the pin for I39's other half: it turns red the day #831 flips `seal` /
`open`.

---

## 13. Summary

CIRISPersist can encrypt the *content* of every substrate at rest —
persist-managed, hardware-rooted, 100% backend-agnostic — while keeping
a plaintext, signed, queryable projection. This is uniquely possible for
CIRIS data because the query set is closed (the projection is knowably
complete), the federation scores derived signals rather than content
(the privacy boundary *is* the queryability boundary), every record is
agent-signed (the projection is plaintext-but-unforgeable), and the
scrubber already located the content/signal seam. The capability is a
federation that measures reasoning quality without reading reasoning
content. V042-final (real shredded columns) is the precondition. The
hard parts — audit-leaf canonical ordering, `trace_llm_calls` lacking a
local signature, per-row KDF throughput, `tickets.email` — are named,
not hidden, and the substrates that do not fit the cleavage are
classified exempt, honestly.

---

**§10 (added 2026-09-09)** locks the blob half: the cohort-keyed DEK
cascade, its real HKDF root, Tink keyset semantics with a destroy state,
and the AV-70 amendment that a destroyed epoch's content must be
re-sealed or evicted first. §3's boundary map for the other substrates
is unchanged, and the attestation question stays open as JC-10.

**§12 (added 2026-09-09, #832)** crosses the envelope with the streaming
substrate: a chunk is a whole blob (its own `CRBLOB` envelope, addressed by
ciphertext), the manifest carries plaintext sizes and is sealed under the same
DEK, the seal door checks chunk ROWS, the range read decrypts per chunk with
per-epoch authorization, the transfer path never decrypts, and `stream_chunks`
is the live-stream handle. AAD per chunk waits on #831.

