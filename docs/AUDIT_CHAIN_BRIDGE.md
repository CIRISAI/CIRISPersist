# Audit Chain Bridge + Identity Registration (v1.3.0+)

Companion doc for CIRISAgent 2.9.0's audit cutover (Lane A → A0b →
A3) and Lane C (federation-verify + steward signing). Covers two
operational questions the agent's adoption code needs answered:

1. **Bridge-entry mechanism** — how to start persist's `cirisaudit`
   chain on top of an existing chain (Sigstore-signed, hand-rolled,
   or otherwise).
2. **`tenant_id` + `signing_key_id` registration** — what values to
   use, where to register the agent's Ed25519 key.

Out of scope: the wire shape itself — see `src/audit/types.rs`
(`AuditEntry`) and `src/federation/types.rs` (`KeyRecord`) for the
canonical types.

## 1. Chain bridge — root the new chain off an existing one

### Concept

Persist's `cirisaudit` chain is per-tenant. Each tenant has its own
monotonic `sequence_number` starting at 1, with `prev_hash` linking
each entry to the previous. The genesis entry (`sequence_number = 1`)
normally has `prev_hash = GENESIS_PREV_HASH` (32 zero bytes).

To **bridge to an existing chain** (e.g., the agent's
pre-2.9.0 audit log signed by a different scheme), the first
`cirisaudit` entry carries:

- `sequence_number = 1`
- `prev_hash = sha256(canonical-bytes-of-legacy-chain-root-marker)`
- `payload` includes the legacy chain's terminal state for forensic
  continuity

The verifier (`AuditService::verify_chain`) flags the genesis row
with `ChainBreakReason::GenesisPrevHashNotZero` — this is **a feature,
not a bug**: it signals "this chain bridges to an upstream chain"
rather than "this is a fresh genesis." Downstream consumers reading
the verification outcome can distinguish a clean genesis (legitimate
new deployment) from a bridge (cutover from prior chain).

### Canonical-bytes rule (reminder)

Every audit entry's `entry_hash` covers the canonical JSON of the
entry **minus the `signature` and `entry_hash` fields**. The
`signature` then covers the canonical bytes **including** the
resolved `entry_hash`. Same shape as the `cirisnode` envelopes
(`src/cirisnode/verify.rs`); the reference implementation is
`compute_entry_hash` in `src/audit/verify.rs`.

In short:

```
canonical_bytes_for_hash = canonical_json(entry minus signature minus entry_hash)
entry_hash = sha256(canonical_bytes_for_hash)
canonical_bytes_for_sign = canonical_json(entry minus signature, WITH entry_hash filled in)
signature = Ed25519(signing_key, canonical_bytes_for_sign)
```

**Canonicalizer:** `PythonJsonDumpsCanonicalizer` — sorted keys, no
whitespace, `ensure_ascii=True`. The exact byte sequence is defined
by persist; **don't reimplement the rule in caller-language**.

### Caller workflow (v1.5.4+)

Persist exposes the two canonicalization phases as PyO3 methods so
callers can plug their own signer (TPM-backed via CIRISVerify, KMS,
HSM, etc.) without reimplementing the canonical-bytes rule:

```python
# Step 1: build the entry with entry_hash="" and signature=""
entry = {
    "entry_id": str(uuid.uuid4()),
    "sequence_number": 1,
    "tenant_id": "...",
    "actor_id": "<base64 Ed25519 pubkey>",
    "action_type": "chain_bridge",
    "subject_kind": "audit_chain",
    "subject_id": "...",
    "payload": {...},
    "prev_hash": "<base64 32 bytes>",
    "entry_hash": "",
    "recorded_at": "...",
    "signature": "",
}

# Step 2: get canonical bytes for the hash phase, compute entry_hash
ch = engine.audit_canonicalize_for_hash(json.dumps(entry))
entry["entry_hash"] = base64.b64encode(hashlib.sha256(ch).digest()).decode()

# Step 3: get canonical bytes for the signing phase, sign externally
cs = engine.audit_canonicalize_for_signing(json.dumps(entry))
sig_bytes = your_signer.sign_ed25519(cs)   # CIRISVerify TPM signer, etc.
entry["signature"] = base64.b64encode(sig_bytes).decode()

# Step 4: submit — persist re-derives entry_hash + verifies signature
engine.audit_record_entry(json.dumps(entry))
```

Stripping rule (locked, audited):
- `audit_canonicalize_for_hash` strips **both** `entry_hash` AND
  `signature` from the top-level JSON object, then canonicalizes.
- `audit_canonicalize_for_signing` strips **only** `signature` —
  `entry_hash` participates in the signed body (binds the signature
  to the chain position).

Persist owns the rule; callers stay in their language.

### Bridge entry shape

```json
{
  "entry_id": "<uuid-v4>",
  "sequence_number": 1,
  "tenant_id": "<see §2.1 below>",
  "actor_id": "<base64 Ed25519 pubkey of the agent's steward key>",
  "action_type": "chain_bridge",
  "subject_kind": "audit_chain",
  "subject_id": "<legacy chain identifier — agent's choice; commonly the legacy DB filename or chain UUID>",
  "payload": {
    "legacy_chain_root_hash": "<hex-or-b64 of the legacy chain's terminal entry hash>",
    "legacy_chain_root_id": "<id of the legacy chain's terminal entry>",
    "legacy_chain_scheme": "sigstore_rekor_v1",
    "legacy_chain_attestation": "<inline attestation or pointer to archived DB>",
    "bridge_reason": "ciris_agent_2_9_0_cutover",
    "archived_at": "<RFC 3339 timestamp when the legacy chain was archived>"
  },
  "prev_hash": "<base64 of sha256(canonical_bytes_of_payload.legacy_chain_root_hash + legacy_chain_root_id)>",
  "entry_hash": "<base64 of sha256(canonical entry minus signature minus entry_hash)>",
  "recorded_at": "<RFC 3339, agent's cutover wall-clock>",
  "signature": "<base64 Ed25519 over canonical_bytes_for_sign>"
}
```

### Bridge `prev_hash` semantic

The `prev_hash` value on a bridge entry is **caller-defined** —
persist doesn't validate it against any external source. The
convention is to derive it deterministically from the legacy chain's
terminal state (so the bridge can be re-verified independently):

```python
legacy_marker = canonical_json({
    "legacy_chain_root_hash": "<...>",
    "legacy_chain_root_id": "<...>",
})
prev_hash = sha256(legacy_marker.encode())  # 32 bytes
```

This makes the bridge entry's `prev_hash` a stable function of the
legacy chain's terminal state — anyone with the legacy DB archive
can recompute and verify.

### `action_type` vocabulary

`"chain_bridge"` is not in CIRISAgent's `AuditEventType` enum yet
(`ciris_engine/schemas/audit/core.py`). Adding it requires:

- Agent-side: append `CHAIN_BRIDGE = "chain_bridge"` to the enum.
- Persist-side: the existing V018 CHECK constraint on
  `cirislens.audit_log.action_type` needs `chain_bridge` added.
  We'll ship this in a follow-up V021 migration when CIRISAgent
  PR adding the enum value lands; coordinate via cross-issue ping.

Until then, agents can either:
- Use the existing `"system_event"` action_type with `subject_kind =
  "audit_chain"` (CHECK passes today)
- Or hold the bridge entry until V021 lands

The `system_event` option is simpler for v2.9.0 first-boot; promote
to `chain_bridge` in v2.10.x when both sides ship the vocab addition.

### Server-side vs client-side hash

**Caller computes `entry_hash` and `signature`.** Persist stores both
verbatim. `signature_verified` is set to `false` on INSERT; persist's
verify path or a cold-path sweep can verify and flip the flag later.

Rationale: persist doesn't have direct access to the agent's TPM-backed
signing key, so the signature MUST be computed caller-side. The agent
computes the canonical bytes, the TPM signs, and the result lands on
persist's row.

The `try_claim_event` path (the atomic-claim variant from v1.0.0) is
the recommended write surface for the bridge entry — passes the
content hash so concurrent agent boots can't double-write the bridge.

## 2. `tenant_id` + `signing_key_id` registration

### 2.1 `tenant_id` semantics

Persist's `cirislens.audit_log.tenant_id` is opaque to persist — the
substrate doesn't dictate the value. The per-tenant isolation
invariant (AV-51) is `UNIQUE (tenant_id, sequence_number)`; that's
the only structural constraint.

**Sovereign-mode single-agent deployments** (most CIRIS agents):

```
tenant_id = sha256(agent_identity_root).hex()[:32]
         OR
tenant_id = agent_id_from_env  // e.g., "agent-8a0b70302aae"
```

Both are stable across reboots and unique-per-deployment. Pick one;
the substrate doesn't care. The sha256-based form has the benefit of
being globally unique across deployments without coordination.

**Multi-tenant deployments** (e.g., a host running several agents):
pick a stable per-agent value (UUID v5 namespaced under a deployment
root works well). The agents see only their own tenant_id; cross-tenant
queries require admin scope.

**Don't change `tenant_id` mid-chain.** A chain with mixed `tenant_id`
values can't be verified — the chain integrity walk is
per-tenant. If an agent's identity changes (key rotation that
changes the identity hash), open a new chain via a bridge entry; do
NOT re-tenant the existing rows.

### 2.2 `signing_key_id` registration

Every audit row carries `signing_key_id` (the actor_id of the
signer's Ed25519 pubkey, base64 encoded). For signature verification
to succeed, the key must be registered in `cirislens.federation_keys`
via the `FederationDirectory::put_public_key` trait method.

**One-time registration** at agent boot:

```python
from ciris_persist import Engine

engine = Engine("sqlite:///agent.db", "agent-steward-v1")

# Build the SignedKeyRecord (existing v0.4.x surface):
#   - key_id: stable identifier; convention "agent-{agent_id}-v{N}"
#   - pubkey_ed25519_base64: agent's TPM-backed pubkey, b64
#   - pubkey_ml_dsa_65_base64: agent's PQC half (optional pre-v1.4)
#   - algorithm: "hybrid" (ed25519 + ml_dsa_65) or "ed25519"
#   - identity_type: "agent" | "steward" | "registry" | "edge"
#   - identity_ref: stable identity ref (e.g., agent_id)
#   - valid_from / valid_until: RFC 3339 timestamps
#   - registration_envelope: signed self-attestation per V004 shape

engine.put_public_key(signed_record_json)
```

**Idempotency**: `put_public_key` is idempotent on `key_id` collision
with matching content (no-op); errors on `key_id` collision with
differing content. Calling it on every agent boot is safe.

**`signing_key_id` value on audit rows**: this is the `key_id` from
the registered `KeyRecord`, NOT the pubkey itself. The pubkey is
looked up via `lookup_public_key(key_id)` at verify time.

### 2.3 First-boot flow for 2.9.0

```python
# Step 1: Engine bootstrap
engine = Engine(connection_string, agent_signing_key_id)

# Step 2: Register agent's steward key (idempotent; safe on every boot)
engine.put_public_key(agent_signed_key_record_json)

# Step 3: Bridge audit chain (if cutting over from a legacy chain)
#         OR start fresh genesis (if first deployment)
if legacy_chain_archive_exists:
    bridge_entry = build_bridge_entry(legacy_chain_terminal_state, agent_steward_key)
    engine.audit_try_claim_event(
        content_hash=sha256(canonical_bytes_for_hash(bridge_entry)),
        entry_json=bridge_entry,
        accessor="agent_boot",
    )
else:
    genesis_entry = build_genesis_entry(agent_steward_key)
    # prev_hash = GENESIS_PREV_HASH (32 zero bytes)
    engine.audit_record_entry(genesis_entry)

# Step 4: Normal operation — record_entry / try_claim_event per action
```

### 2.4 Trust hierarchy registration (Lane C C3)

After v1.3.0, the agent can also register trust grants alongside
the public key (these populate the `trust_type` / `trust_relationship`
/ `trust_domains[]` columns added in V020):

```python
engine.federation_grant_trust({
    "key": "<trusted_peer_key_id>",
    "trust_type": "temporary",          # or "partnered" / "anonymous"
    "trust_relationship": "direct",      # or "registry"
    "trust_domains": null,               # required when registry
    "trusted_by": "<grantor_key_id>",   # MUST differ from key (CHECK)
    "expires_at": null,                  # null = open-ended
})
```

Persist enforces `trusted_by != key` at the column-level CHECK and
auto-writes a `trust_granted` transition entry to `cirisaudit`. The
`trusted_by` value should be the agent's own steward `key_id` for
self-issued grants; for registry-vouched chains (CIRISRegistry-issued
licenses), it's the registry's signing key_id.

## 3. Quick-reference call sites

| Step | Persist call | Module |
|---|---|---|
| Register key | `engine.put_public_key(record)` | federation |
| Bridge audit chain | `engine.audit_try_claim_event(hash, entry, accessor)` | audit |
| Normal audit write | `engine.audit_record_entry(entry)` | audit |
| Verify chain | `engine.audit_verify_chain(tenant_id, from, to)` | audit |
| Grant trust | `engine.federation_grant_trust(grant)` | federation |
| Revoke trust | `engine.federation_revoke_trust(key, revoked_by)` | federation |
| Lookup trust | `engine.federation_lookup_trust(key)` | federation |
| Verify signature | `verify_hybrid_via_directory(directory, canonical, key_id, ed_sig, pqc_sig)` | prelude |
| Sign envelope | `StewardSigner.sign_hybrid(bytes)` | prelude |

## 4. See also

- `src/audit/types.rs` — `AuditEntry`, `AuditEventType`, `ChainBreakReason`
- `src/federation/types.rs` — `KeyRecord`, `SignedKeyRecord`, `TrustGrant`, `TrustRow`
- `src/audit/postgres.rs::compute_entry_hash` — canonical-bytes reference impl
- `migrations/postgres/lens/V014__cirislens_audit_log.sql` — schema with hash-chain semantics
- `migrations/postgres/lens/V020__federation_keys_trust_hierarchy.sql` — trust columns
- CIRISAgent#760 — Counter-RII consent_role A/B/C lock
- CIRISAgent#763 — Lane A/B/C cutover tracker
