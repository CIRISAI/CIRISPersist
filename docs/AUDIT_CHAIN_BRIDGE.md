# Audit Chain Bridge + Identity Registration

How a caller starts persist's `cirisaudit` chain — either fresh or bridged
from an existing chain — and how it registers the keys and trust grants that
chain relies on. Two questions:

1. **Bridge entry** — how to root persist's `cirisaudit` chain on top of an
   existing chain (Sigstore-signed, hand-rolled, or otherwise).
2. **`tenant_id` + `signing_key_id`** — what values to use, and where to
   register the signer's key.

The wire shape itself lives in `src/audit/types.rs` (`AuditEntry`) and
`src/federation/types.rs` (`KeyRecord`).

## 1. Chain bridge — root the new chain off an existing one

### Concept

Persist's `cirisaudit` chain is per-tenant. Each tenant has its own monotonic
`sequence_number` starting at 1, with `prev_hash` linking each entry to the
previous one. A clean genesis entry (`sequence_number = 1`) has
`prev_hash = GENESIS_PREV_HASH` (32 zero bytes).

To **bridge to an existing chain**, the first `cirisaudit` entry carries:

- `sequence_number = 1`
- `prev_hash = sha256(canonical bytes of the legacy chain's root marker)`
- a `payload` that records the legacy chain's terminal state for forensic
  continuity

The write path accepts a non-zero `prev_hash` at `sequence_number = 1` and
logs it as a bridge entry. The verifier (`AuditService::verify_chain`)
reports that row as `ChainBreakReason::GenesisPrevHashNotZero`. This is
deliberate: it lets a consumer tell a clean genesis (a new deployment) from a
bridge (a cutover from a prior chain).

### Canonical-bytes rule

Every audit entry's `entry_hash` covers the canonical JSON of the entry
**minus the `signature` and `entry_hash` fields**. The `signature` then covers
the canonical bytes **including** the resolved `entry_hash`. This is the same
shape as the `cirisnode` envelopes (`src/cirisnode/verify.rs`); the reference
implementation is `compute_entry_hash` in `src/audit/verify.rs`.

```
canonical_bytes_for_hash = canonical_json(entry minus signature minus entry_hash)
entry_hash = sha256(canonical_bytes_for_hash)
canonical_bytes_for_sign = canonical_json(entry minus signature, WITH entry_hash filled in)
signature = Ed25519(signing_key, canonical_bytes_for_sign)
```

**Canonicalizer:** `PythonJsonDumpsCanonicalizer` — sorted keys, no
whitespace, `ensure_ascii=True`. Persist defines the exact byte sequence;
**do not reimplement the rule in the caller's language.**

### Caller workflow

Persist exposes the two canonicalization phases as Python methods, so a
caller can plug in its own signer (TPM-backed via CIRISVerify, KMS, HSM)
without reimplementing the canonical-bytes rule:

```python
# Step 0: read the chain head — the (next_sequence_number, prev_hash) to stamp
head = json.loads(engine.audit_next_chain_position(tenant_id))

# Step 1: build the entry with entry_hash="" and signature=""
entry = {
    "entry_id": str(uuid.uuid4()),
    "sequence_number": 1,
    "tenant_id": "...",
    "actor_id": "<base64 Ed25519 pubkey>",
    "action_type": "system_event",
    "subject_kind": "audit_chain",
    "subject_id": "...",
    "payload": {...},
    "prev_hash": "<base64 32 bytes>",
    "entry_hash": "",
    "recorded_at": "...",
    "signature": "",
}

# Step 2: canonical bytes for the hash phase; compute entry_hash
ch = engine.audit_canonicalize_for_hash(json.dumps(entry))
entry["entry_hash"] = base64.b64encode(hashlib.sha256(ch).digest()).decode()

# Step 3: canonical bytes for the signing phase; sign externally
cs = engine.audit_canonicalize_for_signing(json.dumps(entry))
sig_bytes = your_signer.sign_ed25519(cs)   # CIRISVerify TPM signer, etc.
entry["signature"] = base64.b64encode(sig_bytes).decode()

# Step 4: submit — persist re-derives entry_hash and verifies the signature
engine.audit_record_entry(json.dumps(entry))
```

Stripping rule:
- `audit_canonicalize_for_hash` strips **both** `entry_hash` and `signature`
  from the top-level JSON object, then canonicalizes.
- `audit_canonicalize_for_signing` strips **only** `signature` — `entry_hash`
  is part of the signed body, which binds the signature to the chain
  position.

Persist owns the rule; callers stay in their language.

### Bridge entry shape

```json
{
  "entry_id": "<uuid-v4>",
  "sequence_number": 1,
  "tenant_id": "<see §2.1>",
  "actor_id": "<base64 Ed25519 pubkey of the signer>",
  "action_type": "system_event",
  "subject_kind": "audit_chain",
  "subject_id": "<legacy chain identifier — caller's choice; commonly the legacy DB filename or chain UUID>",
  "payload": {
    "legacy_chain_root_hash": "<hex-or-b64 of the legacy chain's terminal entry hash>",
    "legacy_chain_root_id": "<id of the legacy chain's terminal entry>",
    "legacy_chain_scheme": "sigstore_rekor_v1",
    "legacy_chain_attestation": "<inline attestation or pointer to archived DB>",
    "bridge_reason": "<free text>",
    "archived_at": "<RFC 3339 timestamp when the legacy chain was archived>"
  },
  "prev_hash": "<base64 of sha256(canonical legacy root marker), see below>",
  "entry_hash": "<base64 of sha256(canonical entry minus signature minus entry_hash)>",
  "recorded_at": "<RFC 3339, cutover wall-clock>",
  "signature": "<base64 Ed25519 over canonical_bytes_for_sign>"
}
```

### Bridge `prev_hash` semantic

The `prev_hash` on a bridge entry is **caller-defined** — persist does not
check it against any external source. The convention is to derive it
deterministically from the legacy chain's terminal state, so anyone holding
the legacy archive can recompute and verify the bridge:

```python
legacy_marker = canonical_json({
    "legacy_chain_root_hash": "<...>",
    "legacy_chain_root_id": "<...>",
})
prev_hash = sha256(legacy_marker.encode())  # 32 bytes
```

### `action_type` for a bridge entry

Use `action_type = "system_event"` with `subject_kind = "audit_chain"`. On
postgres, `cirislens.audit_log.action_type` carries a closed-vocabulary CHECK
(V018, extended by V020 and V090) that does not include a dedicated
`chain_bridge` value. SQLite's `audit_log` has no `action_type` CHECK and
treats the value as an opaque producer string; `system_event` is accepted on
both.

### Who computes the hash and signature

**The caller computes `entry_hash` and `signature`**, because persist has no
access to the caller's TPM-backed signing key. `audit_record_entry` then:

1. re-derives `entry_hash` from the canonical bytes and rejects a mismatch
   (AV-49);
2. verifies the Ed25519 signature against `actor_id` (which is the pubkey);
3. checks `sequence_number` is the prior entry's plus one (or 1 for a new
   tenant), and `prev_hash` matches the prior entry's `entry_hash`;
4. inserts the row with `signature_verified = TRUE`.

A second write at the same `(tenant_id, sequence_number)` is a conflict, so
two concurrent boots cannot both write the bridge entry.

## 2. `tenant_id` + `signing_key_id` registration

### 2.1 `tenant_id` semantics

`cirislens.audit_log.tenant_id` is opaque to persist. The per-tenant
isolation invariant (AV-51) is `UNIQUE (tenant_id, sequence_number)`; that is
the only structural constraint.

**Single-agent deployments:**

```
tenant_id = sha256(agent_identity_root).hex()[:32]
         OR
tenant_id = agent_id_from_env  // e.g., "agent-8a0b70302aae"
```

Both are stable across reboots and unique per deployment. The sha256 form is
globally unique across deployments without coordination.

**Multi-tenant deployments** (a host running several agents): pick a stable
per-agent value (UUID v5 namespaced under a deployment root works well).
Each agent sees only its own `tenant_id`; cross-tenant queries require admin
scope.

**Do not change `tenant_id` mid-chain.** The integrity walk is per-tenant, so
a chain with mixed `tenant_id` values cannot be verified. If an agent's
identity changes (a key rotation that changes the identity hash), open a new
chain with a bridge entry; do not re-tenant existing rows.

### 2.2 `signing_key_id` registration

Every audit row carries `signing_key_id` — the `key_id` of the signer's
registered `KeyRecord`, not the pubkey itself. The pubkey is in `actor_id`.
Register the key in `cirislens.federation_keys` through
`FederationDirectory::put_public_key` so other verifiers can resolve the
signer by `key_id` (`lookup_public_key(key_id)`).

```python
from ciris_persist import Engine

engine = Engine("sqlite:///agent.db", "agent-steward-v1")

# SignedKeyRecord fields:
#   - key_id: stable identifier; convention "agent-{agent_id}-v{N}"
#   - pubkey_ed25519_base64: the TPM-backed pubkey, b64
#   - pubkey_ml_dsa_65_base64: the PQC half
#   - algorithm: "hybrid" (ed25519 + ml_dsa_65) or "ed25519"
#   - identity_type, identity_ref
#   - valid_from / valid_until: RFC 3339 timestamps
#   - registration_envelope: signed self-attestation (V004 shape)

engine.put_public_key(signed_record_json)
```

**Idempotency:** `put_public_key` is a no-op on a `key_id` collision with
matching content and an error on a collision with differing content, so
calling it on every boot is safe.

### 2.3 First-boot flow

```python
# Step 1: Engine bootstrap
engine = Engine(connection_string, signing_key_id)

# Step 2: Register the signer's key (idempotent; safe on every boot)
engine.put_public_key(signed_key_record_json)

# Step 3: Bridge the audit chain (cutting over from a legacy chain)
#         OR write a fresh genesis (first deployment)
if legacy_chain_archive_exists:
    bridge_entry = build_bridge_entry(legacy_chain_terminal_state, signer)
    engine.audit_record_entry(bridge_entry)
else:
    genesis_entry = build_genesis_entry(signer)
    # prev_hash = GENESIS_PREV_HASH (32 zero bytes)
    engine.audit_record_entry(genesis_entry)

# Step 4: Normal operation — audit_record_entry per action,
#         stamped from audit_next_chain_position
```

### 2.4 Trust hierarchy registration

A caller can also register trust grants alongside the public key. These
populate the `trust_type` / `trust_relationship` / `trust_domains[]` columns
(V020). A grant is a `SignedTrustGrant`: the `TrustGrant` body plus the
granter's hybrid signature over `trust_grant_signing_bytes`.

```python
engine.federation_grant_trust(json.dumps({
    "grant": {
        "key": "<trusted_peer_key_id>",
        "trust_type": "temporary",          # or "partnered" / "anonymous"
        "trust_relationship": "direct",      # or "registry"
        "trust_domains": None,               # required when registry
        "trusted_by": "<grantor_key_id>",   # MUST differ from key (CHECK)
        "expires_at": None,                  # None = open-ended
    },
    "signature_classical_base64": "<Ed25519 by trusted_by>",
    "signature_pqc_base64": "<ML-DSA-65 by trusted_by>",
}))
```

Persist enforces `trusted_by != key` with a column-level CHECK and writes a
`trust_granted` transition entry to `cirisaudit`. `trusted_by` is the
caller's own `key_id` for self-issued grants; for registry-vouched chains
(CIRISRegistry-issued licenses) it is the registry's signing `key_id`.
A revocation is a `SignedTrustRevocation` (`key`, `revoked_by`, `revoked_at`,
signatures); the revoker must be the stored granter.

## 3. Quick-reference call sites

| Step | Persist call | Module |
|---|---|---|
| Register key | `engine.put_public_key(record)` | federation |
| Chain head | `engine.audit_next_chain_position(tenant_id)` | audit |
| Audit write (bridge, genesis, normal) | `engine.audit_record_entry(entry)` | audit |
| Verify one chain | `engine.audit_verify_chain(tenant_id, from, to)` | audit |
| Verify all chains | `engine.audit_verify_all_chains()` | audit |
| Grant trust | `engine.federation_grant_trust(signed_grant)` | federation |
| Revoke trust | `engine.federation_revoke_trust(signed_revocation)` | federation |
| Lookup trust | `engine.federation_lookup_trust(key)` | federation |
| Verify signature | `engine.verify_hybrid_via_directory(canonical, key_id, ed_sig, pqc_sig, policy)` | verify |

## 4. See also

- `src/audit/types.rs` — `AuditEntry`, `AuditEventType`, `ChainBreakReason`
- `src/audit/verify.rs::compute_entry_hash` — canonical-bytes reference implementation
- `src/audit/service.rs` — `AuditService::record_entry` gate order
- `src/federation/types.rs` — `KeyRecord`, `SignedKeyRecord`, `TrustGrant`, `SignedTrustGrant`, `TrustRow`
- `migrations/postgres/lens/V014__cirislens_audit_log.sql` — schema with hash-chain semantics
- `migrations/postgres/lens/V020__federation_keys_trust_hierarchy.sql` — trust columns
- CIRISAgent#760 — Counter-RII `consent_role` A/B/C
