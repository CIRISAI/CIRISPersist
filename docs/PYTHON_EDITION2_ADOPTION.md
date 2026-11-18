# Edition-2 from Python: adoption notes for the Agent and the Bridge (v62.0.0)

A v62 node reads and produces only **edition-2 statements**: a CBOR payload signed once by a composite key (ML-DSA-65 + Ed25519) as one `COSE_Sign1` (CC 2.6.1). The earlier form (a JSON object signed over its JCS image, with separate classical and PQC scrubs) is refused by name. This page lists what changes for a Python host of the wheel: the CIRISAgent's embedded edge, and any replication bridge written against the Engine.

The witnesses are `tests/python/test_edition2_surface.py` (I2510–I2515).

## What a host stops doing

- **No more JSON rows at the doors.** After the cut, each of these raises `ValueError("federation_malformed_row: <plane>: earlier_form_object …")` before it decodes its argument:
  - `put_public_key`, `register_federation_key`, `rebind_key_record`, `apply_replicated_key_record`;
  - `put_revocation`, `deregister_federation_key`;
  - `put_attestation`, `apply_replicated_attestation`, `apply_replicated_key_grant`, `apply_replicated_accord_evidence`;
  - `put_delivery_receipt`, `put_identity_occurrence_json`, `put_wholeness_witness_json`, `put_family_json`, `put_community_json`, `put_lineage_head_cosign_json`;
  - `put_accord_proposal_json`, `put_accord_participation_json`, `put_accord_decision_json`;
  - `bake_assembled_genesis`, `install_genesis_bundle_roster_json`, `pin_trust_from_bundle_response_json`;
  - `apply_replicated_purge_json`, `purge_rows_json`, `federation_grant_trust`, `federation_revoke_trust`.

  Match on the start of the message (`federation_malformed_row`) and the token `earlier_form_object`, not on the plane. The refusal is terminal: do not re-offer the object.
- **`ciris_persist.earlier_form_doors_shut()`** says whether this wheel refuses them. It is `False` on a wheel built before the doors were shut, and `True` from the release that ships the cut.
- **No PQC attach, no key-id fingerprint.** `attach_*_pqc_signature` and the `<label>-<fp>` key id are gone. A row is signed once, by the composite; there is no second half to attach later.

## The key: `register_self_federation_key`

```python
kid = engine.register_self_federation_key("agent")            # (identity_type, valid_until=None, attestation_evidence_json=None)
assert kid == engine.local_derived_key_id()
# kid == "urn:ietf:params:oauth:ckt:sha-256:<43 base64url chars>"
```

- The call writes this node's `key:record` statement and returns the key's **identity-ref**: the base64url SHA-256 thumbprint of the composite public key, behind the prefix `urn:ietf:params:oauth:ckt:sha-256:`. Treat it as opaque. The CIRISAgent already overwrites `_actor_key_id` from the returned value, which keeps working.
- The `identity_ref`, `registration_envelope_json` and `roles` arguments are gone. The pre-v62 five-argument call raises `TypeError`; it is not read as something else.
- A `node` or `agent` record ends at most 365 days out; a `user` record carries no end. Re-register before the end to keep the key live.
- `lookup_public_key(kid)` still returns a JSON record with `key_id`, `pubkey_ed25519_base64` (32 bytes), `pubkey_ml_dsa_65_base64` (1952 bytes) and `identity_type`. It is a read model of the held `key:record` statements. `identity_type` is now a set, written comma-separated (`"agent"`, `"node,…"`): split on `,` rather than comparing the whole string.

## The statement door: `put_edition2_statement`

```python
out = json.loads(engine.put_edition2_statement(statement_bytes, offered_row_id=None))
# {"plane": "key_plane" | "voice" | "row", "row_id": "<64 lowercase hex>", "new": bool}
```

- `statement_bytes` is one `COSE_Sign1` statement exactly as received. The node computes the row id. If you pass `offered_row_id` (64 hex, any case), it must be that id, or the call raises `ValueError("federation_malformed_row: edition2: row_id_mismatch …")`. A string that is not 64 hex raises `ValueError("offered_row_id: …")` without reaching the door.
- `plane` says where the statement went: `key_plane` (a `key:record` or `key:revocation`), `row` (a new row, through the same gates the JSON door ran), or `voice` (a further signature over a row this node already holds, counted by that row's fold).
- Putting a statement the node already holds changes nothing and returns `new: false` with the row id. A producing node can use this to learn the id of a statement it serves.
- A JSON object, or bytes that are no statement at all, raises `ValueError("federation_malformed_row: edition2: earlier_form_object …")` on every wheel, whatever `earlier_form_doors_shut()` says.

## Replication: serving and applying statements

**Serving** (the sender's side):

```python
cursor = load_cursor()                       # None the first time
page = engine.edition2_statements_since(cursor, 1000)
for cursor, statement in page:               # (str, bytes), in this node's admission order
    row_id = json.loads(engine.put_edition2_statement(statement))["row_id"]   # new is False: it is held
    send(statement, row_id)
save_cursor(cursor)                          # the LAST item's cursor
```

- The cursor is an opaque string; store it and pass it back as given. A page holds at most 1000 statements. A malformed cursor raises `ValueError("cursor: …")`.
- Each statement is served as received, byte for byte (CC 2.6.1.2). Key it by its row id, not by an envelope hash.

**Applying** (the receiver's side):

```python
try:
    out = json.loads(engine.apply_replicated_statement(statement, row_id))
except ValueError as e:
    if str(e).startswith("federation_attester_key_unknown"):
        hold_and_retry_later(statement, row_id)   # do NOT advance past it
    else:
        drop(statement, reason=str(e))            # terminal: a gate refused it
else:
    # out["outcome"]: "admitted" | "unchanged" | "refused"
    advance_cursor()                              # out["advances_cursor"] is always True
```

- `admitted` and `unchanged` carry `plane`, `row_id` and `new`. `refused` carries `reason` (today `store_conflict`: a race the store lost; the held rows are untouched and the statement is safe to offer again later).
- `federation_attester_key_unknown` means the signer's `key:record` has not arrived. Deliver the sender's key-plane statements first, or hold the row and retry. The sender's own serving order already puts a key before the rows it signs.
- Every other `ValueError` is a refusal by name and is terminal for those bytes, with the same text the JSON door used to raise for the same row (for example the attestation gates' tokens).

## Genesis: `bundles_in_force_json`

```python
bundles = json.loads(engine.bundles_in_force_json())
# [{"object_id": "<64 hex>", "version": int, "prev": "<64 hex>" | null, "asserted_at": <POSIX ms>,
#   "family_key_id": str, "holders": [identity-ref, …], "serve_nodes": [identity-ref, …], "counted": […]}]
```

- The bundles in force are the tips of the held `ceg-genesis-bundle/2` lineage (CC 2.6.1.11), followed by `prev` links from a fresh genesis (version 1, no `prev`). An empty list means the node holds no bundle yet (it booted pre-genesis). Two entries are a fork: both are in force, and a reader takes only what both name.
- `holders` is in roster order and `serve_nodes` in seat order; neither has duplicates. The call takes no arguments.
- **Canonical standing** is an identity-ref in `serve_nodes` of the bundle in force. This replaces reading `serve_nodes[].record.key_id` out of a bundle/1 JSON response, and the `ciris-canonical-1-<fp>` key id.
- The accord's roster is `holders`. A halt is one statement from one holder of the bundle in force; there is no proposal, participation or decision object any more.

## Unchanged, or not yet ruled

- **Removed:** `local_sign_hybrid`, `verify_hybrid`, `verify_hybrid_via_directory` and `verify_signed_{key_record,attestation,revocation}`. A v62 signature is one composite, produced through persist's producers; there is no separate classical-plus-PQC pair to sign or verify. The Agent's `substrate_signing.py` must move off them.
- **Kept:** `local_sign` and `local_pqc_sign`, the single-component signers. CC rc20 allows a component signature in two places: on substrate objects (CC 6.1.3, for example the wholeness witness and the fountain aggregation meta) and on the per-chunk media trailer. The local and split planes, such as the audit chain, use them. They cannot produce a mesh row: every door admits only a composite edition-2 statement.
- The local tier (`attestation_upsert_local`), the blob, secrets and trace surfaces keep their calls.
- Errors keep their Python types: an edition-2 refusal is the same `ValueError` the JSON door raised.
