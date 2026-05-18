"""Type stubs for the Rust-built ``ciris_persist`` extension module.

Mission alignment (PLATFORM_ARCHITECTURE.md §3.5): mypy / pyright
support is part of the Phase 1 surface — the lens FastAPI codebase
already runs strict type checking, and these stubs keep ciris-persist
inside that envelope.
"""

from typing import Any, Callable, TypedDict

__version__: str
SUPPORTED_SCHEMA_VERSIONS: list[str]

class LensQueryError(Exception):
    """v0.5.3+ (CIRISPersist#27) — typed exception raised when a Rust
    panic crosses the FFI boundary. Subclasses ``Exception`` (not
    ``BaseException``) so uvicorn's ``try: except Exception:`` catches
    it as a normal 500. The original panic message is preserved as
    ``"rust_panic: <message>"`` in the exception's str form.
    """

class BatchSummary(TypedDict):
    """Result shape from :meth:`Engine.receive_and_persist`."""
    envelopes_processed: int
    trace_events_inserted: int
    trace_events_conflicted: int
    trace_llm_calls_inserted: int
    scrubbed_fields: int
    signatures_verified: int

ScrubberCallable = Callable[[dict[str, Any]], tuple[dict[str, Any], int]]

class Engine:
    """One-instance-per-DSN handle to the Rust persistence pipeline.

    Construction connects to Postgres and runs migrations. Method
    calls are synchronous from Python's view; internally async work
    runs on a tokio runtime cached on the Engine instance.
    """

    def __init__(self, dsn: str, scrubber: ScrubberCallable | None = None) -> None: ...

    def register_public_key(
        self,
        signature_key_id: str,
        public_key_b64: str,
        agent_id_hash: str | None = None,
    ) -> None:
        """Register a raw Ed25519 verifying key in the **lens audit-chain
        directory** (`accord_public_keys`).

        Used by lens-tier verifiers to look up the signing key for an
        audit-chain entry. Distinct from `register_federation_key` /
        `put_public_key`, which write to the **federation directory**
        (`federation_keys` with full signed envelope + V020 trust
        columns + V021 trust grants).

        Idempotent on the same key/value; rejects rotation (registering
        a different key for an existing key id raises).
        """

    def audit_canonicalize_for_hash(self, entry_json: str) -> bytes:
        """v1.5.4 — Return the exact canonical bytes whose SHA-256 equals
        the audit entry's `entry_hash`.

        Workflow:
        1. Build AuditEntry JSON with `entry_hash = ""` and `signature = ""`.
        2. `ch = engine.audit_canonicalize_for_hash(json.dumps(entry))`
        3. `entry["entry_hash"] = base64(sha256(ch).digest())`

        Rule mirrors `crate::audit::verify::compute_entry_hash`: both
        `entry_hash` and `signature` are zeroed pre-canonicalization;
        canonicalization is PythonJsonDumpsCanonicalizer (sorted keys,
        no whitespace, ensure_ascii=True). Companion of
        `audit_canonicalize_for_signing`.
        """

    def audit_canonicalize_for_signing(self, entry_json: str) -> bytes:
        """v1.5.4 — Return the exact canonical bytes the audit entry's
        Ed25519 `signature` covers.

        Workflow:
        4. `cs = engine.audit_canonicalize_for_signing(json.dumps(entry))`
        5. `entry["signature"] = base64(your_signer.sign_ed25519(cs))`
        6. `engine.audit_record_entry(json.dumps(entry))`

        Rule: only `signature` is stripped — `entry_hash` participates
        in the signed body so a chain rewrite that flips a subsequent
        entry's `prev_hash` invalidates this entry's signature too.
        """

    def register_federation_key(
        self,
        identity_type: str,
        identity_ref: str,
        valid_until: str | None = None,
        registration_envelope_json: str | None = None,
        roles: list[str] | None = None,
    ) -> str:
        """v1.5.3 — One-call helper that registers THIS engine's local
        pubkey in the **federation directory** (`federation_keys`).

        Composes the existing canonicalize + sign + put_public_key
        primitives so callers don't re-implement persist's canonical-bytes
        rule in Python. Returns the registered `key_id` (equals
        `engine.local_key_id()`).

        Internally:
        1. Canonicalizes `registration_envelope_json` (defaults to `{}`)
           via persist's `PythonJsonDumpsCanonicalizer`.
        2. Signs canonical bytes with the engine's local Ed25519 key.
        3. Builds a self-signed `SignedKeyRecord` (scrub_key_id =
           local_key_id).
        4. Calls `put_public_key` — backend dispatch + cold-path
           ML-DSA-65 PQC attach handled automatically.

        Raises:
            ValueError: no local signing identity, malformed valid_until,
                or unparseable registration_envelope_json.
            RuntimeError: backend / IO error.
        """

    def receive_and_persist(self, body: bytes) -> BatchSummary:
        """Run the FSD §3.3 ingest pipeline on a batch body.

        Raises:
            ValueError: schema / verify / scrub rejection — caller
                surfaces as HTTP 4xx.
            RuntimeError: backend / IO error — caller surfaces as HTTP
                5xx.
        """

    # ── v1.5.0 Phase H: trust-grant + Merkle transparency surface ────
    #
    # 8 methods wrapping the federation::emit + federation::read APIs.
    # Return shapes are JSON strings (caller parses); typed Python
    # classes are reserved for the Phase J release cut.

    def grant_trust(
        self,
        tenant_id: str,
        grantee_key: str,
        purpose: str,
        scope: str,
        expires_at: str | None,
        rationale: str,
    ) -> str:
        """Emit a signed TrustGrant audit-chain entry (FSD §4.1).

        ``purpose`` must be one of ``"technical" | "deferral" |
        "contribution" | "service"``. ``expires_at`` is ISO-8601 or
        ``None``. Requires a steward key configured on the Engine
        (``local_key_id`` + ``local_key_path``).

        Returns a JSON-encoded ``TrustGrantReceipt`` string with
        ``{ grant_id, chain_event_id, chain_event_hash, tenant_id,
        tree_size_at_emit, sth }``.

        Raises:
            ValueError: malformed purpose / expires_at, self-grant,
                or no steward signer configured.
            RuntimeError: signing or backend failure.
        """

    def revoke_trust_grant(
        self,
        tenant_id: str,
        grantee_key: str,
        purpose: str,
        scope: str,
    ) -> str:
        """Revoke a trust grant per FSD §3.4 (re-issuance with
        ``expires_at = now()``, rationale = ``"revocation"``). Returns
        a JSON-encoded ``TrustGrantReceipt`` for the revocation event."""

    def lookup_trust_grant(
        self,
        grantee_key: str,
        purpose: str,
        scope: str,
    ) -> str:
        """Look up live (non-revoked, non-expired) trust grants for
        ``(grantee_key, purpose, scope)``. Returns a JSON-array string
        of ``TrustGrantRow`` objects. Wildcard scope grants (``"*"``)
        surface alongside exact matches per FSD §3.3."""

    def list_trust_grants(self, filter_json: str) -> str:
        """Filter query over ``federation_trust_grants``. ``filter_json``
        deserializes into ``TrustGrantFilter``. Returns a JSON-array
        string of ``TrustGrantRow`` objects."""

    def get_trust_grant(self, grant_id: str) -> str | None:
        """Point lookup by canonical UUID ``grant_id``. Returns a
        JSON-encoded ``TrustGrantRow`` or ``None``."""

    def current_sth(self, tenant_id: str) -> str | None:
        """Fetch the current ``SignedTreeHead`` for the per-tenant
        Merkle log. Returns a JSON-encoded ``SignedTreeHead`` or
        ``None``."""

    def trust_grant_inclusion_proof(self, grant_id: str) -> str:
        """Generate the full inclusion-proof bundle for a trust grant.
        Returns a JSON object with ``{ sth, merkle_proof,
        leaf_canonical_bytes (base64) }``.

        Raises:
            KeyError: grant_id has no projection row, the tenant has
                no STH, or the merkle leaf is missing.
        """

    # ── v1.5.9 (CIRISPersist#59 #1) — agent tasks substrate ──────────

    def task_upsert(self, task_json: str) -> None:
        """v1.5.9 — Idempotent upsert keyed on ``task_id``.

        ``task_json`` is a JSON-encoded ``Task`` shape (see the
        ``ciris_persist.tasks`` module). Re-insert with the same
        payload is a no-op; re-insert with differing payload
        overwrites the mutable columns and preserves ``created_at``.
        """

    def task_get(self, task_id: str) -> str | None:
        """v1.5.9 — Read one task by id. Returns the JSON-encoded
        ``Task`` row or ``None`` if no matching row exists.
        """

    def task_list(
        self,
        filter_json: str,
        cursor_json: str | None,
        limit: int,
    ) -> str:
        """v1.5.9 — Cursor-paged task listing. Returns the JSON-encoded
        ``TaskListPage`` ({"items": [...], "next_cursor": {...}|None}).
        """

    def task_update_status(
        self,
        task_id: str,
        new_status: str,
        outcome_json: str | None,
    ) -> bool:
        """v1.5.9 — Focused status update + optional outcome merge.

        ``new_status`` is one of ``pending`` / ``active`` /
        ``completed`` / ``failed`` / ``cancelled`` / ``deferred``.
        ``outcome_json`` (when not None) is decoded and stored into the
        ``outcome_json`` column; ``None`` preserves the existing value.

        Returns ``True`` when a row was updated, ``False`` when no
        matching task exists (no error — caller treats as stale id).
        """

    def task_try_claim_shared(self, task_json: str) -> str:
        """v1.5.9 — Atomic INSERT-OR-IGNORE claim keyed on ``task_id``.

        Returns the JSON wire-shape
        ``{"outcome": "stored" | "already_claimed", "task": <Task>}``.
        First caller wins with ``"stored"``; subsequent callers get
        ``"already_claimed"`` carrying the EXISTING row (not the
        caller's payload).
        """

    def task_delete(self, task_id: str) -> bool:
        """v1.5.9 — Delete a task by id.

        Returns ``True`` if a row was deleted, ``False`` on
        missing/already-deleted (idempotent). FK-protected: children
        pointing at this row reject the delete as Conflict.
        """

    # ── v1.5.10 (CIRISPersist#59 #2) — agent thoughts substrate ─────

    def thought_upsert(self, thought_json: str) -> None:
        """v1.5.10 — Idempotent upsert keyed on ``thought_id``.

        ``thought_json`` is a JSON-encoded ``Thought`` shape (see the
        ``ciris_persist.thoughts`` module). Re-insert with the same
        payload is a no-op; re-insert with differing payload
        overwrites the mutable columns and preserves ``created_at``.
        """

    def thought_get(self, thought_id: str) -> str | None:
        """v1.5.10 — Read one thought by id. Returns the JSON-encoded
        ``Thought`` row or ``None`` if no matching row exists.
        """

    def thought_list(
        self,
        filter_json: str,
        cursor_json: str | None,
        limit: int,
    ) -> str:
        """v1.5.10 — Cursor-paged thought listing. Returns the
        JSON-encoded ``ThoughtListPage``
        ({"items": [...], "next_cursor": {...}|None}).
        """

    def thought_update_status(
        self,
        thought_id: str,
        new_status: str,
        final_action_json: str | None,
    ) -> bool:
        """v1.5.10 — Focused status update + optional final_action
        merge.

        ``new_status`` is one of ``pending`` / ``processing`` /
        ``completed`` / ``failed`` / ``deferred``.
        ``final_action_json`` (when not None) is decoded and stored
        into the ``final_action_json`` column; ``None`` preserves the
        existing value.

        Returns ``True`` when a row was updated, ``False`` when no
        matching thought exists (no error — caller treats as stale
        id).
        """

    def thought_get_descendants(self, thought_id: str) -> str:
        """v1.5.10 — Walk the ``parent_thought_id`` chain rooted at
        ``thought_id``.

        Returns the JSON-encoded ``list[Thought]`` (root + transitive
        descendants) ordered by ``(thought_depth ASC, thought_id ASC)``.
        Empty list when the root has no matching row (not an error).
        Uses a recursive CTE on both backends.
        """

    # ── v1.5.11 (CIRISPersist#59 #3) — service correlations substrate

    def correlation_record(self, correlation_json: str) -> None:
        """v1.5.11 — Record a correlation. INSERT-OR-IGNORE keyed on
        ``correlation_id``.

        ``correlation_json`` is a JSON-encoded ``Correlation`` shape
        (see the ``ciris_persist.correlations`` module). First writer
        wins; a re-record with the same ``correlation_id`` is a
        silent no-op (idempotent retry). State advancement is the
        caller's responsibility — use ``correlation_update_status``
        to advance an in-flight row.
        """

    def correlation_get(self, correlation_id: str) -> str | None:
        """v1.5.11 — Read one correlation by id. Returns the JSON-
        encoded ``Correlation`` row or ``None`` when no matching row.
        """

    def correlation_update_status(
        self,
        correlation_id: str,
        new_status: str,
        response_data_json: str | None,
    ) -> bool:
        """v1.5.11 — Focused status update + optional response_data
        merge.

        ``new_status`` is one of ``pending`` / ``active`` /
        ``completed`` / ``failed`` / ``cancelled``.
        ``response_data_json`` (when not None) is decoded and stored
        into the ``response_data`` column; ``None`` preserves the
        existing value.

        Returns ``True`` when a row was updated, ``False`` when no
        matching correlation exists (no error — caller treats as
        stale id).
        """

    def correlation_query(
        self,
        filter_json: str,
        cursor_json: str | None,
        limit: int,
    ) -> str:
        """v1.5.11 — Cursor-paged query. Returns JSON-encoded
        ``CorrelationListPage`` (``{"items": [...], "next_cursor":
        {...}|None}``). The filter shape mirrors
        ``CorrelationFilter`` — supported fields:
        ``service_type``, ``correlation_type``, ``trace_id``,
        ``metric_name``, ``retention_policy``,
        ``agent_occurrence_id``, ``timestamp_after`` /
        ``timestamp_before`` (event-time window),
        ``updated_after`` / ``updated_before`` (row-update window).
        Cursor pagination on ``(updated_at, correlation_id)``.
        """

    def trust_grant_consistency_proof(
        self,
        tenant_id: str,
        old_size: int,
        new_size: int,
    ) -> str:
        """Generate an RFC 6962 §2.1.2 consistency proof between two
        tree sizes for a tenant. Returns a JSON-encoded
        ``ConsistencyProof``."""
