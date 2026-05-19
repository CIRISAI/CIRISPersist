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

    def task_upsert(self, task_json: str) -> str:
        """v1.5.9 — Idempotent upsert keyed on ``task_id``.

        ``task_json`` is a JSON-encoded ``Task`` shape (see the
        ``ciris_persist.tasks`` module). Re-insert with the same
        payload is a no-op; re-insert with differing payload
        overwrites the mutable columns and preserves ``created_at``.

        Returns the JSON-encoded ``TaskUpsertOutcome`` envelope
        ``{"outcome": "stored" | "already_exists", "task": <Task>}``
        (v1.5.22, CIRISPersist#61). ``stored`` carries the
        canonical post-upsert row (caller's ``task_id`` wins).
        ``already_exists`` carries the EXISTING row when the V036
        unique index on ``(agent_occurrence_id,
        context_json->>'correlation_id')`` would have been violated
        by a fresh ``task_id`` — caller reconciles to the canonical
        ``task_id``. The ``already_exists`` outcome only fires when
        ``context.correlation_id`` is set; rows without one insert
        normally as ``stored``.

        **Breaking change in v1.5.22:** prior versions returned
        ``None``. Callers that ignored the return value continue to
        work; callers that want dedup-detection use the new envelope.
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

        ``filter_json`` accepts (all optional): ``agent_occurrence_id``,
        ``status``, ``channel_id``, ``parent_task_id``,
        ``updated_after``, ``updated_before``, and as of v1.5.21
        (CIRISPersist#62) ``created_before`` / ``created_after``
        (RFC 3339 timestamps; emitted as SQL ``created_at < ?`` /
        ``created_at >= ?`` predicates so callers don't paginate
        whole occurrences and filter in Python).
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

        ``filter_json`` accepts (all optional): ``source_task_id``,
        ``status``, ``agent_occurrence_id``, ``parent_thought_id``,
        ``updated_after``, ``updated_before``, and as of v1.5.21
        (CIRISPersist#62) ``created_before`` / ``created_after``
        (RFC 3339 timestamps; SQL ``created_at`` range predicate
        emitted server-side).
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

    def thought_delete(self, thought_id: str) -> bool:
        """v1.5.20 (CIRISPersist#60) — Delete a thought by id.

        Returns ``True`` if a row was deleted, ``False`` on missing or
        already-deleted (idempotent). The self-FK on
        ``parent_thought_id`` rejects the delete with ``Conflict`` if
        children exist — caller deletes leaves-first or walks
        :meth:`thought_get_descendants` first. The cascade on
        ``source_task_id`` (V035) is the inverse direction:
        :meth:`task_delete` of a parent task automatically cascades
        its thoughts.
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

    # ── v1.5.12 (CIRISPersist#59 #4) — scheduled tasks substrate

    def scheduled_task_upsert(self, task_json: str) -> None:
        """v1.5.12 — Upsert a scheduled task. ``task_json`` is a
        JSON-encoded ``ScheduledTask`` (see the
        ``ciris_persist.scheduled_tasks`` module). INSERT on first
        call, UPDATE on conflict by ``id``. All columns except
        ``created_at`` overwrite on conflict; ``created_at`` is
        preserved.

        Note: the ``status`` field on the wire is lowercase
        snake_case (``"pending"`` / ``"active"`` / ``"complete"`` /
        ``"failed"``) while the SQL CHECK vocabulary is UPPERCASE
        — Rust handles the translation. ``origin_thought_id`` must
        reference an existing row in ``cirislens.thoughts`` (PG:
        DEFERRABLE FK; SQLite: immediate FK).
        """

    def scheduled_task_list_due(
        self,
        agent_occurrence_id: str,
        now_iso: str,
        limit: int,
    ) -> str:
        """v1.5.12 — Scheduler tick query. Returns JSON-encoded
        ``list[ScheduledTask]`` of tasks where
        ``next_trigger_at <= now`` AND status is ``PENDING`` or
        ``ACTIVE``, scoped to the given occurrence. Ordered ASC by
        ``next_trigger_at`` for fair scheduling. ``now_iso`` is
        RFC 3339; ``limit`` is the batch size (typical 100). Hits
        the ``scheduled_tasks_due`` partial index.
        """

    def scheduled_task_update_after_trigger(
        self,
        task_id: str,
        last_triggered_at_iso: str,
        next_trigger_at_iso: str | None,
        deferral_count: int,
        deferral_history_json: str | None = None,
        new_status: str | None = None,
    ) -> bool:
        """v1.5.12 — Post-fire bookkeeping. Updates
        ``last_triggered_at`` + ``next_trigger_at`` (None → NULL) +
        ``deferral_count``. Optional ``deferral_history_json``
        (None → preserve existing). Optional ``new_status`` advances
        the lifecycle (None → preserve existing); accepts lowercase
        snake_case wire format (``pending`` / ``active`` /
        ``complete`` / ``failed``).

        Returns ``True`` when a row was updated, ``False`` when no
        matching task exists (no error — caller treats as stale id).
        """

    # ── v1.5.13 (CIRISPersist#59 #5) — tickets substrate

    def ticket_upsert(self, ticket_json: str) -> None:
        """v1.5.13 — Upsert a ticket. ``ticket_json`` is a
        JSON-encoded ``Ticket`` (see the ``ciris_persist.tickets``
        module). INSERT on first call, UPDATE on conflict by
        ``ticket_id``. All columns except ``created_at`` and
        ``submitted_at`` overwrite on conflict; both creation-time
        columns are preserved.

        Note: the ``status`` field on the wire is lowercase
        snake_case 8-value (``"pending"`` / ``"assigned"`` /
        ``"in_progress"`` / ``"blocked"`` / ``"deferred"`` /
        ``"completed"`` / ``"cancelled"`` / ``"failed"``) — matches
        the SQL CHECK vocabulary directly. ``priority`` is 1-10
        (default 5). ``agent_occurrence_id`` default is
        ``"__shared__"`` (cross-occurrence work items).
        """

    def ticket_get(self, ticket_id: str) -> str | None:
        """v1.5.13 — Point lookup. Returns JSON-encoded ``Ticket`` or
        ``None`` when no matching row."""

    def ticket_list(
        self,
        filter_json: str,
        cursor_json: str | None,
        limit: int,
    ) -> str:
        """v1.5.13 — Cursor-paged query. Returns JSON-encoded
        ``TicketListPage`` (``{"items": [...], "next_cursor":
        {...}|None}``). The filter shape mirrors ``TicketFilter`` —
        supported fields: ``sop``, ``ticket_type``, ``status``,
        ``email``, ``agent_occurrence_id``, ``automated``,
        ``deadline_before`` (due-deadline scan; only tickets with a
        non-NULL deadline at or before this timestamp),
        ``last_updated_after`` / ``last_updated_before``
        (row-update window). Cursor pagination on
        ``(last_updated, ticket_id)``, newest-first.
        """

    def ticket_assign(
        self,
        ticket_id: str,
        user_identifier: str,
        new_status: str | None = None,
    ) -> bool:
        """v1.5.13 — Atomic assignment + status flip. Sets
        ``user_identifier`` to the supplied value, advances
        ``status`` (default ``assigned``, or caller-supplied via
        ``new_status`` — lowercase snake_case wire format), bumps
        ``last_updated`` to NOW. Idempotent on ``(ticket_id,
        user_identifier)``: re-assigning the same ticket to the same
        user is a no-op (returns True; the row is already in the
        assigned state). Returns ``False`` when no matching ticket.
        """

    def ticket_update_status(
        self,
        ticket_id: str,
        new_status: str,
        completed_at_iso: str | None = None,
        notes: str | None = None,
    ) -> bool:
        """v1.5.13 — Focused status update. ``new_status`` is the
        lowercase snake_case wire format. Optional
        ``completed_at_iso`` (RFC 3339) — on terminal-state
        transitions (``completed`` / ``cancelled`` / ``failed``)
        the caller supplies the timestamp; the trait doesn't enforce.
        Optional ``notes`` overwrites the existing value when
        supplied (``None`` preserves the existing value). Bumps
        ``last_updated`` to NOW.

        Returns ``True`` when a row was updated, ``False`` when no
        matching ticket (no error — callers treat as stale id).
        """

    # ── v1.5.14 (CIRISPersist#59 #6) — deferral_reports substrate

    def deferral_record(self, report_json: str) -> str:
        """v1.5.14 — Record a deferral report. ``report_json`` is a
        JSON-encoded ``DeferralReport`` (see the
        ``ciris_persist.deferral_reports`` module).

        Returns a JSON-encoded ClaimResult wire shape:
        ``{"outcome": "stored" | "already_claimed",
        "report": <DeferralReport>}``. The race winner sees
        ``"stored"`` and their own row; race losers see
        ``"already_claimed"`` and the EXISTING row.

        FK semantics: ``task_id`` must reference an existing row in
        ``cirislens.tasks``, and ``thought_id`` must reference an
        existing row in ``cirislens.thoughts``. PG: both FKs are
        DEFERRABLE INITIALLY DEFERRED so a single tx can write
        ``(task, thought, deferral_report)`` in order. SQLite: FKs
        are immediate; callers ensure parent rows exist before
        recording.
        """

    def deferral_get(self, message_id: str) -> str | None:
        """v1.5.14 — Point lookup. Returns JSON-encoded
        ``DeferralReport`` or ``None`` when no matching row."""

    def deferral_list_active(self, filter_json: str, limit: int) -> str:
        """v1.5.14 — WA queue: list deferrals awaiting resolution
        (``resolved_at IS NULL``), newest-first by ``created_at``.
        ``filter_json`` is a JSON-encoded ``DeferralFilter`` —
        supported fields: ``task_id``, ``thought_id``,
        ``created_after``, ``created_before`` (RFC 3339 timestamps).
        Returns JSON-encoded ``list[DeferralReport]``. Hits the
        partial index ``deferral_reports_active``.
        """

    def deferral_resolve(
        self,
        message_id: str,
        resolved_at: str,
        resolution_notes: str | None = None,
    ) -> bool:
        """v1.5.14 — Mark a deferral as resolved. Sets
        ``resolved_at`` (RFC 3339 ISO string) and
        ``resolution_notes`` (overwrites; ``None`` clears).

        Returns ``True`` when a row was updated, ``False`` when no
        matching row (no error — callers treat as stale id).
        """

    # ── v1.5.15 (CIRISPersist#59 #7) — maintenance_locks substrate

    def lock_try_acquire(
        self,
        lock_key: str,
        locked_by: str,
        timeout_seconds: int,
        metadata_json: str | None = None,
    ) -> str | None:
        """v1.5.15 — Atomic try-acquire of a named lock. Returns the
        JSON-encoded ``MaintenanceLock`` (race winner — clean
        acquire or steal-the-stale of an expired holder) or
        ``None`` (contention — held by another active caller; the
        caller should treat ``None`` as "try again later", NOT as
        an exception).

        Race-safe: implemented as a single-statement UPSERT with a
        WHERE clause that gates on
        ``locked_by IS NULL OR locked_by = caller OR locked_at +
        timeout < server_now``. PG uses ``NOW()`` server-side;
        SQLite uses ``julianday('now')`` server-side. Both stamp
        ``locked_at`` against the same server clock so the
        steal-vs-active decision is consistent.

        Same-holder re-acquire succeeds and refreshes
        ``lock_timeout_seconds`` + ``locked_at`` + ``metadata`` to
        the new caller-supplied values.

        ``metadata_json`` is an optional JSON-encoded payload (any
        valid JSON value: object, array, scalar). Stored verbatim
        in the row's ``metadata`` column for operator
        observability.
        """

    def lock_release(self, lock_key: str, locked_by: str) -> bool:
        """v1.5.15 — Release a lock IFF the caller still holds it.
        Returns ``True`` when the lock was cleared; ``False`` when
        the row doesn't exist or the row's ``locked_by`` doesn't
        match the supplied ``locked_by`` (no-op — caller treats
        ``False`` as "not yours to release").
        """

    def lock_get(self, lock_key: str) -> str | None:
        """v1.5.15 — Read current lock state. Returns the
        JSON-encoded ``MaintenanceLock`` or ``None`` when no row
        for ``lock_key`` exists. ``locked_by IS NULL`` AND
        ``locked_at IS NULL`` means the row exists but no caller
        currently holds the lock; callers also check ``locked_at
        + lock_timeout_seconds`` against wall-clock to decide if a
        present-but-expired holder is stealable.
        """

    # ── v1.5.16 (CIRISPersist#59 #8) — creation_ceremonies substrate

    def ceremony_record(self, ceremony_json: str) -> str:
        """v1.5.16 — Record a creation ceremony. ``ceremony_json``
        is a JSON-encoded ``CreationCeremony`` (see the
        ``ciris_persist.creation_ceremonies`` module). INSERT ON
        CONFLICT (ceremony_id) DO NOTHING — write-once shape.

        Returns a JSON-encoded ClaimResult object:
        ``{"outcome": "stored" | "already_claimed",
          "ceremony": <CreationCeremony>}``.
        The race winner sees ``"stored"`` and their own row; race
        losers see ``"already_claimed"`` and the EXISTING row
        (the loser's payload is discarded — write-once contract).
        """

    def ceremony_get(self, ceremony_id: str) -> str | None:
        """v1.5.16 — Point lookup. Returns JSON-encoded
        ``CreationCeremony`` or ``None`` when no matching row."""

    def ceremony_list(self, filter_json: str, limit: int) -> str:
        """v1.5.16 — History query. ``filter_json`` is a
        JSON-encoded ``CeremonyFilter`` — supported fields:
        ``creator_agent_id``, ``creator_human_id``,
        ``wise_authority_id``, ``new_agent_id``,
        ``ceremony_status`` (lowercase snake_case),
        ``timestamp_after``, ``timestamp_before`` (RFC 3339
        timestamps).

        Returns JSON-encoded ``list[CreationCeremony]`` ordered by
        ``(timestamp, ceremony_id)``, newest-first, limited.
        """

    def ceremony_update_status(
        self,
        ceremony_id: str,
        new_status: str,
    ) -> bool:
        """v1.5.16 — Atomic ceremony-status advance. ``new_status``
        is a lowercase snake_case string from the 5-value
        vocabulary (``pending`` | ``in_progress`` | ``completed`` |
        ``failed`` | ``revoked``).

        Returns ``True`` when a row was updated, ``False`` when no
        matching row (no error — callers treat as stale id).
        """

    # ── v1.5.17 (CIRISPersist#59 #9) — continuity_awareness substrate

    def continuity_record(self, record_json: str) -> str:
        """v1.5.17 — Record a shutdown event. ``record_json`` is a
        JSON-encoded ``ContinuityAwareness`` (see the
        ``ciris_persist.continuity_awareness`` module). INSERT ON
        CONFLICT (id) DO NOTHING — write-once shape.

        First substrate with a cross-substrate FK: the
        ``(preservation_node_id, preservation_scope)`` pair MUST
        reference an existing cirisgraph node row. A missing parent
        surfaces as ``Conflict``.

        Returns a JSON-encoded ClaimResult object:
        ``{"outcome": "stored" | "already_claimed",
          "record": <ContinuityAwareness>}``.
        The race winner sees ``"stored"`` and their own row; race
        losers see ``"already_claimed"`` and the EXISTING row.
        """

    def continuity_get_latest(self, agent_id: str) -> str | None:
        """v1.5.17 — Get the most recent shutdown for an agent —
        used on next boot to surface "where did I leave off."
        Returns JSON-encoded ``ContinuityAwareness`` or ``None``
        when the agent has no recorded shutdowns. Ordered by
        ``shutdown_timestamp DESC``, ``LIMIT 1``.
        """

    def continuity_record_reactivation(self, agent_id: str) -> bool:
        """v1.5.17 — Increment ``reactivation_count`` on the
        most-recent non-terminal shutdown for ``agent_id``. Used
        when the agent successfully resumes from a non-terminal
        shutdown.

        Returns ``True`` when a row was updated, ``False`` when the
        agent has only terminal shutdowns or no shutdowns at all
        (callers treat as "nothing to reactivate" — not an error).
        """

    # ── v1.5.18 (CIRISPersist#59 #10) — feedback_mappings substrate

    def feedback_record(self, feedback_json: str) -> str:
        """v1.5.18 — Record a feedback row. ``feedback_json`` is a
        JSON-encoded ``FeedbackMapping`` with 5 fields:
        ``feedback_id`` (PK, required), ``source_message_id``
        (optional wire-message id), ``target_thought_id`` (optional
        FK to ``cirislens.thoughts``), ``feedback_type`` (free-form
        string — agent uses ``approval`` / ``correction`` /
        ``clarification``), ``created_at`` (RFC 3339 timestamp).
        INSERT ON CONFLICT (feedback_id) DO NOTHING — write-once
        shape.

        FK semantics: when ``target_thought_id`` is non-NULL the
        referenced thought MUST exist or the call returns
        ``Conflict``. NULL ``target_thought_id`` bypasses the FK on
        both backends.

        Returns a JSON-encoded ClaimResult object:
        ``{"outcome": "stored" | "already_claimed",
          "feedback": <FeedbackMapping>}``.
        The race winner sees ``"stored"`` and their own row; race
        losers see ``"already_claimed"`` and the EXISTING row.
        """

    def feedback_list_for_thought(self, thought_id: str, limit: int) -> str:
        """v1.5.18 — List feedback rows attached to a specific
        thought. Ordered ``created_at DESC, feedback_id DESC``.
        Returns JSON-encoded ``list[FeedbackMapping]``. Hits the
        partial index ``feedback_mappings_thought``.
        """

    def feedback_list(self, filter_json: str, limit: int) -> str:
        """v1.5.18 — Filter-query feedback rows. ``filter_json`` is a
        JSON-encoded ``FeedbackFilter`` — supported fields:
        ``source_message_id``, ``feedback_type``, ``created_after``,
        ``created_before`` (RFC 3339 timestamps for the time
        window). Returns JSON-encoded ``list[FeedbackMapping]``,
        ordered DESC by ``created_at``.
        """

    # ── v1.5.19 (CIRISPersist#59 #11, FINAL) — wa_cert substrate

    def wa_cert_upsert(self, cert_json: str) -> None:
        """v1.5.19 — Idempotent upsert of a WA cert. ``cert_json`` is
        a JSON-encoded ``WaCert`` with 24 fields: ``wa_id`` (PK,
        required), ``name`` (required), ``role`` (required;
        ``root`` | ``authority`` | ``observer``), ``pubkey``
        (required), ``jwt_kid`` (required, UNIQUE across the
        directory), ``password_hash``, ``api_key_hash``,
        ``oauth_provider``, ``oauth_external_id``, ``oauth_links``
        (JSON object), ``veilid_id``, ``auto_minted`` (bool,
        default False), ``parent_wa_id`` (self-FK; nullable),
        ``parent_signature``, ``scopes`` (JSON array, required),
        ``custom_permissions`` (JSON object), ``adapter_id``,
        ``adapter_name``, ``adapter_metadata`` (JSON object),
        ``token_type`` (``standard`` | ``session`` | ``api_key`` |
        ``oauth`` | ``service``; default ``standard``), ``created``
        (RFC 3339, required, PRESERVED across upserts),
        ``last_login`` (RFC 3339, nullable), ``active`` (bool,
        default True).

        UPSERT on ``wa_id`` — every column except ``wa_id`` +
        ``created`` overwrites on conflict. Duplicate ``jwt_kid``
        across different ``wa_id``s raises ``Conflict``; non-NULL
        ``parent_wa_id`` referencing a missing parent raises
        ``Conflict``.
        """

    def wa_cert_get(self, wa_id: str) -> str | None:
        """v1.5.19 — Point lookup by ``wa_id``. Returns JSON-encoded
        ``WaCert`` or ``None`` when no row matches.
        """

    def wa_cert_get_by_kid(self, jwt_kid: str) -> str | None:
        """v1.5.19 — JWT verification hot path. Lookup by
        ``jwt_kid`` via the unique ``wa_cert_jwt_kid`` index.
        Returns JSON-encoded ``WaCert`` or ``None``.
        """

    def wa_cert_get_by_oauth(
        self, oauth_provider: str, oauth_external_id: str
    ) -> str | None:
        """v1.5.19 — OAuth login path. Lookup by
        ``(oauth_provider, oauth_external_id)`` via the partial
        ``wa_cert_oauth`` index. Returns JSON-encoded ``WaCert`` or
        ``None``.
        """

    def wa_cert_list_by_role(self, role: str, limit: int) -> str:
        """v1.5.19 — Role-based listing. ``role`` is the lowercase
        SQL string (``root`` | ``authority`` | ``observer``).
        Returns JSON-encoded ``list[WaCert]`` of certs with
        ``active = True`` filtered by role. Ordered
        ``created DESC, wa_id DESC``. Hits the partial
        ``wa_cert_role_active`` index.
        """

    def wa_cert_set_active(self, wa_id: str, active: bool) -> bool:
        """v1.5.19 — Activity toggle. Sets ``active`` to the
        supplied value. Returns ``True`` if the row exists
        (idempotent for same-value toggles); ``False`` if ``wa_id``
        doesn't exist.
        """

    def wa_cert_update_last_login(
        self, wa_id: str, login_time_iso: str
    ) -> bool:
        """v1.5.19 — Last-login bookkeeping. ``login_time_iso`` is
        an RFC 3339 timestamp string. Returns ``True`` if the row
        was updated; ``False`` if ``wa_id`` doesn't exist.
        """

    # ── v1.5.23 (CIRISPersist#64) — service-token revocation substrate

    def service_token_revocation_record(self, revocation_json: str) -> None:
        """v1.5.23 (CIRISPersist#64) — Record a service-token revocation.

        Idempotent on ``token_hash`` (PK; ON CONFLICT DO NOTHING).
        First record wins. ``revocation_json`` is a JSON-encoded
        ``RevokedServiceToken`` shape:
        ``{"token_hash": "...", "revoked_at": "<rfc3339>", "revoked_by": "...", "reason": "..."}``.
        All four fields required (non-empty).

        Replaces CIRISAgent's standalone ``revoked_service_tokens.db``
        aiosqlite file — last aiosqlite consumer in the agent.
        """

    def service_token_revocation_list(self) -> str:
        """v1.5.23 (CIRISPersist#64) — List ALL revoked tokens.

        Returns the JSON-encoded ``list[RevokedServiceToken]``.
        Agent caches in memory on startup; this method runs once at
        boot. Order unspecified (caller indexes by token_hash).
        """

    def service_token_revocation_check(self, token_hash: str) -> str | None:
        """v1.5.23 (CIRISPersist#64) — Point-lookup check.

        Returns the JSON-encoded ``RevokedServiceToken`` row if
        revoked, ``None`` otherwise. Backed by the PRIMARY KEY index.
        """

    # ── v1.5.24 (CIRISPersist#66) — agent-detected secret store ─────

    def secrets_store_detected_secret(
        self,
        payload_json: str,
        accessor: str,
    ) -> str:
        """v1.5.24 (CIRISPersist#66) — Store an agent-detected secret
        with a **caller-supplied UUID** + full metadata bundle.

        ``payload_json`` is a JSON-encoded ``DetectedSecret`` shape:

        .. code-block:: json

            {
              "secret_uuid": "<uuid-v4>",
              "value": "<plaintext>",
              "description": "...",
              "sensitivity": "low" | "medium" | "high" | "critical",
              "detected_pattern": "regex:openai_key_v1",
              "context_hint": "in tool_args.api_key",
              "source_message_id": "msg-123",
              "auto_decapsulate_for_actions": ["tool"],
              "manual_access_only": false
            }

        Returns the JSON envelope
        ``{"outcome": "stored" | "already_claimed", "ref": <SecretReference>}``.

        ``stored`` — clean insert under the caller's UUID.
        ``already_claimed`` — same plaintext exists (content_hmac
        match across any caller path). The returned ``ref`` may
        carry a **different** ``uuid`` than the caller supplied —
        agent reconciles to the canonical id.

        Distinct from :meth:`secrets_store_secret` (manually-keyed;
        persist generates the UUID; no detection metadata) and
        :meth:`secrets_process_incoming_text` (persist's regex
        catalog detects; agent has no UUID control).

        Raises:
            ValueError: empty ``secret_uuid`` / ``value`` /
                ``detected_pattern`` / ``description``, malformed
                UUID, or ``secret_uuid`` already in use for a
                *different* plaintext (agent UUID-allocation bug).
            RuntimeError: backend / IO error.

        Replaces the agent-side ``SecretRecord`` write path in
        CIRISAgent ``secrets/store.py`` for the 2.9.0 Phase 2a
        cutover.
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
