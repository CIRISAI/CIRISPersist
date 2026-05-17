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

    def trust_grant_consistency_proof(
        self,
        tenant_id: str,
        old_size: int,
        new_size: int,
    ) -> str:
        """Generate an RFC 6962 §2.1.2 consistency proof between two
        tree sizes for a tenant. Returns a JSON-encoded
        ``ConsistencyProof``."""
