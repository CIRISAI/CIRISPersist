"""Type stubs for the Rust-built ``ciris_persist`` extension module.

Mission alignment (PLATFORM_ARCHITECTURE.md §3.5): mypy / pyright
support is part of the Phase 1 surface — the lens FastAPI codebase
already runs strict type checking, and these stubs keep ciris-persist
inside that envelope.

**This stub is READ.** Since CIRISPersist#581 the wheel ships a PEP 561
``py.typed`` marker, so a checker no longer skips the package and infers
``Any``: it believes what is written here. An omitted method is reported to
a consumer as *not existing*, for API that works. ``scripts/pyi_surface.py
check`` fails the build if any PyO3-exported symbol is missing
(CIRISPersist#595).

**Complete is not correct.** Parameter names, arity, defaults and types are
DERIVED from ``src/ffi/``: authoritative for the FFI boundary, because PyO3
generates the conversion from exactly those Rust types. What is *not*
verified is meaning — ``-> str`` is true and says nothing about the JSON
schema inside the string. Entries marked ``(derived)`` carry that weaker
claim; hand-written entries carry more.

The taxonomy
------------
Members are grouped by **what different kind of wrong happens if you vary
them** (CIRISConstitution#83), not by name shape. Four groups are BINDING;
the rest are descriptive.

====================  ========  ==================================================
group                 force     varying one of these...
====================  ========  ==================================================
``structural``        BINDING   breaks the process, the handle, or dispatch
``deontic``           BINDING   changes what the mesh permits — a security finding
``testimonial``       BINDING   makes the record unable to prove what happened
``axiomatic``         BINDING   changes the premise two repos cross-check
``ontological``       descr.    changes who this node / key / identity IS
``nomological``       descr.    changes the model every other symbol reasons under
``epistemic``         descr.    changes how uncertainty is held — bands, absence
``empirical``         descr.    makes a checkable, re-derivable world-fact wrong
``axiotic``           descr.    re-ranks outcomes without newly permitting an act
``procedural``        descr.    changes orchestration — when and by whom
``pragmatic``         descr.    changes register or address, not content
====================  ========  ==================================================

The pin is ``scripts/ffi_taxonomy.tsv``, one reviewed row per symbol, so a
reclassification is a visible one-line diff rather than an edit nobody sees.

**One hazard the ``deontic`` group exists to make loud**: the ``*_json``
adjudicators return a JSON string on BOTH arms, so the refusal
``'{"eligible": false}'`` is TRUTHY.
``if engine.resolve_transit_eligibility_json(...)`` permits exactly what the
method refused. Parse the string; never truth-test it.
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

class PersistError(Exception):
    """v1.0.0-scaffold (CIRISPersist#194) — base of the typed
    retry-policy hierarchy. A consumer's HTTP layer dispatches its
    retry / status-code policy off the subclass, not off a string."""

class NotFound(PersistError):
    """The addressed row does not exist. Terminal — do not retry."""

class Conflict(PersistError):
    """A uniqueness, FK, or optimistic-concurrency constraint refused
    the write. Terminal for the same payload; the caller re-reads."""

class Transient(PersistError):
    """A backend / IO condition that may clear on its own. Retryable."""

class Permanent(PersistError):
    """The operation cannot succeed as issued. Never retry."""

class EngineConfigMismatch(PersistError):
    """v1.6.8 (CIRISPersist#75-78) — ``Engine(...)`` was constructed a
    second time in this process with a DIFFERENT config. The
    process-singleton is already built; there is no second runtime."""

class EngineClosed(PersistError):
    """v1.6.8 (CIRISPersist#77) — a method was called after
    :meth:`Engine.close`. Every handle shares the closed flag."""

class EngineUsedAcrossFork(PersistError):
    """v1.6.8 (CIRISPersist#78) — the engine was constructed before a
    ``fork()`` and used in the child. A tokio runtime does not survive
    a fork; construct ``Engine`` after all forking is done."""

class BatchSummary(TypedDict):
    """Result shape from :meth:`Engine.receive_and_persist`."""
    envelopes_processed: int
    trace_events_inserted: int
    trace_events_conflicted: int
    trace_llm_calls_inserted: int
    scrubbed_fields: int
    signatures_verified: int

ScrubberCallable = Callable[[dict[str, Any]], tuple[dict[str, Any], int]]

# --- pyi_surface: BEGIN GENERATED REGION ---


class Engine:
    """Process-singleton handle to the Rust persistence pipeline.

    v1.6.8 (CIRISPersist#75-78): the tokio runtime + connection pool
    are built **exactly once per process**. Constructing ``Engine``
    again with the same config returns a cheap handle to the
    existing engine — no second runtime. A different config raises
    :class:`EngineConfigMismatch`.

    In-process cohabitation contract (CIRIS 3.0 — agent + NodeCore +
    LensCore in one process):

    - One owner constructs ``Engine(...)`` first; adapters attach by
      constructing with the **same** config.
    - The owner calls :meth:`close` at shutdown; adapters do not.
      Use after :meth:`close` raises :class:`EngineClosed`.
    - Construct ``Engine`` **after** all forking is done — a tokio
      runtime does not survive ``fork()``. Use across a fork raises
      :class:`EngineUsedAcrossFork`.

    See ``docs/COHABITATION.md`` for the full doctrine.
    """

    # ==============================================================
    # STRUCTURAL  (BINDING)
    # Varying one of these breaks the process, the handle, or dispatch — the machine stops working.
    # ==============================================================

    def __init__(
        self,
        dsn: str,
        signing_key_id: str,
        scrubber: ScrubberCallable | None = None,
        local_key_id: str | None = None,
        local_key_path: str | None = None,
        local_pqc_key_id: str | None = None,
        local_pqc_key_path: str | None = None,
        identity_dir: str | None = None,
        keystore_alias: str | None = None,
        create_identity_if_missing: bool = False,
        pqc_sweep_on_init: bool = True,
        replication_sweeper_enabled: bool = True,
        cache_mode: str | None = None,
        max_cache_bytes: str | None = None,
        cache_ttl_seconds: int | None = None,
        disk_pressure: Any = None,
    ) -> None:
        """Build (or attach to) the process-singleton engine.

        IDENTITY — two ways, and production wants the first.

        ``identity_dir`` + ``keystore_alias`` (CIRISPersist#616) resolve **this
        node's own** identity from its keystore, so no key material crosses the
        boundary::

            Engine(dsn, signing_key_id,
                   identity_dir="/var/lib/ciris/identity",
                   keystore_alias="ciris-agent-bootstrap")

        The classical half is opened from its sealed blob (TPM / Secure Enclave /
        StrongBox, or software-encrypted); the ML-DSA-65 half is read from
        ``<identity_dir>/ml_dsa_65.seed`` if present, and its absence is not fatal
        — no TPM does ML-DSA, and a classical-only node is refused by the
        federation-tier ingest gate, not by this constructor.

        **A missing identity is an ERROR, not a new identity.** This path uses the
        keystore's ``open_existing``, never ``open_or_create``: minting on a
        missing seed is how a node silently acquires a SECOND identity, which is
        CIRISAgent#1009 and CIRISServer#380 (71 hours between them). Pass
        ``create_identity_if_missing=True`` only from a provisioning tool that
        intends to create one; a booting node never should.

        **There are no classical-only paths (CIRISPersist#620).** A missing
        ``ml_dsa_65.seed`` is an ERROR, not a silently classical-only node, and
        there is deliberately no ``allow_classical_only`` opt-in — the state does
        not make sense in CIRIS, so it is not something a caller may request.
        ``create_identity_if_missing=True`` mints BOTH halves or fails naming
        what it could not create: "create my identity" never means "create half
        of it."

        ``local_key_id`` + ``local_key_path`` remain for tests and harnesses. They
        take a 32-byte **bare** Ed25519 seed, which a keystore-custodied node does
        not have — its plaintext seed is archived to ``ed25519.seed.migrated``
        once adopted. Passing both pairs is refused: a node has one identity.

        ``signing_key_id`` is REQUIRED — persist instantiates the scrub-signing
        key through ciris-keyring, generating it if absent and returning the
        existing one otherwise. This stub previously declared only
        ``(dsn, scrubber=None)``, which made a checker reject every correct
        construction; CIRISPersist#595.

        ``cache_mode`` is ``"proxy" | "cache" | "server"``; ``max_cache_bytes``
        takes a human string (``"10GB"``, ``"500MiB"``). Resolution order is
        kwarg > environment > mode default (CIRISPersist#148 §3).

        ``disk_pressure`` is a dict of
        ``{warn_free_bytes, crit_free_bytes, stop_free_bytes,
        host_at_risk_bytes, poll_interval, monitor_path}``. Passing one — even
        ``{}`` — ACTIVATES the monitor with its tiers on (CIRISPersist#149).

        Constructing again with the same config returns a cheap handle to the
        existing engine. A different config raises
        :class:`EngineConfigMismatch`; use after a ``fork()`` raises
        :class:`EngineUsedAcrossFork`.
        """

    def blob_storage_capsule(self) -> Any:
        """v2.11.0 (CIRISPersist#115) — the shared blob-storage substrate as a
        ``PyCapsule``.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def close(self, force: bool = False) -> None:
        """v1.6.8 (CIRISPersist#77) — deterministic teardown.

        Flips the process-singleton's closed flag (every ``Engine``
        handle shares it) and clears the global slot so a later
        ``Engine(...)`` rebuilds. Idempotent. Only the lifecycle
        owner should call this; in-process adapters attach and
        detach but never close. After ``close()`` every method
        raises :class:`EngineClosed`.

        v1.7.0 (CIRISPersist#80): refuses with ``RuntimeError`` if
        any consumer is still registered (see
        :meth:`register_consumer`). Pass ``force=True`` to close
        regardless — for a hard process shutdown.
        """

    def close_blocking(
        self, timeout_seconds: float = 10.0, force: bool = False
    ) -> str:
        """v24.3.0 (CIRISPersist#572) — close and WAIT for teardown.

        The bounded-wait sibling of :meth:`close`. Returns a token
        naming what actually happened:

        * ``"drained"`` — the tokio runtime and the backend pool are
          fully wound down; nothing of this engine is still running.
        * ``"deferred"`` — other live ``Engine`` handles (or an
          operation still in flight on another thread) still
          reference the cell, so teardown could not complete here.
          It will finish when the last reference goes; poll with
          :func:`engine_teardown_wait`.
        * ``"timed_out"`` — teardown is still running after
          ``timeout_seconds``.
        * ``"no_engine"`` — nothing was pinned; a no-op.

        **Check the return value.** A ``"deferred"`` that a caller
        reads as success is how a test suite ends up asserting
        against a half-torn-down engine.

        The wait happens with the GIL RELEASED, so a watchdog thread
        (pytest-timeout's thread method) can still fire while it
        runs — that is the whole point of #572.
        """

    @property
    def consumer_count(self) -> int:
        """v1.7.0 (CIRISPersist#80) — number of registered
        consumers. :meth:`close` (without ``force``) refuses while
        this is non-zero."""

    def deregister_consumer(self, name: str) -> bool:
        """v1.7.0 (CIRISPersist#80) — deregister a consumer on its
        teardown. Returns ``True`` if it was registered. Idempotent.
        """

    def directory_ops_capsule(self) -> Any:
        """v11.6.0 (CIRISPersist#320) — the ABI-STABLE successor to
        :meth:`federation_directory_capsule`. Serialised-op handle, so the two
        cdylibs never share a Rust vtable layout. Prefer this one.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def engine_handle(self) -> Engine:
        """v1.7.0 (CIRISPersist#79) — return a fresh handle to the
        process-singleton engine.

        Cheap ``Arc``-clone — shares the runtime, pool, signer,
        closed flag, and consumer registry. The lifecycle owner uses
        this to hand the engine to an in-process adapter (NodeCore,
        LensCore) explicitly ("injected engine, first parameter")
        without the adapter needing the DSN / signing key.
        """

    def executor_capsule(self) -> Any:
        """v3.13.0 (CIRISPersist#157) — the ABI-stable async-executor handle.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def federation_directory_capsule(self) -> Any:
        """v2.7.0 (CIRISPersist#109) — the shared ``Arc<dyn FederationDirectory>``
        as a ``PyCapsule``, so an in-process adapter reads the SAME directory
        this engine writes rather than opening a second one.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    @property
    def is_closed(self) -> bool:
        """v1.6.8 — ``True`` once :meth:`close` has run on this
        engine (or any handle sharing its singleton cell)."""

    def keyring_signer_capsule(self) -> Any:
        """v2.7.0 (CIRISPersist#109) — the federation keyring signer handle as a
        ``PyCapsule``.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def list_consumers(self) -> str:
        """v1.7.0 (CIRISPersist#80) — JSON snapshot of the attached-
        consumer registry: ``{name: {"substrates": [...],
        "registered_at": "<rfc3339>"}}``. Diagnostics — "who is
        using persist right now."
        """

    def list_subscriptions(self) -> str:
        """v1.9.0 (CIRISPersist#84) — JSON snapshot of the change-feed
        subscription registry: ``{"<id>": "<substrate>", ...}``."""

    def local_signer_capsule(self) -> Any:
        """v3.1.1 (CIRISPersist#119) — the agent's transport-identity
        ``LocalSigner`` as a ``PyCapsule``.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def outbound_queue_capsule(self) -> Any:
        """v2.7.0 (CIRISPersist#109) — the shared outbound-queue substrate as a
        ``PyCapsule``.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def outbound_queue_ops_capsule(self) -> Any:
        """v11.7.0 (CIRISPersist#320) — the ABI-STABLE successor to
        :meth:`outbound_queue_capsule`. Prefer this one.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def publish_change(self, substrate: str, event_json: str) -> int:
        """v1.9.0 (CIRISPersist#84) — publish a change event to every
        callback subscribed to ``substrate``; returns the number of
        callbacks invoked.

        ``event_json`` is an opaque JSON string (the wire shape is a
        producer/subscriber contract; persist does not parse it).
        Dispatch is synchronous and in-process: every matching
        callback runs, in subscription-id order, before this returns.
        A callback that raises is caught and logged — the exception
        does not propagate here and does not stop the other
        callbacks. No persistence/replay: a subscriber attaching after
        a publish does not see that event.
        """

    def register_consumer(
        self, name: str, substrates: list[str] | None = None
    ) -> None:
        """v1.7.0 (CIRISPersist#80) — register an attached consumer.

        In-process adapters call this on bring-up. ``substrates``
        declares the substrate families the consumer owns (e.g.
        ``["cirisnode"]``). Idempotent — re-registering an existing
        ``name`` updates its substrate list. While any consumer is
        registered, :meth:`close` refuses without ``force=True``.

        v1.7.4 (CIRISPersist#82) — each declared substrate name is
        validated against the known persist substrate-family set
        (``cirislens``, ``cirislens_secrets``, ``cirislens_derived``,
        ``cirisgraph``, ``cirisnode``); an unknown name raises
        ``ValueError``.

        v1.7.5 — ``name`` longer than 256 bytes raises ``ValueError``;
        registering a new consumer when the shared registry already
        holds 64 raises ``RuntimeError`` (a leak guard). Registering
        on a closed engine raises ``EngineClosed``.
        """

    def runtime_handle_capsule(self) -> Any:
        """v2.8.0 (CIRISPersist#111) — a clone of the engine's own
        ``tokio::runtime::Handle``, so a cohabiting cdylib schedules onto the
        one runtime this process has instead of building a second.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def set_perceptual_hash_matcher(self, matcher: Any) -> None:
        """v3.6.0 (CIRISPersist#134) — install a Python-side perceptual-hash
        matcher on the backend.

        Structural because it replaces a dispatch target inside the engine:
        every later media-admission call runs through whatever is installed
        here, and an object that does not implement the expected callable
        shape fails at the call site, not at install time.

        **Build-conditional** — present only in wheels built with the
        ``cirisnode`` Cargo feature. Guard with ``hasattr``.
        """

    def signer_ops_capsule(self) -> Any:
        """v11.7.0 (CIRISPersist#320) — the **SECURITY-CRITICAL** ABI-stable
        successor to :meth:`keyring_signer_capsule`. This hands another cdylib
        the ability to SIGN AS THIS NODE. Prefer this one; hand it to nothing
        that is not part of the same process's CIRIS stack.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def subscribe(
        self, substrate: str, callback: Callable[[str, str], object]
    ) -> int:
        """v1.9.0 (CIRISPersist#84) — register a change-feed callback.

        ``callback`` is invoked as ``callback(substrate, event_json)``
        each time a producer calls :meth:`publish_change` for
        ``substrate``. ``substrate`` must be a known substrate family
        (``cirislens``, ``cirislens_secrets``, ``cirislens_derived``,
        ``cirisgraph``, ``cirisnode``) — an unknown name raises
        ``ValueError``. Returns an opaque subscription id for
        :meth:`unsubscribe`.
        """

    @property
    def subscription_count(self) -> int:
        """v1.9.0 (CIRISPersist#84) — number of live change-feed
        subscriptions."""

    def substrate_owner(self, substrate: str) -> str | None:
        """v1.7.4 (CIRISPersist#82) — name of the registered consumer
        that declared ownership of ``substrate``, or ``None`` if none
        does. Cooperative, advisory check — persist does not hard-
        reject foreign writes under the singleton engine. If multiple
        consumers declared it, the lexicographically-first name wins.
        """

    def trust_scoring_capsule(self) -> Any:
        """v3.5.1 (CIRISPersist#129) — the ``Arc<dyn TrustScoring>`` from the
        currently-installed admission gate.

        **Not a Python object.** The capsule is an opaque C-ABI handle whose
        only legal consumer is another CIRIS cdylib in THIS process. Passing it
        anywhere else, or holding it past :meth:`close`, is undefined behaviour
        at the C level — CIRISPersist#320 was exactly this class (a raw
        ``Arc<dyn>`` vtable whose order the compiler does not guarantee, which
        hung the process rather than erroring).
        """

    def unsubscribe(self, subscription_id: int) -> bool:
        """v1.9.0 (CIRISPersist#84) — remove a change-feed callback by
        the id :meth:`subscribe` returned. ``True`` if it was
        registered. Idempotent."""


    # ==============================================================
    # DEONTIC  (BINDING)
    # Varying one of these changes what the mesh permits — a wrong entry here is a security finding.
    # ==============================================================

    def accord_nonce_issued(self, family_key_id: str, nonce: str) -> bool:
        """(derived) deontic — #302 (M4) — has (family_key_id, nonce) been issued?"""

    def add_community_member(self, community_key_id: str, member_json: str) -> bool:
        """(derived) deontic — #249 Cut B — incrementally add one member to a community roster (mirror of add_family_member). member_json is a [crate::federation::types::Communit..."""

    def add_moderator(self, community_id: str, moderator_key_id: str, duty: str) -> str:
        """(derived) deontic — v9.3.0 (#249, §11.10/§11.11) — appoint moderator_key_id a named moderator of community_id for duty (moderate/takedown/ review). Admissible IFF the..."""

    def add_peer_record_json(self, payload_json: str) -> None:
        """(derived) deontic — Federation directory: add a peer record. Atomically inserts a federation_keys identity row + a federation_peer_metadata row with default trust = "u..."""

    def adopt_scrub_upgrade(
        self,
        signed_key_record_json: str,
    ) -> str:
        """v12.2.0 (CIRISPersist#351) — adopt-scrub-**upgrade** this node's
        own key row: replace its self-signed record with the
        accord-anchor-scrubbed one (same `key_id` + pubkey) so it can root.
        FFI mirror of the Rust `Engine.adopt_scrub_upgrade`.

        `signed_key_record_json` is the granting-authority-scrubbed
        `SignedKeyRecord` (`scrub_key_id` = an accord holder). Verifies the
        scrub-signature (Strict, same gate as `register_federation_key`)
        THEN the backend's monotonic gated UPDATE.

        Returns:
            ``"upgraded"`` or ``"already_adopted"``.

        Raises:
            ValueError: JSON decode failure, verification failure, pubkey
                change, anchored-to-a-different-record, or missing row.
            RuntimeError: backend / IO error.
        """

    def apply_replicated_accord_evidence(self, evidence_json: str) -> str:
        """(derived) deontic — v31.1.0 (CIRISPersist#662) — admit one replicated accord evidence bundle (JSON, as list_signed_accord_quorum_evidence_since returns its elements) b..."""

    def apply_replicated_key_record(
        self,
        signed_key_record_json: str,
    ) -> str:
        """v13.0.0 (CIRISPersist#371) — **upgrade-aware replicated
        Key-plane apply**. FFI mirror of the Rust
        `Engine.apply_replicated_key_record` — the apply the replication
        bridge routes `apply_key` to instead of raw `put_public_key`
        (which keeps its insert-only semantics for direct registration).

        `signed_key_record_json` is the replicated `SignedKeyRecord`.

        Returns:
            ``"inserted"`` — new key_id, stored with every put_public_key
            admission gate intact; ``"upgraded"`` — the existing
            self-signed row adopted the anchor-scrubbed record (same
            hybrid pubkeys, scrub Strict-verified against the
            directory-resolved scrubber, and the v12.6.0
            ``owner_of(key_id)`` gate resolved exactly one live owner);
            ``"unchanged"`` — byte-identical re-apply; ``"refused"`` —
            pubkey swap / anchored-to-self downgrade / re-scrub /
            conflicting version / unverifiable scrub / unowned or
            ambiguous owner (fail-closed; the existing row is untouched).
            Refusals are outcomes, not exceptions, so an apply loop stays
            total over unsolicited records.

        Raises:
            ValueError: SignedKeyRecord JSON decode failure or a
                malformed record no policy can classify.
            RuntimeError: backend / IO error.
        """

    def attestation_promote(self, attestation_id: str, cohort_scope: str) -> bool:
        """(derived) deontic — v4.9.0 (CIRISPersist#171 phase 2, CEG §10.1.5) — promote a local-tier self-attestation to federation tier: the local→public transition the agent's..."""

    def bake_assembled_genesis(self, bundle_json: str) -> str:
        """(derived) deontic — v19.1.0 (CIRISPersist#490) — bake an assembled genesis trust-root bundle (the ceremony artifact JSON, the operator-saved genesis_v2.json). Verifies... [build-conditional: #[cfg(any(feature = "postgres", feature = "sqlite"))]]"""

    def blackhole_prune_expired_iso(self, now_iso: str) -> int:
        """(derived) deontic — Federation blackhole rules: drop every rule whose until is in the past relative to now_iso. Permanent rules (until IS NULL) are NEVER pruned. Retur..."""

    def blackhole_record_hit(self, identity_hash: bytes) -> None:
        """(derived) deontic — Federation blackhole rules: increment the hit counter for a rule. Race-tolerant: silent no-op when no rule exists for identity_hash."""

    def blackhole_remove(self, identity_hash: bytes) -> None:
        """(derived) deontic — Federation blackhole rules: drop a rule. Silent no-op when the identity isn't in the table (POSIX rm -f ergonomics)."""

    def blackhole_upsert(self, identity_hash: bytes, until_iso: str | None, reason: str | None) -> None:
        """(derived) deontic — Federation blackhole rules: insert or revise a rule."""

    def build_corpus_want_v1(self, payload_json: str) -> str:
        """(derived) deontic — #356 — build a signed CorpusWantV1 wire JSON from a payload JSON. payload_json carries {node_id, epoch_id, cohort_scope, size_cap_bytes, remaining_..."""

    def build_storage_budget_v1(self, payload_json: str) -> str:
        """(derived) deontic — #356 (CC 6.1.5.2 §Q / CIRISVerify#170) — build a signed StorageBudgetV1 wire JSON from a payload JSON, bound-hybrid signing its CC 6.1.3 preimage w..."""

    def check_no_moderator_federate_json(self, community_id: str) -> str:
        """v13.0.0 (CIRISPersist#369, CC 4.5.4 / §11.11) — the directly drivable
        **no-moderator-no-federate admission verdict** for one community: exactly
        the decision the federation-apply gate makes inside every backend's
        ``put_attestation``.

        Returns the verdict as JSON. **Both arms are truthy strings**; parse it.
        This is a read of the same predicate the write path enforces, so a
        consumer that truth-tests it will believe a community may federate when
        the engine will refuse the write.
        """

    def cirisnode_cast_vote(self, envelope_json: str) -> None:
        """(derived) deontic — v0.7.0 — Verify-and-insert a Vote envelope. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_process_takedown_admission_json(
        self, notice_payload_json: str, signer_key_id: str, now_iso: str
    ) -> str:
        """v3.6.0 (CIRISPersist#134) — run the takedown-admission orchestration
        over a JSON ``TakedownNoticePayload``, consulting the installed
        ``MultimediaConfig`` (or persist's defaults when none is installed) for
        the immediate-eviction decision and the counter-notice window.

        Returns the admission outcome as JSON — **a truthy string on the refusal
        arm too**. This one both DECIDES and ACTS: a caller who mis-reads the
        verdict may re-drive it and evict content twice.
        """

    def cirisnode_put_key_grant_json(self, envelope_json: str) -> None:
        """(derived) deontic — v16 (CIRISPersist#432, CC 5.1 CLM-epoch-keying) — the dedicated key_grant WRITER; the emission half of [cirisnode_list_key_grants_for_stream_epoch_... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_moderation_event(self, event_json: str) -> None:
        """(derived) deontic — v0.7.0 — Verify-and-insert a ModerationEvent. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_promotion_attestation(self, att_json: str) -> None:
        """(derived) deontic — v0.7.2 (CIRISPersist#32) — Verify-and-insert a PromotionAttestation AND transactionally flip the named target rows' is_canonical to TRUE. Caller pa... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_reconsideration_attestation(self, att_json: str) -> None:
        """(derived) deontic — v0.7.0 — Verify-and-insert a ReconsiderationAttestation. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_reconsideration_request(self, req_json: str) -> None:
        """(derived) deontic — v0.7.0 — Verify-and-insert a ReconsiderationRequest. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_slashing_attestation(self, att_json: str) -> None:
        """(derived) deontic — v0.7.0 — Verify-and-insert a SlashingAttestation. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_retire_key_grants_json(self, actor_key_id: str, now_iso: str) -> str:
        """(derived) deontic — v3.6.0 (CIRISPersist#134) — emit a supersedes Contribution against every prior key_grant Contribution issued by actor_key_id. Uses the engine's com... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def clear_active_halt(self, family_key_id: str, active_halt_id: str) -> None:
        """(derived) deontic — #302 (H2) — clear the active halt iff it matches (a resume)."""

    def cohort_add_member(self, cohort: str, group_key_id: str, member_json: str) -> bool:
        """(derived) deontic — #249 Cut G1 (§1) — admit a [crate::federation::cohort::RosterMember] (JSON) into a family/community roster. Returns True on a genuine add, False if..."""

    def cohort_build_membership_change_envelope(self, cohort: str, group_key_id: str, new_member_key_ids_json: str, entrenched: bool, consensus_protocol: str | None = None) -> str:
        """(derived) deontic — #249 Cut G3.5 (§5) — build the canonical membership-change payload for a roster change on group_key_id (verify v6.9.0's build_membership_change, wi..."""

    def cohort_revoke_member(self, cohort: str, group_key_id: str, removed_key_id: str, revoke_spec_json: str) -> None:
        """(derived) deontic — #249 Cut G1 (§1) — remove removed_key_id from a cohort roster via the append-only revocation table. revoke_spec_json is a [crate::federation::cohor..."""

    def cohort_supersede_group(self, cohort: str, new_group_json: str, authorization_json: str | None = None) -> int:
        """(derived) deontic — #249 Cut G2 (§3) — supersede a family/community with new content (new_group_json is the raw Family/Community object, like put_family_json) as a new..."""

    def cohort_supersede_group_with_quorum(self, cohort: str, new_group_json: str, change_envelope_json: str, signatures_json: str) -> int:
        """(derived) deontic — #249 Cut G3 (§3/§4/§5) — quorum-gated supersede: verify the current roster's strict-majority quorum cosigned change_envelope_json, then supersede n..."""

    def cohort_swap_member(self, cohort: str, group_key_id: str, out_key_id: str, in_member_json: str, revoke_spec_json: str) -> bool:
        """(derived) deontic — #249 Cut G1 (§6) — atomically swap out_key_id for the [crate::federation::cohort::RosterMember] in in_member_json (revoke then add) in a family/com..."""

    def cohort_verify_membership_quorum(self, cohort: str, group_key_id: str, change_envelope_json: str, signatures_json: str) -> None:
        """(derived) deontic — #249 Cut G3 (§4/§5), robust on G3.5 — verify a membership change is authorized by the group's current strict-majority quorum (composes verify v6.9...."""

    def corpus_want_admits(self, wire_json: str, content_id: str, object_bytes: int) -> bool:
        """(derived) deontic — #356 (§Q B4 wanted-then-pulled) — may a producer push content_id of object_bytes against this signed CorpusWantV1 wire JSON? True iff the id is wan..."""

    def deregister_federation_key(
        self,
        signed_revocation_json: str,
    ) -> None:
        """v8.8.0 (CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15) — the
        symmetric **deregister** path: the revocation teeth a withdrawn
        `consent:replication` relies on. FFI mirror of the Rust
        `Engine.deregister_federation_key`; a thin alias over the
        existing `put_revocation` store path (same `SignedRevocation`
        JSON shape, same trust / region / anti-rollback gates). A
        consumer then ceases admitting the deregistered peer's rows on
        read (`revocations_for` + the key's `valid_until`).
        """

    def emit_attestation(self, input_json: str) -> str:
        """(derived) deontic — v9.3.0 (CIRISPersist#248) — emit ONE signed, federation-tier CEG attestation. input_json is an EmitAttestationInput (attestation_type, attestation_..."""

    def emit_attestation_self(self, input_json: str) -> str:
        """(derived) deontic — v9.4.0 (CIRISPersist#253) — node-self emit over the engine's OWN composed signer (the common case: a node emitting a federation-tier row about itse..."""

    def evict_actor_json(self, attesting_key_id: str, now_iso: str) -> str:
        """(derived) deontic — v3.5.0 (CIRISPersist#125) — Federation blob storage: per-actor eviction. Deletes every federation_blobs row this Engine holds for attesting_key_id,..."""

    def federation_grant_trust(self, trust_grant_json: str) -> None:
        """(derived) deontic — Federation directory: grant trust to a key."""

    def federation_revoke_trust(self, key: str, revoked_by: str) -> None:
        """(derived) deontic — Federation directory: revoke trust for a key. Idempotent — revoking an already-expired key is a no-op."""

    def file_moderation(self, content_sha256: str, community_id: str, duty: str, allegation_type: str) -> str:
        """(derived) deontic — v9.3.0 (#249, §11.10 EMIT) — file a moderation report: a scores on the moderation:{allegation_type} dimension over content_sha256, naming community..."""

    def grant_delegation(self, delegate_key_id: str, scopes: list[str], sub_delegation: bool, delegation_purpose: str | None = None) -> str:
        """(derived) deontic — v9.3.0 (#249) — emit a general delegates_to edge: authorize delegate_key_id within scopes (a list of scope tokens), with an explicit sub_delegation..."""

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

    def has_accord_conferred_role(self, key_id: str, role: str) -> bool:
        """(derived) deontic — v17.0.0 (CIRISPersist#440, CC 3.4.9) — does key_id hold role effectively? True iff the stored federation_keys row claims role on either role surfac..."""

    def install_storage_budget_v1(self, wire_json: str, ed25519_pubkey_base64: str, ml_dsa_65_pubkey_base64: str) -> int:
        """(derived) deontic — #370 (§Q B2/B3, CC 6.1.5.2) — INSTALL a signed StorageBudgetV1 so it governs this node's capacity eviction. Verifies the bound-hybrid signature aga..."""

    def is_load_bearing_json(
        self, object_kind: str, object_id: str, object_id2: str | None = None
    ) -> str:
        """CIRISPersist#564 — **is this CEG object load-bearing on THIS node?**

        ``object_kind`` is one of ``"attestation"``, ``"key_record"``,
        ``"transport_destination"``, ``"fountain_content"``,
        ``"hard_case_event"``. ``object_id2`` carries the second key for the
        composite-keyed classes (``transport_destination`` -> ``transport_kind``,
        ``fountain_content`` -> ``corpus_kind``) and is **required** for those --
        it raises rather than defaulting, because a defaulted second key
        answers about a different object than you asked about.

        Three-valued, and the third value is the point. The verdict JSON is
        ``{"yes": {"because": [...]}}``, the bare string ``"no"``, or
        ``{"unknown": {"family": ..., "reason": ...}}`` -- *unknown* means this
        node cannot see the dependents, which is NOT *no*.

        **Every arm is a truthy string**, including ``"no"``. Treating the
        return as a boolean releases an object the node is still load-bearing
        for, and treats "I cannot tell" as "safe to erase".
        """

    def is_named_moderator_json(self, key_id: str, community_id: str, duty: str) -> str:
        """#249 Cut A — is ``key_id`` a **named moderator** of ``community_id``
        for ``duty`` (``"moderate"`` / ``"takedown"`` / ``"review"``)? Returns the
        JSON literal ``"true"`` or ``"false"``.

        **``"false"`` is a truthy Python string.** ``json.loads`` it; a bare
        ``if`` grants moderator authority to every key. Fail-closed underneath —
        an unknown community answers ``false`` rather than raising, so a wrong
        community id reads as "not a moderator", never as an error.
        """

    def is_steward_bound_json(self, key_id: str) -> str:
        """#249 Cut A — is ``key_id`` **steward-bound**: does it resolve to a
        ``user``-role human identity, directly, via an occurrence, or via a live
        ``delegates_to`` from a user-role granter? Returns the JSON literal
        ``"true"`` or ``"false"``.

        **``"false"`` is a truthy Python string** — see
        :meth:`is_named_moderator_json`. Fail-closed: a key whose chain to a human
        cannot be walked answers ``false``.
        """

    def issue_accord_nonce(self, family_key_id: str, nonce: str) -> None:
        """(derived) deontic — #302 (M4) — record a server-issued proposal nonce."""

    def may_release_copy_json(
        self, object_kind: str, object_id: str, object_id2: str | None = None
    ) -> str:
        """CIRISPersist#564 stage 2 -- **may this node release its copy?**

        ``is_load_bearing(X) == "no"`` **and** ``anti_entropy_satisfied(X)``.
        Arguments are identical to :meth:`is_load_bearing_json`, including the
        ``object_id2`` rule.

        Returns ``"yes"`` or ``{"no": {"load_bearing": ..., "anti_entropy":
        ...}}`` -- the refusal reports BOTH halves, so you never have to guess
        which one blocked it.

        **Today this always answers no.** Persist cannot verify that an object
        resides anywhere else: it has no peer transport, its replication
        surface is inbound-apply plus outbound-pull (a pull never learns who
        kept what), and nothing records a peer acknowledging a holding. The
        second conjunct is structurally unsatisfiable here -- fail-secure by
        construction, not by policy.

        **Both arms are truthy strings.** This is the surface you would gate a
        deletion on, so ``if engine.may_release_copy_json(...)`` deletes
        exactly what the primitive refused. ``json.loads`` it and branch on the
        parsed arm.

        Read-only -- it releases, evicts and mutates nothing.
        """

    def put_accord_decision_json(self, payload_json: str) -> None:
        """(derived) deontic — #302 — record the server's frozen-L decision. payload_json = { "decision": <AccordDecision>, "steward_signatures": <obj|null> }. Immutable (M2)."""

    def put_accord_participation_json(self, payload_json: str) -> None:
        """(derived) deontic — #302 — admit an accord_participation. payload_json = { "participation": <AccordParticipation>, "standing_roster": [<ThresholdMember>...] }. Verify-..."""

    def put_accord_proposal_json(self, payload_json: str) -> None:
        """(derived) deontic — #302 — admit an accord_proposal. payload_json = { "proposal": <AccordProposal>, "authority_signature": <obj|null> }. M4 fail-closed on an unissued..."""

    def put_attestation(self, signed_attestation_json: str) -> None:
        """Admit a ``SignedAttestation`` into ``federation_attestations``.

        Persist verifies the scrub-signature against the caller-named
        ``scrub_key_id``'s pubkey in ``federation_keys`` BEFORE writing.
        Reserved-prefix admission rules (v3.0.0 #102, CEG §7.0) and
        the v3.4.0 #123 trust gate both fire ahead of the DB write.

        Signed-attestation JSON shape::

            {
                "record": {
                    "attestation_id": str,           # UUID
                    "attesting_key_id": str,
                    "attestation_type": str,         # e.g. "holds_bytes:sha256:..."
                    "attestation_envelope": <opaque JSON>,
                    "references_attestation_id": str | None,
                    "references_attestation_type": str | None,
                    "asserted_at": str,               # RFC 3339
                    ...
                },
                "original_content_hash_hex": str,    # sha256 of canonical envelope
                "scrub_signature_classical": str,    # base64 Ed25519
                "scrub_signature_pqc": str | None,
                "scrub_key_id": str,
                "scrub_timestamp": str
            }

        Idempotent on ``(references_attestation_id, attestation_type,
        attesting_key_id)`` triple — duplicate replay is silent ``Ok``
        (CEG §6.1 dedup + precedence). Replay with different content
        raises ``federation_conflict``.

        Raises:
            ValueError: ``federation_signature_invalid`` /
                ``federation_conflict`` / ``federation_reserved_prefix_emitter_mismatch``
                / ``federation_trust_below_threshold`` (#123) /
                ``federation_invalid_argument``.
            RuntimeError: backend / IO error.
        """

    def put_blob_signing(
        self,
        sha256_hex: str,
        body_inline_b64: str | None,
        external_ref_json: str | None,
        media_type: str | None,
        attesting_key_id: str,
        now_iso: str,
        attestation_id_uuid: str,
    ) -> None:
        """v3.3.0 (#121) — One-call blob ingest: persist computes the
        holds_bytes envelope, canonicalizes via the production
        ``PythonJsonDumpsCanonicalizer``, signs via the engine's own
        ``HardwareSigner``, and atomically commits the blob row + the
        holder attestation.

        ``body_inline_b64`` XOR ``external_ref_json`` — exactly one
        body source. Inline bodies are base64-standard-alphabet;
        external refs are a JSON-encoded ``{"url": ..., "size_bytes": N}``.
        ``now_iso`` is RFC 3339 UTC; ``attestation_id_uuid`` is
        caller-supplied (typically ``str(uuid.uuid4())``) — explicit so
        replay / migration paths can pin specific IDs.

        Use this instead of hand-assembling a ``SignedAttestation`` —
        persist owns the canonicalizer choice and would silently fail
        verification if a downstream JCS-canonicalized envelope were
        passed in (#121 trap discipline).

        Raises:
            ValueError: ``blob_hash_mismatch`` / ``blob_inline_size_exceeded``
                / ``blob_invalid_argument`` / ``blob_attestation_emission_failed``
                / ``blob_trust_below_threshold`` (v3.4.0 #123 admission
                gate) / ``federation_*`` for the holder attestation write.
            RuntimeError: backend / IO error.
        """

    def put_community_json(self, payload_json: str) -> None:
        """(derived) deontic — v10.4.0 (CIRISPersist#290) — admit a Community row, symmetric to [Self::put_family_json]. The put_community backend trait method has always existed..."""

    def put_edge_detection_event(self, event_json: str) -> None:
        """(derived) deontic — v3.1.1 (CIRISPersist#118) — admission for cirislens.edge_detection_events (V020). Unblocks edge#39 ProbePatternObserver emit_verdict."""

    def put_family_json(self, payload_json: str) -> None:
        """(derived) deontic — v3.12.0 (CIRISPersist#153 Ask 2, CEG 0.7 §5.6.8.9) — admit a family row."""

    def put_fountain_content(self, manifest_json: str, symbols_json: str) -> None:
        """(derived) deontic — v8.0.0 (CIRISPersist#227) — admit a fountain-coded content unit (manifest + N+K symbols), JSON-over-FFI. manifest_json decodes to a FountainManifes..."""

    def put_identity_occurrence_json(self, payload_json: str) -> None:
        """(derived) deontic — v3.12.0 (CIRISPersist#153 Ask 1, CEG 0.7 §5.6.8.8) — admit an identity_occurrence binding (this occurrence_key_id IS also identity_key_id)."""

    def put_org_membership(self, signed_json: str) -> None:
        """(derived) deontic — Federation directory: admit an org_membership envelope (role- gated; CEG 1.0-RC2 §5.6.8.13). Same arg shape as [put_organization](Self::put_organiz..."""

    def put_organization(self, signed_json: str) -> None:
        """(derived) deontic — Federation directory: admit an organization envelope (role-gated; CEG 1.0-RC2 §5.6.8.13). signed_json = SignedOrganization; key_directory_json = [T..."""

    def put_partner_record(self, signed_json: str) -> None:
        """(derived) deontic — Federation directory: admit a partner_record envelope (M-of-N steward quorum; CEG 1.0-RC2 §5.6.8.13). signed_json = SignedPartnerRecord (carries th..."""

    def put_public_key(self, signed_key_record_json: str) -> None:
        """(derived) deontic — Federation directory: register a public key."""

    def put_revocation(self, signed_revocation_json: str) -> None:
        """(derived) deontic — Federation directory: write a revocation."""

    def put_scope_blob(self, record_id: bytes, symbol_index: int, nonce: bytes, ciphertext: bytes, tag: bytes, group_dek_ref_json: str) -> None:
        """(derived) deontic — v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243; FFI #271) — admit one caller-pre-encrypted (XChaCha20-Poly1305) RaptorQ symbol into the scope-blob..."""

    def reachable_under_scope(self, issuer_key_id: str, target_key_id: str, scope: str, max_depth: int) -> bool:
        """(derived) deontic — #249 Cut B — the general scoped-delegation reachability primitive: does issuer_key_id reach target_key_id via a delegates_to chain where every edge..."""

    def reachable_under_scope_with_reasons(
        self, issuer_key_id: str, target_key_id: str, scope: str, max_depth: int
    ) -> str:
        """v10.0.0 (CIRISPersist#272) — the refusal-reason companion of
        :meth:`reachable_under_scope`. Same scope-bearing ``delegates_to`` walk,
        but returns a stable snake_case verdict TOKEN so a consumer can route a
        distinct audit entry per refusal reason.

        ``"reachable"`` is the only admitting token. Every refusal token
        (``"retracted_at_root"``, ``"depth_exceeded"``, ...) is a non-empty
        string, so **``if`` on this return permits everything**. Compare against
        ``"reachable"`` explicitly, or use :meth:`reachable_under_scope` when you
        only need the bool.
        """

    def register_federation_key(
        self,
        signed_key_record_json: str,
    ) -> None:
        """v8.8.0 (CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15) — the
        **canonical federation-key registration admission gate**. FFI
        mirror of the Rust `Engine.register_federation_key`.

        `signed_key_record_json` is the same `SignedKeyRecord` JSON shape
        `put_public_key` takes. Unlike `put_public_key`, this runs the
        §5.6.8.15 gate FIRST: hybrid-verify (Ed25519 + ML-DSA-65,
        Strict) the scrub signature over
        `ceg_produce_canonicalize(registration_envelope)` against
        `scrub_key_id`'s pubkeys, then `put_public_key` (which keeps its
        accord_holder + algorithm gates). ANY verification failure ⇒ the
        row is NOT stored (fail-secure). Because the gate is Strict, a
        hybrid-pending (Ed25519-only) record is rejected — use
        `put_public_key` for the soft-PQC write window.

        NOTE (v8.8.0 breaking rename): in v1.5.3–v8.7.x this name was the
        self-registration convenience helper (build + sign THIS engine's
        own key); that helper is now `register_self_federation_key`. This
        name now belongs to the canonical admission gate so it is
        symmetric with the Rust API.

        Raises:
            ValueError: SignedKeyRecord JSON decode failure, or a
                federation verification/admission error (bad/missing
                signature, hash mismatch, unknown signer, non-hybrid).
            RuntimeError: backend / IO error.
        """

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

    def rematerialize_role_withdrawals(self) -> str:
        """(derived) deontic — v31.1.0 (CIRISPersist#662) — the repair door: re-derive every role-withdrawal tombstone this node's stored accord evidence supports, returning the..."""

    def remove_moderator(self, community_id: str, target_attestation_id: str, moderator_key_id: str, duty: str) -> str:
        """(derived) deontic — v9.3.0 (#249, §11.10) — remove a named moderator: withdraws against the appointment edge target_attestation_id. moderator_key_id keys the retractio..."""

    def remove_peer_record(self, key_id: str, hard: bool) -> None:
        """(derived) deontic — Federation directory: remove a peer record. hard=false soft-marks removed_at; hard=true cascades through the FK to delete the federation_keys row (..."""

    def resolve_key_statement_standing_json(self, key_id: str, statement_at: str | None = None, now: str | None = None) -> str:
        """CIRISServer#356 — **do this key's past statements still stand?**

        Returns the fold as JSON: ``{key_id, statement_at, standing,
        covered_by, considered}``. ``standing`` is one of three stable tokens
        and **they are not two**:

        * ``"stands"`` -- no revocation this node holds covers a statement made
          at ``statement_at``.
        * ``"suspect_after_bound"`` -- a covering revocation exists and it is
          history-bounded: this key said this *after* the bound. The key's
          honest past is untouched.
        * ``"suspect_unbounded"`` -- an unbounded revocation covers the key.
          Everything it ever said is in doubt, because the revocation declined
          to say otherwise.

        Collapsing the middle token into either neighbour throws away exactly
        what a bounded de-admission bought: before it, a key compromised on
        Tuesday cost every honest signature it had ever made.

        **Every arm is a truthy string**, including ``"suspect_unbounded"``.
        ``json.loads`` it and read ``["standing"]``; a bare truth-test reads a
        corpus-wide compromise as an approval.

        ``statement_at`` and ``now`` are RFC 3339 and both default to the
        current instant. **Clock-dependent** on ``now``: a revocation whose
        ``effective_at`` has not arrived is not counted yet, so this transitions
        on elapsed time with no new row. Read-only.
        """

    def resolve_mesh_config_json(self, node_key_id: str, baseline_json: str | None = None, now: str | None = None) -> str:
        """CIRISPersist#570 ask 1 — **what mesh configuration does this node
        actually run?**

        Returns the fold as JSON: ``{node_key_id, roots, settings}``.
        ``settings`` carries **one entry per registered key, always** (nine on
        this cut), so a consumer never has to tell "not set" from "not
        returned". Each entry is ``{key, polarity, unit, baseline, effective,
        relieved, decided_by_root?, row_id?, decided_by?, delegation_id?,
        form?, expires_at?, grounds?, per_root, clamped_roots}``.

        **Read ``effective``. That is the number to run.** The rest is
        evidence: ``per_root`` is every trust root's own answer including the
        ones that lost, and ``clamped_roots`` names every root whose value was
        refused for asking this node to do MORE than its owner consented to.

        Two guarantees hold whatever any root signed, per CC 4.2.1:

        * **relieve-never-expand** -- ``effective`` never means more flow than
          ``baseline``.
        * **most-restrictive-across-roots** -- where roots disagree the
          tightest value binds, on every node, whatever order they are in.

        **Do not assume smaller is tighter.** Which direction is "more flow"
        is per key and is carried in ``polarity``:
        ``"higher_means_more_flow"`` for ``redundancy.k_repair_target``,
        ``"lower_means_more_flow"`` for ``antientropy.round_secs`` (longer
        between rounds is *less* gossip) and ``backpressure.summary_only``.

        ``baseline_json`` is what this node's owner consented to: a JSON
        object ``{"<key>": <int>}`` covering only the keys you pin, with
        anything omitted taking that key's registered default. Values are
        integers on every key; a ratio is carried in centi-units (``100`` =
        1.00x). An unregistered key name raises ``ValueError`` rather than
        being ignored -- the registry is closed (CC 4.2.1), and a baseline
        half-applied would measure relieve-never-expand against a ceiling you
        never set.

        ``now`` is RFC 3339, defaulting to the current instant.
        **Clock-dependent**: a TTL-expired row stops binding at read time,
        with nothing revoked and nobody notified.

        **This returns a JSON string, so it is truthy in Python.**
        ``if engine.resolve_mesh_config_json(n)`` is ``True`` for every
        possible answer, including one where every key sits at its default.
        Sharper here than elsewhere: a flag key's ``effective`` is the JSON
        number ``0`` or ``1``, and ``'..."effective":0...'`` is a truthy
        string. ``json.loads`` it, find the entry whose ``["key"]`` matches,
        and read ``["effective"]``.

        Read-only -- this never records a row.
        """

    def resolve_quarantine_json(self, key_id: str, now: str | None = None) -> str:
        """CIRISServer#356 — **is this key withheld from serving?**

        Returns the fold as JSON: ``{key_id, state, marker_id?, decided_by?,
        delegation_id?, effective_at?, grounds?, marker_ids}``. ``state`` is
        one of three stable tokens, and the third one is the point:

        * ``"not_quarantined"`` -- no marker about this key has taken effect
          here.
        * ``"withheld"`` -- the governing marker withholds; the serve paths skip
          this key's rows.
        * ``"released"`` -- a quarantine was raised and lifted. **Serving, and
          it was not always.** Deliberately distinct from ``"not_quarantined"``:
          "never withheld" and "withheld and released" are different facts, and
          an operator reviewing a key deserves the second one.

        The serve decision is ``state == "withheld"`` and nothing else --
        ``"released"`` does **not** withhold. ``marker_ids`` names the whole
        evidence set, not only the winner; that enumeration is what a
        compromised-authority review reads.

        **Every arm is a truthy string.** ``json.loads`` it and read
        ``["state"]``; ``if engine.resolve_quarantine_json(k)`` is ``True`` for
        a key this node is refusing to serve.

        ``now`` is RFC 3339, defaulting to the current instant.
        **Clock-dependent**: a marker whose ``effective_at`` has not arrived
        does not count yet. Read-only -- this never records a marker.
        """

    def resolve_reverse_quorum_json(self, cohort: str, cohort_key_id: str, action_attestation_id: str, now: str | None = None) -> str:
        """CIRISServer#356 — **is a brake active on this action, and did the
        duty-holders answer?**

        One call for both reverse-quorum signals, because they are already one
        fold. The payload carries ``standing`` -- *does the action stand?*
        (``"not_governed"`` / ``"window_open"`` / ``"stood"`` /
        ``"reversed"``), with ``distinct_objectors``, ``required``,
        ``roster_size`` and the counted/dismissed objection ids beside it --
        and ``escalation[]``, one record per objection, each carrying
        ``steward``: *did the people carrying the duty answer?*

        **``steward`` has three separate zeroes and they do not share a
        token.** ``"silent"`` (nobody answered), ``"overruled"`` (somebody
        answered, but the answer was an undo, and undos are never unilateral)
        and ``"no_duty_holders"`` (there was nobody to answer) all open
        escalation and are three different diagnoses of *why*. Mapping them to
        one value re-introduces the defect the type was built to prevent: a
        failing commons and a healthy one must not read identically.
        ``"awaiting"`` is **not** a zero -- it is the healthy in-progress
        state, and treating it as silence escalates every objection the moment
        it is raised.

        ``cohort`` is ``"self"`` / ``"family"`` / ``"community"`` /
        ``"affiliations"``. An ``action_attestation_id`` this node does not
        hold raises ``ValueError`` rather than returning a fold about nothing
        -- an empty fold would be indistinguishable from a real
        ``"not_governed"`` verdict.

        **Every arm is a truthy string**, including ``"reversed"``.
        ``json.loads`` it.

        ``now`` is RFC 3339, defaulting to the current instant.
        **Clock-dependent**: the objection window and the steward deadline both
        close on elapsed time, with no new row. Read-only -- the objected-to
        row is never touched.
        """

    def resolve_transit_eligibility_json(self, user_key_id: str, peer_key_id: str) -> str:
        """v24.1.0 (CIRISPersist#561) — **may ``peer_key_id`` carry our relay
        traffic?** Returns the verdict as JSON
        ``{"eligible": bool, "valid_until": ..., "via_root": ...}``.

        **The refusal arm is a TRUTHY string.** ``'{"eligible": false}'`` is a
        non-empty ``str``, so ``if engine.resolve_transit_eligibility_json(...)``
        routes traffic through a peer this method just refused. Parse it::

            if json.loads(engine.resolve_transit_eligibility_json(u, p))["eligible"]:
                ...
        """

    def revoke_delegation(self, target_attestation_id: str, delegate_key_id: str) -> str:
        """(derived) deontic — v9.3.0 (#249, §3.2.3) — revoke a prior delegates_to (target_attestation_id) by emitting a withdraws. delegate_key_id is the key the revoked edge de..."""

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

    def secrets_decapsulate(self, action_type: str, action_params_json: str, ctx_json: str) -> str:
        """(derived) deontic — Walk action_params_json, replacing every {SECRET:<uuid>:<description>} placeholder with the decrypted plaintext (when the action_type is in the sec... [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_decrypt(self, ciphertext: str) -> str:
        """(derived) deontic — v0.6.1 — Direct AES-GCM decrypt. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_forget_secret(self, uuid: str, accessor: str) -> bool:
        """(derived) deontic — v0.6.1 — Audited delete. Returns true if the secret existed. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_migrate_to_hardware_key(self, accessor: str) -> str:
        """(derived) deontic — v0.6.1 — Migrate master key to CIRISVerify hardware path. Returns SecretsError::HardwareKeyUnavailable in v0.6.1 (waits on ciris-keyring/symmetric-... [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_process_incoming_text(self, text: str, source_message_id: str, accessor: str) -> str:
        """(derived) deontic — v1.5.7 (CIRISPersist#57) — Detect and encrypt-and-store every secret in text per the configured filter catalog. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_recall_secret(self, uuid: str, purpose: str, accessor: str, decrypt: bool) -> str | None:
        """(derived) deontic — v0.6.1 — Recall a detected secret by UUID. Returns JSON-encoded SecretRecallResult or None. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_reencrypt_all(self, new_master_key_ref_json: str, accessor: str) -> str:
        """(derived) deontic — v0.6.1 — Re-encrypt every stored secret under a new master. Atomic. Returns JSON-encoded RotationResult. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_retrieve_secret(self, key: str, accessor: str) -> str | None:
        """(derived) deontic — v0.6.1 — Retrieve a manually-keyed secret. Returns plaintext or None. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_rotate_master_key(self, new_master_b64: str | None, accessor: str) -> str:
        """(derived) deontic — v0.6.1 — Generate a fresh master key (or use supplied bytes). new_master_b64 is Some(base64(32-byte key)) or None to auto-generate. Returns JSON-en... [build-conditional: #[cfg(feature = "secrets")]]"""

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

    def secrets_store_secret(self, key: str, value: str, accessor: str) -> None:
        """(derived) deontic — v0.6.1 — Store a manually-keyed secret. AES-256-GCM encrypts under the active master key; audited. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_update_filter_config(self, updates_json: str, accessor: str) -> str:
        """(derived) deontic — v0.6.1 — Write a new filter pattern catalog. Returns JSON-encoded FilterUpdateResult. [build-conditional: #[cfg(feature = "secrets")]]"""

    def serve_blob_to_peer_json(self, sha256_hex: str, requesting_peer_key_id: str) -> str:
        """(derived) deontic — v6.8.0 (CIRISPersist#149) — serve blob bytes to a federation PEER, with the proactive disk-pressure gate on the proxy-SERVE path. At the stop tier..."""

    def service_token_revocation_check(self, token_hash: str) -> str | None:
        """v1.5.23 — point-lookup the revocation record for a service token hash.

        **The polarity is inverted from what the name suggests**: a non-``None``
        return means the token IS REVOKED (it is the revocation row); ``None``
        means no revocation is recorded. ``if engine.service_token_revocation_check(h):``
        therefore reads correctly as "revoked", but
        ``assert engine.service_token_revocation_check(h)`` before honouring a
        token has it exactly backwards.
        """

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

    def set_active_halt(self, family_key_id: str, active_halt_id: str) -> None:
        """(derived) deontic — #302 (H2) — set the active CONSTITUTIONAL halt for a family."""

    def set_consent_role(self, key_id: str, consent_role: str | None = None) -> None:
        """(derived) deontic — v13.0.0 (CIRISPersist#365, CC 3.4.7.2 OQ-1) — assign or overwrite the Counter-RII consent_role of key_id. consent_role=None revokes it (resets the..."""

    def set_multimedia_config_json(self, config_json: str | None) -> None:
        """(derived) deontic — v3.6.0 (CIRISPersist#134) — install / clear the media-sharing operator config ([MultimediaConfig](crate::cirisnode::MultimediaConfig)). Wire shape:... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def set_retention(self, table_name: str, min_keep_secs: int, time_column: str, pressure_trigger_bytes: int | None = None, pressure_target_bytes: int | None = None, interval_secs: int = ...) -> None:
        """(derived) deontic — v6.0.1 (CIRISPersist#218) — Set (upsert) the retention policy for table_name. table_name and time_column are validated as strict SQL identifiers in..."""

    def set_storage_budget_bytes(self, budget: int) -> None:
        """(derived) deontic — v3.4.0 (CIRISPersist#123) — set the local federation_blobs storage budget in bytes. Above budget × steady_state_utilization the eviction sweeper dr..."""

    def set_trust_threshold(self, threshold: float) -> None:
        """(derived) deontic — v3.4.0 (CIRISPersist#123) — set the trust-score admission threshold consulted by every write path. Range [0.0, 1.0]; out-of-range values are clampe..."""

    def steward_bind(self, node_or_agent_key_id: str, infra_scopes: list[str], delegation_purpose: str | None = None) -> str:
        """(derived) deontic — v9.3.0 (#249, CC 4.4.3.4.3) — steward-bind a node/agent occurrence by granting it infra:-only scopes (passes the node-agency gate on a node-only ke..."""

    def steward_bind_incapacity(self, ward_key_id: str, domains: list[str], legitimacy_source: str, valid_until: str, binding_tier: str | None = None, petitioner_key_id: str | None = None) -> str:
        """(derived) deontic — v16.0.0 (#433, CC 3.4.12) — the adult-incapacity guardianship emit aperture: a delegates_to(S → ward) carrying the CC 3.4.12 binding fields (bindin..."""

    def storage_budget_supersedes(self, candidate_json: str, existing_json: str) -> bool:
        """(derived) deontic — #356 (§Q B3 anti-rollback) — does candidate supersede existing? Both are signed StorageBudgetV1 wire JSONs; True iff same node_id and strictly-high..."""

    def supersede_canonical(self, old_key_id: str, signed_key_record_json: str, proposal_digest: str) -> None:
        """(derived) deontic — v13.1.0 (CIRISPersist#377, CC 3.4.7.1 / FSD Trust Root) — supersede (rotate) a canonical server. signed_key_record_json is the successor's SignedKe..."""

    def trust_root_verdict_json(self, user_key_id: str, root_key_id: str) -> str:
        """CIRISServer#356 — **does this node still have a live trust root at
        all, and when was it last drilled?**

        The full verdict as JSON: ``{edge_exists, root_self_declares,
        charter_has_recovery, last_drill_at, drill_freshness, halt_latched,
        valid, root_kind, charter_quorum?, bounded_until?}``. One call for two
        signals, because they are one verdict -- a drill is a property *of* a
        root, and the walk that decides validity is the walk that finds the
        drill.

        **``drill_freshness`` is a signal, never a gate.** ``valid`` does not
        consult it and must not be made to. A root is valid until revoked,
        halted, or un-trusted; a stale drill distinguishes *governed* from
        *abandoned*, which is a thing to show a human, not a thing to withhold
        service over. Gating on it re-introduces the deadman that gave a
        genesis root a ~90-day shelf life -- every node depending on it going
        dark together, with no error at the point of use.

        **It is clock-dependent, and nothing about that is visible in the
        rows.** ``drill_freshness`` crosses ``"Green"`` -> ``"Yellow"`` ->
        ``"Red"`` at 90 and 180 days with no state change and no new row. Two
        reads either side of a boundary differ and nothing caused the
        difference: diff these as a gauge, never as a ledger.
        ``last_drill_at`` is the stable fact underneath, and ``"Red"`` covers
        *never drilled* as well as *long ago* -- ``last_drill_at is None`` is
        what tells those apart.

        Note the case: ``drill_freshness`` serializes **PascalCase**, its
        pre-existing wire contract. :meth:`node_state_json` carries the same
        three states in a lowercase band vocabulary.

        **``valid: false`` is a truthy string.**
        ``if engine.trust_root_verdict_json(u, r)`` is ``True`` for a verdict
        that just said this node's root does not check out. ``json.loads`` it
        and read ``["valid"]``. Read-only.
        """

    def unwrap_dek_b64(self, recipient_x25519_priv_b64: str, wrap_json: str) -> str:
        """(derived) deontic — v3.8.0 — unwrap a KeyGrantWrap JSON envelope using the recipient's X25519 private key. Returns the recovered DEK b64."""

    def unwrap_dek_v2_b64(self, recipient_x25519_priv_b64: str, recipient_ml_kem_priv_b64: str, recipient_ml_kem_pub_b64: str, wrap_json: str) -> str:
        """(derived) deontic — v4.x (CIRISPersist#142 Cut C3b) — unwrap a KeyGrantWrapV2 JSON envelope using the recipient's X25519 private key + ML-KEM-768 private/public keys...."""

    def update_peer_policy(self, key_id: str, policy_json: str) -> None:
        """(derived) deontic — Federation directory: set peer policy blob. policy_json is the JSON-encoded shape (any valid JSON value). Persist round-trips it verbatim; the shap..."""

    def update_peer_trust(self, key_id: str, trust_wire: str) -> None:
        """(derived) deontic — Federation directory: set peer trust class. trust_wire is the snake_case TEXT form (untrusted / trusted / restricted / blocked); unrecognized value..."""

    @staticmethod
    def verify_coord_check_observed_region(observed_region: str) -> None:
        """(derived) deontic — v3.11.0 (CIRISPersist#143) — validate a producer-side observed_region value against the closed set {us, eu, apac} without writing a row. Raises Val..."""

    def verify_corpus_want_v1(self, wire_json: str, ed25519_pubkey_base64: str, ml_dsa_65_pubkey_base64: str) -> bool:
        """(derived) deontic — #356 — verify a signed CorpusWantV1 wire JSON at ingest. Same contract as [Self::verify_storage_budget_v1_py]."""

    def verify_hybrid(
        self,
        canonical_bytes: bytes,
        ed25519_sig_b64: str,
        ml_dsa_65_sig_b64: str | None,
        ed25519_pubkey_b64: str,
        ml_dsa_65_pubkey_b64: str | None,
        policy: str,
    ) -> None:
        """Verify a hybrid (Ed25519 + ML-DSA-65) signature over
        ``canonical_bytes`` against caller-supplied pubkeys. ``policy``
        is one of ``"strict"`` (both signatures required) /
        ``"either"`` (one or the other) / ``"prefer_pqc"`` (PQC if
        present, fall back to classical).

        Raises:
            ValueError: ``verify_signature_invalid`` /
                ``verify_unknown_algorithm`` / ``verify_policy_violation``.
        """

    def verify_hybrid_via_directory(self, canonical_bytes: bytes, signature_key_id: str, ed25519_sig_b64: str, ml_dsa_65_sig_b64: str | None, policy: str, soft_freshness_window_seconds: float | None = None, row_age_seconds: float | None = None) -> dict[str, Any]:
        """(derived) deontic — v0.4.0 / v0.4.1 — Hybrid verify with internal directory lookup. v0.4.1 backs onto the Rust free function crate::verify::verify_hybrid_via_directory..."""

    def verify_signed_attestation(self, signed_attestation_json: str, policy: str, soft_freshness_window_seconds: float | None = None, row_age_seconds: float | None = None) -> dict[str, Any]:
        """(derived) deontic — v0.4.0 — Verify a SignedAttestation envelope. Same shape as verify_signed_key_record; canonical bytes come from attestation_envelope."""

    def verify_signed_key_record(self, signed_key_record_json: str, policy: str, soft_freshness_window_seconds: float | None = None, row_age_seconds: float | None = None) -> dict[str, Any]:
        """(derived) deontic — v0.4.0 — Verify a SignedKeyRecord envelope's scrub signature. Looks up the scrub_key_id's pubkeys, recomputes canonical bytes from registration_env..."""

    def verify_signed_revocation(self, signed_revocation_json: str, policy: str, soft_freshness_window_seconds: float | None = None, row_age_seconds: float | None = None) -> dict[str, Any]:
        """(derived) deontic — v0.4.0 — Verify a SignedRevocation envelope. Same shape as verify_signed_attestation; canonical bytes come from revocation_envelope."""

    def verify_skill_import_manifest_b64(
        self,
        manifest_bytes_b64: str,
        steward_ed25519_pub_b64: str,
        steward_ml_dsa_65_pub_b64: str,
    ) -> str:
        """v3.8.0 — verify a ``SkillImportManifest`` against a trusted steward's
        Ed25519 + ML-DSA-65 pubkey PAIR (hybrid; both must verify).

        Returns ``'{"valid": true, "source": ..., ...}'`` on success and
        **RAISES** with the structured reason on signature or canonicalisation
        failure. So the failure mode here is an exception, not a falsy return —
        do not wrap it in a bare ``except`` that continues.
        """

    def verify_storage_budget_v1(self, wire_json: str, ed25519_pubkey_base64: str, ml_dsa_65_pubkey_base64: str) -> bool:
        """(derived) deontic — #356 — verify a signed StorageBudgetV1 wire JSON at ingest (structure + PQC-mandatory bound-hybrid signature) against the owner's raw pubkeys (base..."""

    def wa_cert_set_active(self, wa_id: str, active: bool) -> bool:
        """v1.5.19 — Activity toggle. Sets ``active`` to the
        supplied value. Returns ``True`` if the row exists
        (idempotent for same-value toggles); ``False`` if ``wa_id``
        doesn't exist.
        """

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

    def withdraw_canonical_role(self, key_id: str, proposal_digest: str) -> None:
        """(derived) deontic — v13.1.0 (CIRISPersist#377, CC 3.4.7.1 / FSD Trust Root) — withdraw the canonical role from key_id (the DESTRUCTIVE Trust Root op). proposal_digest..."""

    def wrap_dek_for_recipient_b64(self, recipient_x25519_pub_b64: str, dek_b64: str) -> str:
        """(derived) deontic — v3.8.0 — wrap a 32-byte DEK for an X25519 recipient. Returns the KeyGrantWrap JSON envelope. Composes with the substrate's subject_kind: key_grant..."""

    def wrap_dek_for_recipient_v2_b64(self, recipient_x25519_pub_b64: str, recipient_ml_kem_pub_b64: str, dek_b64: str) -> str:
        """(derived) deontic — v4.x (CIRISPersist#142 Cut C3b, CEG §10.5.3) — wrap a 32-byte DEK under wrap_algorithm: v2 (X25519 + ML-KEM-768 hybrid PQC), the mandatory wrap for..."""


    # ==============================================================
    # TESTIMONIAL  (BINDING)
    # Varying one of these makes the record unable to prove what happened; everything still runs.
    # ==============================================================

    def audit_chain_proof(self, trace_id: str) -> str:
        """(derived) testimonial — v2.7.0 (CIRISPersist#104) — Audit-lineage walk for a trace_id. Locates the cirislens_audit_log row whose subject_id == trace_id, then walks back to... [build-conditional: #[cfg(feature = "cirisaudit")]]"""

    def audit_list_entries(
        self,
        filter_json: str,
        cursor_json: str | None = None,
        limit: int = 100,
    ) -> str:
        """List audit entries for one tenant (AV-51).

        Returns a JSON ``AuditListPage``.

        Raises:
            ValueError: malformed filter.
            RuntimeError: backend error.
        """

    def audit_next_chain_position(self, tenant_id: str) -> str:
        """(derived) testimonial — v10.2.0 (CIRISPersist#281) — the audit chain HEAD for tenant_id: the (next_sequence_number, prev_hash) a client must stamp onto the next chained Au... [build-conditional: #[cfg(feature = "cirisaudit")]]"""

    def audit_record_entry(self, entry_json: str) -> None:
        """Record a verified audit entry into the hash chain.

        The entry must carry a valid ``entry_hash`` (matching canonical
        bytes) and ``signature`` (Ed25519 over canonical signing bytes).
        Persist re-derives both and rejects on mismatch (AV-49).

        Raises:
            ValueError: hash / signature / chain integrity failure.
            RuntimeError: backend error.
        """

    def audit_verify_all_chains(self) -> str:
        """v2.0.5 — verify ALL tenants' audit chains in one call.

        Independent of any external registry — persist validates its
        own chain integrity. Returns JSON summary::

            {"tenants_checked": N, "total_entries_walked": N,
             "all_ok": bool, "breaks": [...]}

        Raises:
            RuntimeError: backend error.
        """

    def audit_verify_chain(
        self,
        tenant_id: str,
        from_sequence: int,
        to_sequence: int | None = None,
    ) -> str:
        """AV-50 chain-walk verify for one tenant.

        Returns a JSON ``ChainVerification`` with typed break diagnostic
        on first observed integrity violation. Independent of any
        external registry — validates the local audit chain only.

        Raises:
            ValueError: invalid arguments.
            RuntimeError: backend error.
        """

    def cirisnode_put_delivery_attestation(self, attestation_json: str) -> None:
        """(derived) testimonial — v2.1 (CIRISPersist#101) — Verify-and-insert a [DeliveryAttestation](crate::cirisnode::DeliveryAttestation). Idempotent on (announcement_id, peer_ke... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def compare_wholeness_witnesses_json(self, peer_ids_json: str | None = None) -> str:
        """(derived) testimonial — v16 (CIRISPersist#431, N4) — classify the stored, VERIFIED witnesses of peer_ids_json (a JSON array of peer ids; None = every peer in the corpus) i..."""

    def current_sth(self, tenant_id: str) -> str | None:
        """Fetch the current ``SignedTreeHead`` for the per-tenant
        Merkle log. Returns a JSON-encoded ``SignedTreeHead`` or
        ``None``."""

    def delete_traces_for_agent(self, agent_id_hash: str, signature_key_id: str, include_federation_key: bool = False) -> dict[str, Any]:
        """(derived) testimonial — v0.3.6 (CIRISPersist#15, CIRISLens#8 ASK 1) — GDPR Article 17 / DSAR primitive. Per-key scope: deletion is scoped to (agent_id_hash, signing_key_id)."""

    def delete_traces_for_agent_id_hash(self, agent_id_hash: str) -> dict[str, Any]:
        """(derived) testimonial — v7.0.0 (CIRISPersist#222) — GDPR Art. 17 / DSAR full erasure of an agent's trace corpus, keyed on agent_id_hash alone (all signing keys). Unlike de..."""

    def descend_aggregated_sources(self, aggregate_content_id: str, sources_json: str, consent: str, under_capacity_pressure: bool, target_tier: str | None = None) -> int:
        """(derived) testimonial — v8.4.0 (CEG 1.0-RC14 §19.7 / CIRISPersist#230) — descent orchestration for a completed fold, JSON-over-FFI, gated on §19.7.1.1 descent integrity an..."""

    def evict_fountain_content_hard_delete(self, content_id: str, corpus_kind: str) -> int:
        """(derived) testimonial — v8.1.0 (CEG 1.0-RC11 §19 / CIRISPersist#228 N5) — revocation HardDelete: drop ALL symbols for a withdrawn / revoked content_id, leaving the manifes..."""

    def hash_chain_gaps(self, agent_id_hash: str, window_json: str, caller_occurrence_key_id: str | None) -> str:
        """(derived) testimonial — Audit-chain gaps for an agent over a window. Returns JSON array of HashChainGap."""

    def latest_stream_sth(self, stream_id: str) -> str | None:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C1b) — the latest STH (highest tree_size) stored for stream_id, as a serialized SignedTreeHead JSON string, or None if..."""

    def list_delivery_receipts_for(self, stream_id: str, limit: int) -> str:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C4) — list stored delivery receipts for stream_id, ascending (k, subscriber_key_id), bounded by limit. Returns a JSON a..."""

    def list_witness_equivocations_json(self, peer_id: str) -> str:
        """(derived) testimonial — v16 (CIRISPersist#431, N4 read-back) — the non-repudiable equivocations visible for peer_id: a JSON array of records each carrying the proof scalar..."""

    def lookup_signed_record_by_content_hash(self, kind: str, content_hash: str) -> bytes | None:
        """(derived) testimonial — v21.1.0 (CIRISPersist#507b) — the content-hash point-read: kind is the EnvelopeKind::as_str() token, content_hash the lowercase-hex sha256 over the..."""

    def maintenance_archive_expired(self, window_seconds: int | None = None) -> str:
        """(derived) testimonial — v1.2.0 (CIRISPersist#48) — Archive expired rows across substrate modules (telemetry, secrets access_log, closed incidents, expired federation_keys)..."""

    def maintenance_prune_audit_chain(self, tenant: str, before: str) -> str:
        """(derived) testimonial — v1.2.0 (CIRISPersist#48) — Prune audit-chain entries for tenant strictly older than before (RFC 3339). Returns a JSON-encoded PruneReport. Stub in..."""

    def next_sequence(self, identity: str, stream: str) -> int:
        """v1.7.1 (CIRISPersist#83) — Atomically bump and return the
        next monotonic value for ``(identity, stream)``.

        First call for a pair returns 1, then 2, 3, … Durable,
        monotonic, and correct under concurrent callers.

        A CIRIS 3.0 runtime holds exactly one Ed25519 identity, and
        every in-process consumer (agent, NodeCore, LensCore) plus
        every agent occurrence signs with that one key. Anything
        emitting *ordered* signed output (e.g. NodeCore
        network-message sequence numbers) needs a counter atomic
        across all of those signers — otherwise two occurrences both
        emit seq N and the signed stream forks. This is that
        counter. The bump is a single atomic
        ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING``.

        ``identity`` and ``stream`` must both be non-empty. The
        ``stream`` namespaces independent counters under one
        identity (e.g. one stream per signed output kind).
        """

    def peek_sequence(self, identity: str, stream: str) -> int:
        """v1.7.1 (CIRISPersist#83) — Read the last-issued value for
        ``(identity, stream)`` WITHOUT bumping it.

        Returns ``0`` if the pair has never been issued. ``identity``
        and ``stream`` must both be non-empty.
        """

    def provenance_chain(self, key_id: str) -> str:
        """(derived) testimonial — Verify-consumable provenance read (CIRISVerify WS-4)."""

    def put_delivery_receipt(self, receipt_json: str) -> None:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C4, CEG §10.5.4) — store a subscriber delivery receipt (receipt_json is a serialized DeliveryReceipt). Runs the JOIN-ag..."""

    def put_stream_sth(self, sth_json: str, producer_key_id: str) -> None:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C1b) — store a producer-signed Signed Tree Head for a stream's transparency log (CEG §10.5.1)."""

    def put_wholeness_witness_json(self, witness_json: str, sig_ed25519_b64: str, sig_mldsa65_b64: str, ed25519_pubkey_b64: str, mldsa65_pubkey_b64: str, leaves_b64_json: str | None = None) -> str:
        """(derived) testimonial — v16 (CIRISPersist#431, N3 + N4) — admit a WholenessWitness to the corpus, PQC-verified-BEFORE-persist: the full hybrid gate over the §19.1 canonica..."""

    def rebuild_signed_wire_index(self) -> int:
        """(derived) testimonial — v21.1.0 (CIRISPersist#507b) — full rebuild/backfill of the signed_wire_index: scans every covered kind's current rows and upserts (kind, content_ha..."""

    def receive_and_persist(self, body: bytes) -> BatchSummary:
        """Run the FSD §3.3 ingest pipeline on a batch body.

        Raises:
            ValueError: schema / verify / scrub rejection — caller
                surfaces as HTTP 4xx.
            RuntimeError: backend / IO error — caller surfaces as HTTP
                5xx.
        """

    def run_retention(self, now: str | None = None) -> str:
        """(derived) testimonial — v6.0.1 (CIRISPersist#218) — Run one pressure-gated retention pass over every stored policy and return a JSON-encoded array of RetentionReport. The..."""

    def seal_stream(self, stream_id: str) -> str:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C1a) — seal a live stream into a content-addressed chunk DAG. Walks the federation_stream_chunks index in seq order, wr..."""

    def stream_consistency_proof(self, stream_id: str, from_size: int, to_size: int) -> str | None:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C1b) — RFC 6962 §2.1.2 consistency proof between from_size and to_size, as a serialized ConsistencyProof JSON string. N..."""

    def stream_inclusion_proof(self, stream_id: str, leaf_index: int, tree_size: int) -> str | None:
        """(derived) testimonial — v4.1 (CIRISPersist#142, Cut C1b) — RFC 6962 inclusion proof for the chunk at leaf_index against a tree_size-leaf tree, as a serialized MerkleProof..."""

    def sweep_ttl_expired(self) -> int:
        """(derived) testimonial — v0.4.0 — Sweep TTL-expired rows."""

    def trust_grant_consistency_proof(
        self,
        tenant_id: str,
        old_size: int,
        new_size: int,
    ) -> str:
        """Generate an RFC 6962 §2.1.2 consistency proof between two
        tree sizes for a tenant. Returns a JSON-encoded
        ``ConsistencyProof``."""

    def trust_grant_inclusion_proof(self, grant_id: str) -> str:
        """Generate the full inclusion-proof bundle for a trust grant.
        Returns a JSON object with ``{ sth, merkle_proof,
        leaf_canonical_bytes (base64) }``.

        Raises:
            KeyError: grant_id has no projection row, the tenant has
                no STH, or the merkle leaf is missing.
        """

    def tsdb_prune_summaries(
        self,
        level: str,
        tenant_id: str,
        before_rfc3339: str,
    ) -> int:
        """v1.6.0 (CIRISPersist#63) — Delete summary nodes whose
        ``period_end < before`` for ``(level, tenant_id)``.
        Cascades incident TEMPORAL_NEXT edges. Returns the count of
        summary nodes deleted (edges deleted silently as part of the
        cascade).

        Used by CIRISAgent 2.9.0 Phase 3b's TSDB retention sweep:
        once daily summaries roll up basic ones, the basic-tier rows
        are purged after a retention window passes.
        """

    def verify_locale_inclusion_json(self, leaf_json: str, proof_json: str, expected_root_hex: str) -> str:
        """(derived) testimonial — v3.8.0 — verify a LocaleInclusionProof against the expected per-target Merkle root. Returns JSON {"valid": true, ...} on success; raises with the s..."""


    # ==============================================================
    # ONTOLOGICAL  (descriptive)
    # Varying one of these changes who this node, this key, or this identity IS.
    # ==============================================================

    def attach_attestation_pqc_signature(self, attestation_id: str, scrub_signature_pqc: str) -> None:
        """(derived) ontological — Federation directory: attach PQC signature to a hybrid-pending federation_attestations row."""

    def attach_key_pqc_signature(self, key_id: str, pubkey_ml_dsa_65_base64: str, scrub_signature_pqc: str) -> None:
        """(derived) ontological — Federation directory: attach the cold-path PQC signature to a hybrid-pending federation_keys row. See docs/FEDERATION_DIRECTORY.md §"Trust contract..."""

    def attach_revocation_pqc_signature(self, revocation_id: str, scrub_signature_pqc: str) -> None:
        """(derived) ontological — Federation directory: attach PQC signature to a hybrid-pending federation_revocations row."""

    def canonical_bootstrap_hints(self) -> str:
        """(derived) ontological — v13.6.0 (CIRISPersist#402, CIRISEdge#296) — the accord-attested bootstrap dial set as a compact JSON list edge consumes directly:"""

    def deregister_occurrence(self, occurrence_id: str) -> bool:
        """v1.7.3 (CIRISPersist#81) — Clean shutdown: remove the
        occurrence row immediately, without waiting for TTL expiry.

        Returns ``True`` if a row was removed, ``False`` if it wasn't
        registered. Idempotent. This is what distinguishes a clean
        shutdown from a crash (which ages out via TTL instead).
        """

    def heartbeat_occurrence(self, occurrence_id: str, ttl_seconds: int) -> bool:
        """v1.7.3 (CIRISPersist#81) — Bump ``last_heartbeat`` and
        ``expires_at`` for an already-registered occurrence.

        Returns ``False`` if ``occurrence_id`` is not in the registry
        — a heartbeat for an unknown occurrence is a no-op, not an
        error; the caller should ``register_occurrence`` first.
        ``ttl_seconds`` must be > 0.
        """

    def initiate_classical_kex_b64(self, recipient_x25519_pub_b64: str) -> str:
        """(derived) ontological — v3.8.0 — initiate side of classical X25519-only KEX (fallback)."""

    def initiate_hybrid_kex_b64(self, recipient_x25519_pub_b64: str, recipient_mlkem768_pub_b64: str) -> str:
        """(derived) ontological — v3.8.0 — initiate side of hybrid X25519 + ML-KEM-768 KEX. Returns the handshake message + session key as JSON (caller MUST keep the session_key_b64..."""

    def keyring_path(self) -> str | None:
        """(derived) ontological — v0.1.9 — return the authoritative seed-storage path for observability surfaces (lens /health)."""

    def keyring_storage_kind(self) -> str:
        """(derived) ontological — v0.1.9 — return a stable string-token classifying the signer's storage location for /health surfacing or readiness probes."""

    def list_identity_occurrences_for_json(self, identity_key_id: str) -> str:
        """(derived) ontological — v3.12.0 — list every currently-stored occurrence of identity_key_id. Returns a JSON array of IdentityOccurrence objects (the shape put_identity_occ..."""

    def list_live_occurrences(self, identity: str) -> str:
        """v1.7.3 (CIRISPersist#81) — List currently-live occurrences
        for ``identity`` — rows whose ``expires_at > now``.

        Returns a JSON-encoded array of ``OccurrenceRecord``, ordered
        by ``occurrence_id`` ascending. Expired rows are filtered out
        (not deleted — this method is read-only). All occurrences of
        one agent share a single Ed25519 ``identity``; this answers
        "which endpoints for identity X are reachable right now."
        """

    def local_derived_key_id(self) -> str:
        """(derived) ontological — v10.6.0 (CIRISPersist#295) — Return this Engine's registered (derived) federation key_id: derive_key_id(<keystore alias>, <ed25519 pubkey>) = "<lab..."""

    def local_identity_aggregate(self, transport_x25519_b64: str | None = None, transport_ed25519_b64: str | None = None) -> str:
        """(derived) ontological — v5.4.0 (CIRISPersist#198, CEG 1.0 §5.6.8.8.2) — return this node's [LocalIdentityAggregate](crate::federation::LocalIdentityAggregate) as JSON: a s..."""

    def local_key_id(self) -> str:
        """(derived) ontological — v1.4.0 (CIRISPersist#51) — Return the configured local_key_id — the stable identifier for this Engine's local Ed25519 signing identity. Used as key..."""

    def local_pqc_key_id(self) -> str:
        """(derived) ontological — v1.4.0 (CIRISPersist#51) — Return the configured local_pqc_key_id. Distinct from local_key_id (the Ed25519 identity); deployments will typically pi..."""

    def local_pqc_public_key_b64(self) -> str:
        """(derived) ontological — v1.4.0 (CIRISPersist#51) — Return the local-process ML-DSA-65 public key (base64) for publishing to consumers (federation_keys.pubkey_ml_dsa_65_bas..."""

    def local_pqc_sign(self, message: bytes) -> bytes:
        """(derived) ontological — v1.4.0 (CIRISPersist#51) — Sign arbitrary bytes with the local ML-DSA-65 signing key. Returns the 3309-byte raw signature (FIPS 204 final)."""

    def local_public_key_b64(self) -> str:
        """(derived) ontological — v1.4.0 (CIRISPersist#51) — Return the local-process Ed25519 public key (base64) for publishing to consumers (registry pinning, federation_keys.pubk..."""

    def local_sign(self, message: bytes) -> bytes:
        """(derived) ontological — v1.4.0 (CIRISPersist#51) — Sign arbitrary bytes with the local Ed25519 signing key. Returns the 64-byte raw signature."""

    def local_sign_hybrid(self, message: bytes) -> dict[str, Any]:
        """(derived) ontological — v17.7.0 (CIRISPersist#470) — the SINGLE hybrid-sign verb across the Engine PyO3 boundary. Delegates to [LocalSigner::sign_hybrid] so the canonical..."""

    def lookup_identity_for_occurrence_json(self, occurrence_key_id: str) -> str | None:
        """(derived) ontological — v3.12.0 — reverse lookup: which identity does this occurrence_key_id speak for? Returns JSON IdentityOccurrence object or None (null) if the key is..."""

    def lookup_keys_for_identity(self, identity_ref: str) -> str:
        """(derived) ontological — Federation directory: lookup all public keys for an identity_ref. Returns a JSON array string of KeyRecord objects."""

    def lookup_public_key(self, key_id: str) -> str | None:
        """(derived) ontological — Federation directory: lookup a public key by key_id. Returns the JSON-encoded KeyRecord string, or None."""

    def public_key_b64(self) -> str:
        """(derived) ontological — Return the deployment's Ed25519 public key (base64) — for publishing to the registry / lens-discovery layer at deploy time. Same key that signs eve..."""

    def register_occurrence(
        self,
        occurrence_id: str,
        identity: str,
        ttl_seconds: int,
        metadata_json: str | None = None,
    ) -> None:
        """v1.7.3 (CIRISPersist#81) — Register (or re-register) a live
        occurrence with a liveness TTL.

        Idempotent on ``occurrence_id``: re-registering refreshes
        ``registered_at``, ``last_heartbeat``, and ``expires_at``.
        ``ttl_seconds`` must be > 0; ``expires_at = now + ttl_seconds``.
        A crashed occurrence ages out past ``expires_at`` without a
        clean deregister — TTL-based liveness, not membership.

        Under the one-key model (PoB §3.2) every occurrence of an
        agent signs with the *same* Ed25519 ``identity``, so this
        registry is endpoint liveness under a stable identity, not a
        membership change. ``metadata_json``, if provided, must be a
        JSON value (e.g. endpoint addresses, version).

        ``occurrence_id`` and ``identity`` must both be non-empty.
        """

    def register_self_federation_key(
        self,
        identity_type: str,
        identity_ref: str,
        valid_until: str | None = None,
        registration_envelope_json: str | None = None,
        roles: list[str] | None = None,
    ) -> str:
        """v1.5.3 (renamed from `register_federation_key` in v8.8.0) —
        One-call helper that registers THIS engine's local pubkey in the
        **federation directory** (`federation_keys`).

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

    def respond_classical_kex_b64(self, recipient_x25519_priv_b64: str, handshake_msg_json: str) -> str:
        """(derived) ontological — v3.8.0 — respond side of classical X25519-only KEX (fallback)."""

    def respond_hybrid_kex_b64(self, recipient_x25519_priv_b64: str, recipient_mlkem768_priv_b64: str, recipient_mlkem768_pub_b64: str, handshake_msg_json: str) -> str:
        """(derived) ontological — v3.8.0 — respond side of hybrid KEX. Returns the matching session key as JSON."""

    def root_binding(self, key_id: str, claimed_pubkey_ed25519_base64: str) -> str:
        """(derived) ontological — Cold-start binding-rooting primitive (CIRISPersist#94)."""

    def self_enc_pubkeys(self) -> dict[str, Any]:
        """(derived) ontological — v19.2.0 (CIRISPersist#493) — the node's own content-tier self-encryption pubkeys, derived from the engine's local signing seed (public halves only)..."""

    def self_key_id(self) -> str | None:
        """(derived) ontological — v22.0.0 (CIRISPersist#543 / AV-77) — this node's declared own key id, or None when the host has not declared one (in which case the de-admission ga..."""

    def set_self_key_id(self, key_id: str | None) -> None:
        """(derived) ontological — v22.0.0 (CIRISPersist#543 / AV-77) — declare THIS NODE'S OWN federation key id, which is what activates the peer de-admission gate. Call it once at..."""

    def sign(self, message: bytes) -> bytes:
        """(derived) ontological — v0.2.1 — Sign arbitrary bytes with the deployment's Ed25519 signing key (the hot-path signature in the hybrid writer contract). Returns the 64-byte..."""


    # ==============================================================
    # NOMOLOGICAL  (descriptive)
    # Varying one of these changes the model every other symbol reasons under.
    # ==============================================================

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

    def canonicalize_envelope(self, envelope_json: str) -> bytes:
        """Canonicalize an arbitrary envelope via the production
        ``PythonJsonDumpsCanonicalizer`` (sorted keys, no whitespace,
        ``ensure_ascii=True``). Returns the canonical bytes the
        substrate signs and verifies.

        **Do not use** ``serde_json_canonicalizer`` (JCS RFC 8785) on
        downstream — it is ``#[cfg(test)]`` only and produces different
        bytes for non-ASCII envelopes. Use this canonicalizer
        end-to-end so signature verify holds across the cohabitation
        boundary (v3.3.0 #121 trap discipline).
        """

    def canonicalize_envelope_for_signing(self, envelope_json: str) -> bytes:
        """Canonicalize for signing — same canonicalizer as
        :meth:`canonicalize_envelope`. Separate entry point preserved
        for callers (CIRISEdge, CIRISConformance) that key off the
        function name semantically.
        """

    def cohort_scope_crypto_tier(self, cohort_scope: str, cohort_subkind: str | None = None) -> str:
        """(derived) nomological — CC 4.4.3.2.8 / #308 — resolve a cohort_scope wire token to its at-rest crypto tier, exposing [crate::federation::types::cohort_scope::crypto_tier]..."""

    def debug_canonicalize(self, body: bytes) -> list[Any]:
        """(derived) nomological — v0.1.18 — debug helper for canonical-byte drift diagnosis (CIRISPersist#6 follow-up). Pipes a raw HTTP body through persist's schema parse + canoni..."""

    def envelope_vocabulary(self) -> dict[str, Any]:
        """(derived) nomological — v20.0.0 (CIRISPersist#495) — the pinned envelope-vocabulary manifest and its sha256, as {"manifest_json", "sha256"}. A cross-repo harness asserts e..."""

    def is_canonical(self, key_id: str) -> bool:
        """(derived) nomological — v13.0.0 (CIRISPersist#372, CC 3.4.7.1) — is key_id a canonical / founding bootstrap server? Returns True iff its federation_keys row's identity_typ..."""

    def maintenance_tighten_vocabulary(self, target_json: str, dry_run: bool = False) -> str:
        """(derived) nomological — v25.1.0 (CIRISPersist#582) — Run one vocabulary tightening: retire every federation-tier attestation carrying a non-conformant wire value at a name..."""

    def trace_summary_extraction(self) -> dict[str, Any]:
        """(derived) nomological — v19.2.0 (CIRISPersist#494) — the pinned trace-summary EXTRACTION manifest and its sha256, as {"manifest_json", "sha256"}. This names which fields a..."""

    def validate_envelope_canonical_form(self, envelope_json: str, now_iso: str | None = None) -> None:
        """(derived) nomological — v3.5.0 (CIRISPersist#126) — opt-in CEG §0.5/§0.6/§0.7 validation. Walks envelope_json and rejects:"""

    @staticmethod
    def verify_coord_constants_json() -> str:
        """(derived) nomological — v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL §3.3.2) — verify-coord R1+Q1 constants as a JSON dict for consumer code that needs t..."""


    # ==============================================================
    # EPISTEMIC  (descriptive)
    # Varying one of these changes how uncertainty is held — bands, absence, liveness.
    # ==============================================================

    def age_band_fine_json(self, key_id: str) -> str:
        """(derived) epistemic — v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — the finer four-band age resolution of key_id, the policy vocabulary ABOVE the binary [age_band_json]. Re..."""

    def age_band_json(self, key_id: str) -> str:
        """(derived) epistemic — v11.5.0 (CIRISPersist#306, CC 3.3.12 / CC 1.15.6) — the I1 age band of key_id, resolved from its incoming age attestations (witness age_assurance:..."""

    def cache_budget_bytes(self) -> int:
        """(derived) epistemic — v6.8.0 (CIRISPersist#148) — the operator-set (or mode-default) storage budget in bytes. u64::MAX ⇒ unbounded (Server mode)."""

    def cache_usage_bytes(self) -> int:
        """(derived) epistemic — v6.8.0 (CIRISPersist#148) — current total local federation_blobs bytes (the cache usage). For ops monitoring."""

    def capacity_state_json(self, key_id: str, domain: str) -> str:
        """(derived) epistemic — v11.9.0 (CIRISPersist#309, CC 3.4.12) — the resolved capacity state of key_id for decision-domain, from its incoming witness capacity_assurance::{d..."""

    def corpus_shape(self, filter_json: str, caller_occurrence_key_id: str | None) -> str:
        """(derived) epistemic — Corpus-shape rollup over a filtered window — the coarse distribution a caller reads BEFORE deciding what to query in detail. Reports shape, not row..."""

    def cross_agent_divergence(self, deployment_domain: str, window_json: str, metric: str, caller_occurrence_key_id: str | None) -> str:
        """(derived) epistemic — Cross-agent divergence z-scores. metric is one of "csdma_plausibility", "dsdma_domain_alignment", "idma_k_eff", "idma_correlation_risk", "conscienc..."""

    def disk_pressure_state(self) -> dict[str, Any]:
        """(derived) epistemic — v6.8.0 (CIRISPersist#149) — live disk-pressure snapshot for monitoring. Re-polls the (injectable) free-bytes source, returns a dict: {free_bytes, t..."""

    def get_repository_statistics(self, filter_json: str, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) epistemic — Corpus-shape rollup for a window — distinct trace counts by task_class, QA language / question_num, agent name / version, primary model, deployment..."""

    def list_signed_accord_quorum_evidence_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) epistemic — v31.1.0 (CIRISPersist#662) — bulk-list the signed accord EVIDENCE bundles (proposal + its hybrid-signed participations) since a cursor, as a JSON a..."""

    def list_signed_communities_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full SignedCommunity wrappers since a cursor, as a JSON array. Same contract as [list_signed_famil..."""

    def list_signed_community_membership_revocations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full SignedCommunityMembershipRevocation wrappers since a cursor, as a JSON array. Same contract a..."""

    def list_signed_families_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.0.0 (CIRISPersist#504 FLOOR, edge advertise/serve bridge) — bulk-list the full SignedFamily wrappers (row + the V110 authority signature put_fa..."""

    def list_signed_family_membership_revocations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full SignedFamilyMembershipRevocation wrappers since a cursor, as a JSON array. Same contract as [..."""

    def list_signed_identity_occurrence_revocations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.1.0 (CIRISPersist#507c) — bulk-list the full SignedIdentityOccurrenceRevocation wrappers since a cursor, as a JSON array. Signed rows only; ord..."""

    def list_signed_identity_occurrences_for_json(self, identity_key_id: str) -> str:
        """(derived) testimonial — v14.1.0 (CIRISPersist#418, replication read) — the signed-put occurrences of identity_key_id, each as a full SignedIdentityOccurrence JSON object (..."""

    def list_signed_identity_occurrences_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.1.0 (CIRISPersist#507c) — bulk-list the full SignedIdentityOccurrence wrappers since a cursor, as a JSON array. Signed rows only (trusted-local..."""

    def list_signed_key_records_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.1.0 (CIRISPersist#507c, edge advertise/serve bridge) — bulk-list SignedKeyRecord wrappers since a cursor, as a JSON array, ordered (scrub_times..."""

    def list_signed_location_proofs_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full SignedLocationProof wrappers since a cursor, as a JSON array. Same contract as [list_signed_f..."""

    def list_signed_partner_records_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v5.2.0 (CIRISPersist#194, CIRISEdge#65 v2 bridge) — bulk-list the full SignedPartnerRecord wrappers (row + the M-of-N steward signature set + thres..."""

    def list_signed_revocations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) epistemic — v31.1.0 (CIRISPersist#655) — bulk-list SignedRevocation wrappers since a cursor, as a JSON array, ordered (scrub_timestamp ASC, revocation_id ASC)...."""

    def list_signed_transport_destinations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) testimonial — v21.1.0 (CIRISPersist#507c) — bulk-list the full SignedTransportDestination wrappers since a cursor, as a JSON array. Signed rows only; RETIRED row..."""

    def node_state_json(self, self_key_id: str | None = None, root_key_id: str | None = None, now: str | None = None, sla_seconds: int | None = None) -> str:
        """CIRISServer#356 — **how is this node?**, in one call.

        Folds the node-scoped state signals into one payload, so a dashboard
        refresh is one round-trip instead of ten and the composition lives in
        persist rather than being reimplemented per consumer::

            {as_of, self_key_id?, band, unknown[], clock_dependent[], targeted[],
             trust_root:    {band, standing, root_ref?, roots_considered,
                             verdict?, last_drill_at?, drill_freshness?,
                             drill_band},
             key_statements:{band, standing?, statement_at, covered_by[],
                             considered},
             quarantine:    {band, state?, marker_id?, decided_by?, grounds?},
             consent_sla:   {band, overdue?, sla_seconds,
                             sample_attestation_ids[], read_only},
             peer_quota:    {band, observation?, note}}

        **A gauge, not a gate.** Nothing in this payload may be gated on. Every
        band renders an authority that lives elsewhere, and the authority is
        what a decision must consult: :meth:`trust_root_verdict_json` decides
        whether a root serves, :meth:`resolve_quarantine_json`'s
        ``state == "withheld"`` decides whether a key is served. This is a
        summary taken at an instant, and summaries lose information on purpose.

        **Bands, never floats -- and a band never replaces a token.** ``band``
        is ``"green"`` / ``"yellow"`` / ``"red"`` / ``"unknown"``, mirroring the
        three names ``drill_freshness`` already shipped. Every signal carries
        its band **and** its underlying typed token, because the band is lossy
        and the token is not. Where two states share a band their tokens still
        differ.

        That is the *distinguish the zeroes* rule applied here: the four ways
        of having no valid trust root are four tokens (``"no_self_key"`` /
        ``"no_trust_edges"`` / ``"no_valid_root"`` / ``"unreadable"``) on two
        different bands; ``"not_quarantined"`` and ``"released"`` are two
        tokens on two bands; ``overdue: 0`` and ``overdue: None`` are two facts
        on two bands.

        **A red headline does not mean an invalid root.** The drill band is
        folded in, because "last drill performed 200 days ago" is precisely
        what an operator surface should show -- but it stays a *signal*, and
        ``trust_root.verdict["valid"]`` does not consult it. A node can read
        ``band: "red"`` here and serve perfectly.

        **``"unknown"`` is not ``"green"``, and it is never absent.** Any signal
        this node cannot currently compute renders ``"unknown"``. Most failure
        modes here are silent ones -- a host that never called
        :meth:`set_self_key_id`, a backend that does not implement a read, a
        counter never exercised -- and every one of them produces *no bad
        news*. ``unknown`` ranks between yellow and red in the top-level
        roll-up, and because a roll-up could otherwise let an unknown hide
        behind a red, **``unknown[]`` names every unknown signal
        individually**. Read that list; do not infer it from the headline.

        **Which signals move with the clock alone**: ``clock_dependent[]``
        names them, and they are not few. Drill freshness crosses its bands at
        90 and 180 days, a consent SLA goes overdue, a future-dated revocation
        or quarantine marker takes effect -- all with no state change and no
        new row. A consumer diffing two reads will see transitions nothing
        caused. ``as_of`` is the instant every band was evaluated against; pass
        ``now`` to pin it.

        **What is deliberately not here**: four signals are answers about a
        *target* -- a peer, an object, an objection -- not facts about a node.
        Inventing a target would produce an answer indistinguishable from a
        real one. ``targeted[]`` names each with the binding that answers it,
        so the omission is legible rather than silent.

        **This writes nothing**, including the consent-SLA leg, which uses the
        read-only overdue query. Poll it freely.

        **The return is a truthy string on every arm.** A node whose every
        signal reads ``"red"`` still returns a non-empty ``str``.
        ``json.loads`` it and read ``["band"]`` and ``["unknown"]``.

        ``self_key_id`` defaults to the id declared via
        :meth:`set_self_key_id`. ``root_key_id`` pins the trust-root walk to
        one root instead of enumerating this node's own ``trust:accepts``
        edges. ``now`` is RFC 3339.
        """

    def peer_quota_observation_json(self) -> str | None:
        """CIRISServer#356 — the peer-write-quota **tail-squeeze tripwire**, as
        JSON ``{process_local, tracked_peers, slot_denials}``, or ``None`` when
        this backend holds no quota.

        **Read the volatility before the numbers.** ``process_local`` is always
        ``True``, and it is in the payload rather than only in this docstring
        on purpose. The quota is held per backend instance, never as a process
        global, so both counters **reset on restart**, **differ between
        processes serving one node**, and are **stored nowhere** -- no row backs
        them, no replication carries them, and no peer can be shown them as
        evidence.

        This is a gauge *of this process*, not a fact about the node. Summing
        it across replicas, diffing it across restarts, or putting it on a
        trust card would each read it as something it is not. Making it durable
        is a schema change and was deliberately not taken.

        **What it is genuinely for**: ``slot_denials`` **must be 0** -- the
        tracked-peers cap is derived to make the branch that increments it
        unreachable by arithmetic. A non-zero reading does not mean "traffic is
        heavy", it means *the inequality the derivation gate asserts no longer
        holds in this build*. It is **not** a throttling metric; ordinary
        per-peer quota refusals are a different and far more common thing, and
        are not counted here at all.

        Those arrive as a ``RuntimeError`` on the **write** path, and since
        v28.3.0 they name which budget refused. The message is::

            federation_rate_limited: <token> (retry_after_seconds=<n>)

        ``<token>`` is a stable program constant -- one of ``peer_burst``,
        ``peer_sustained``, ``untracked_tail_burst``,
        ``untracked_tail_sustained``, ``node_burst``, ``node_sustained``,
        ``reserved_burst``, ``reserved_sustained`` and their ``_bytes_``
        counterparts (``peer_bytes_burst``, ``node_bytes_sustained``, ...).
        The row tokens and the byte tokens are what let you tell a **row**
        flood from a **storage** flood, and ``_burst`` from ``_sustained``
        tells "slow down for seconds" from "the day's budget is gone". Branch
        on the token, never on the sentence around it; the token set is
        append-only.

        Those refusals are ordinary throttling and are **not** counted in
        ``slot_denials`` -- this method is a different signal.

        **Zero is not health until the tripwire has been exercised.**
        ``slot_denials == 0`` on a freshly-booted process is *untested*, not
        *clean*. ``tracked_peers`` is the denominator that tells those apart:
        ``0`` means no peer write has been charged here at all.
        :meth:`node_state_json` applies exactly that rule and bands this
        ``"unknown"`` rather than ``"green"`` -- do the same if you render it
        yourself.

        Read-only.
        """

    def secrets_is_healthy(self) -> bool:
        """(derived) epistemic — v0.6.1 — Liveness probe. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_test_encryption(self) -> bool:
        """(derived) epistemic — v0.6.1 — Encrypt-decrypt round-trip health check. [build-conditional: #[cfg(feature = "secrets")]]"""

    def temporal_drift(self, agent_id_hash: str, baseline_json: str, comparison_json: str, caller_occurrence_key_id: str | None) -> str:
        """(derived) epistemic — Temporal drift between two windows for one agent. Returns JSON array of TemporalDriftRow."""

    def verify_trace(self, complete_trace_json: str) -> dict[str, Any]:
        """(derived) testimonial — v0.4.0 — Verify a CompleteTrace envelope end-to-end. Looks up signature_key_id via the federation directory, reconstructs canonical bytes per trace..."""


    # ==============================================================
    # EMPIRICAL  (descriptive)
    # Varying one of these makes a checkable, re-derivable world-fact wrong.
    # ==============================================================

    def active_community_members_json(self, community_key_id: str) -> str:
        """(derived) empirical — #249 Cut B — the active member roster of community_key_id (members MINUS effective membership revocations). Returns a JSON array of [crate::federat..."""

    def active_family_members_json(self, family_key_id: str) -> str:
        """(derived) empirical — #249 Cut B — the active member roster of family_key_id. Returns a JSON array of [crate::federation::types::FamilyMember]."""

    def attestation_insert_local(self, input_json: str) -> str:
        """(derived) empirical — v4.4.0 (CIRISPersist#171) — insert (append) a local-tier attestation for a multi-valued dimension (memory / per-thought verdicts). Same shape as [a..."""

    def attestation_insert_local_many(self, inputs_json: str) -> str:
        """(derived) empirical — v5.0.0 (CIRISPersist#171) — batched [attestation_insert_local](Self::attestation_insert_local) for multi-valued / event dimensions (memory, per-tho..."""

    def attestation_upsert_local(self, input_json: str) -> str:
        """(derived) empirical — v4.4.0 (CIRISPersist#171, CEG §10.1.3) — upsert a local-tier self-attestation (input_json = a LocalAttestationInput). Replace-on-(occurrence, dimen..."""

    def attestation_upsert_local_many(self, inputs_json: str) -> str:
        """(derived) empirical — v5.0.0 (CIRISPersist#171, CEG §10.1.3) — batched [attestation_upsert_local](Self::attestation_upsert_local). inputs_json is a JSON array of LocalAt..."""

    def blackhole_list_json(self) -> str:
        """(derived) empirical — Federation blackhole rules: list every rule."""

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

    def cirisgraph_count_edges(self, scope: str) -> int:
        """v1.5.25 (CIRISPersist#65) — Count edges within ``scope``.

        ``scope`` is one of ``"local"``, ``"identity"``,
        ``"environment"``, ``"community"`` (the
        :class:`cirisgraph.GraphScope` SQL strings). Returns the raw
        integer.
        """

    def cirisgraph_count_nodes(self, filter_json: str) -> int:
        """v1.5.25 (CIRISPersist#65) — Count nodes matching ``filter_json``.

        ``filter_json`` is a JSON-encoded ``NodeFilter`` — same shape
        accepted by :meth:`cirisgraph_query_nodes`, including the
        v1.5.25 ``exclude`` field for the compound exclusion rule
        (``NOT (node_type = ... AND node_id LIKE ...)``) and the
        v1.6.1 ``attribute_match`` field for JSON-attribute-path
        equality / array-containment filtering:

        .. code-block:: json

            {
              "scope": "local",
              "attribute_match": {
                "path": "created_by",
                "equals_any": ["alice", "bob"],
                "array_contains_any": ["alice"]
              }
            }

        Both ``equals_any`` and ``array_contains_any`` are optional;
        when both are set they OR-combine (row matches if either arm
        does). ``path`` must be alphanumeric + underscore.

        The ``scope`` field is required (AV-47 — no implicit
        "all scopes" reads).

        Returns the raw integer (not a JSON envelope).

        Unblocks CIRISAgent 2.9.0 Phase 4
        (``COUNT(*) FROM graph_nodes`` API tile) and Phase 5
        (the agent's OBSERVER user-filter Layer 1 in
        ``memory_query_helpers.py``).
        """

    def cirisgraph_count_nodes_by_type(self, scope: str) -> str:
        """v1.5.25 (CIRISPersist#65) — Group-by-type histogram of
        nodes in ``scope``.

        Returns the JSON-encoded ``dict[str, int]`` mapping
        ``node_type`` → row count. Useful for the dashboard
        "memory composition by type" tile (replacing the agent's raw
        ``SELECT node_type, COUNT(*) FROM graph_nodes GROUP BY
        node_type`` SQL).
        """

    def cirisgraph_delete_node(self, node_id: str, scope: str, hard: bool) -> bool:
        """(derived) empirical — v0.8.0 — Soft- or hard-delete a node. Hard delete cascades edges. Returns true if a row was affected. [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisgraph_get_edges_for_node(self, node_id: str, scope: str, direction: str, relationship_filter_json: str | None) -> str:
        """(derived) empirical — v0.8.0 — Incident edges from a node. Returns JSON array of GraphEdge. direction is "outgoing" | "incoming" | "both"; relationship_filter is None fo... [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisgraph_get_node(self, node_id: str, scope: str) -> str | None:
        """(derived) empirical — v0.8.0 — Point-lookup one node. Returns JSON GraphNode or None. [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisgraph_query_nodes(self, filter_json: str, cursor_json: str | None, limit: int) -> str:
        """(derived) empirical — v0.8.0 — Cursor-paged node listing. Returns JSON NodeListPage. AV-47: filter MUST name a scope. [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisgraph_traverse_k_hop(self, start_node_id: str, scope: str, config_json: str) -> str:
        """(derived) empirical — v0.8.0 — AV-46 bounded k-hop traversal. Returns JSON array of KhopEntry. [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisgraph_upsert_edge(self, edge_json: str, bulk_import: bool = False) -> None:
        """(derived) empirical — v0.8.0 — Insert a directed edge. Idempotent on edge_id. [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisgraph_upsert_node(self, node_json: str, expected_version: int, bulk_import: bool = False) -> None:
        """(derived) empirical — v0.8.0 — Upsert a graph node with AV-48 optimistic-concurrency gate. Pass expected_version = 0 for new rows; current version for updates. [build-conditional: #[cfg(feature = "cirisgraph")]]"""

    def cirisnode_count_delivery_attestations(self, announcement_id: str) -> int:
        """(derived) empirical — v2.1 (CIRISPersist#101) — Count delivery attestations for a federation_announcement. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_get_goal_json(self, goal_id: str) -> str | None:
        """(derived) empirical — Federation directory: fetch a Goal by goal_id."""

    def cirisnode_list_contributions(self, filter_json: str, cursor_json: str | None, limit: int) -> str:
        """(derived) empirical — v0.7.0 — Page through cirisnode.contributions. Returns JSON ContributionListPage (items + optional next_cursor). [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_delivery_attestations(self, announcement_id: str) -> str:
        """(derived) empirical — v2.1 (CIRISPersist#101) — List all delivery attestations for a federation_announcement, newest-first. Returns a JSON array of [DeliveryAttestation]... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_goals_json(self, goals_filter_json: str) -> str:
        """(derived) empirical — Federation directory: list goals matching goals_filter_json."""

    def cirisnode_list_key_grants_for_content_json(self, content_sha256: str, recipient_key_id: str) -> str:
        """(derived) empirical — List key_grant Contributions matching BOTH content_sha256 AND recipient_key_id. JSON array of [ContributionEnvelope](crate::cirisnode::Contribution... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_key_grants_for_filtered_json(self, recipient_key_id: str, filter_json: str | None = None, cursor_json: str | None = None, limit: int = 100) -> str:
        """(derived) empirical — v6.3.0 (CIRISPersist#135, Lane C) — key-grants to recipient_key_id, cursor-paged + filtered. JSON-encoded [KeyGrantListPage](crate::cirisnode::KeyG... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_key_grants_for_json(self, recipient_key_id: str) -> str:
        """(derived) empirical — List key_grant Contributions for recipient_key_id. JSON array of [ContributionEnvelope](crate::cirisnode::ContributionEnvelope). [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_key_grants_for_stream_epoch_json(self, stream_id: str, epoch: int) -> str:
        """(derived) empirical — v4.x (CIRISPersist#142 Cut C3b, CEG §10.5.3) — list every stream/epoch-addressed key_grant Contribution for (stream_id, epoch), newest-first. JSON... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_takedowns_for_filtered_json(self, target_content_sha256: str, filter_json: str | None = None, cursor_json: str | None = None, limit: int = 100) -> str:
        """(derived) empirical — v6.3.0 (CIRISPersist#135, Lane C) — takedowns against target_content_sha256, cursor-paged + filtered. JSON-encoded [TakedownListPage](crate::cirisn... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_takedowns_for_json(self, content_sha256: str) -> str:
        """(derived) empirical — List takedown_notice Contributions for content_sha256. JSON array of [ContributionEnvelope](crate::cirisnode::ContributionEnvelope). [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_list_votes(self, filter_json: str, cursor_json: str | None, limit: int) -> str:
        """(derived) empirical — v0.7.0 — Page through cirisnode.votes. Returns JSON VoteListPage. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_contribution(self, envelope_json: str) -> None:
        """(derived) empirical — v0.7.0 — Verify-and-insert a Contribution envelope. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_put_goal_json(self, goal_json: str) -> None:
        """(derived) empirical — Federation directory: insert a typed Goal."""

    def cirisnode_retire_goal_json(self, goal_id: str, retired_at_rfc3339: str) -> None:
        """(derived) empirical — Federation directory: retire a Goal. Idempotent — a second call against an already-retired goal returns Ok without changing the stored retired_at."""

    def cohort_active_member_keys_json(self, cohort: str, group_key_id: str) -> str:
        """(derived) empirical — #249 Cut G1 (§2) — active roster of group_key_id resolved to pinned hybrid pubkeys. Returns a JSON array of [crate::federation::types::KeyRecord]...."""

    def cohort_active_members_json(self, cohort: str, group_key_id: str) -> str:
        """(derived) empirical — #249 Cut G1 (§1) — active roster of group_key_id in cohort. Returns a JSON array of [crate::federation::cohort::RosterMember]."""

    def cohort_group_at(self, cohort: str, group_key_id: str, version: int) -> str | None:
        """(derived) empirical — #249 Cut G2 (§8) — the family/community at a specific version. Returns the [crate::federation::cohort::GroupVersion] JSON or None."""

    def cohort_group_history(self, cohort: str, group_key_id: str) -> str:
        """(derived) empirical — #249 Cut G2 (§8) — the full version chain of a family/community (superseded history + the live current). Returns a JSON array of [crate::federation..."""

    def cohort_groups_of_json(self, cohort: str, member_key_id: str) -> str:
        """(derived) empirical — #249 Cut G1 (§1) — every group in cohort that member_key_id is currently a member of. Returns a JSON array of [crate::federation::cohort::GroupRef]."""

    def cohort_lookup_group_json(self, cohort: str, group_key_id: str) -> str | None:
        """(derived) empirical — #249 Cut G1 (§1) — look up a group uniformly. Returns the [crate::federation::cohort::GroupRef] JSON, or None if unknown."""

    def consent_role_json(self, key_id: str) -> str:
        """(derived) empirical — v13.0.0 (CIRISPersist#365, CC 3.4.7.2 consent-counter) — resolve the Counter-RII consent_role of key_id. Returns a JSON string: the assigned role t..."""

    def continuity_get_latest(self, agent_id: str) -> str | None:
        """v1.5.17 — Get the most recent shutdown for an agent —
        used on next boot to surface "where did I leave off."
        Returns JSON-encoded ``ContinuityAwareness`` or ``None``
        when the agent has no recorded shutdowns. Ordered by
        ``shutdown_timestamp DESC``, ``LIMIT 1``.
        """

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

    def continuity_record_reactivation(self, agent_id: str) -> bool:
        """v1.5.17 — Increment ``reactivation_count`` on the
        most-recent non-terminal shutdown for ``agent_id``. Used
        when the agent successfully resumes from a non-terminal
        shutdown.

        Returns ``True`` when a row was updated, ``False`` when the
        agent has only terminal shutdowns or no shutdowns at all
        (callers treat as "nothing to reactivate" — not an error).
        """

    def correlation_get(self, correlation_id: str) -> str | None:
        """v1.5.11 — Read one correlation by id. Returns the JSON-
        encoded ``Correlation`` row or ``None`` when no matching row.
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

    def count_identity_changes(self, filter_json: str, caller_occurrence_key_id: str | None = None) -> int:
        """(derived) empirical — Granular: count agent_name changes (identity changes)."""

    def count_overrides(self, filter_json: str, caller_occurrence_key_id: str | None = None) -> int:
        """(derived) empirical — Granular: count traces where conscience overrode the action."""

    def count_traces(self, filter_json: str, caller_occurrence_key_id: str | None = None) -> int:
        """(derived) empirical — Granular: count distinct trace_id matching filter."""

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

    def delegates_to_graph(self, from_key: str, max_depth: int) -> str:
        """(derived) empirical — v2.7.0 (CIRISPersist#104) — Delegation-graph BFS from from_key. Returns a JSON [crate::federation::DelegationGraph] with one [crate::federation::De..."""

    def delegations_to_json(self, key_id: str) -> str:
        """(derived) empirical — #249 Cut B — the inbound delegates_to edges naming key_id as recipient ("who delegated TO me?" — the reverse of delegates_to_graph). Returns a JSON..."""

    def duty_holders_for_community_json(self, community_id: str, duty: str) -> str:
        """(derived) empirical — #249 Cut A — the duty-holders of a bare community-scoped action (a moderation: / reconsideration: over community_id with no content subject) for du..."""

    def duty_holders_for_content_json(self, content_sha256: str, community_id: str, duty: str) -> str:
        """(derived) empirical — #249 Cut A — the duty-holders of a content target (content_sha256) for duty (moderate / takedown / review): the content's resolved subjects ∪ the n..."""

    def federation_directory_query(self, filter_json: str) -> str:
        """(derived) empirical — v2.7.0 (CIRISPersist#104) — Trust-Topology aggregate query. Walks federation_attestations to produce a [TrustTopology] with nodes (resolved through..."""

    def federation_list_trusted_keys(self, trust_filter_json: str) -> str:
        """(derived) empirical — Federation directory: list trusted keys matching a filter. Returns a JSON-array string of TrustRow objects."""

    def federation_lookup_trust(self, key: str) -> str | None:
        """(derived) empirical — Federation directory: look up the trust row for a key. Returns a JSON-encoded TrustRow string, or None if no trust grant exists."""

    def feedback_list(self, filter_json: str, limit: int) -> str:
        """v1.5.18 — Filter-query feedback rows. ``filter_json`` is a
        JSON-encoded ``FeedbackFilter`` — supported fields:
        ``source_message_id``, ``feedback_type``, ``created_after``,
        ``created_before`` (RFC 3339 timestamps for the time
        window). Returns JSON-encoded ``list[FeedbackMapping]``,
        ordered DESC by ``created_at``.
        """

    def feedback_list_for_thought(self, thought_id: str, limit: int) -> str:
        """v1.5.18 — List feedback rows attached to a specific
        thought. Ordered ``created_at DESC, feedback_id DESC``.
        Returns JSON-encoded ``list[FeedbackMapping]``. Hits the
        partial index ``feedback_mappings_thought``.
        """

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

    def fetch_trace_events_page(self, after_event_id: int = 0, limit: int = 1000, agent_id_hash: str | None = None) -> list[Any]:
        """(derived) empirical — v0.3.5 (CIRISLens#8 ASK 3) — Page-cursor read primitive for analytical streaming. Returns up to limit trace_events rows where event_id > after_even..."""

    def get_accord_decision_json(self, proposal_digest: str) -> str | None:
        """(derived) empirical — #302 — the stored decision as JSON, or None."""

    def get_accord_proposal_json(self, proposal_digest: str) -> str | None:
        """(derived) empirical — #302 — the stored proposal as JSON, or None."""

    def get_active_halt_json(self, family_key_id: str) -> str | None:
        """(derived) empirical — #302 (H2) — the active halt for a family as JSON, or None."""

    def get_blob_json(self, sha256_hex: str) -> str | None:
        """v2.3.0 (#103) — Read a blob by full SHA-256. Returns a
        JSON-encoded ``BlobBody`` (``{"Inline": <bytes>}`` or
        ``{"External": {...}}``) or ``None`` if absent.

        Every successful read bumps ``federation_blobs.access_count``
        and refreshes ``last_accessed_at`` (v3.4.0 #123 access
        tracking). Use :meth:`list_holders_json` to find the live
        attesters for a SHA before reading.

        Raises:
            ValueError: ``blob_invalid_argument`` on malformed SHA.
            RuntimeError: backend / IO error.
        """

    def get_calibration_bundle_by_version(self, version: int) -> str | None:
        """(derived) empirical — Lens-derived: get the bundle for a specific ratchet_calibration_version."""

    def get_classifications(self, trace_id: str, thought_id: str) -> str:
        """(derived) empirical — v0.6.0 (CIRISPersist#19) — read per-component classification matches for a (trace_id, thought_id) pair from cirislens.trace_events.classifications... [build-conditional: #[cfg(feature = "classify")]]"""

    def get_current_calibration_bundle(self) -> str | None:
        """(derived) empirical — Lens-derived: get the bundle with is_current = TRUE. Returns JSON-encoded CalibrationBundle or None."""

    def get_detection_events(self, filter_json: str | None) -> str:
        """(derived) empirical — Lens-derived: query detection events. Filter is JSON-encoded EventFilter ({"trace_id": ?, "detector": ?, "since": ?}; any field may be null/absent)..."""

    def get_edge_detection_events(self, filter_json: str | None) -> str:
        """(derived) empirical — v2.13.0 (CIRISPersist#113) — query the V020 edge_detection_events table. Filter is JSON-encoded EdgeEventFilter:"""

    def get_features(self, trace_id: str, thought_id: str) -> str | None:
        """(derived) empirical — v0.6.0 (CIRISPersist#19) — read typed Features for a (trace_id, thought_id) pair from cirislens.trace_events.extracted_features (V009 column). [build-conditional: #[cfg(feature = "extract")]]"""

    def get_fountain_content(self, content_id: str, corpus_kind: str) -> str | None:
        """(derived) empirical — Each present symbol's SHA-256 is re-verified against the signed symbol_hashes on read; a mismatch raises a ValueError (fountain_integrity) rather t..."""

    def get_installed_storage_budget_json(self, node_id: str) -> str | None:
        """(derived) empirical — #370 — the installed StorageBudgetV1 wire JSON for node_id, VERBATIM as accepted (re-verifiable with verify_storage_budget_v1). None when no budget..."""

    def get_multimedia_config_json(self) -> str | None:
        """(derived) empirical — v3.6.0 (CIRISPersist#134) — snapshot of the currently-installed media-sharing config as a JSON string. Returns the wire shape (see [MultimediaConfi... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def get_retention(self, table_name: str) -> str | None:
        """(derived) empirical — v6.0.1 (CIRISPersist#218) — Stored retention policy for table_name as a JSON-encoded RetentionPolicy, or None when no policy exists."""

    def get_scope_blob(self, record_id: bytes, symbol_index: int) -> Any:
        """(derived) empirical — v9.1.0 (FSD §2.4, CIRISPersist#243; FFI #271) — read one scope-blob symbol back by (record_id, symbol_index). Returns None if absent; otherwise a (..."""

    def get_trace_detail(self, trace_id: str, caller_occurrence_key_id: str | None = None) -> str | None:
        """(derived) empirical — Full trace reconstruction. Returns JSON-encoded TraceDetail or None. Drives /repository/traces/{trace_id}."""

    def get_trace_summary(self, trace_id: str, caller_occurrence_key_id: str | None = None) -> str | None:
        """(derived) empirical — Single-trace summary lookup. Returns JSON-encoded TraceSummary or None."""

    def get_trust_grant(self, grant_id: str) -> str | None:
        """Point lookup by canonical UUID ``grant_id``. Returns a
        JSON-encoded ``TrustGrantRow`` or ``None``."""

    def has_blob_json(self, sha256_hex: str) -> bool:
        """(derived) empirical — Federation blob storage: existence check by SHA-256 (hex)."""

    def incident_correlate(self, tenant_id: str, key: str) -> str:
        """(derived) empirical — v0.8.3 — Reverse-lookup incidents naming a given correlation key. Returns JSON array of IncidentRef. [build-conditional: #[cfg(feature = "cirisincident")]]"""

    def incident_list(self, filter_json: str, cursor_json: str | None, limit: int) -> str:
        """(derived) empirical — v0.8.3 — Cursor-paged tenant-scoped incident listing. [build-conditional: #[cfg(feature = "cirisincident")]]"""

    def incident_record(self, incident_json: str) -> str:
        """(derived) empirical — v0.8.3 — Record an incident (correlation-keyed dedup; bumps occurrences on existing open match). Returns the incident_id of the row that took the w... [build-conditional: #[cfg(feature = "cirisincident")]]"""

    def incident_transition(self, transition_json: str) -> None:
        """(derived) empirical — v0.8.3 — AV-55 state-machine transition. Notes required for Resolved/Closed targets. [build-conditional: #[cfg(feature = "cirisincident")]]"""

    def list_accord_participations_json(self, proposal_digest: str) -> str:
        """(derived) empirical — #302 — all participations for a proposal as a JSON array."""

    def list_accord_proposals_by_anchor_json(self, action: str, prior_family_digest: str) -> str:
        """(derived) empirical — #302 — proposals over (action, prior_family_digest) (H4) as a JSON array."""

    def list_attestations(self, filter_json: str, cursor_json: str | None, limit: int, caller_occurrence_key_id: str | None) -> str:
        """(derived) empirical — Bulk-list federation_attestations. Returns JSON-encoded AttestationListPage."""

    def list_attestations_by(self, attesting_key_id: str) -> str:
        """(derived) empirical — Federation directory: list attestations issued by attesting_key_id."""

    def list_attestations_for(self, target_key_id: str, cursor_json: str | None = None, limit: int = 100, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) empirical — #135 + part of #150 — list every attestation whose subject is target_key_id (attested_key_id = target_key_id), newest-first, cursor-paged. Scope is..."""

    def list_attestations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) empirical — v21.1.0 (CIRISPersist#507c) — bulk-list Attestation rows since a cursor, as a JSON array, federation tier only (the E5 invariant — a local-tier row..."""

    def list_canonical_servers(self) -> str:
        """(derived) empirical — v13.0.0 (CIRISPersist#372, CC 3.4.7.1) — enumerate the canonical / founding bootstrap servers as a JSON array of KeyRecords (federation_keys rows w..."""

    def list_canonical_withdrawals(self) -> str:
        """(derived) empirical — v13.1.0 (CIRISPersist#377) — the canonical-role withdrawal tombstones (V095) as a JSON array of CanonicalWithdrawals (stable-sorted by key_id) — th..."""

    def list_communities_for_member_active_json(self, member_identity_key_id: str) -> str:
        """(derived) empirical — #249 Cut A — communities member_identity_key_id is currently an active member of (roster − effective revocations). Returns JSON array of Community..."""

    def list_communities_for_member_json(self, member_identity_key_id: str) -> str:
        """(derived) empirical — #249 Cut A — list every community that member_identity_key_id belongs to (full-history roster, no revocation filter). Returns JSON array of Communi..."""

    def list_community_membership_revocations_for_json(self, community_key_id: str) -> str:
        """(derived) empirical — #249 Cut A — all community-membership revocations for community_key_id (full history). Returns JSON array of CommunityMembershipRevocation objects...."""

    def list_consent_peers(self, node_key_id: str) -> str:
        """(derived) empirical — v21.0.0 (CIRISPersist#502 E7) — federation directory: the revocation-folded consent_peer_set read. node_key_id's live consent:replication:v1 peers,..."""

    def list_consent_revocation_promotion_overdue_json(self, sla_seconds: int | None = None) -> str:
        """(derived) empirical — v16 (CIRISPersist#434, CC 5.3.2.2) — the consent-revocation promotion-overdue reader: every subject-side consent:state:revoked still resting LOCAL-..."""

    def list_consent_revocation_promotion_overdue_readonly_json(self, sla_seconds: int | None = None) -> str:
        """CIRISServer#356 — **the overdue question, asked without answering in
        the audit log.**

        Identical payload to
        :meth:`list_consent_revocation_promotion_overdue_json` for the same
        ``sla_seconds`` -- the same JSON array of ``{attestation_id,
        target_key_id, subject_key_id, asserted_at, age_seconds, tier}``,
        computed by the same predicate over the same rows -- with the
        ``hard_case`` emission removed. The two share one predicate rather than
        copying it, so they cannot drift into disagreeing about what "overdue"
        means.

        **Writes nothing, on any backend, on every call.** The emitting sibling
        is *idempotent*, which means no duplicate rows -- it does not mean no
        writes: it re-executes ``record_hard_case`` for every overdue row on
        every call, so a dashboard polling it drives audit-plane writes forever
        while the row count sits perfectly still. Poll this one instead; use the
        emitting sibling for a watcher tick or an operator acknowledging the
        condition. Reading and attesting are two different acts and they now
        have two method names.

        ``attestation_id`` is the :meth:`attestation_promote` handle that
        clears each row. ``sla_seconds`` defaults to 86400, the 24 h
        never-rest-local tripwire.

        **The return is JSON text**, so ``'[]'`` is a non-empty ``str`` --
        ``if engine.list_consent_revocation_promotion_overdue_readonly_json()``
        is ``True`` even when nothing is overdue. ``json.loads`` it.
        """

    def list_families_for_member_active_json(self, member_identity_key_id: str) -> str:
        """(derived) empirical — #249 Cut A — families member_identity_key_id is currently an active member of (roster − effective revocations). Returns JSON array of Family object..."""

    def list_families_for_member_json(self, member_identity_key_id: str) -> str:
        """(derived) empirical — v3.12.0 — list every family that member_identity_key_id belongs to. Returns JSON array of Family objects."""

    def list_family_membership_revocations_for_json(self, family_key_id: str) -> str:
        """(derived) empirical — #249 Cut A — all family-membership revocations for family_key_id (full history, no effective_at filter). Returns JSON array of FamilyMembershipRevo..."""

    def list_federation_keys(self, filter_json: str, cursor_json: str | None, limit: int, caller_occurrence_key_id: str | None) -> str:
        """(derived) empirical — Bulk-list federation_keys with filter + cursor pagination. Returns JSON-encoded FederationKeyListPage."""

    def list_held_by_json(self, attesting_key_id: str) -> str:
        """(derived) empirical — v3.5.0 (CIRISPersist#125) — Federation blob storage: "whose bytes do I hold for actor X?". Returns a JSON array of hex SHA-256 strings (64-char eac..."""

    def list_held_fountain_content(self, publisher_key_id: str) -> str:
        """(derived) empirical — v8.0.0 (CIRISPersist#227) — typed degraded read of a fountain content unit, JSON-over-FFI. Returns a JSON string:"""

    def list_holders_json(self, sha256_hex: str) -> str:
        """v2.3.0 (#103) — JSON-encoded list of ``attesting_key_id``
        for every currently-live holder of this blob. Filters out
        rows past the CEG §10.1.2 24-hour TTL AND rows with a
        ``withdraws`` structural composer from the attester. Empty
        list when no live holders.

        Used by CIRISConformance to verify the §9.1 identity-aware-
        storage property: "whose bytes am I holding?" The substrate
        owns this query — consumers do not reproduce it.

        Raises:
            ValueError: ``blob_invalid_argument`` on malformed SHA.
            RuntimeError: backend / IO error.
        """

    def list_llm_calls(self, filter_json: str, cursor_json: str | None, limit: int, caller_occurrence_key_id: str | None) -> str:
        """(derived) empirical — Page through cirislens.trace_llm_calls rows. Filters compose AND-style; cursor-paged newest-first. Returns JSON-encoded LlmCallListPage."""

    def list_local_holders_json(self, sha256_hex: str) -> str:
        """(derived) empirical — v3.5.2 (CIRISPersist#130) — Federation blob storage: local-truth holder query. Returns a JSON array of attesting_key_id strings for every holds_byt..."""

    def list_org_memberships_for(self, org_id: str) -> str:
        """(derived) empirical — Federation directory: list all org_membership rows for one org_id. Returns a JSON array of OrgMembership."""

    def list_org_memberships_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) empirical — Federation directory: bulk-list org_membership rows since a cursor. Same contract as [list_organizations_since](Self::list_organizations_since)."""

    def list_organizations_for(self, org_id: str) -> str:
        """(derived) empirical — Federation directory: list all organization rows for org_id (full history; callers resolve current state). Returns a JSON array of Organization."""

    def list_organizations_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) empirical — Federation directory: bulk-list organization rows since a cursor (CIRISEdge#65 v2 bridge). since_rfc3339 = None/empty for from- the-start, else an..."""

    def list_outbound(self, limit: int = 100, status: str | None = None, destination_key_id: str | None = None, sender_key_id: str | None = None, message_type: str | None = None, enqueued_after_rfc3339: str | None = None) -> list[Any]:
        """(derived) empirical — v0.4.0 — List outbound rows with optional filters. Returns a list of dicts. All filter parameters are optional; combine with AND."""

    def list_partner_records_for(self, license_id: str) -> str:
        """(derived) empirical — Federation directory: list all partner_record rows for license_id. Returns a JSON array of PartnerRecord."""

    def list_partner_records_since(self, since_rfc3339: str | None, limit: int) -> str:
        """(derived) empirical — Federation directory: bulk-list partner_record rows since a cursor. Same contract as [list_organizations_since](Self::list_organizations_since)."""

    def list_retention(self) -> str:
        """(derived) empirical — v6.0.1 (CIRISPersist#218) — All stored retention policies as a JSON-encoded array of RetentionPolicyRow ({table_name, policy})."""

    def list_revocations(self, filter_json: str, cursor_json: str | None, limit: int, caller_occurrence_key_id: str | None) -> str:
        """(derived) empirical — Bulk-list federation_revocations. Returns JSON-encoded RevocationListPage."""

    def list_tasks(self, filter_json: str, cursor_json: str | None, limit: int, caller_occurrence_key_id: str | None) -> str:
        """(derived) empirical — Page through tasks, each task carrying its component trace summaries. Drives task-axis views (qa-eval, discord, wakeup, real-user). Returns JSON-en..."""

    def list_trace_summaries(self, filter_json: str, cursor_json: str | None = None, limit: int = 100, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) empirical — Lens-bleeding endpoint /repository/traces driver. Returns a JSON string of TraceListPage."""

    def list_trust_grants(self, filter_json: str) -> str:
        """Filter query over ``federation_trust_grants``. ``filter_json``
        deserializes into ``TrustGrantFilter``. Returns a JSON-array
        string of ``TrustGrantRow`` objects."""

    def lookup_community_json(self, community_key_id: str) -> str | None:
        """(derived) empirical — #249 Cut A — fetch a single community by community_key_id. Returns JSON Community object or None (null). Structural mirror of [Self::lookup_family_..."""

    def lookup_family_json(self, family_key_id: str) -> str | None:
        """(derived) empirical — v3.12.0 — fetch a single family by family_key_id. Returns JSON Family object or None (null)."""

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

    def moderators_of_json(self, community_key_id: str, duty: str) -> str:
        """(derived) empirical — #249 Cut B — the FULL named-moderator set of community_key_id for duty (moderate / takedown / review): steward-bound authority roots ∪ their duty-s..."""

    def nodes_stewarded_by_json(self, steward_user_key_id: str) -> str:
        """(derived) empirical — CIRISPersist#299 — the OUTBOUND steward-binding reader: the nodes steward_user_key_id owns (exact inverse of steward_bindings_of_json — n ∈ nodes_s..."""

    def outbound_status(self, queue_id: str) -> dict[str, Any] | None:
        """(derived) empirical — v0.4.0 — Look up a row by queue_id. Returns the row dict or None. Used by DurableHandle::status()."""

    def owner_of_json(self, key_id: str) -> str:
        """(derived) empirical — v13.2.0 (CIRISPersist#378, CC 3.2 rc2 single-owner) — the single responsible owner of key_id, purpose-filtered to the owner-binding sub-relation →..."""

    def peer_metadata_for_json(self, key_id: str) -> str | None:
        """(derived) empirical — v3.4.1 (CIRISPersist#127) — Federation directory: read peer metadata row. Returns the JSON-encoded PeerMetadataRow (carrying alias, trust, notes, p..."""

    def put_blob_chunk(self, stream_id: str, seq: int, body_b64: str, epoch: int) -> str:
        """(derived) empirical — v4.1 (CIRISPersist#142, Cut C1a) — live-append one chunk to a stream. Inserts the chunk's bytes as a content-addressed federation_blobs row AND the..."""

    def put_blob_chunks_json(self, payload_json: str) -> None:
        """(derived) empirical — v4.1 (CIRISPersist#142, Cut B) — atomic chunked-blob upload."""

    def put_blob_json(self, payload_json: str) -> None:
        """v2.3.0 (#103) — Lower-level blob ingest accepting a fully
        pre-signed ``PutBlobAttestation`` envelope. Use only when you
        have an already-signed envelope (re-emit of remote announcement,
        HSM-batched signing, replay with caller-determined timestamps).
        Most callers want :meth:`put_blob_signing` — it owns
        canonicalization + signing end-to-end.

        Payload JSON shape::

            {
                "sha256_hex": str,
                "body": {"Inline": <base64-bytes>} | {"External": {...}},
                "media_type": str | None,
                "attestation": {
                    "attesting_key_id": str,
                    "attestation_id": str,            # UUID
                    "original_content_hash_hex": str,  # sha256 of the canonical envelope
                    "scrub_signature_classical": str,  # base64 Ed25519
                    "scrub_signature_pqc": str | None,
                    "scrub_key_id": str,
                    "scrub_timestamp": str             # RFC 3339
                }
            }

        Raises:
            ValueError: ``blob_hash_mismatch`` / ``blob_inline_size_exceeded``
                / ``blob_attestation_emission_failed`` /
                ``blob_trust_below_threshold``.
            RuntimeError: backend / IO error.
        """

    def put_calibration_bundle(self, bundle_json: str) -> None:
        """(derived) empirical — Lens-derived: write a calibration bundle."""

    def put_detection_event(self, event_json: str) -> None:
        """(derived) empirical — Lens-derived: write a detection event."""

    def revocations_for(self, revoked_key_id: str) -> str:
        """(derived) empirical — Federation directory: list revocations targeting revoked_key_id."""

    def secrets_get_access_logs(self, secret_uuid: str | None, limit: int) -> str:
        """(derived) empirical — v0.6.1 — Audit-log query. secret_uuid=None returns the global tail. Returns JSON array of AccessLogEntry. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_get_filter_config(self) -> str:
        """(derived) empirical — v0.6.1 — Read current filter pattern catalog. Returns JSON-encoded FilterConfig. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_get_service_stats(self) -> str:
        """(derived) empirical — v0.6.1 — Service-wide observability stats. Returns JSON-encoded SecretsServiceStats. [build-conditional: #[cfg(feature = "secrets")]]"""

    def secrets_list_stored(self, limit: int, filter_json: str) -> str:
        """(derived) empirical — v0.6.1 — Metadata-only listing. Returns JSON array of SecretReference. [build-conditional: #[cfg(feature = "secrets")]]"""

    def service_token_revocation_list(self) -> str:
        """v1.5.23 (CIRISPersist#64) — List ALL revoked tokens.

        Returns the JSON-encoded ``list[RevokedServiceToken]``.
        Agent caches in memory on startup; this method runs once at
        boot. Order unspecified (caller indexes by token_hash).
        """

    def set_classifications(self, trace_id: str, thought_id: str, classifications_json: str) -> None:
        """(derived) empirical — v1.5.8 (CIRISPersist#57) — write per-component classification matches for a (trace_id, thought_id) pair into the V009 / V023 classifications column. [build-conditional: #[cfg(feature = "classify")]]"""

    def set_features(self, trace_id: str, thought_id: str, features_json: str) -> None:
        """(derived) empirical — v1.5.8 (CIRISPersist#57) — write typed Features for a (trace_id, thought_id) pair into the V009 / V023 extracted_features column. [build-conditional: #[cfg(feature = "extract")]]"""

    def steward_binding_chain_json(self, key_id: str) -> str:
        """(derived) empirical — #249 Cut B — the steward-binding PATH (user → … → key_id, anchor-first) for audit — the chain, not just the endpoints. Returns a JSON array of key_..."""

    def steward_bindings_of_json(self, key_id: str) -> str:
        """(derived) empirical — #249 Cut B — the user-role key(s) that steward-bind key_id (who key_id is steward-bound TO). Returns a JSON array of key_ids; empty when key_id is..."""

    def store_blob_local_json(self, payload_json: str) -> None:
        """(derived) empirical — v3.9.2 (CIRISPersist#153 Ask 5, CEG 0.7 §10.1.4) — store blob bytes WITHOUT emitting a holds_bytes directory attestation."""

    def task_delete(self, task_id: str) -> bool:
        """v1.5.9 — Delete a task by id.

        Returns ``True`` if a row was deleted, ``False`` on
        missing/already-deleted (idempotent). FK-protected: children
        pointing at this row reject the delete as Conflict.
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

    def telemetry_list_metrics(self, filter_json: str, cursor_json: str | None, limit: int) -> str:
        """(derived) empirical — v0.8.2 — Cursor-paged tenant-scoped metric listing. [build-conditional: #[cfg(feature = "telemetry")]]"""

    def telemetry_record_metric(self, obs_json: str) -> None:
        """(derived) empirical — v0.8.2 — Record one telemetry observation. [build-conditional: #[cfg(feature = "telemetry")]]"""

    def telemetry_record_metrics_batch(self, obs_json: str) -> int:
        """(derived) empirical — v0.8.2 — Bulk-record N observations. Returns affected row count. [build-conditional: #[cfg(feature = "telemetry")]]"""

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

    def thought_get(self, thought_id: str) -> str | None:
        """v1.5.10 — Read one thought by id. Returns the JSON-encoded
        ``Thought`` row or ``None`` if no matching row exists.
        """

    def thought_get_descendants(self, thought_id: str) -> str:
        """v1.5.10 — Walk the ``parent_thought_id`` chain rooted at
        ``thought_id``.

        Returns the JSON-encoded ``list[Thought]`` (root + transitive
        descendants) ordered by ``(thought_depth ASC, thought_id ASC)``.
        Empty list when the root has no matching row (not an error).
        Uses a recursive CTE on both backends.
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

    def thought_upsert(self, thought_json: str) -> None:
        """v1.5.10 — Idempotent upsert keyed on ``thought_id``.

        ``thought_json`` is a JSON-encoded ``Thought`` shape (see the
        ``ciris_persist.thoughts`` module). Re-insert with the same
        payload is a no-op; re-insert with differing payload
        overwrites the mutable columns and preserves ``created_at``.
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

    def tsdb_count_edges_by_relationship_in_window(
        self,
        from_rfc3339: str,
        to_rfc3339: str,
    ) -> str:
        """v1.6.0 (CIRISPersist#63) — Histogram of edges within
        ``[from, to)`` grouped by ``relationship``. Filters
        ``scope='ENVIRONMENT'`` (the TSDB scope).

        Returns the JSON-encoded ``dict[str, int]``. Caller's
        ``edge_manager.py`` rolls these counts into the daily
        summary's attributes for cross-period observability.
        """

    def tsdb_get_summary(
        self,
        level: str,
        tenant_id: str,
        metric_name: str,
        period_start_rfc3339: str,
    ) -> str | None:
        """v1.6.0 (CIRISPersist#63) — Point-lookup of one summary by
        the deterministic ``(level, tenant_id, metric_name,
        period_start)`` key. Returns the JSON-encoded
        ``MetricSummary`` row or ``None``.
        """

    def tsdb_query_summaries(
        self,
        level: str,
        tenant_id: str,
        from_rfc3339: str,
        to_rfc3339: str,
    ) -> str:
        """v1.6.0 (CIRISPersist#63) — Return every ``MetricSummary``
        whose ``(consolidation_level, tenant_id)`` matches and whose
        ``period_start ∈ [from, to)``. Ordered by
        ``(period_start ASC, metric_name ASC)``.

        ``level`` is one of ``"basic" | "daily" | "weekly" |
        "monthly"``. ``from`` / ``to`` are RFC 3339 timestamps.
        ``to`` must be > ``from``.

        Returns the JSON-encoded ``list[MetricSummary]``. Empty list
        when no rows match (not an error).

        Backs CIRISAgent 2.9.0 Phase 3b's Basic (6h) / extensive
        (week) / profound (month) period-window queries.
        """

    def tsdb_query_summary_nodes(
        self,
        node_type: str,
        level: str,
        tenant_id: str,
        from_rfc3339: str,
        to_rfc3339: str,
    ) -> str:
        """v1.6.2 (CIRISPersist#68) — Read typed summary nodes by
        ``node_type``. Returns a JSON ``list[dict]`` — each entry is
        the raw ``attributes`` JSON for one matching summary row.

        ``node_type`` is one of
        ``"task_summary" | "conversation_summary" |
        "trace_summary" | "audit_summary"``.

        Callers deserialize the dict per summary type
        (``TaskSummary``, ``ConversationSummary``, ``TraceSummary``,
        ``AuditSummary``) on their side — persist doesn't enforce
        the per-type Python class because the agent owns those.

        ``level`` filters ``consolidation_level``; ``tenant_id``
        matches ``attributes.tenant_id``; ``from_rfc3339`` /
        ``to_rfc3339`` bracket ``attributes.period_start``
        (half-open). Results ordered by ``period_start ASC``.

        Empty list when no rows match (not an error).
        """

    def update_peer_alias(self, key_id: str, alias_json: str) -> None:
        """(derived) empirical — Federation directory: set peer alias. alias_json is the JSON-encoded value (e.g. "null", "\"my-peer\"") so None can be distinguished from empty-str..."""

    def update_peer_notes(self, key_id: str, notes_json: str) -> None:
        """(derived) empirical — Federation directory: set peer notes. notes_json is the JSON-encoded value (e.g. "null", "\"contact ops\"")."""

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

    def wa_cert_update_last_login(
        self, wa_id: str, login_time_iso: str
    ) -> bool:
        """v1.5.19 — Last-login bookkeeping. ``login_time_iso`` is
        an RFC 3339 timestamp string. Returns ``True`` if the row
        was updated; ``False`` if ``wa_id`` doesn't exist.
        """


    # ==============================================================
    # AXIOTIC  (descriptive)
    # Varying one of these re-ranks outcomes without newly permitting any act.
    # ==============================================================

    def aggregate_audit_chain(self, filter_json: str, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) axiotic — Granular: audit-chain aggregate. Returns JSON-encoded AuditChainAggregate."""

    def aggregate_llm_costs(self, filter_json: str, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) axiotic — Cost rollup by model / agent / deployment domain + window totals. Returns JSON-encoded LlmCostAggregate."""

    def aggregate_scoring_factors(self, agent_id_hash: str, window_json: str, baseline_window_json: str | None = None, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) axiotic — Bundled scoring factor aggregate. Replaces api/scoring.py's raw SQL. Returns JSON-encoded ScoringFactorAggregate. baseline_window_json=None → drift..."""

    def aggregate_scoring_factors_batch(self, agent_id_hashes_json: str, window_json: str, baseline_window_json: str | None = None, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) axiotic — Batch variant — fleet-wide score sweep. agent_id_hashes_json is a JSON array of strings. Returns JSON array of ScoringFactorAggregate in input order."""

    def aggregate_scoring_factors_stream(self, agent_id_hashes_json: str, window_json: str, baseline_window_json: str | None = None, caller_occurrence_key_id: str | None = None) -> ScoringFactorStream:
        """(derived) axiotic — Streaming variant (CIRISPersist#197, CIRISLensCore#44) — returns an async-iterator yielding one ScoringFactorAggregate JSON string per agent as it..."""

    def aggregate_scrub_stats(self, since_iso8601: str, until_iso8601: str, caller_occurrence_key_id: str | None) -> str:
        """(derived) axiotic — Scrub-stats aggregate for a window. Drives privacy dashboards. Returns JSON-encoded ScrubAggregate."""

    def cirisnode_get_credits_ledger(self, contributor_id: str, domain: str, language: str, subject: str) -> str | None:
        """(derived) axiotic — v0.7.0 — Point-lookup one Credits ledger row. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_get_expertise_ledger(self, contributor_id: str, domain: str, language: str) -> str | None:
        """(derived) axiotic — v0.7.0 — Point-lookup one Expertise ledger row. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_read_vote_weight(self, contributor_id: str, domain: str, language: str, subject: str) -> str | None:
        """(derived) axiotic — v0.7.0 — Compute Credits × expertise_multiplier × active_tier_multiplier for vote-weighting per SCHEMA.md §5.2. Returns JSON-encoded VoteWeight or... [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_routable_contributors(self, domain: str, language: str) -> str:
        """(derived) axiotic — v0.7.0 — List active routable contributors for (domain, language). Returns JSON array of RoutableContributor. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_update_credits_ledger(self, update_json: str) -> None:
        """(derived) axiotic — v0.7.0 — Upsert one row in credits_ledger. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def cirisnode_update_expertise_ledger(self, update_json: str) -> None:
        """(derived) axiotic — v0.7.0 — Upsert one row in expertise_ledger. [build-conditional: #[cfg(feature = "cirisnode")]]"""

    def conscience_override_rates(self, deployment_domain: str, window_json: str, caller_occurrence_key_id: str | None) -> str:
        """(derived) axiotic — Per-agent conscience-override rates within a deployment domain. Returns JSON array of OverrideRateRow."""

    def get_aggregation(self, aggregate_content_id: str) -> str | None:
        """(derived) axiotic — v8.3.0 (CIRISPersist#230) — read a composite's aggregation record, JSON-over-FFI. Returns a JSON string with the [AggregationRecordV1](crate::fount..."""

    def list_aggregations_at_level(self, level: int, limit: int) -> str:
        """(derived) axiotic — v8.3.0 (CIRISPersist#230) — list aggregation records at a pyramid level, capped at limit, ordered by recency then id (the O(log T) level-walk). Ret..."""

    def list_scores(self, filter_json: str, cursor_json: str | None = None, limit: int = 100, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) axiotic — v17.4.0 (FSD-005 Appendix C) — the durable scores LIST read. Ordered subject+dimension seek over the V106 projection; the §4.3 gate is built from c..."""

    def put_aggregated_tier(self, manifest_json: str, symbols_json: str, agg_json: str, aggregated_at_unix_ms: int) -> None:
        """(derived) axiotic — v8.3.0 (CEG 1.0-RC12 §19.7 / CIRISPersist#230) — admit an aggregate composite + record its §19.7 aggregation provenance, JSON-over-FFI. manifest_js..."""

    def resolve_scores(self, filter_json: str, policy: str, trace: bool = False, caller_occurrence_key_id: str | None = None) -> str:
        """(derived) axiotic — v17.4.0 (FSD-005 Appendix C) — the durable scores RESOLVE read: the composed verdict (band + n's + open trace). Runs the precedence + CC 4.4.2 pola..."""

    @staticmethod
    def verify_coord_compare_for_merge(a_json: str, b_json: str) -> int:
        """(derived) axiotic — v3.11.0 (CIRISPersist#143) — Q1 deterministic 3-tier merge comparator exposed for consumer code that needs to score-rank competing revocations with..."""


    # ==============================================================
    # PROCEDURAL  (descriptive)
    # Varying one of these changes orchestration — when and by whom, not what is true.
    # ==============================================================

    def backfill_trace_attestations(self) -> str:
        """(derived) procedural — v19.2.0 (CIRISPersist#494) — the trace-summary extraction-path contract: {"manifest_json": …, "sha256": …}. CIRISServer serves the hash on /v1/heal... [build-conditional: #[cfg(any(feature = "postgres", feature = "sqlite"))]]"""

    def backfill_v020_trust_rows(self, tenant_id: str) -> str:
        """(derived) procedural — v1.5.0 Phase I (FSD §6.2) — One-shot V020 → V021 backfill for the supplied tenant. Walks federation_keys for rows where trusted_by equals this Engi... [build-conditional: #[cfg(feature = "cirisaudit")]]"""

    def cancel_outbound(self, queue_id: str) -> None:
        """(derived) procedural — v0.4.0 — Operator-driven cancellation. Idempotent."""

    def claim_pending_outbound(self, batch_size: int, claim_duration_seconds: int, claimed_by: str) -> list[Any]:
        """(derived) procedural — v0.4.0 — Atomic claim of up to batch_size pending rows. Returns a list of dicts (one per claimed row)."""

    def enqueue_outbound(self, sender_key_id: str, destination_key_id: str, message_type: str, edge_schema_version: str, envelope_bytes: bytes, body_sha256: bytes, body_size_bytes: int, requires_ack: bool, max_attempts: int, ttl_seconds: int, initial_next_attempt_after_rfc3339: str, ack_timeout_seconds: int | None = None) -> str:
        """(derived) procedural — v0.4.0 (CIRISPersist#16) — Enqueue an outbound row in pending state. Returns the server-generated queue_id the caller stores in its DurableHandle."""

    def evict_aggregated_tier(self, aggregate_content_id: str, tier: int) -> int:
        """(derived) procedural — v8.6.0 (§19.7.3 / verify v5.11.0 / CEG RC16) — execute an EjectAggregatedTierOnly stratum-shed, JSON-over-FFI. Shed exactly one pyramid stratum — t..."""

    def evict_fountain_content_to_tier(self, content_id: str, corpus_kind: str, tier: str) -> int:
        """(derived) procedural — v8.0.0 (CIRISPersist#227) — evict a content unit's symbols to a named fountain tier ("full" | "t2" | "t3" | "t4" | "t5"), dropping by retention_pri..."""

    def lock_get(self, lock_key: str) -> str | None:
        """v1.5.15 — Read current lock state. Returns the
        JSON-encoded ``MaintenanceLock`` or ``None`` when no row
        for ``lock_key`` exists. ``locked_by IS NULL`` AND
        ``locked_at IS NULL`` means the row exists but no caller
        currently holds the lock; callers also check ``locked_at
        + lock_timeout_seconds`` against wall-clock to decide if a
        present-but-expired holder is stealable.
        """

    def lock_release(self, lock_key: str, locked_by: str) -> bool:
        """v1.5.15 — Release a lock IFF the caller still holds it.
        Returns ``True`` when the lock was cleared; ``False`` when
        the row doesn't exist or the row's ``locked_by`` doesn't
        match the supplied ``locked_by`` (no-op — caller treats
        ``False`` as "not yours to release").
        """

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

    def maintain(self) -> str:
        """(derived) procedural — v1.2.0 (CIRISPersist#48) — Run the maintenance umbrella: vacuum → archive_expired(SubstrateDefault). Returns a JSON-encoded MaintenanceReport. Prun..."""

    def maintenance_vacuum(self) -> str:
        """(derived) procedural — v1.2.0 (CIRISPersist#48) — Run a substrate-wide VACUUM (PG: VACUUM ANALYZE via dedicated non-transactional client; SQLite: VACUUM; ANALYZE; via spa..."""

    def mark_ack_received(self, queue_id: str, ack_envelope_bytes: bytes) -> None:
        """(derived) procedural — v0.4.0 — Record the receiver's ACK envelope on a matched awaiting_ack row and transition to delivered."""

    def mark_replay_resolved(self, queue_id: str) -> None:
        """(derived) procedural — v0.4.0 — Treat a previously-sent row as delivered (the receiver replied replay_detected; the original send already landed before the ACK could arri..."""

    def mark_transport_delivered(self, queue_id: str, transport: str) -> None:
        """(derived) procedural — v0.4.0 — Transport reports successful delivery. Transitions the row to delivered (no ACK) or awaiting_ack (ACK required)."""

    def mark_transport_failed(self, queue_id: str, error_class: str, error_detail: str, transport: str, next_attempt_after_rfc3339: str) -> dict[str, Any]:
        """(derived) procedural — v0.4.0 — Transport reports failure. Returns a dict shaped {"outcome": "retrying"|"abandoned", "attempt": int|None}."""

    def match_ack_to_outbound(self, in_reply_to_sha256: bytes) -> dict[str, Any] | None:
        """(derived) procedural — v0.4.0 — Look up an awaiting_ack row by the receiver's in_reply_to hash. Returns the row dict or None."""

    def promote_consented_backlog(self) -> dict[str, Any]:
        """(derived) procedural — v21.2.0 (CIRISPersist#509 FLOOR) — run the promote-on-consent sweep ON DEMAND: the same idempotent Engine::promote_consented_backlog primitive the... [build-conditional: #[cfg(any(feature = "postgres", feature = "sqlite"))]]"""

    def repair_stranded_scope_backlog(self) -> dict[str, Any]:
        """(derived) procedural — v21.12.0 (CIRISPersist#530) — the REPAIR sweep: correct stranded (self|family, federation) rows to their covering grant's federation-visible audien..."""

    def replay_abandoned(self, queue_id: str) -> None:
        """(derived) procedural — v0.4.0 — Operator-driven replay. Resets attempt_count=0 and requeues an abandoned row."""

    def run_deletion_window_watch_json(self, now_iso: str | None = None) -> str:
        """(derived) procedural — v22.0.0 (CIRISPersist#543 / ciris.ai/contextual-integrity) — drive ONE deletion-window breach sweep and return the pass report as JSON ({rows_scann..."""

    def run_legacy_graph_migration(self, options_json: str) -> str:
        """v1.6.4 (CIRISPersist#70) — Absorb the A0a legacy-graph
        migration. Reads ``public.graph_nodes`` + ``public.graph_edges``
        (legacy 2.8.x agent schema) and re-upserts into
        ``cirisgraph.nodes`` / ``cirisgraph.edges``.

        ``options_json`` is a JSON-encoded ``LegacyMigrationOptions``::

            {"dry_run": false,
             "attributes_cap_bytes": 1048576,
             "legacy_schema": "public",
             "stop_after_errors": 100}

        All fields optional; ``{}`` decodes to safe defaults
        (``dry_run=False``, default 1 MiB cap, ``legacy_schema="public"``,
        ``stop_after_errors=100``).

        Returns the JSON-encoded ``LegacyMigrationStats``::

            {"outcome": "ok" | "errors" | "partial",
             "nodes_read": int, "nodes_written": int,
             "nodes_skipped_already_present": int,
             "nodes_skipped_too_large": int,
             "edges_read": int, "edges_written": int,
             "edges_skipped_already_present": int,
             "edges_skipped_dangling_fk": int,
             "errors": int,
             "first_error_at_node_id": str | null,
             "first_error_message": str | null}

        ``first_error_message`` (v1.6.5, CIRISPersist#72) carries the
        human-readable text of the first error so callers can
        diagnose without bisecting.

        v1.6.5 also fixes the legacy ``timestamp without time zone``
        column type: the pre-v2.9.0 agent schema declares
        ``graph_nodes.created_at`` / ``updated_at`` as naive
        timestamps. The reader now casts them ``::text`` and parses
        both naive (UTC-assumed) and offset-bearing forms — earlier
        versions errored on every node against a real legacy
        Postgres database.

        v1.6.6 (CIRISPersist#73): legacy ``graph_edges.edge_id`` is
        arbitrary ``text``, but ``cirisgraph.edges.edge_id`` is a
        ``uuid`` column. Non-UUID legacy edge ids are now mapped to
        a deterministic UUIDv5 (valid-UUID ids pass through
        verbatim) — applied on both backends so a legacy DB migrates
        to identical edge ids regardless of target. Earlier versions
        errored on every non-UUID edge.

        Per-row decision tree:

        - Lowercase legacy scope values are normalized to UPPERCASE
          before lookup against the ``cirisgraph`` schema's CHECK
          constraint.
        - Attributes JSON is re-serialized and size-checked against
          ``attributes_cap_bytes`` (default 1 MiB). Over-cap rows
          increment ``nodes_skipped_too_large`` and do NOT call
          ``upsert_node``.
        - ``dry_run=True`` reads + parses + size-checks every row
          but does NOT write.
        - The underlying ``upsert_node`` is called with
          ``bulk_import=true`` so the graph layer's AV-45 cap is
          bypassed — this method re-checks against the operator-
          supplied bound itself so the count stays honest.
        - ``stop_after_errors=Some(n)`` halts the per-row loop once
          the error count reaches ``n`` (default 100). Partial
          progress is still returned (with ``outcome="partial"`` if
          any nodes were written, ``"errors"`` otherwise).

        Idempotent — re-running is safe (existing substrate rows
        are skipped via ``expected_version`` / PK semantics). On
        SQLite, if the legacy tables are absent (fresh install that
        never ran the 2.8.x agent), returns a zeroed-counter
        ``outcome="ok"`` so the agent's bootstrap path can proceed.

        Replaces the agent-side ``tools/ops/migrate_to_persist.py``
        psycopg2/sqlite3 reader so CIRISAgent can drop both deps
        from production ``requirements.txt`` (CIRISAgent#763 Phase 5
        close-out — the LAST raw-SQL gap in CIRISAgent 2.9.0).
        """

    def run_pqc_sweep(self, batch_size: int = 1000) -> dict[str, Any]:
        """(derived) procedural — v0.3.2 (CIRISPersist#11) — Walk hybrid-pending federation rows across federation_keys / federation_attestations / federation_revocations and drive..."""

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

    def sweep_ack_timeouts(self) -> int:
        """(derived) procedural — v0.4.0 — Sweep ACK timeouts. Returns the count of rows touched (retried or abandoned)."""

    def sweep_consent_decay_once(self) -> int:
        """(derived) procedural — #227 (residual) — drive one consent-decay sweep synchronously (the time-driven twin of [Self::sweep_evictions_once]). Ages every fountain content u..."""

    def sweep_evictions_once(self) -> int:
        """(derived) procedural — v3.4.0 (CIRISPersist#123) — drive one sweep cycle synchronously. Returns the number of rows evicted in this pass. Sovereign callers (Pi-cron, k8s C..."""

    def sweep_expired_claims(self) -> int:
        """(derived) procedural — v0.4.0 — Sweep expired claims (revert sending → pending for rows whose claimed_until elapsed)."""

    def task_try_claim_shared(self, task_json: str) -> str:
        """v1.5.9 — Atomic INSERT-OR-IGNORE claim keyed on ``task_id``.

        Returns the JSON wire-shape
        ``{"outcome": "stored" | "already_claimed", "task": <Task>}``.
        First caller wins with ``"stored"``; subsequent callers get
        ``"already_claimed"`` carrying the EXISTING row (not the
        caller's payload).
        """

    def telemetry_consolidate_period(self, req_json: str) -> str:
        """(derived) procedural — v0.8.2 — Run 6-hour rollup for one (period, tenant) window. AV-53 stale-lock auto-break; AV-54 TEMPORAL_NEXT chain. Returns JSON ConsolidationOutcome. [build-conditional: #[cfg(feature = "telemetry")]]"""

    def tsdb_consolidate_audit(self, req_json: str) -> str:
        """v1.6.2 (CIRISPersist#68) — Consolidate audit-log rows into
        an ``audit_summary`` graph node.

        Aggregates ``cirislens.audit_log`` over the window. The
        audit_log schema uses ``tenant_id`` directly (NOT
        ``agent_occurrence_id``) and ``recorded_at`` (NOT
        ``created_at``) per the V014 column shape. Builds a
        ``by_action_type`` histogram + total count + distinct
        ``actor_id`` count.

        Emits an ``AuditSummary`` JSON ``attributes`` blob:

        .. code-block:: json

            {
              "tenant_id": "...",
              "period_start": "...",
              "period_end":   "...",
              "total_events": 12,
              "by_action_type": {"task_signed": 6, "config_changed": 2},
              "unique_actors": 4,
              "consolidation_level": "basic"
            }

        Returns the JSON-encoded ``TypedConsolidationOutcome``.
        """

    def tsdb_consolidate_conversations(self, req_json: str) -> str:
        """v1.6.2 (CIRISPersist#68) — Consolidate conversation-shaped
        service correlations into a ``conversation_summary`` graph
        node.

        Filters ``cirislens.service_correlations`` to rows whose
        ``action_type`` is one of ``speak | observe | speak_action |
        observe_action`` (case-insensitive). Counts total matches +
        distinct ``request_data->>'actor_id'`` over the window
        (scoped by ``agent_occurrence_id = tenant_id``).

        Emits a ``ConversationSummary`` JSON ``attributes`` blob:

        .. code-block:: json

            {
              "tenant_id": "...",
              "period_start": "...",
              "period_end":   "...",
              "total_messages": 17,
              "unique_actors": 3,
              "consolidation_level": "basic"
            }

        Returns the JSON-encoded ``TypedConsolidationOutcome``.
        """

    def tsdb_consolidate_tasks(self, req_json: str) -> str:
        """v1.6.2 (CIRISPersist#68) — Consolidate task source data
        over the request's period window into a ``task_summary``
        graph node.

        ``req_json`` is a JSON-encoded ``ConsolidationRequest`` — same
        shape ``telemetry_consolidate_period`` accepts:

        .. code-block:: json

            {
              "tenant_id": "agent-datum",
              "period_start": "2026-05-19T00:00:00Z",
              "period_end":   "2026-05-19T06:00:00Z",
              "locked_by":    "tsdb-worker",
              "level":        "basic"
            }

        Aggregates ``cirislens.tasks`` (status histogram, total) +
        ``cirislens.thoughts`` (mean ``thought_depth``) over the
        window, filtered by ``agent_occurrence_id = tenant_id``.
        UPSERTs one ``task_summary`` row into ``cirisgraph.nodes``
        (scope ``ENVIRONMENT``) carrying a ``TaskSummary`` JSON
        ``attributes`` blob:

        .. code-block:: json

            {
              "tenant_id": "agent-datum",
              "period_start": "...",
              "period_end":   "...",
              "total_tasks": 42,
              "by_status": {"completed": 30, "failed": 2, ...},
              "mean_thought_depth": 1.8,
              "consolidation_level": "basic"
            }

        Returns the JSON-encoded ``TypedConsolidationOutcome``
        (``{"summary_written": bool, "source_rows": int}``).

        Final blocker for CIRISAgent 2.9.0 Phase 3b — the agent's
        TSDB pipeline emits these typed summaries alongside the
        metric ``tsdb_summary`` so the UI can surface per-period
        task / conversation / trace / audit rollups.
        """

    def tsdb_consolidate_traces(self, req_json: str) -> str:
        """v1.6.2 (CIRISPersist#68) — Consolidate trace-shaped
        service correlations into a ``trace_summary`` graph node.

        Filters ``cirislens.service_correlations`` where
        ``correlation_type = 'trace'`` over the window (scoped by
        ``agent_occurrence_id = tenant_id``). Builds a
        ``by_action_type`` histogram + total count.

        Emits a ``TraceSummary`` JSON ``attributes`` blob:

        .. code-block:: json

            {
              "tenant_id": "...",
              "period_start": "...",
              "period_end":   "...",
              "total_traces": 8,
              "by_action_type": {"call": 5, "tool_invoke": 3},
              "consolidation_level": "basic"
            }

        Returns the JSON-encoded ``TypedConsolidationOutcome``.
        """


    # ==============================================================
    # PRAGMATIC  (descriptive)
    # Varying one of these changes register or address, not content.
    # ==============================================================

    def body_sha256(self, body_bytes: bytes) -> bytes:
        """(derived) pragmatic — v0.4.1 (CIRISEdge ask) — SHA-256 of body verbatim wire bytes. Used by body_sha256_prefix forensic join key and in_reply_to content-derived ACK matc..."""

    def get_blob_range(self, sha256_hex: str, start: int, end_inclusive: int) -> Any:
        """(derived) pragmatic — v4.1 (CIRISPersist#142, Cut A) — byte-range read over a blob by SHA-256 (hex). RFC 9110 §14.4 semantics: end_inclusive is clamped to size-1; a star..."""

    def locale_leaf_hash_hex(self, leaf_json: str) -> str:
        """(derived) pragmatic — v3.8.0 — compute the per-locale leaf hash for a LocaleLeaf JSON envelope. Returns the 32-byte SHA-256 as hex."""

    def locale_merkle_root_hex(self, leaves_json: str) -> str:
        """(derived) pragmatic — v3.8.0 — compute the RFC 6962-style Merkle root over a list of LocaleLeaf JSON envelopes. Returns root as hex."""

    def secrets_encrypt(self, plaintext: str) -> str:
        """(derived) pragmatic — v0.6.1 — Direct AES-GCM encrypt. Returns base64(salt || nonce || ciphertext). [build-conditional: #[cfg(feature = "secrets")]]"""

    def wholeness_witness_root_hex(self, leaf_bytes_b64_json: str) -> str:
        """(derived) pragmatic — v16 (CIRISPersist#431) — pure §19.1 root builder: the WW-scheme Merkle root (lexicographic leaf order, odd-duplication, WW-v1-empty empty sentinel)..."""


class ScoringFactorStream:

    # ==============================================================
    # STRUCTURAL  (BINDING)
    # Varying one of these breaks the process, the handle, or dispatch — the machine stops working.
    # ==============================================================

    def __aiter__(self) -> ScoringFactorStream:
        """``async for`` entry point — returns self."""

    def __anext__(self) -> Any:
        """The next per-agent aggregate JSON, wrapped in an already-resolved
        asyncio future; raises ``StopAsyncIteration`` when the buffer drains.

        Typed ``Any`` and not ``Awaitable[str]`` deliberately: the object is
        an ``asyncio.Future`` built at call time, and the annotation a checker
        needs here is whatever ``await`` accepts. ``async for x in stream``
        binds ``x`` to ``str``.
        """

    def __iter__(self) -> ScoringFactorStream:
        """Sync iterator entry point — the same pre-computed buffer, for
        callers outside an event loop (tests, batch tools)."""

    def __len__(self) -> int:
        """Number of buffered per-agent rows. Counts what was BUFFERED, which
        is not what was requested — read :meth:`summary` for skipped/aborted."""

    def __next__(self) -> str | None:
        """The next per-agent aggregate JSON, or ``None`` (``StopIteration``)
        once the buffer is drained."""


    # ==============================================================
    # EPISTEMIC  (descriptive)
    # Varying one of these changes how uncertainty is held — bands, absence, liveness.
    # ==============================================================

    def summary(self) -> str:
        """(derived) epistemic — The terminal StreamSummary JSON (emitted/skipped/aborted/ cache_hit/evaluated_at_unix_ms). Read after the loop completes."""


class ReconsiderDosGuard:

    # ==============================================================
    # STRUCTURAL  (BINDING)
    # Varying one of these breaks the process, the handle, or dispatch — the machine stops working.
    # ==============================================================

    def __init__(self) -> None:
        """Construct a guard with the CIRISVerify defaults: 10 concurrent
        reconsiderations per moderation event, 30 filings per actor per 7 days,
        harassment-cluster threshold 2.0 distinct events per
        ``(requester, target)`` pair in the window.

        State lives in THIS object, in process memory. Two guards do not share
        budgets, so constructing a fresh one per request silently disables
        every limit — hold one for the process.
        """

    def __repr__(self) -> str:
        """A constant ``"ReconsiderDosGuard()"``. Deliberately reports NOTHING
        about the guard's state: it never takes the lock, so it cannot deadlock
        when called from inside a panic, and it cannot leak filing contents.
        Do not parse it for occupancy — there is none to read."""


    # ==============================================================
    # DEONTIC  (BINDING)
    # Varying one of these changes what the mesh permits — a wrong entry here is a security finding.
    # ==============================================================

    def admit_filing(self, event_id: str, requester_id: str, target_id: str, now_ms: int) -> str:
        """(derived) deontic — Run the composed admit-time check (harassment cluster → actor budget → per-event rate limit)."""

    def record_outcome(self, event_id: str, requester_id: str, outcome: str) -> None:
        """(derived) deontic — Record the outcome of a previously-admitted filing."""


# ====================================================================
# MODULE-LEVEL FUNCTIONS
# ====================================================================

# ==================================================================
# STRUCTURAL  (BINDING)
# Varying one of these breaks the process, the handle, or dispatch — the machine stops working.
# ==================================================================

def _test_inject_panic(panic_msg: str) -> None:
    """v0.5.4 (CIRISPersist#29) — deliberately panic inside Rust so the Python
    regression suite can assert the panic crosses the FFI as
    :class:`LensQueryError` rather than aborting the interpreter.

    **Build-conditional and test-only** — present only under the
    ``test-panic`` Cargo feature. Never in a release wheel.
    """

def engine_teardown_wait(timeout_seconds: float = 10.0) -> str:
    """v24.3.0 (CIRISPersist#572) — block until every in-flight engine
    teardown has finished.

    Returns ``"drained"`` if the process is quiescent (no teardown
    still running) or ``"timed_out"`` if one is still going after
    ``timeout_seconds``.

    This is the second half of the fixture recipe #572 exists to
    enable, replacing a ``time.sleep(0.2)`` guess::

        reset_engine(); del engine; gc.collect(); engine_teardown_wait()

    The wait is performed with the GIL released, so it cannot wedge
    the interpreter and a watchdog can still fire through it.
    """

def engine_teardowns_in_flight() -> int:
    """v24.3.0 (CIRISPersist#572) — how many engine teardowns are
    still winding down, right now.

    ``0`` means the process is quiescent. Cheap and non-blocking —
    for assertions and diagnostics; use :func:`engine_teardown_wait`
    when you want to *wait* rather than observe.
    """

def install_panic_logger() -> bool:
    """v3.12.x (CIRISPersist#156) — arm the panic-logging hook by hand;
    ``True`` if it is active, ``False`` if ``CIRIS_PERSIST_PANIC_LOG`` was
    unset at call time.

    **Build-conditional** — see :func:`panic_count`.
    """

def panic_count() -> int:
    """v3.12.x (CIRISPersist#156) — panics captured by the logging hook since
    process start; ``0`` if the hook was never armed.

    **Build-conditional** — present only in wheels built with the
    ``debug-tools`` Cargo feature, which release wheels do not set. A stub
    cannot express that, so guard with ``hasattr(ciris_persist, "panic_count")``
    rather than trusting this declaration.
    """

def reset_engine(timeout_seconds: float = 10.0) -> str:
    """v1.10.1 (CIRISPersist#88) — handle-free reset of the
    process-singleton engine.

    Closes and un-pins whatever engine is the current process
    singleton so the next ``Engine(...)`` constructs cleanly with any
    config. Unlike :meth:`Engine.close` it needs no ``Engine``
    handle, so it recovers the "orphan" case — a fixture that
    dropped its Python reference without closing. A no-op when no
    engine is pinned; idempotent and safe under repeated
    reset/construct cycles.

    **v24.3.0 (CIRISPersist#572) — BEHAVIOURAL CHANGE, and it is the
    reason this signature is worth reading.** This used to free the
    slot *synchronously* and return ``None``. It now returns one of
    ``"drained"`` / ``"deferred"`` / ``"timed_out"`` / ``"no_engine"``
    (see :meth:`Engine.close_blocking`), and ``"deferred"`` is the
    common case whenever another handle is still alive. Waiting
    synchronously for teardown while holding the GIL is exactly the
    wedge #572 fixed, so the wait is now bounded and reported rather
    than silently performed.

    A caller that wants the old "it is really gone now" guarantee
    follows up with :func:`engine_teardown_wait`.

    Intended for consumer test-suite isolation (call it in fixture
    teardown) and as a deterministic teardown door for in-process
    cohabitation.
    """


# ==================================================================
# AXIOMATIC  (BINDING)
# Varying one of these changes the decomposition premise two repos are cross-checking.
# ==================================================================

def namespace_manifest_version() -> str:
    """v21.7.0 (CIRISPersist#519) — the vendored namespace-supersets manifest
    version (``_meta.manifest_version``).

    Axiomatic: a cross-repo harness asserts every wheel pins the
    byte-identical manifest cut. Two processors on different cuts are not
    running the same experiment.
    """

def persist_field_conformance() -> list[str]:
    """v21.7.0 (CIRISPersist#519 / CIRISConformance#83) — run the
    manifest-driven field-conformance harness against the LIVE wheel.

    Returns the list of violations; **an EMPTY list means conformant**. Pure —
    no engine handle needed.

    Axiomatic: this is what a shared cross-repo harness calls to establish
    that persist and its sibling processors are decomposing the same fields
    the same way. Get it wrong and two repos agree while comparing different
    things, which no downstream test can detect.
    """

def transform_algebra_hash() -> str:
    """v21.7.0 (CIRISPersist#519) — the pinned ``TRANSFORM_ALGEBRA_HASH``, the
    third leg of the manifest-hash tripod.

    Axiomatic: cross-checked against the other processors' pinned copies.
    """

# --- pyi_surface: END GENERATED REGION ---
