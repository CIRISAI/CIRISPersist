"""Type stubs for the Rust-built ``ciris_persist`` extension module.

Mission alignment (PLATFORM_ARCHITECTURE.md §3.5): mypy / pyright
support is part of the Phase 1 surface — the lens FastAPI codebase
already runs strict type checking, and these stubs keep ciris-persist
inside that envelope.
"""

from typing import Any, Callable, TypedDict

__version__: str
SUPPORTED_SCHEMA_VERSIONS: list[str]

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
        """Register the agent's Ed25519 verifying key.

        Idempotent on the same key/value; rejects rotation (registering
        a different key for an existing key id raises).
        """

    def receive_and_persist(self, body: bytes) -> BatchSummary:
        """Run the FSD §3.3 ingest pipeline on a batch body.

        Raises:
            ValueError: schema / verify / scrub rejection — caller
                surfaces as HTTP 4xx.
            RuntimeError: backend / IO error — caller surfaces as HTTP
                5xx.
        """
