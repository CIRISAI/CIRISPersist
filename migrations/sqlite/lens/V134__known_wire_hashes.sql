-- V134: the KNOWN-but-not-held wire-hash set (CIRISPersist#785).
-- SQLite twin of migrations/postgres/lens/V134__known_wire_hashes.sql —
-- same columns, same nullability, same index names.
-- Dialect translations: TIMESTAMPTZ -> TEXT (RFC 3339); the schema
-- qualifier is dropped rather than folded into the name, matching V111
-- `signed_wire_index`, this table's sibling and the one it must stay
-- distinguishable from.
--
-- ─── What this answers, and what it must never answer ───────────────
--
-- `signed_wire_index` (V111) answers "WHAT DO I HOLD". Every entry there
-- carries a NOT NULL `record_key` pointing at the row, which is exactly
-- right for the #780 point-read and the holdings half of
-- `want = remote ∖ holdings`.
--
-- This table answers a DIFFERENT question: "WHAT EXISTS IN THE
-- FEDERATION", for records whose bodies this node deliberately does not
-- hold. Under the hash-first directory (CIRISEdge#552) a node converges
-- the hash set at federation tier and fetches a body only on demand, so
-- most known hashes will never have a row and can never appear in the
-- wire index.
--
-- ─── Why a SEPARATE TABLE and not a flag on signed_wire_index ────────
--
-- These two sets MUST NEVER be unioned into the holdings read. If a
-- known-but-not-held hash reaches `holdings`, the node concludes it
-- already has everything it has merely HEARD OF and silently stops
-- fetching: nothing errors, anti-entropy goes quiet, and the corpus
-- freezes at whatever it had (CIRISEdge#416's non-convergence with the
-- sign flipped).
--
-- Today that union is UNREPRESENTABLE, and it is the schema that makes
-- it so: `signed_wire_index.record_key` is NOT NULL, so a hash with no
-- row cannot be inserted there at all. Adding these as a flag on that
-- table would require making `record_key` NULLABLE — spending the one
-- constraint that makes the mistake impossible, in a migration that
-- reads like housekeeping. Hence a distinct table with NO `record_key`
-- column: not as a convention, but so that pointing one of these rows
-- at a held record is not a thing that can be spelled.
--
-- Note also that the read path cannot warn you. #780's
-- `lookup_signed_record_by_content_hash` returns `Ok(None)` on a stale
-- or mismatched entry by design (self-healing posture) — so a polluted
-- holdings read raises nothing on either side. "We would notice" is not
-- available as a mitigation here.
--
-- ─── Columns ────────────────────────────────────────────────────────
--
-- `kind`               — the `EnvelopeKind::as_str()` token, same
--                        vocabulary as `signed_wire_index.kind`.
-- `content_hash`       — lowercase-hex sha256, the same value the
--                        advertising peer computed; identical
--                        derivation to the wire index, so a hash can be
--                        compared across the two sets even though the
--                        ROWS may never be joined.
-- `last_advertised_at` — the moment a peer most recently advertised
--                        this hash. THIS COLUMN MUST MOVE. Edge's
--                        advertise axis is a watermark sweep with a
--                        rolling re-sweep that WRAPS, so every live
--                        hash is re-advertised once per wrap period,
--                        forever. Ageing on a first-seen column instead
--                        would reproduce #776 exactly: that prune aged
--                        on `asserted_at`, a value the writer freezes,
--                        so the cutoff never advanced, the prune never
--                        fired, and both consumers independently
--                        refused to call it rather than reporting a
--                        fault. The column that moves is the one the
--                        re-sweep touches.
-- `advertised_by`      — LOCAL-ONLY. The peer that advertised this hash
--                        to this node. See the replication note below.
--
-- ─── advertised_by is an OBSERVATION, never a CLAIM, and never leaves ─
--
-- It records "this peer advertised H to me", NOT "this peer holds H".
-- It is deliberately absent from every replication policy kind and from
-- the wire index, and no type carrying it reaches an envelope. A
-- replicated version would be a who-holds-what index over the ENTIRE
-- corpus — a strictly larger disclosure than the one CIRISPersist#784
-- is trying to keep out of moderation records for a handful of
-- moderated subjects. Staying local adds no disclosure at all, since it
-- is derived from Summaries that peer already sent us: the information
-- is ours either way, and what matters is that it never becomes anyone
-- else's.
--
-- No BEGIN/COMMIT: refinery wraps each migration in its own transaction
-- (V019 rule).

CREATE TABLE IF NOT EXISTS known_wire_hashes (
    kind                TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    last_advertised_at  TEXT NOT NULL,
    advertised_by       TEXT,
    PRIMARY KEY (kind, content_hash)
);

-- `last_advertised_at` LEADS, because that is what the eviction predicate
-- filters on and eviction takes no kind: `DELETE ... WHERE
-- last_advertised_at < $1`. A kind-leading index cannot serve that range
-- delete at all, so every sweep would scan the whole table — and this set
-- is larger than the held set BY DESIGN, which is the same O(everything)
-- shape #775 had to take off the health-poll path.
--
-- Paging does not need this index: `list_known_wire_hashes_since` orders by
-- `(kind, content_hash)` and is served by the PRIMARY KEY.
CREATE INDEX IF NOT EXISTS known_wire_hashes_age
    ON known_wire_hashes (last_advertised_at);
