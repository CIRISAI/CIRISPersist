# Migration immutability — an applied migration's bytes are the contract

**CIRISPersist#840.** A one-word edit inside a SQL *comment* took the CIRIS
canonical down for ~7 minutes and crash-looped it 16 times, and bricked every
release from v43.0.0 through v44.1.0 for any node that had applied V070 before
2026-09-09. This document states the invariant that edit broke, the repair for
the nodes it already reached, and the gate that makes the class unrepeatable.

## 1. What refinery actually checksums

`refinery` 0.9 computes a migration's checksum as

```
SipHasher13( name, version, sql )
```

where `sql` is the **entire file text**. Comments, whitespace and blank lines
are inside the hash. The value is written to the schema-history table
(`refinery_schema_history` on sqlite, `ciris_persist_schema_history` on
postgres) at apply time, and on every later boot `verify_migrations` compares
the applied row against the file:

```rust
if migration != app { return Err(DivergentVersion(app, migration)) }   // abort_divergent defaults TRUE
```

`Migration`'s `PartialEq` is `version && name && checksum`. So a changed
comment is indistinguishable from changed DDL, and the failure lands inside
`run_migrations`, inside `Engine::with_*`, **before anything binds** — the node
does not start.

This was known and written down. `src/store/postgres.rs` has carried a v7.0.0
note since the TimescaleDB removal explaining that V079 is "left IMMUTABLE and
unmodified … because the shipped migration is unchanged, its checksum still
matches what `schema_history` recorded". The doctrine was correct and a
documentation rename walked straight past it, because doctrine is not a gate.

## 2. The invariant

> **I43 — a migration file that has shipped in a release is immutable.**
> Not "its DDL is immutable": its **bytes** are. A correction to a shipped
> migration is a NEW migration, never an edit to the old one.

The one thing a shipped migration may not carry is a reference that has to be
kept current. A comment naming a design document is a liability the moment the
document is renamed, which is exactly how #840 happened. Shipped migrations
name documents **as of their own date**; the reader follows the pointer through
the FSD index, not by trusting the comment to be fresh. V070's comment
therefore still says `ENCRYPTED_AT_REST.md`, which is this document's
predecessor under its former name, and it stays that way permanently.

## 3. Two populations, and why a plain revert is not enough

The reported fix — revert the comment — is correct and is what this cut does.
But it is only half the repair, because by 2026-09-11 there are two populations
of nodes and they recorded **different** checksums for the same version:

| population | applied V070 | recorded checksum | plain revert |
|---|---|---|---|
| **A** — with history | before 2026-09-09, from ≤ v42.1.0 | pre-edit | un-bricked |
| **B** — fresh since the break | on/after 2026-09-09, from v43.0.0–v44.1.0 | post-edit | **newly bricked** |

Population B is every node whose database was created in the two days the
broken releases were current. A revert alone moves the outage from A to B, and
B's failure would look identical and arrive with the fix that was supposed to
end it.

So the cut **normalises** instead of merely reverting: the file returns to its
pre-edit bytes, and before refinery validates anything, persist rewrites a V070
history row carrying the post-edit checksum to the pre-edit one.

> **I44 — a node that recorded the bricked V070 checksum boots.**

The repair is deliberately the narrowest thing that can work:

- it matches **version 70 and the exact name** and nothing else;
- it matches the **one** literal post-edit checksum for that dialect, so it
  cannot touch a row that diverged for any other reason;
- it writes the **one** literal pre-edit checksum — both values are pinned as
  constants, and a test recomputes them from the shipped file to prove the
  pinned numbers are the checksums they claim to be;
- it runs **before** the runner, inside postgres's existing migration advisory
  lock, so two booting workers cannot race it;
- it is idempotent, and a no-op on a fresh database (the history table does not
  exist yet) and on every node in population A.

It is not a general checksum-repair facility, and must not become one. A
divergence that is not this exact one is a real divergence and must still
abort.

## 4. The gate

`evidence/migration_checksums.tsv` pins `(dialect, version, name, checksum)`
for every migration file in the tree. The from-disk witness in
`src/store/migration_immutability.rs` recomputes each file's checksum with
refinery's own `Migration::unapplied` and compares.

Editing any shipped migration reds it. Adding a migration reds it until the new
row is added, which is the moment to notice that the file is now permanent.
Because a from-disk gate fails toward a pass when it simply finds nothing, the
witness also asserts the **count** both ways: a file with no row and a row with
no file are both red.

This closes #840's second ask. The deploy role that diagnosed the outage
proposed exactly this gate, keyed on released tags; keying on a pinned manifest
instead makes it hermetic — it needs no tags, no network and no git history, so
it runs identically in a shallow CI clone and in a worktree.

## 5. What this does not cover

The scan that found #840 also found two older migrations whose bytes changed
after their first release: postgres `V001__trace_events.sql` (0.1.0 → 0.1.2,
2026-04-30) and postgres `V059__ceg_07_identity_occurrence_and_family.sql`
(3.12.0 → 3.12.1, 2026-06-03). Both were same-day corrections, and V059's
original was **rejected by postgres** (sqlstate 42P17) so no node can have
recorded it. Neither is live today. They are pinned at their current bytes,
which is what any surviving node has, and the gate holds them there from here.

## 6. Schema text a shipped migration cannot change: the portable-default repair (#845)

Thirty-seven `NOT NULL` timestamp columns across twenty-one shipped sqlite
migrations, V010 through V143, default to `datetime('now', 'subsec')` — the
systematic sqlite translation of postgres's `NOW()`. The `subsec` modifier
was added in SQLite 3.42.0. Below that, an unrecognised modifier does not
error: `datetime()` returns **NULL**, silently, and the `INSERT` that relied
on the default meets `NOT NULL`. Debian bookworm — current stable — ships
3.40.1; Ubuntu 22.04 ships 3.37. On either, the first encrypted-at-rest
write fails at `federation_content_master.created_at` and nothing after it
succeeds. Every CI lane runs a newer SQLite, so the class was invisible until
CIRISEdge's mesh harness ran on a bookworm image (CIRISEdge#600).

### 6.1 Why neither obvious fix is available

- The migrations that declare the defaults have **shipped**. §2 forbids
  editing them, and #840 is what editing one costs.
- SQLite cannot `ALTER COLUMN … SET DEFAULT`. The sanctioned rebuild recipe
  (§11 of the at-rest FSD, the V136/V141 shape) rebuilds a table to change a
  column; for a DEFAULT *expression* on twenty-odd tables carrying indexes,
  foreign keys and a self-FK, that is a large, risky operation to change text
  that stores nothing.

### 6.2 The repair

A DEFAULT expression is schema **text**. SQLite documents a procedure for
schema changes `ALTER TABLE` cannot express: under `PRAGMA writable_schema`,
rewrite the `sql` column of `sqlite_master`, bump `schema_version` so every
connection reloads, and `integrity_check`. Persist runs exactly that, once,
idempotently, after refinery on every boot:

```
datetime('now', 'subsec')   →   strftime('%Y-%m-%d %H:%M:%f', 'now')
```

The replacement yields byte-identical text (`YYYY-MM-DD HH:MM:SS.SSS`, 23
characters) on every SQLite this crate has ever linked, so existing rows,
cursors and readers see no difference. The rewrite touches `type = 'table'`
rows only, is a no-op when no `subsec` remains (a fresh database after the
first boot, every later boot), and is followed by an `integrity_check` that
must answer `ok` and a post-condition that no `subsec` remains — either
failing aborts the boot loudly rather than leaving a schema half-repaired.

It lives beside the #840 repair (`repair_v070_checksum`) and for the same
reason: a shipped migration is immutable, so what a shipped migration got
wrong is corrected at the boundary where the database meets the current
crate, not in the ledger.

### 6.3 Invariants

| # | invariant | falsified by | gate |
|---|---|---|---|
| I55 | After `run_migrations` on sqlite, no `CREATE TABLE` text in `sqlite_master` contains `subsec`; an `INSERT` omitting a defaulted timestamp column succeeds and stores the 23-character form; a second run rewrites nothing. | a bookworm host that cannot write; a repair that changes the stored format | behavioural (sqlite), and the bookworm witness |
| I56 | No migration file after V144, in either dialect, contains `subsec`; the shipped set's count is pinned (44 in sqlite, 0 in postgres). | a new migration that reintroduces the modifier | from-disk |
| I57 | The shell witness `scripts/sqlite_portability_witness.sh` and the Rust repair carry the same two literals, so what CI proves on 3.40.1 is what the crate does. | a witness that tests a different rewrite | from-disk |

The bookworm witness runs the shipped sqlite migrations and the repair
through Debian's own `libsqlite3` 3.40.1 in a `debian:bookworm-slim`
container, asserts the pre-repair `NOT NULL` failure, then the post-repair
success. It is the only place in the stack a pre-3.42 SQLite runs, which is
the reason it exists.

### 6.4 The rule going forward

`subsec` is never written into a migration again. New timestamp defaults use
the portable form. The floor this crate supports is what Debian stable ships;
a modifier newer than that floor is a portability bug whether or not CI can
see it.

### 6.5 Statements, not only defaults

The audit that built the repair found a second class the repair cannot
reach: nine runtime SQL statements in `src/` evaluated
`datetime('now', 'subsec')` directly — the community-DEK epoch rotation
(`rotated_at`), maintenance locks, incident records, telemetry locks and
workers. On 3.40.1 those wrote NULL silently into a nullable column, or failed
`NOT NULL`. They are source, so they are simply changed to the portable form;
what keeps them changed is I58.

| # | invariant | falsified by | gate |
|---|---|---|---|
| I58 | The `subsec` modifier appears in no source file except the one that owns the two literals — doc comments included, so the old spelling is never copied out of one. | a new statement or default that evaluates the modifier at runtime | from-disk |

