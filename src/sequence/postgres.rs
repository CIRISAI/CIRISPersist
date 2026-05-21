//! PostgreSQL impl of [`SequenceService`] (v1.7.1, CIRISPersist#83).
//!
//! One row per `(identity, stream)`, PK on the pair. The
//! `next_sequence` path is a single-statement
//! `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` — the bump and
//! the read happen atomically, so concurrent callers across
//! occurrences + in-process consumers sharing one Ed25519 identity
//! each get a distinct value with no forks.

use super::service::SequenceService;
use super::Error;
use crate::store::postgres::PostgresBackend;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        Some(c) if c == SqlState::UNIQUE_VIOLATION => {
            Error::Conflict(format!("{op} UNIQUE: {detail}"))
        }
        Some(c) if c == SqlState::NOT_NULL_VIOLATION => {
            Error::InvalidArgument(format!("{op} NOT NULL: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

fn validate_key(identity: &str, stream: &str) -> Result<(), Error> {
    if identity.is_empty() {
        return Err(Error::InvalidArgument("identity required".into()));
    }
    if stream.is_empty() {
        return Err(Error::InvalidArgument("stream required".into()));
    }
    Ok(())
}

impl SequenceService for PostgresBackend {
    async fn next_sequence(&self, identity: &str, stream: &str) -> Result<u64, Error> {
        validate_key(identity, stream)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Atomic bump-and-return: a single statement increments the
        // counter and RETURNs the new value. Correct under
        // concurrent callers — the row lock taken by ON CONFLICT
        // DO UPDATE serializes the bump.
        let row = client
            .query_one(
                "INSERT INTO cirislens.identity_sequences (\
                    identity, stream, next_value, updated_at\
                 ) VALUES ($1, $2, 1, NOW()) \
                 ON CONFLICT (identity, stream) DO UPDATE \
                   SET next_value = cirislens.identity_sequences.next_value + 1, \
                       updated_at = NOW() \
                 RETURNING next_value",
                &[&identity, &stream],
            )
            .await
            .map_err(|e| map_pg_error(e, "next_sequence"))?;
        let value: i64 = row
            .try_get("next_value")
            .map_err(|e| Error::Backend(format!("decode next_value: {e}")))?;
        super::decode_sequence_value(value)
    }

    async fn peek_sequence(&self, identity: &str, stream: &str) -> Result<u64, Error> {
        validate_key(identity, stream)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT next_value FROM cirislens.identity_sequences \
                 WHERE identity = $1 AND stream = $2",
                &[&identity, &stream],
            )
            .await
            .map_err(|e| map_pg_error(e, "peek_sequence"))?;
        match row_opt {
            None => Ok(0),
            Some(row) => {
                let value: i64 = row
                    .try_get("next_value")
                    .map_err(|e| Error::Backend(format!("decode next_value: {e}")))?;
                super::decode_sequence_value(value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn unique_id() -> String {
        format!("id-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn next_sequence_increments_1_2_3() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id();
        let stream = "net-messages";
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn streams_under_same_identity_are_independent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id();
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, "stream-a")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, "stream-a")
                .await
                .unwrap(),
            2
        );
        // Different stream — fresh counter.
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, "stream-b")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn identities_are_independent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id_a = unique_id();
        let id_b = unique_id();
        assert_eq!(
            SequenceService::next_sequence(&backend, &id_a, "s")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            SequenceService::next_sequence(&backend, &id_a, "s")
                .await
                .unwrap(),
            2
        );
        // Different identity — fresh counter.
        assert_eq!(
            SequenceService::next_sequence(&backend, &id_b, "s")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn peek_sequence_does_not_bump() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id();
        let stream = "s";
        // Cold pair — peek returns 0.
        assert_eq!(
            SequenceService::peek_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            0
        );
        SequenceService::next_sequence(&backend, &identity, stream)
            .await
            .unwrap();
        SequenceService::next_sequence(&backend, &identity, stream)
            .await
            .unwrap();
        // Peek returns last-issued without bumping — repeated.
        assert_eq!(
            SequenceService::peek_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            SequenceService::peek_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            2
        );
        // Next issue continues from 3 — peek did not consume.
        assert_eq!(
            SequenceService::next_sequence(&backend, &identity, stream)
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn empty_identity_or_stream_rejected_invalid_argument() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let r = SequenceService::next_sequence(&backend, "", "s").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = SequenceService::next_sequence(&backend, "id", "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = SequenceService::peek_sequence(&backend, "", "s").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = SequenceService::peek_sequence(&backend, "id", "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn concurrent_next_sequence_yields_distinct_set() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = std::sync::Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
        backend.run_migrations().await.unwrap();

        let identity = unique_id();
        let stream = "concurrent";
        let mut handles = Vec::new();
        for _ in 0..20 {
            let b = backend.clone();
            let id = identity.clone();
            handles.push(tokio::spawn(async move {
                SequenceService::next_sequence(b.as_ref(), &id, stream)
                    .await
                    .unwrap()
            }));
        }
        let mut got = std::collections::HashSet::new();
        for h in handles {
            got.insert(h.await.unwrap());
        }
        // Atomicity proof: 20 concurrent callers, exactly {1..=20},
        // no duplicates.
        let expected: std::collections::HashSet<u64> = (1..=20).collect();
        assert_eq!(got, expected);
    }
}
