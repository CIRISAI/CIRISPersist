//! v62.0.0 (CC 2.7, wave P9) — **I3607: a wait reaches Python as
//! `ciris_persist.Waiting`, keeping the type it had.**
//!
//! [`federation_err_to_py`](super::federation_err_to_py) raises every error
//! whose [`is_wait`](crate::federation::Error::is_wait) holds as `Waiting`, a
//! `ValueError` subclass, with the SAME `args` the arm raised before (so
//! `str(e)` and `e.args` are unchanged) and the attributes `kind` (the token)
//! and `retryable` (`True`). Every wait arm mapped to `ValueError` before
//! v62, so `except ValueError` still catches each one: the memory rule "a new
//! error arm keeps the Python type of the arm it replaces". A terminal
//! refusal is NOT `Waiting`; `NoActorSignature` stays `RuntimeError`; a
//! relayed (capsule) wait is `Waiting`, a relayed terminal `RuntimeError`
//! (the type every capsule failure had before v62).

use super::{federation_err_to_py, Waiting};
use crate::federation::{Error, SignerNotActingReason};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

fn s(x: &str) -> String {
    x.to_owned()
}

/// I3607 — waits are `Waiting` (a ValueError), with their args and the two
/// attributes; terminals are not.
#[test]
fn i3607_a_wait_is_waiting_and_keeps_its_python_type() {
    Python::initialize();
    let waits = vec![
        Error::AttesterKeyUnknown {
            attesting_key_id: s("k"),
            plane: "attestation",
        },
        Error::link_not_held("family", "insert family: FOREIGN KEY constraint failed"),
        Error::WithdrawsTargetUnheld {
            attestation_id: s("w"),
            target_attestation_id: s("t"),
        },
        Error::SignerDoesNotActFor {
            attesting_key_id: s("k"),
            identity_key_id: s("i"),
            plane: "identity_occurrence",
            reason: SignerNotActingReason::NotBound,
        },
        Error::WriteScopeRefused(crate::scope::ScopeRefusalReason::MembershipUnresolved),
        Error::RosterAuthorityUnauthorized {
            group_key_id: s("g"),
            offered_authority_key_id: s("a"),
            rule: crate::federation::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
            shortfall: None,
        },
        Error::Relayed {
            kind: "federation_attester_key_unknown",
            wait: true,
            message: s("relayed"),
        },
    ];
    for e in waits {
        let kind = e.kind();
        assert!(e.is_wait(), "I3607: the table holds waits only ({kind})");
        let py_err = federation_err_to_py(e);
        Python::attach(|py| {
            assert!(
                py_err.is_instance_of::<Waiting>(py),
                "I3607: {kind} is Waiting"
            );
            assert!(
                py_err.is_instance_of::<PyValueError>(py),
                "I3607: {kind} is still a ValueError"
            );
            let v = py_err.value(py);
            let text = v.to_string();
            assert!(text.starts_with(kind), "I3607: led by the kind: {text}");
            let got_kind: String = v.getattr("kind").expect("kind").extract().expect("str");
            assert_eq!(got_kind, kind, "I3607: the kind attribute");
            let retryable: bool = v
                .getattr("retryable")
                .expect("retryable")
                .extract()
                .expect("bool");
            assert!(retryable, "I3607: retryable");
        });
    }

    let terminals = vec![
        Error::InvalidArgument(s("bad")),
        Error::SignerDoesNotActFor {
            attesting_key_id: s("k"),
            identity_key_id: s("i"),
            plane: "identity_occurrence",
            reason: SignerNotActingReason::GenesisEvicted,
        },
        Error::malformed_row(
            "attestation",
            crate::federation::malformed_row::NO_SIGNER,
            "x",
        ),
    ];
    for e in terminals {
        let kind = e.kind();
        let py_err = federation_err_to_py(e);
        Python::attach(|py| {
            assert!(
                !py_err.is_instance_of::<Waiting>(py),
                "I3607: {kind} is not Waiting"
            );
            assert!(
                py_err.is_instance_of::<PyValueError>(py),
                "I3607: {kind} keeps ValueError"
            );
        });
    }

    for (e, what) in [
        (
            Error::NoActorSignature {
                attestation_id: s("a"),
                attesting_key_id: s("k"),
            },
            "NoActorSignature",
        ),
        (
            Error::Relayed {
                kind: "federation_malformed_row",
                wait: false,
                message: s("relayed"),
            },
            "a relayed terminal",
        ),
    ] {
        let py_err = federation_err_to_py(e);
        Python::attach(|py| {
            assert!(
                py_err.is_instance_of::<PyRuntimeError>(py),
                "I3607: {what} keeps RuntimeError"
            );
            assert!(
                !py_err.is_instance_of::<Waiting>(py),
                "I3607: {what} is not Waiting"
            );
        });
    }
}

/// I3607 — a purge refusal's `(token, body)` args survive the re-raise: a
/// retryable `purge_unauthorised` reason is `Waiting` with the SAME two args.
#[test]
fn i3607_the_args_survive_the_reraise() {
    Python::initialize();
    let body = serde_json::json!({
        "reason": crate::federation::steward_purge::unauthorised_reason::ROOT_NOT_HELD,
    });
    let e = Error::PurgeRefused {
        token: crate::federation::steward_purge::token::UNAUTHORISED,
        body: body.clone(),
    };
    assert!(e.is_wait(), "I3607: root_not_held is an ordering gap");
    let py_err = federation_err_to_py(e);
    Python::attach(|py| {
        assert!(py_err.is_instance_of::<Waiting>(py), "I3607: Waiting");
        let args: (String, String) = py_err
            .value(py)
            .getattr("args")
            .expect("args")
            .extract()
            .expect("a (token, body) pair");
        assert_eq!(
            args,
            (
                crate::federation::steward_purge::token::UNAUTHORISED.to_owned(),
                body.to_string()
            ),
            "I3607: the args are the arm's"
        );
    });
}
