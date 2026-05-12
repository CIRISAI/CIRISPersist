//! Feature extraction — typed [`Features`] projection from a
//! verified BatchEnvelope.
//!
//! Lifted from CIRISLensCore `src/extract/` (v0.6.0-α3). The extract
//! stage runs after scrub + classify and populates a typed
//! [`Features`] struct that downstream consumers (RATCHET cohort
//! routing, capacity scoring, manifold-conformity detectors,
//! sovereign agents computing their own scores) read directly off
//! the `cirislens.trace_events.extracted_features` JSONB column (V009).
//!
//! # Sub-modules
//!
//! - [`features`] — typed [`Features`] struct + sub-types
//!   ([`DeclaredCohortAxes`], [`StepTimestamps`],
//!   [`ObservationWeights`], [`ModelClass`]).
//! - [`json_path`] — dot-notation path resolver + JSON value
//!   coercions.
//! - [`static_extract`] — static-coded extraction function
//!   ([`extract_features`]).
//!
//! # Cohort axes
//!
//! Phase 1 cohort cell is the 5-tuple `(agent_role, agent_template,
//! deployment_domain, deployment_type, deployment_region)`. The
//! 6th axis (`deployment_trust_mode`) is carried for analytics but
//! is NOT a cohort key per the RATCHET 2026-05-04 lock-in.

pub mod features;
pub mod json_path;
pub mod static_extract;

pub use features::{DeclaredCohortAxes, Features, ModelClass, ObservationWeights, StepTimestamps};
pub use json_path::{
    resolve_json_path, value_to_bool, value_to_float, value_to_int, value_to_string,
};
pub use static_extract::extract_features;
