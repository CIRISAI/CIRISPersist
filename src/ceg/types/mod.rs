//! Shared read-surface types — time windows, cursors, filter shapes.
//!
//! Moved from `src/read/types.rs` in v4.0 (FSD §3.3). The v3.x single
//! `read::types` module is split along subject lines:
//!
//! - [`window`] — [`TimeWindow`], the `(since, until)` pair every
//!   windowed primitive takes (sections E / F / G / H).
//! - [`cursor`] — [`TraceCursor`], the §A trace-listing cursor.
//! - [`filter`] — [`TraceFilter`] + [`DeviationMetric`] (sections A / E / F).
//!
//! The FSD §5/§6 `Filter` + `Aggregate` traits land in later v4.0
//! commits; this module currently re-homes only the relocated v3.x
//! shapes so the move is behaviour-neutral.

pub mod cursor;
pub mod filter;
pub mod window;

pub use cursor::TraceCursor;
pub use filter::{DeviationMetric, TraceFilter};
pub use window::TimeWindow;
