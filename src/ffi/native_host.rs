//! v62.0.0 (slice A, P9) — **the native host's lifecycle adapter.**
//!
//! Node code waits on a [`Lifecycle`](crate::host::Lifecycle) and holds no
//! `cfg(unix)` / `cfg(windows)` (FSD WASM_NODE §4.1 rule 2). A native host
//! turns the operating system's shutdown signals into a
//! [`LifecycleEvent::Shutdown`] here: SIGINT / SIGTERM on unix, Ctrl+C /
//! Ctrl+Break on windows (CIRISPersist#200). This is the one place that
//! signal handling lives; it replaces `queue::shutdown_signal`.

use crate::host::{Lifecycle, LifecycleEvent, TaskHandle};

/// A future that resolves on the OS shutdown signal: SIGINT or SIGTERM on
/// unix, Ctrl+C or Ctrl+Break on windows. On any other target there is no
/// such signal and it never resolves; that host delivers
/// [`LifecycleEvent::Shutdown`] itself.
#[cfg(unix)]
pub async fn os_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => tracing::info!("received SIGTERM; beginning graceful shutdown"),
        _ = int.recv()  => tracing::info!("received SIGINT; beginning graceful shutdown"),
    }
}

/// Windows analog (CIRISPersist#200): Ctrl+C (≈ SIGINT) + Ctrl+Break (the
/// closest console-event analog of SIGTERM).
#[cfg(windows)]
pub async fn os_shutdown_signal() {
    use tokio::signal::windows::{ctrl_break, ctrl_c};
    let mut cc = ctrl_c().expect("install Ctrl+C handler");
    let mut cb = ctrl_break().expect("install Ctrl+Break handler");
    tokio::select! {
        _ = cc.recv() => tracing::info!("received Ctrl+C; beginning graceful shutdown"),
        _ = cb.recv() => tracing::info!("received Ctrl+Break; beginning graceful shutdown"),
    }
}

/// No OS shutdown signal exists on this target: never resolves.
#[cfg(not(any(unix, windows)))]
pub async fn os_shutdown_signal() {
    std::future::pending::<()>().await;
}

/// **Wire the OS signals to `lifecycle`**: spawns a task that waits for
/// [`os_shutdown_signal`] and delivers [`LifecycleEvent::Shutdown`]. Abort
/// the returned handle to stop listening.
pub fn deliver_os_signals(lifecycle: Lifecycle) -> TaskHandle {
    crate::host::rt::spawn(async move {
        os_shutdown_signal().await;
        lifecycle.deliver(LifecycleEvent::Shutdown);
    })
}
