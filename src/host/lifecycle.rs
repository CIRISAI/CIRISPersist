//! v62.0.0 (slice A, P9) — **lifecycle is an event the host delivers.**
//!
//! FSD WASM_NODE §5.2: `sigterm-broker` → `on-event(lifecycle)`; there are
//! no signals in a browser Worker or under the EFI shim, and node code holds
//! no `cfg(unix)` / `cfg(windows)` (§4.1 rule 2: wasm is neither, which is
//! exactly how `queue::shutdown_signal` stopped resolving on wasm32).
//!
//! The node waits on a [`Lifecycle`]; the host calls
//! [`Lifecycle::deliver`]. A native host maps SIGINT / SIGTERM (unix) or
//! Ctrl+C / Ctrl+Break (windows) onto [`LifecycleEvent::Shutdown`] with the
//! adapter in [`crate::ffi::native_host`], which is where the target `cfg`
//! now lives.

use std::sync::Arc;

use tokio::sync::watch;

/// An event the host delivers about the node's lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleEvent {
    /// Begin a graceful shutdown. Sticky: once delivered it stays delivered.
    Shutdown,
    /// The host moved the node to the background (mobile, a hidden tab).
    EnterBackground,
    /// The host brought the node back to the foreground.
    EnterForeground,
}

/// What the node knows of its lifecycle so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LifecycleState {
    /// A [`LifecycleEvent::Shutdown`] has been delivered.
    pub shutdown: bool,
    /// The last background/foreground event left the node in the background.
    pub background: bool,
    /// How many events have been delivered.
    pub delivered: u64,
}

/// The node's lifecycle channel. Cheap to clone; every clone sees the same
/// events.
#[derive(Debug, Clone)]
pub struct Lifecycle {
    tx: Arc<watch::Sender<LifecycleState>>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// A fresh channel: running, foreground, nothing delivered.
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(LifecycleState::default());
        Self { tx: Arc::new(tx) }
    }

    /// **The host's call.** Deliver `event` to every waiter.
    pub fn deliver(&self, event: LifecycleEvent) {
        match event {
            LifecycleEvent::Shutdown => {
                tracing::info!("lifecycle: shutdown delivered; beginning graceful shutdown");
            }
            LifecycleEvent::EnterBackground | LifecycleEvent::EnterForeground => {
                tracing::debug!(?event, "lifecycle event delivered");
            }
        }
        self.tx.send_modify(|s| {
            s.delivered = s.delivered.saturating_add(1);
            match event {
                LifecycleEvent::Shutdown => s.shutdown = true,
                LifecycleEvent::EnterBackground => s.background = true,
                LifecycleEvent::EnterForeground => s.background = false,
            }
        });
    }

    /// The state now.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        *self.tx.borrow()
    }

    /// True once a shutdown has been delivered.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.state().shutdown
    }

    /// Resolves once [`LifecycleEvent::Shutdown`] is delivered (at once if it
    /// already was). The trigger for
    /// [`PersisterHandle::shutdown`](crate::queue::PersisterHandle::shutdown)
    /// in a long-running deployment.
    pub async fn shutdown(&self) {
        let mut rx = self.tx.subscribe();
        // `wait_for` checks the current value first; the sender lives in
        // `self`, so the channel cannot close while this borrow is held.
        let _ = rx.wait_for(|s| s.shutdown).await;
    }

    /// A receiver that observes every state change (for loops that react to
    /// background / foreground).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<LifecycleState> {
        self.tx.subscribe()
    }
}
