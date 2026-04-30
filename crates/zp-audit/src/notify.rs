//! Post-commit append notification — the seam that lets external orchestrators
//! (e.g., the Merkle anchor pipeline) react to chain growth without the audit
//! store having to know about them.
//!
//! The store fires a [`AppendNotifier::notify`] call **after** the row has been
//! committed. The notifier receives the sealed entry and its rowid (treated as
//! the chain sequence number — monotonic with insertion order). Implementors
//! must do their work asynchronously (typically `tokio::spawn`) and must not
//! block the append path.

use std::sync::Arc;

use zp_core::AuditEntry;

/// Hook invoked after every successful append to the audit store.
///
/// Wired in `AuditStore::set_notifier`. Used by the anchoring pipeline to
/// detect trigger events and seal Merkle epochs in response.
pub trait AppendNotifier: Send + Sync {
    /// Called once per committed entry. `sequence` is the SQLite rowid (1-based,
    /// monotonic). Implementations must not block the calling thread.
    fn notify(&self, entry: &AuditEntry, sequence: i64);
}

/// Type alias for the boxed notifier the store actually stores.
pub type SharedNotifier = Arc<dyn AppendNotifier>;
