//! Canonical bind helpers for HTTP / TCP loopback servers.
//!
//! See module docs in `lib.rs` for the rationale.

use tokio::net::TcpListener;

/// Result of a dual-stack loopback bind.
///
/// `v4` is the required listener — IPv4 loopback is the substrate's
/// minimum guarantee. `v6` is best-effort: a successful IPv6 bind
/// closes the resolver-order trap (clients that resolve `localhost`
/// to `::1` first); a failed IPv6 bind is logged and `v6` is `None`.
pub struct DualStackListener {
    pub v4: TcpListener,
    pub v6: Option<TcpListener>,
}

impl DualStackListener {
    /// Stacks actually bound, in canonical form for the
    /// `bound_stacks` receipt field. Always contains `"ipv4"`;
    /// contains `"ipv6"` iff `v6` is `Some`.
    pub fn bound_stacks(&self) -> Vec<&'static str> {
        if self.v6.is_some() {
            vec!["ipv4", "ipv6"]
        } else {
            vec!["ipv4"]
        }
    }
}

/// Bind both IPv4 and IPv6 loopback at the given port.
///
/// IPv4 (`127.0.0.1:<port>`) is the required minimum — if it fails,
/// the function returns `Err`. IPv6 (`[::1]:<port>`) is best-effort:
/// success returns it in `DualStackListener::v6`; failure logs a
/// warning and leaves `v6` as `None`.
///
/// Why both: on macOS (and many Linux configurations), `localhost`
/// resolves to BOTH `::1` and `127.0.0.1`. Clients that don't do
/// happy-eyeballs fallback (RFC 6555) try `::1` first, get
/// connection-refused, and surface "transport error" without
/// retrying IPv4 — silently breaking every client reaching the
/// substrate via `localhost:<port>`. Binding both loopback stacks
/// on the same port closes the trap.
pub async fn bind_loopback(port: u16) -> anyhow::Result<DualStackListener> {
    let v4 = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    // ── Dual-stack loopback: also bind IPv6 ::1 when running loopback ──
    // On macOS (and many Linux configurations), `localhost` resolves to BOTH
    // ::1 and 127.0.0.1. Clients that don't do happy-eyeballs fallback
    // (RFC 6555) try ::1 first, get connection-refused, and surface
    // "transport error" without retrying IPv4 — silently breaking every
    // client reaching the substrate via `localhost:<port>`. Binding both
    // loopback stacks on the same port closes the trap. Network-facing
    // binds (0.0.0.0, public IPs) are unchanged.
    let v6 = match TcpListener::bind(format!("[::1]:{}", port)).await {
        Ok(l) => {
            tracing::info!("Loopback dual-stack: also listening on [::1]:{}", port);
            Some(l)
        }
        Err(e) => {
            tracing::warn!(
                "IPv6 loopback bind failed for [::1]:{}: {} — \
                 IPv6-preferring clients may fail to reach the substrate.",
                port,
                e
            );
            None
        }
    };

    Ok(DualStackListener { v4, v6 })
}

/// Bind a non-loopback (network-facing) listener at the explicit
/// address. Single listener, no dual-stack semantics.
///
/// Use this for `bind_addr=0.0.0.0` or explicit public IPs. The
/// caller is responsible for any external warning (TLS recommended,
/// firewall posture, etc.) — this helper exists so the bind site
/// is still canonical even when not loopback.
pub async fn bind_network(addr: &str, port: u16) -> anyhow::Result<TcpListener> {
    let listener = TcpListener::bind(format!("{}:{}", addr, port)).await?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bind_loopback` produces an IPv4 listener and the
    /// `bound_stacks` summary reflects which stacks succeeded.
    #[tokio::test]
    async fn bind_loopback_returns_v4_and_summary() {
        // Port 0 → OS picks a free ephemeral port. Note: IPv6 will
        // get a different ephemeral port than v4 since we ask the
        // OS for "any free port" twice. That's fine for this test —
        // we're confirming the dual-stack semantics, not port
        // alignment. Production callers always pass an explicit
        // port so v4 and v6 share it.
        let listener = bind_loopback(0).await.expect("bind_loopback failed");
        let v4_addr = listener.v4.local_addr().expect("v4 local_addr");
        assert!(v4_addr.is_ipv4(), "v4 listener must be IPv4");

        let summary = listener.bound_stacks();
        assert!(summary.contains(&"ipv4"));
        if listener.v6.is_some() {
            assert!(summary.contains(&"ipv6"));
        }
    }

    /// Empty `bound_stacks` is structurally impossible — IPv4 is
    /// always present (the function returns `Err` otherwise).
    #[tokio::test]
    async fn bound_stacks_always_contains_ipv4() {
        let listener = bind_loopback(0).await.expect("bind_loopback failed");
        assert!(listener.bound_stacks().contains(&"ipv4"));
    }
}
