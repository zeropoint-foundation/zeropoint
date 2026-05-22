//! Canonical peer-URL / peer-URI builders for substrate-internal clients.
//!
//! See module docs in `lib.rs` for the rationale. This module is the
//! client-side symmetric counterpart to `bind.rs` and `grpc.rs`: where
//! those guarantee that loopback servers bind both IPv4 and IPv6, this
//! one guarantees that clients reaching a substrate peer service over
//! loopback choose the same canonical host every time — explicit IPv4
//! literal `127.0.0.1`.
//!
//! # Why normalize `localhost` to `127.0.0.1`
//!
//! On macOS (and many Linux configurations) `localhost` resolves to
//! both `::1` and `127.0.0.1`. Even with dual-stack binding in place
//! (Phase 1), routing client URLs through the IPv6-preferring path
//! depends on resolver order and on the client's RFC 6555 happy-
//! eyeballs implementation. Both are out-of-substrate variables.
//!
//! Picking IPv4-explicit removes the variable: `127.0.0.1:<port>`
//! resolves to one fixed address and the dual-stack bind guarantees
//! the listener is there. Substrate-internal client URLs are
//! machine-to-machine — there is no operator reading `localhost` and
//! typing it — so the canonical form is the IPv4 literal.
//!
//! # When to use which helper
//!
//! - [`peer_url`] — full URL with path, e.g.
//!   `http://127.0.0.1:17010/api/v1/security/policy-version`.
//! - [`peer_origin`] — host-only URL with no path, e.g.
//!   `http://127.0.0.1:17010`. Use this for tool `url:` fields the
//!   dashboard renders, and as a 1:1 replacement for legacy
//!   `format!("http://127.0.0.1:{}", port)` calls.
//! - [`peer_grpc_uri`] — `http::Uri` form for tonic client channels.
//!
//! # Loopback normalization
//!
//! All three helpers apply the same host-normalization rule:
//!
//! | Caller passes | Helper uses |
//! |---|---|
//! | `"localhost"` | `"127.0.0.1"` (normalized) |
//! | `"127.0.0.1"` | `"127.0.0.1"` (preserved) |
//! | `"[::1]"` or `"::1"` | `"[::1]"` (preserved, bracketed) |
//! | anything else | passed through unchanged |
//!
//! Non-loopback hosts (mesh peers, user-supplied endpoints) pass
//! through unchanged so the builder doesn't accidentally rewrite a
//! foreign hostname.

/// Normalize the host segment for a loopback peer URL.
///
/// `localhost` → `127.0.0.1`. Explicit `127.0.0.1` preserved.
/// `::1` is bracketed to `[::1]` so the result is a valid URL
/// authority. Any other input is passed through unchanged.
fn normalize_host(host: &str) -> String {
    match host {
        "localhost" => "127.0.0.1".to_string(),
        "::1" => "[::1]".to_string(),
        other => other.to_string(),
    }
}

/// Normalize a path fragment so callers can pass `""`, `"/"`, or
/// `"/api/...".` interchangeably. Returns a string that either is
/// empty or begins with `/`.
fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

/// Build an HTTP URL for a substrate peer service on loopback.
///
/// Returns `http://<host>:<port><path>` with `host` loopback-
/// normalized per [`normalize_host`]. Servers are guaranteed
/// dual-stack via Phase 1, so the IPv4 path is always reachable and
/// the URL is resolver-order-immune.
///
/// `path` may be `""`, `"/"`, or a path that does or does not start
/// with `/` — the builder normalizes so callers don't have to.
///
/// # Examples
///
/// ```
/// use zp_net::{peer_url, peer_url_with_path};
/// assert_eq!(peer_url("localhost", 17010), "http://127.0.0.1:17010");
/// assert_eq!(
///     peer_url_with_path("127.0.0.1", 9100, "/healthz"),
///     "http://127.0.0.1:9100/healthz",
/// );
/// ```
pub fn peer_url(host: &str, port: u16) -> String {
    format!("http://{}:{}", normalize_host(host), port)
}

/// Same as [`peer_url`] but with a path component appended.
///
/// `path` may begin with or without `/` — the builder normalizes.
/// An empty `path` produces the same result as [`peer_url`].
pub fn peer_url_with_path(host: &str, port: u16, path: &str) -> String {
    format!(
        "http://{}:{}{}",
        normalize_host(host),
        port,
        normalize_path(path)
    )
}

/// Build an `Origin:`-header value for a substrate peer service on
/// loopback — the scheme + host + port form with no path.
///
/// Functionally identical to [`peer_url`] today; named separately so
/// call sites that build `Origin` header values are visibly using the
/// origin form rather than borrowing a URL builder.
pub fn peer_origin(host: &str, port: u16) -> String {
    format!("http://{}:{}", normalize_host(host), port)
}

/// Build a gRPC client target URI for a substrate peer service on
/// loopback. Returns `http://<host>:<port>/` as an `http::Uri` — the
/// form tonic `Channel::builder` / `Endpoint::from_shared` accept.
///
/// Loopback normalization matches [`peer_url`].
///
/// # Panics
///
/// Panics if the resulting URI string fails to parse as a valid
/// `http::Uri`. The inputs are constrained (a host string and a
/// `u16`) and the format template is fixed; the only way this can
/// fail is if `host` contains characters illegal in a URI authority,
/// which is a programmer error worth catching loudly.
pub fn peer_grpc_uri(host: &str, port: u16) -> http::Uri {
    let s = format!("http://{}:{}/", normalize_host(host), port);
    s.parse()
        .unwrap_or_else(|e| panic!("peer_grpc_uri produced invalid URI {:?}: {}", s, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Smoke test (the one referenced in the Phase 2 design + brief). ──
    //
    // The tool-launch path historically passed `localhost` to launched
    // tools. After migrating peer-URL construction through `peer_url`,
    // the launched tool sees `127.0.0.1` and the IPv4 path is
    // exercised first — closing the resolver-order trap on the
    // client side.
    #[test]
    fn peer_url_normalizes_localhost_to_ipv4() {
        assert_eq!(peer_url("localhost", 17010), "http://127.0.0.1:17010");
    }

    #[test]
    fn peer_url_preserves_explicit_ipv4_literal() {
        assert_eq!(peer_url("127.0.0.1", 9100), "http://127.0.0.1:9100");
    }

    #[test]
    fn peer_url_brackets_bare_ipv6_literal() {
        assert_eq!(peer_url("::1", 9100), "http://[::1]:9100");
    }

    #[test]
    fn peer_url_preserves_non_loopback_hosts() {
        assert_eq!(
            peer_url("api.example.com", 443),
            "http://api.example.com:443"
        );
    }

    #[test]
    fn peer_url_with_path_handles_path_variants() {
        assert_eq!(
            peer_url_with_path("localhost", 17010, ""),
            "http://127.0.0.1:17010"
        );
        assert_eq!(
            peer_url_with_path("localhost", 17010, "/"),
            "http://127.0.0.1:17010/"
        );
        assert_eq!(
            peer_url_with_path("localhost", 17010, "/api/v1/healthz"),
            "http://127.0.0.1:17010/api/v1/healthz"
        );
        // Path without leading slash gets one added.
        assert_eq!(
            peer_url_with_path("localhost", 17010, "api/v1/healthz"),
            "http://127.0.0.1:17010/api/v1/healthz"
        );
    }

    #[test]
    fn peer_origin_matches_peer_url() {
        assert_eq!(
            peer_origin("localhost", 17010),
            peer_url("localhost", 17010)
        );
    }

    #[test]
    fn peer_grpc_uri_parses_and_normalizes() {
        let uri = peer_grpc_uri("localhost", 17011);
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.host(), Some("127.0.0.1"));
        assert_eq!(uri.port_u16(), Some(17011));
    }

    #[test]
    fn peer_grpc_uri_preserves_ipv4_literal() {
        let uri = peer_grpc_uri("127.0.0.1", 17011);
        assert_eq!(uri.host(), Some("127.0.0.1"));
    }
}
