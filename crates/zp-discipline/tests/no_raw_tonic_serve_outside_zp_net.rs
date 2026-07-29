//! Discipline: tonic gRPC servers MUST NOT use the address-passing
//! `.serve(<addr>)` form. All loopback gRPC binds must route through
//! `zp_net::serve_loopback_grpc_with_shutdown`; all network-facing
//! gRPC binds must route through `zp_net::serve_network_grpc_with_shutdown`.
//!
//! # Why (singular loopback binding, 2026-05-21)
//!
//! tonic's `Server::builder().add_service(...).serve(addr)` binds
//! IPv4 only when `addr` is an IPv4 SocketAddr. It repeats the
//! resolver-order trap for gRPC clients calling `localhost:<port>`
//! that resolve to `::1` first. The helpers in `zp-net` use
//! `serve_with_incoming_shutdown` under the hood and wire both
//! stacks (loopback) or one stack (network) through a single
//! `CancellationToken` so all listener tasks drain coherently.
//!
//! See
//! `docs/design/SINGULAR-LOOPBACK-BINDING-2026-05.md`.
//!
//! # Why this pin forbids only `.serve(` (and not `Server::builder()`)
//!
//! `Server::builder()` legitimately appears at call sites *inside the
//! factory closure* that the helper takes as a parameter — the
//! factory is called once per stack to produce a fresh `Router`. The
//! anti-pattern is the address-passing serve form, not the builder
//! itself. Forbidding `.serve(` cleanly enforces "the bind happens in
//! zp-net" while letting factory closures keep using `Server::builder()`
//! to assemble the per-task router.
//!
//! `axum::serve(...)` is a free function in a different namespace; it
//! has no leading dot and does not match `\.serve\(`.

use zp_discipline::Discipline;

#[test]
fn loopback_grpc_must_route_through_zp_net() {
    Discipline::new("no_raw_tonic_serve_outside_zp_net")
        .cite_invariant(
            "Principle 8 (one canonical path) — singular loopback binding",
        )
        .rationale(
            "The tonic address-passing serve form binds a single \
             SocketAddr and repeats the IPv6-first resolver trap for \
             gRPC clients calling `localhost:<port>`. All gRPC binds \
             must route through zp_net's serve_loopback_grpc / \
             serve_network_grpc helpers which bind via the incoming- \
             stream form and wire shutdown through a CancellationToken.",
        )
        // The address-passing serve form. Catches:
        //   .serve(addr)
        //   .serve(grpc_addr)
        //   .serve( anything_else )
        // Does NOT catch:
        //   .serve_with_incoming_shutdown(stream, token.cancelled_owned())
        //   .serve_with_incoming(stream)
        //   axum::serve(listener, app)   (no leading dot)
        .forbid_pattern(r"\.serve\(")
        // Canonical implementation site.
        .allow_path("crates/zp-net/src/")
        // Skip comment lines (module docs mention the forbidden form).
        .skip_lines_containing("//")
        // Skip pin-declaration lines in this file itself.
        .skip_lines_containing("forbid_pattern")
        .assert();
}
