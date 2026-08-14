//! Discipline: a process MUST NOT be spawned with a **non-literal program
//! name** outside `zp_host`. Variable-program spawns must route through
//! `zp_host::HostContext::spawn_process`, which gates the call and seals a
//! chain entry before the effect occurs.
//!
//! # Why (Whonix precedent, 2026-08-14)
//!
//! `docs/design/WHONIX-LESSONS.md` §3.1 records the load-bearing lesson from
//! Whonix's two-VM split: *remove the capability, don't police it.* Whonix's
//! IP-hiding guarantee survives deleting both firewalls, because the
//! Workstation has no NIC wired to anything but the Gateway. The firewall is
//! convenience; the topology is the guarantee.
//!
//! ZeroPoint's shape is currently the inverse. `zp-host`'s crate doc
//! (`crates/zp-host/src/lib.rs:8-15`) is accurate within its scope — no
//! `Command::new` is reachable through its public API — but the boundary is a
//! crate API inside one address space. An audit on 2026-08-14 found **109
//! `Command::new` call sites across 27 files in 7 crates**, exactly one of
//! them in `zp-host`.
//!
//! # Why *variable* program names specifically
//!
//! Most of the 109 are fixed-literal capability probes — `ioreg`, `lsusb`,
//! `sysctl`, `which`, `lsof`, `kill`, `pgrep`, `git`. Those are a bounded,
//! auditable set: the program name is a constant visible in the source, and
//! no caller-controlled input selects it. Pinning them all would land this
//! test red on 109 sites and teach nothing.
//!
//! The governance-relevant subset is the sites where the program name is a
//! **variable** — where config, request payload, or tool manifest becomes a
//! program name with no gate evaluation and no chain entry between the two:
//!
//! | site | expression |
//! |---|---|
//! | `zp-server/src/lib.rs:6416` | `Command::new(&lc.command)` |
//! | `zp-server/src/auth.rs:1140` | `Command::new(&self.program)` |
//! | `zp-server/src/onboard/preflight.rs:1650` | `Command::new(program)` |
//! | `zp-server/src/onboard/configure.rs:86` | `Command::new(&zp_bin)` |
//! | `zp-cli/src/main.rs:2785` | `Command::new(&command[0])` |
//! | `zp-cli/src/run.rs:568` | `Command::new(&launch.command)` |
//! | `zp-cli/src/secure.rs:1233,1253,1560` | `Command::new(&zp_bin)`, `Command::new(cmd)` |
//!
//! This is the same distinction `no_sh_c_in_tool_launch` already draws, one
//! level up. That pin removed the shell, which removed string re-parsing. It
//! did not remove ambient spawn authority — `tool_launch.rs` still reaches
//! `Command::new` with a program name it was handed.
//!
//! # Ratchet, not cleanup
//!
//! This pin lands **green**. Every existing variable-program site is
//! allowlisted below with its migration phase named. The pin's job today is
//! to make the 110th site fail the build, not to fail on the 109.
//!
//! Migration is `docs/design/HOST-BROKER-2026-08.md` §10 Phase 3, which
//! widens this pin as sites move. Order matters there: `zp-regent` and
//! `zp-server/src/regent.rs:858` go first, on the principle that the apex
//! cognitive agent should be the most governed component, not the least.
//!
//! # Allowlist
//!
//! - `crates/zp-host/src/` — the canonical implementation site. This is the
//!   one place a variable program name is *supposed* to reach `Command::new`,
//!   and it does so only after `gate.evaluate` and a chain append.
//!
//! - `crates/zp-preflight/src/platform.rs` — `Command::new(cmd)` at :210 is a
//!   capability probe (does this binary exist and answer `--version`).
//!   Bind-and-drop shaped, same rationale as the `zp-preflight` allowance in
//!   `no_raw_tcp_bind_outside_zp_net`. Not a tool launch.
//!
//! - `crates/execution-engine/src/executor.rs` — `Command::new(cmd)` at :95 is
//!   the interpreter-discovery probe (`python3 --version` and friends). The
//!   *actual* interpreter spawn in this file already routes through
//!   `host.spawn_process` (`executor.rs:230-242`); only the probe is direct.
//!
//! - `crates/zp-discipline/tests/` — discipline pins quote forbidden forms in
//!   their `rationale` prose by nature; `no_sh_c_in_tool_launch.rs:60` carries
//!   `Command::new(shell).arg(-c)` inside a rationale string continuation,
//!   which no `//` skip can reach. Pin files scan; they do not spawn.
//!
//! - `crates/zp-cli/src/main.rs` — **deferred, Phase 3.** Contains both
//!   legitimate supervisor self-relaunch (`Command::new(&exe)` at :1718,
//!   :1968, :2039, :2086 — the CLI re-executing itself is the user's own
//!   hands, not agent-directed) and one genuine hole: `Command::new(&command[0])`
//!   at :2785 spawns an arbitrary program from a vector. `allow_path` is
//!   file-granular, so the hole rides in on the supervisor's allowance. Split
//!   the supervisor spawns into a helper module when this migrates so the
//!   allowlist can narrow to it.
//!
//! - `crates/zp-cli/src/run.rs`, `crates/zp-cli/src/secure.rs` — **deferred,
//!   Phase 3.** `run.rs:568` (`Command::new(&launch.command)`) is a tool
//!   launch and migrates with the `zp-server` launch paths. `secure.rs`
//!   re-executes `zp` under a hardened environment (:1233, :1253) and probes
//!   a variable command at :1560.
//!
//! - `crates/zp-server/src/lib.rs`, `auth.rs`, `onboard/` — **deferred,
//!   Phase 3.** These are the tool-launch paths and the reason the broker
//!   exists. They migrate to `zp_host::Client` wholesale.
//!
//! - `crates/trust-triangle/` — standalone reference demo, excluded from the
//!   workspace (`Cargo.toml:27`); migration not planned.
//!
//! Note what is *absent* from this allowlist and required no entry:
//! `zp-keys/src/sovereignty/` (18 sites) and `zp-regent/src/awareness.rs` are
//! entirely fixed-literal hardware and host probes — `ioreg`, `lsusb`,
//! `bioutil`, `system_profiler`, `fprintd-verify`, `sysctl`, `vm_stat`. They
//! pass this pin unmodified, which is the intended shape.

use zp_discipline::Discipline;

#[test]
fn variable_program_spawns_must_route_through_zp_host() {
    Discipline::new("no_raw_variable_spawn_outside_zp_host")
        .cite_invariant(
            "Principle 8 (one canonical path) — host effects cross the host boundary",
        )
        .rationale(
            "A spawn whose program name is a variable turns config, request \
             payload, or tool manifest into an executable with no gate \
             evaluation and no chain entry between the two. zp_host::\
             HostContext::spawn_process is the only path that evaluates the \
             gate and seals a receipt before the effect occurs. Fixed-literal \
             probes (ioreg, lsusb, which, kill) are a bounded auditable set \
             and are deliberately out of scope; see the module doc.",
        )
        // Reference form: `Command::new(&exe)`, `Command::new(&self.program)`,
        // `Command::new(&lc.command)`, `Command::new(&command[0])`.
        // Matches under any path prefix — bare, `std::process::`, `tokio::process::`.
        .forbid_pattern(r"Command::new\(\s*&")
        // Bare-identifier form: `Command::new(program)`, `Command::new(cmd)`,
        // `Command::new(docker_desktop)`. Deliberately does not match a string
        // literal, which begins with a quote rather than an identifier char.
        .forbid_pattern(r"Command::new\(\s*[a-z_][A-Za-z_0-9]*\s*\)")
        // ── Canonical site ────────────────────────────────────────────────
        .allow_path("crates/zp-host/src/")
        // ── Capability probes (not tool launches) ─────────────────────────
        .allow_path("crates/zp-preflight/src/platform.rs")
        .allow_path("crates/execution-engine/src/executor.rs")
        // ── Pin files quote forbidden forms in prose ──────────────────────
        .allow_path("crates/zp-discipline/tests/")
        // ── Deferred to HOST-BROKER Phase 3 ───────────────────────────────
        .allow_path("crates/zp-cli/src/main.rs")
        .allow_path("crates/zp-cli/src/run.rs")
        .allow_path("crates/zp-cli/src/secure.rs")
        .allow_path("crates/zp-server/src/lib.rs")
        .allow_path("crates/zp-server/src/auth.rs")
        .allow_path("crates/zp-server/src/onboard/")
        // ── Excluded from the workspace ───────────────────────────────────
        .allow_path("crates/trust-triangle/")
        // Doc comments across the tree quote the forbidden forms verbatim
        // (zp-host/src/lib.rs:9, context.rs:11, tool_launch.rs:3, this file).
        .skip_lines_containing("//")
        // Skip this pin's own declarations.
        .skip_lines_containing("forbid_pattern")
        .assert();
}
