# Sentinel v1 MVP — what the Sentinel observes, and where it has to stand

**Document type:** Tier 2 elaboration. Scopes the Sentinel role to what the
hardware and the placement can actually deliver.
**Status:** proposed 2026-08-12 · no code written
**Filename note:** dated `-2026-07` because `HARDWARE-ROLE-SEPARATION-2026-07`
and `TWO-NODE-GENESIS-COORDINATION-2026-07` have forward-referenced it under
that name since 2026-07-27. Authored 2026-08-12; the date in the name is the
reference it satisfies, not the day it was written.
**Elaborates:** `HARDWARE-ROLE-SEPARATION-2026-07.md` (the Sentinel role).

---

## 0. Why this document exists

Two Tier 2 documents have cited this file since 2026-07-27 and it was never
written. In the meantime `HARDWARE-ROLE-SEPARATION-2026-07` acquired a
description of the Sentinel that the implementation does not match and the
hardware cannot support. This document supplies the missing scope and corrects
the claim.

The correction matters more than the omission. The substrate's position is that
a negative claim requires observation — *nothing unauthorized left this machine*
is only sayable if something watched. A Sentinel described as seeing all traffic,
and actually reading DNS logs, produces exactly the false assurance the substrate
exists to refuse.

## 1. What the Sentinel is today, measured

`tools/sentinel/zp_sentinel/` — 3,250 lines of Python, four platform profiles
(`merlin`, `linux-systemd`, `openwrt`, `docker`).

| Module | Source it reads | What it can say |
|---|---|---|
| `dns_monitor.py` | dnsmasq query log | which names were resolved, which were blocked against a hosts-style blocklist |
| `device_monitor.py` | DHCP lease file | which devices joined, which MACs were refused |
| `anomaly.py` | the two streams above | DNS-rate spike, device-join spike, port-scan attempts, domain entropy (DGA-shaped names), external recursion |
| `mesh.py` | — | mesh peer identity, `AgentAnnounce`, heartbeats |
| `gate.py`, `audit.py`, `notifier.py` | — | policy evaluation, hash-chained local ledger, alerting |

**There is no packet capture.** No `pcap`, `scapy`, `AF_PACKET`, `nfqueue`, or
raw sockets anywhere in the tree. **There is no flow accounting.** No
`conntrack`, `netflow`, `nftables` or `iptables` either. The Sentinel is a
log-and-table observer, and everything it currently attests is downstream of
name resolution and device admission.

That is a reasonable thing to be. It is not what the corpus said it was.

## 2. The finding that reframes the question: coverage follows placement

The instinct is to ask whether a Pi 5 is fast enough. It is the wrong first
question, and answering it alone would have produced a confidently wrong design.

A Pi 5 8GB has one gigabit NIC and a quad Cortex-A76 at 2.4GHz with roughly
17GB/s of memory bandwidth. Gigabit Ethernet at small frames is on the order of
1.5 million packets per second; userspace capture on that CPU is not in that
range, and with a single NIC the board cannot sit inline without a second
adapter or a trunk-on-a-stick VLAN. So mirror-mode packet inspection is out on
capacity grounds.

But the binding constraint is placement, not throughput. **The Sentinel can only
observe traffic that passes through the host it runs on.** The `linux-systemd`
profile states its own ceiling plainly: *"dnsmasq (optional — Sentinel runs
without it, just no DNS monitoring)."* A Pi sitting *adjacent* to the router,
which is the reference topology in `HARDWARE-ROLE-SEPARATION`, is the
configuration in which the Sentinel observes **nothing at all** — dnsmasq and the
kernel flow table both live on the router, and the Pi degrades to a mesh peer
with no observation surface.

The Merlin profile, which runs inside router firmware, is the one with real
coverage today, because that is where the traffic is.

### The three honest topologies

| Topology | Observes | Can attest |
|---|---|---|
| **A — Sentinel on the router** (`merlin`, `openwrt`) | all LAN DNS and all routed flows | egress for every device, including the Regent |
| **B — Pi is the LAN's DNS server and gateway** (`linux-systemd`) | all LAN DNS and all routed flows | same as A, with the Pi as the sovereign-controlled chokepoint |
| **C — Pi adjacent, router unchanged** | its own traffic only | nothing about the Regent — and must say so |

Topology C is the current reference framing and the weakest. Either the Pi is
placed in the path, or the Sentinel runs where the path already is. **A Sentinel
that is not in the path must not emit egress findings**, because absence of a
finding would read as absence of egress.

## 3. v1 scope — flow accounting from conntrack

The kernel already maintains the flow table. Reading it is metadata only —
5-tuple, direction, byte and packet counters — with no payload inspection, no
TLS interception, and negligible CPU. This is the honest form of the
"destination monitoring" the corpus already promised.

**Consume the event stream, not the table.** Polling `/proc/net/nf_conntrack`
samples: any flow that opens and closes between two polls is never seen, and a
short exfiltration is exactly that shape. `conntrack -E` (libnetfilter_conntrack)
delivers `NEW` / `UPDATE` / `DESTROY`, and `DESTROY` carries the final counters —
so every flow is accounted exactly once, at teardown. On a home LAN that is tens
to hundreds of events per second; a Pi 5 is not troubled by it, and a scan burst
into the thousands still is not.

**`nf_conntrack_acct` must be verified, not assumed.** Byte and packet counters
are off by default on most kernels (`net.netfilter.nf_conntrack_acct=0`). With
accounting disabled the event stream still arrives and the counters read zero —
which looks like a quiet network rather than a disabled feature. v1 checks the
sysctl at startup, refuses to claim volume accounting when it is off, and says
which of the two it is doing. This is a boot invariant, not a config note.

### v1 deliverables

1. `flow_monitor.py` — a conntrack event consumer, structurally parallel to
   `dns_monitor.py`, evaluating each destination against the chain-anchored
   allowlist through the existing `GovernanceGate`.
2. A startup placement declaration — which topology (A, B or C) the Sentinel is
   in, derived from what it can actually reach rather than from config, and
   anchored so every later finding is scoped by it.
3. `nf_conntrack_acct` verification, with volume claims suppressed when off.
4. Anomaly checks over flows, in the shape `anomaly.py` already uses: new
   destination, volume against baseline, beaconing periodicity.

### Explicit non-goals

Deep packet inspection, TLS interception, and inline blocking are all out.
The first two are beyond the hardware and against the thesis; the third needs a
second NIC. Enforcement stays what it already is — DNS sinkholing, which is
built, and router cooperation, which `HARDWARE-ROLE-SEPARATION` already names.

## 4. Receipts

v1 adds to the existing `sentinel:` family rather than opening a namespace.
Registering them in the code registry is part of v1, not a follow-up: the corpus
already documents 752 receipt types across 104 namespaces with no implemented
family, and this document must not add to that count.

- `sentinel:placement:declared` — topology A, B or C, with what was reachable
- `sentinel:flow:observed` — destination, counters, allowlist verdict
- `sentinel:flow:unauthorized` — a destination outside the allowlist
- `sentinel:accounting:degraded` — `nf_conntrack_acct` off; volume unclaimed

## 5. What the Sentinel must never claim

It may not report *no unauthorized egress* while in topology C, or while
accounting is disabled, or for any protocol path that does not traverse it. The
correct output in each case is a scoped statement of what was watched. Silence
about coverage is the failure this document exists to prevent.

## 6. Open

- **SV-A** — Should topology C be supported at all, or refused at startup?
  Refusing is cleaner and would remove a whole class of false assurance; it also
  makes the Pi useless in the deployment the corpus currently recommends.
- **SV-B** — `tools/merlin-sentinel/` duplicates all nine modules of
  `tools/sentinel/zp_sentinel/` byte-for-byte. Only the lenses HTML references
  it; all four design documents reference `tools/sentinel/`. It looks like the
  pre-consolidation copy, left behind when `merlin` became a platform profile.
  Removal is proposed, not assumed.
- **SV-C** — IPv6. conntrack covers it; the allowlist format has not been
  checked for it.
