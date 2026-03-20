# ZeroPoint Sentinel v0.3: From One Router to Every Router

Three weeks ago I wrote about deploying ZeroPoint's governance model to my home router — an ASUS RT-AX58U running Merlin firmware in my barn. A 32-bit ARM processor, 256MB of RAM, Python on a USB stick. The point was to prove that cryptographic governance works on real, constrained hardware.

Today I'm releasing what grew out of that experiment.

## What changed

The Sentinel is no longer a single-router tool. It's a multi-platform package that installs on any router running dnsmasq, any Linux box with systemd, any Raspberry Pi, or any Docker host. One installer, auto-detection, four platform profiles.

```
curl -fsSL https://zeropoint.global/sentinel/install.sh | sh
```

That's it. The installer detects whether you're on ASUS Merlin, OpenWrt, standard Linux, or Docker, loads the right platform profile, and sets everything up — Python dependencies, init system, config paths, service wrapper. If auto-detection doesn't work, you tell it:

```
curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform openwrt
```

There's also an interactive configurator at [zeropoint.global/sentinel](https://zeropoint.global/sentinel) that generates the right install command for your setup.

## The real news: mesh participation

The Sentinel is now a first-class peer in the ZeroPoint trust mesh.

When you set `core_url` in the config, the Sentinel generates an Ed25519 keypair on first boot, computes a 128-bit destination hash (the same addressing scheme as the Rust `zp-mesh` crate), and sends an `AgentAnnounce` envelope to Core. It declares its capabilities — DNS filtering, device monitoring, anomaly detection, MAC blocking, alert notification — and maintains a heartbeat every 30 seconds.

Core receives the announce, adds the Sentinel to its peer table, and broadcasts the topology update over WebSocket. The Bridge dashboard renders it in real time. Your router shows up as a node in the trust mesh, with its health status, trust tier, and capabilities.

This matters because the Sentinel isn't just a monitoring tool anymore. It's infrastructure that *participates* in the trust fabric. It has a cryptographic identity. It announces what it can do. It can be wired into governance flows. It's the same protocol whether the peer is a router, a Raspberry Pi, a Mac Mini, or an agent framework.

One protocol. One graph. End to end.

## What the Sentinel does

For those who missed the first post, here's the quick version:

The Sentinel monitors your network through a governance pipeline. Every DNS query, every device connection, every anomaly flows through Guard → Policy → Audit. Decisions are recorded in a Blake3 hash-chained SQLite ledger — tamper-evident by construction. Alerts push to your phone via Ntfy, Slack, or any webhook. Critical alerts repeat until you acknowledge them.

It blocks ads and trackers at the DNS level using Steven Black blocklists. It tracks every device on your network via DHCP. It detects DNS spikes, port scans, DGA-like domains, and device floods. And now it reports all of this to the mesh.

## Supported platforms

The v0.3 release supports four platforms out of the box:

**ASUS Merlin** — The original. Any ASUS router running Asuswrt-Merlin with Entware and a USB drive. RT-AX58U, RT-AX86U, GT-AX11000, and anything else Merlin supports.

**OpenWrt** — Any OpenWrt 21.02+ device. GL.iNet routers, Turris Omnia, or anything running OpenWrt with opkg. Uses procd for service management.

**Linux (systemd)** — Ubuntu, Debian, Fedora, Raspberry Pi OS, anything with systemd and Python 3.11+. Includes a hardened systemd unit with NoNewPrivileges and filesystem protection.

**Docker** — Run anywhere. Multi-arch Dockerfile for x86_64, ARM64, and ARM32. Mount your dnsmasq log for DNS monitoring, or run as a standalone mesh peer.

## What's next

The Sentinel proves the model: governance at the network edge, with cryptographic mesh participation, on hardware you already own. The same pattern applies to every other component that joins the mesh — agent frameworks, monitoring collectors, vault services, ledger nodes. They all speak the same protocol, show up in the same topology, and participate in the same trust fabric.

If you have a router, a Pi, or a spare Linux box, try it. If you're building agent systems and want governance that doesn't depend on a platform, look at the mesh protocol. If the idea of portable trust infrastructure resonates, the entire thing is open source.

[GitHub: zeropoint-foundation/zeropoint](https://github.com/zeropoint-foundation/zeropoint)

[Sentinel Install Configurator](https://zeropoint.global/sentinel)

---

*Ken Romero is the founder of ThinkStream Labs and creator of ZeroPoint. He writes about cryptographic governance, autonomous systems, and building trust infrastructure for the Agentic Age.*
