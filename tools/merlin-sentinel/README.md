# ZeroPoint Network Sentinel

**Governance-based network monitoring for ASUS Merlin routers.**

The Sentinel turns your home router into a governed network appliance — every DNS query, device connection, and anomaly is evaluated through ZeroPoint's cryptographic governance pipeline and recorded in a hash-chained audit trail.

This is the first **onramp** for ZeroPoint adoption: a working tool that solves a real problem (network visibility and control) while introducing governed decision-making and tamper-evident audit trails.

## What It Does

- **DNS Governance** — Monitors DNS queries against configurable blocklists (Steven Black, AdAway, etc.). Every query flows through the governance gate.
- **Device Access Control** — Tracks devices via DHCP leases. Block suspicious MAC addresses with a single command.
- **Anomaly Detection** — Identifies DNS spikes, rapid device connections, port scans, and DGA-like domain queries.
- **Hash-Chained Audit Trail** — Every decision is recorded in SQLite with SHA-256 hash linking. Each entry contains the hash of the previous entry. Verify integrity anytime with `zp-sentinel verify`.
- **Push Notifications** — Alerts via syslog, file, and webhook (Ntfy/Pushover/Slack). Observable by default — silent mode is an explicit opt-in, not the other way around.
- **ZeroPoint Governance Pipeline** — Guard → Policy Engine → Audit Store → Notifier. Maps directly to ZeroPoint's Rust primitives.

## Requirements

- ASUS router running [Asuswrt-Merlin](https://www.asuswrt-merlin.net/) or [GNUton's fork](https://github.com/gnuton/asuswrt-merlin.ng)
- [Entware](https://github.com/Entware/Entware/wiki) installed on a USB drive
- SSH access to the router

## Install

SSH into your router and run:

```sh
curl -fsSL https://raw.githubusercontent.com/zeropoint-foundation/zeropoint/main/tools/merlin-sentinel/install.sh | sh
```

Or clone and install locally:

```sh
git clone https://github.com/zeropoint-foundation/zeropoint.git
cd zeropoint/tools/merlin-sentinel
sh install.sh
```

## Configure

Edit `/opt/etc/zp-sentinel.toml`:

```toml
[dns]
log_path = "/var/log/dnsmasq.log"
blocklist_urls = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

[device]
mac_blocklist = [
    "aa:bb:cc:dd:ee:ff",  # Suspicious IoT device
]

[notifications]
min_level = "medium"       # low, medium, high, critical
syslog = true              # Router system log
file = true                # alerts.log
webhook_url = ""           # "https://ntfy.sh" for push notifications
webhook_topic = "my-sentinel"
silent = false             # true = log-only mode
```

### Push Notifications

1. Install [Ntfy](https://ntfy.sh) on your phone (free, no account needed)
2. Subscribe to a unique topic
3. Set `webhook_url = "https://ntfy.sh"` and your `webhook_topic` in the config
4. Restart — high-severity events push to your phone

## Commands

```
zp-sentinel status            Sentinel health and stats
zp-sentinel monitor           Start monitoring (foreground)
zp-sentinel alerts            Recent alert notifications
zp-sentinel audit             Audit trail entries
zp-sentinel audit -a DNS      Filter by actor
zp-sentinel verify            Verify hash chain integrity
zp-sentinel devices           Known devices
zp-sentinel block <MAC>       Block a MAC address
zp-sentinel unblock <MAC>     Unblock a MAC address
zp-sentinel ack <pattern>     Acknowledge critical alerts
```

Service management:

```
/opt/etc/init.d/S99zp-sentinel start|stop|restart|status
```

## Architecture

```
DNS Query / Device Event / Anomaly
              │
              ▼
     ┌─────────────┐
     │    Guard     │  Blocklist + rate limiting
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │   Policy     │  Rule evaluation + trust classification
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │   Audit      │  SHA-256 hash-chained SQLite
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │  Notifier    │  Syslog → File → Webhook (Ntfy)
     └─────────────┘
```

Every component maps to ZeroPoint's Rust governance primitives. The Sentinel is a Python reference implementation that proves the model works on real, constrained infrastructure.

## Notification Tiers

| Risk Level | Examples | Channels |
|------------|----------|----------|
| Low | Known ad domain blocked | Syslog + File |
| Medium | New unknown device joins | Syslog + File |
| High | DGA pattern, DNS spike, port scan | Syslog + File + Webhook |
| Critical | Multiple anomalies, persistent threat | All + Repeat every 5 min |

Critical alerts repeat until acknowledged: `zp-sentinel ack <pattern>`

## File Layout

```
/opt/etc/zp-sentinel.toml              Configuration
/opt/etc/zp-sentinel/zp_sentinel/      Python modules
/opt/bin/zp-sentinel                   CLI wrapper
/opt/etc/init.d/S99zp-sentinel         Init script
/opt/var/zp-sentinel/audit.db          Hash-chained audit database
/opt/var/zp-sentinel/alerts.log        Alert log
/opt/var/log/zp-sentinel.log           Service log
/opt/var/cache/zp-sentinel/            Blocklist cache
```

## Why ZeroPoint?

Most network monitoring tools log events. The Sentinel *governs* them — every decision flows through a policy pipeline, every action is hash-chained for tamper evidence, and every notification is itself an auditable event.

You install it for the network visibility. ZeroPoint's trust infrastructure comes with it.

## Links

- [ZeroPoint](https://zeropoint.global) — Portable trust infrastructure for the Agentic Age
- [Asuswrt-Merlin](https://www.asuswrt-merlin.net/) — Enhanced firmware for ASUS routers
- [Entware](https://github.com/Entware/Entware/wiki) — Software packages for embedded Linux
- [Ntfy](https://ntfy.sh) — Simple push notifications

## License

ZeroPoint Foundation · [zeropoint.global](https://zeropoint.global)
