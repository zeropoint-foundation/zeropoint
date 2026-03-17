# ZeroPoint Network Sentinel - Quick Start Guide

## 30-Second Setup

```bash
cd /opt/etc/zp-sentinel
chmod +x install.sh
./install.sh
```

## First Run

```bash
# Check status
/opt/bin/zp-sentinel status

# Review configuration
cat /opt/etc/zp-sentinel.toml

# Start the service
/opt/etc/init.d/S99zp-sentinel start

# Watch logs
tail -f /opt/var/log/zp-sentinel.log

# View recent decisions
/opt/bin/zp-sentinel audit
```

## Essential Commands

```bash
# Service control
/opt/etc/init.d/S99zp-sentinel {start|stop|restart|status}

# Monitor status
/opt/bin/zp-sentinel status

# View audit trail
/opt/bin/zp-sentinel audit -n 50
/opt/bin/zp-sentinel audit --actor DNS

# Device management
/opt/bin/zp-sentinel devices
/opt/bin/zp-sentinel block 38:a5:c9:20:4a:a5
/opt/bin/zp-sentinel unblock 38:a5:c9:20:4a:a5

# Verify integrity
/opt/bin/zp-sentinel verify
```

## Configuration Quick Reference

### DNS Blocking
Edit `/opt/etc/zp-sentinel.toml`:
```toml
[dns]
blocklist_urls = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
```

### MAC Address Blocking
```toml
[device]
mac_blocklist = [
    "38:a5:c9:20:4a:a5",  # Tuya
]
```

### Log Level
```toml
[service]
log_level = "DEBUG"  # or INFO, WARNING, ERROR
```

## Enable DNS Logging

Add to dnsmasq config:
```bash
echo "log-queries=extra" >> /jffs/configs/dnsmasq.conf.add
service restart_dnsmasq
```

## Monitor Logs

```bash
# Sentinel logs
tail -f /opt/var/log/zp-sentinel.log

# DNS queries (if logging enabled)
tail -f /var/log/dnsmasq.log | grep query
```

## Troubleshooting

```bash
# Test imports
/opt/bin/python3 -c "import zp_sentinel; print('OK')"

# Check syntax
/opt/bin/python3 -m py_compile /opt/etc/zp-sentinel/zp_sentinel/*.py

# Verbose logging
/opt/bin/zp-sentinel monitor --verbose

# Check config
/opt/bin/zp-sentinel status
```

## Architecture Overview

```
dnsmasq/DHCP → Monitor → PolicyContext → Gate → Decision → Audit
                ↓                                           ↓
              Parse                                    Blake3 Hash Chain
```

## Key Concepts

- **PolicyDecision**: Allow, Block, Warn, Review, Sanitize
- **Guard**: Blocklist + Rate Limiting (first stage)
- **PolicyEngine**: Rule-based evaluation (second stage)
- **AuditStore**: Hash-chained trail (third stage)
- **TrustTier**: Trusted, Untrusted, Unknown, Suspicious, Blocked

## Persistent Storage

For audit trail to survive reboot:
```bash
# Mount USB
mkdir -p /mnt/usb/zp-sentinel

# Update config
sed -i 's|/opt/var/zp-sentinel|/mnt/usb/zp-sentinel|g' /opt/etc/zp-sentinel.toml

# Restart
/opt/etc/init.d/S99zp-sentinel restart
```

## Performance Tuning

```toml
[service]
# Increase monitoring interval for lower CPU
monitor_interval = 10  # default: 5

[dns]
# Reduce blocklist size
blocklist_urls = ["https://adaway.org/hosts.txt"]

[anomaly]
# Adjust detection thresholds
rate_limit_qps = 200  # higher = less sensitive
```

## Debugging

```bash
# Run monitoring loop in foreground
/opt/bin/python3 -m zp_sentinel.main monitor --verbose

# Check database
sqlite3 /opt/var/zp-sentinel/audit.db "SELECT COUNT(*) FROM audit_log;"

# Verify chain
/opt/bin/zp-sentinel verify
```

## Integration Example

Block unwanted traffic from IoT devices:
```bash
# Identify device MAC
/opt/bin/zp-sentinel devices

# Block it
/opt/bin/zp-sentinel block aa:bb:cc:dd:ee:ff

# Verify
/opt/bin/zp-sentinel devices
/opt/bin/zp-sentinel audit --actor DEVICE
```

## File Locations

| Path | Purpose |
|------|---------|
| `/opt/etc/zp-sentinel/` | Python modules |
| `/opt/etc/zp-sentinel.toml` | Configuration |
| `/opt/var/zp-sentinel/` | Audit database |
| `/opt/var/log/zp-sentinel.log` | Service logs |
| `/opt/var/cache/zp-sentinel/` | Blocklist cache |
| `/opt/bin/zp-sentinel` | CLI wrapper |
| `/opt/etc/init.d/S99zp-sentinel` | Init script |

## Next Steps

1. Edit config for your network
2. Enable DNS logging in dnsmasq
3. Start the service
4. Monitor audit trail
5. Add custom blocking rules
6. Set up USB for persistence
