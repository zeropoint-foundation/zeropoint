# Infrastructure

## Hetzner Server — zp-playground
- **IP:** 89.167.86.60
- **SSH:** `ssh -i ~/.ssh/hetzner_zp root@89.167.86.60`
- **SSH Key name (Hetzner):** ken-zeropoint
- **SSH Key fingerprint:** 09:c7:29:c6:53:46:44:0f:d7:ec:07:5d:87:c7:d5:56
- **Local private key:** ~/.ssh/hetzner_zp
- **Spec:** CX23 — 2 VCPU, 4 GB RAM, 40 GB disk
- **Location:** Helsinki (hel1-dc2)
- **Price:** $3.49/mo
- **IPv6:** 2a01:4f9:c013:fdef::/64
- **Console:** https://console.hetzner.com/projects/13634360/servers/122384600/overview

## Domain — zeropoint.global
- **Registrar/CDN:** Cloudflare
- **Dashboard:** https://dash.cloudflare.com/
- **Hosting:** Cloudflare Workers (static site)

## GitHub
- **Repo:** zeropoint-foundation/zeropoint
- **URL:** https://github.com/zeropoint-foundation/zeropoint
- **Note:** zeropoint.global/ directory is gitignored — use `git add -f`
