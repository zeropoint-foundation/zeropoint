# ZeroPoint Deployment Guide

Two static sites + one Rust API server. Total cost: ~$5/month.

---

## Architecture

```
                    Cloudflare Pages (free)
                    ┌──────────────────────┐
  zeropoint.global ─┤  Static HTML/CSS/JS  │
                    │  + /api/* proxied ────┼──┐
                    └──────────────────────┘  │
                                              │
                    Cloudflare Pages (free)    │    Hetzner CX22 (~€4/mo)
                    ┌──────────────────────┐  │    ┌─────────────────────┐
thinkstreamlabs.ai ─┤  Static HTML/CSS/JS  │  └───▶│  zp-server :3000    │
                    └──────────────────────┘       │  Caddy reverse proxy│
                                                   └─────────────────────┘
```

---

## Option A: Cloudflare Pages + Hetzner VPS (Recommended)

### Step 1: Static sites on Cloudflare Pages

1. Push the repo to GitHub (if not already).

2. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) → Pages → Create a project.

3. **For zeropoint.global:**
   - Connect your GitHub repo
   - Build settings:
     - Build command: *(leave empty — no build step)*
     - Build output directory: `zeropoint.global`
   - Deploy
   - Add custom domain: `zeropoint.global`

4. **For thinkstreamlabs.ai:**
   - Create another Pages project
   - Build output directory: `thinkstreamlabs.ai`
   - Add custom domain: `thinkstreamlabs.ai`

5. DNS: Point both domains' nameservers to Cloudflare (they'll guide you through this).

That's it for the static sites. Deploys automatically on every push to main.

### Step 2: API server on Hetzner

1. **Create a Hetzner CX22** (2 vCPU, 4GB RAM, 40GB disk — ~€3.79/month):
   - OS: Ubuntu 22.04
   - Add your SSH key

2. **SSH in and install dependencies:**

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Caddy
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

3. **Clone and build:**

```bash
git clone https://github.com/zeropoint-foundation/zeropoint.git
cd zeropoint
cargo build --release -p zp-server
```

4. **Create a systemd service** at `/etc/systemd/system/zp-server.service`:

```ini
[Unit]
Description=ZeroPoint API Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/zeropoint
ExecStart=/opt/zeropoint/zp-server
Environment=RUST_LOG=info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

5. **Deploy the binary:**

```bash
sudo mkdir -p /opt/zeropoint
sudo cp target/release/zp-server /opt/zeropoint/
sudo chown -R www-data:www-data /opt/zeropoint
sudo systemctl enable zp-server
sudo systemctl start zp-server
```

6. **Configure Caddy** (only needed if serving API through the VPS directly):

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy
```

### Step 3: Connect playground to API

The playground and chain demo use `fetch()` with a configurable `BASE_URL`. By default they try `window.location.origin`. Two options:

**Option A — Cloudflare proxy rule:**
Add a Cloudflare Worker or Page Rule that proxies `/api/*` to your Hetzner VPS IP. This keeps everything on one domain.

**Option B — Dedicated API subdomain:**
Point `api.zeropoint.global` to your Hetzner VPS. Update the `BASE_URL` in playground.html and demo-chain.html to `https://api.zeropoint.global`. Uncomment the api subdomain block in the Caddyfile.

---

## Option B: VPS Only (Simpler, More Sovereign)

If you'd rather not use Cloudflare at all, serve everything from the VPS:

1. Set up the Hetzner CX22 as above.

2. Deploy static files:

```bash
sudo mkdir -p /var/www/zeropoint.global /var/www/thinkstreamlabs.ai
sudo cp -r zeropoint.global/* /var/www/zeropoint.global/
sudo cp -r thinkstreamlabs.ai/* /var/www/thinkstreamlabs.ai/
```

3. Use the full Caddyfile (it serves both static sites + proxies the API).

4. Point both domain A records to the VPS IP. Caddy handles HTTPS automatically via Let's Encrypt.

---

## Option C: Docker (for either host)

```bash
docker build -t zp-server .
docker run -d --name zp-server -p 3000:3000 --restart unless-stopped zp-server
```

---

## Updating

```bash
cd zeropoint && git pull

# Rebuild server
cargo build --release -p zp-server
sudo cp target/release/zp-server /opt/zeropoint/
sudo systemctl restart zp-server

# Update static sites (if VPS-hosted)
sudo cp -r zeropoint.global/* /var/www/zeropoint.global/
sudo cp -r thinkstreamlabs.ai/* /var/www/thinkstreamlabs.ai/
```

If using Cloudflare Pages, static sites update automatically on push.

---

## Verification

```bash
# Server health
curl https://zeropoint.global/api/v1/health

# Server identity
curl https://zeropoint.global/api/v1/identity

# Test governance evaluation
curl -X POST https://zeropoint.global/api/v1/guard/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action": "deploy surveillance toolkit", "trust_tier": "Tier1"}'
# Should return: decision "Block", rule "HarmPrincipleRule"
```
