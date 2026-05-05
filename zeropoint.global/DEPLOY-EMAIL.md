# ZeroPoint Email — Deployment Guide

## Prerequisites

- Cloudflare account with zeropoint.global zone
- Node.js 18+ and `wrangler` CLI authenticated
- Resend account (free tier: 100 emails/day, 3k/month)

## Step 1: Create D1 Database

```bash
wrangler d1 create zpmail
```

Copy the `database_id` from the output into `wrangler.toml`.

## Step 2: Create R2 Bucket

```bash
wrangler r2 bucket create zp-storage
```

## Step 3: Run Database Migration

```bash
# Local first (for testing)
npm run db:migrate:local

# Then remote
npm run db:migrate:remote
```

## Step 4: Configure Outbound Email

### Option A: Resend (recommended for low volume)

1. Sign up at https://resend.com
2. Add and verify `zeropoint.global` domain in Resend dashboard
3. Resend provides the DNS records — add them in Cloudflare:
   - SPF (TXT record)
   - DKIM (TXT records — usually 3)
   - DMARC (TXT record)
4. Set the API key:

```bash
wrangler secret put RESEND_API_KEY
```

### Option B: Amazon SES

1. Verify `zeropoint.global` in SES console
2. Add DKIM records from SES to Cloudflare DNS
3. Request production access (SES starts in sandbox mode)
4. Set credentials:

```bash
wrangler secret put AWS_ACCESS_KEY_ID
wrangler secret put AWS_SECRET_ACCESS_KEY
```

5. Update `wrangler.toml`:

```toml
[vars]
EMAIL_PROVIDER = "ses"
```

## Step 5: Configure Inbound Email

1. In Cloudflare dashboard → Email Routing → Enable
2. Add MX records (Cloudflare provides these automatically):
   ```
   zeropoint.global  MX  10  route1.mx.cloudflare.net
   zeropoint.global  MX  20  route2.mx.cloudflare.net
   zeropoint.global  MX  30  route3.mx.cloudflare.net
   ```
3. Under Routes → Catch-all → Send to Worker → select `zeropoint-global`

## Step 6: DNS Records Summary

After setup, your DNS should include:

```
; MX — inbound to Cloudflare Email Routing
zeropoint.global    MX    10  route1.mx.cloudflare.net
zeropoint.global    MX    20  route2.mx.cloudflare.net
zeropoint.global    MX    30  route3.mx.cloudflare.net

; SPF — authorize relay to send for your domain
zeropoint.global    TXT   "v=spf1 include:resend.com ~all"

; DKIM — provided by Resend/SES during domain verification
; (multiple CNAME or TXT records)

; DMARC — policy with reporting
_dmarc.zeropoint.global  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@zeropoint.global"
```

Note: Start DMARC with `p=quarantine` during testing. Move to `p=reject` once
deliverability is confirmed.

## Step 7: Deploy

```bash
wrangler deploy
```

## Step 8: Verify

```bash
# Health check
curl https://zeropoint.global/api/health

# Send a test email (from APOLLO or any machine)
curl -X POST https://zeropoint.global/api/mail/ken/send \
  -H "Content-Type: application/json" \
  -d '{"to":["ken@thinkstreamlabs.ai"],"subject":"Test from ZP","text":"Mail is flowing."}'

# Check inbox
curl https://zeropoint.global/api/mail/ken
```

## Security Notes

- The `/api/mail/*` endpoints are currently unauthenticated — add auth before
  exposing beyond the pixel-streaming client.
- Secrets are stored in Cloudflare's encrypted secret store, not in code.
- DMARC reports go to dmarc@zeropoint.global, processed by the email worker.
