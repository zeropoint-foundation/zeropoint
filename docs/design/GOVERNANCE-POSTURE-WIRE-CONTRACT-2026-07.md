# Governance Posture Wire Contract

**Date:** 2026-07-03
**Status:** Design sketch
**Scope:** ZP substrate → tenant gateway → tenant frontend

## Problem

A governed tenant tile can show a status shield when running in a TEE, but historically has no
surface for ZeroPoint governance posture. The operator can only learn that
the tenant is governed/hardened/registered via `zp doctor` on the CLI. The
information the tile already knows — "I'm governed by ZP, all officers attested
me, no warnings" — is invisible in the surface the operator actually looks at.

ZP's `GET /api/v1/tools` handler hardcodes `governance: "genesis-bound"` for
every tool instead of returning the real computed posture. No endpoint exposes
per-tool facets or attestation data.

## Design

Three layers, each with a clean contract boundary:

```
ZP substrate                   tenant backend              tenant frontend
─────────────                  ──────────────              ───────────────
GET /api/v1/tools/:name/posture                           
  (ZP-Sig auth)          →     ZpClient::fetch_posture()
                                  → cache in AppState     →  governance shield
                                  → /api/gateway/status        (topbar badge
                                     includes posture          + hover popover)
```

### Layer 1: ZP Substrate Endpoint

**Endpoint:** `GET /api/v1/tools/:name/posture`
**Auth:** `ZP-Sig` envelope (same as gate calls — the tool is asking about itself)
**Scope:** Read-only. A governed tool querying its own standing.

**Response:**

```json
{
  "tool": "{tool_name}",
  "facets": ["registered", "governed", "hardened"],
  "attestations": [
    { "officer": "steward", "attested_at": "2026-07-03T14:22:01Z" },
    { "officer": "sentinel", "attested_at": "2026-07-03T14:22:01Z" },
    { "officer": "forge", "attested_at": "2026-07-03T14:22:01Z" },
    { "officer": "cleo", "attested_at": "2026-07-03T14:22:01Z" },
    { "officer": "aegis", "attested_at": "2026-07-03T14:22:01Z" }
  ],
  "warnings": [],
  "computed_at": "2026-07-03T14:25:33Z"
}
```

**Fields:**

| Field | Type | Semantics |
|-------|------|-----------|
| `tool` | string | Tool name as known to the substrate |
| `facets` | string[] | Currently-true governance facets (union model — any subset possible; e.g., "Registered + Governed but not Provisioned" means delegation exists but vault entries are missing). Full facet vocabulary per `TOOL-GOVERNANCE-LIFECYCLE-2026-07.md` §4: `unregistered`, `registered`, `provisioned`, `governed`, `hardened`, `delegated_autonomous`. |
| `attestations` | object[] | Officers that attested (name + timestamp of most recent attestation). All five officers report. |
| `warnings` | string[] | Active officer warnings for this tool (empty = clean) |
| `computed_at` | ISO 8601 | When the posture was computed |

Note: earlier drafts of this contract included a `level: u8` field encoding facets as an ordinal 1-5. That model is superseded by the union-of-facets model per the July 2026 corpus audit resolution of Decision H. Facets are independent flags, not rank-ordered levels — "Registered + Governed but not Provisioned" is a valid state the union model surfaces honestly and the ordinal collapse would hide.

**Implementation in `zp-server/src/lib.rs`:**

```rust
async fn tool_posture_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Json<serde_json::Value> {
    // Build snapshot from port registry (same as tools_list_handler).
    let bindings = state.0.port_registry.list();
    let mut snapshot = ToolRegistrySnapshot::default();
    for b in &bindings { /* ... same pattern ... */ }

    // Compute posture from chain evidence.
    let store = state.0.audit_store.lock().unwrap();
    let chain = ChainReader::new(&store);
    let postures = compute_postures(&chain, &snapshot, &UnregisteredTools::new());

    let posture = postures.iter().find(|p| p.tool_name == name);

    // Fetch attestation timestamps from chain.
    let attestations = build_attestation_list(&chain, &name);

    // ... serialize and return
}
```

The function reuses `compute_postures()` (already proven by `zp doctor`) and
adds a targeted chain search for attestation timestamps — the same
`search_by_keyword("attested:", ...)` the posture scanner already does, but
extracting `entry.timestamp` alongside the officer name.

**Route registration:**

```rust
.route("/api/v1/tools/:name/posture", get(tool_posture_handler))
```

No new auth needed — the existing auth middleware accepts both session tokens and
`ZP-Sig` envelopes on all routes.

### Layer 2: Tenant Backend

**`ZpClient` addition:**

```rust
pub async fn fetch_governance_posture(&self) -> Result<GovernancePosture, ZpError> {
    let path = format!("/api/v1/tools/{}/posture", self.tool_name);
    self.signed_get(&path).await
}
```

Uses the same Genesis-signed envelope auth that gate calls already use. The
`tool_name` comes from `TENANT_ZP_TOOL_NAME` (in the tenant's ZpConfig, defaults to
the tool's registered name).

**Caching:** The posture is slow-changing (facets shift on lifecycle events, not
per-request). Cache for 60 seconds in `AppState`. The gateway status poller
already runs on a 30s interval — the posture fetch can piggyback on this cycle
with a 60s TTL so it only hits ZP every other poll.

**Gateway status enrichment:**

The existing `GET /api/gateway/status` response gains a `zp_governance` field:

```json
{
  "version": "0.4.2",
  "commit_hash": "abc123",
  "engine_v2_enabled": true,
  "sse_connections": 2,
  "ws_connections": 1,
  "uptime_secs": 3600,
  "zp_governance": {
    "facets": ["registered", "governed", "hardened"],
    "attestations": [
      { "officer": "steward", "attested_at": "2026-07-03T14:22:01Z" },
      { "officer": "sentinel", "attested_at": "2026-07-03T14:22:01Z" },
      { "officer": "forge", "attested_at": "2026-07-03T14:22:01Z" },
      { "officer": "cleo", "attested_at": "2026-07-03T14:22:01Z" },
      { "officer": "aegis", "attested_at": "2026-07-03T14:22:01Z" }
    ],
    "warnings": []
  }
}
```

When ZP integration is disabled (`TENANT_ZP_ENABLED=false`), `zp_governance`
is `null`. The frontend treats null as "no governance surface to show."

### Layer 3: Tenant Frontend

**Component:** Governance shield, following the TEE shield pattern.

**Placement:** Topbar, to the left of the TEE shield (governance is
substrate-level; TEE is infrastructure-level — substrate first).

**Visual states:**

The frontend renders the strongest facet in the union as the badge text — this is a presentation choice for glance-level clarity, not a wire-level ordering claim. The full facet set (including partial states like "Registered + Governed but not Provisioned") appears in the hover popover.

| Strongest facet in set | Badge | Color |
|-----------------------|-------|-------|
| `hardened` present | `ZP Hardened` | green (var(--success)) |
| `governed` present (no `hardened`) | `ZP Governed` | blue (var(--accent-brand)) |
| `registered` present (no `governed`, no `hardened`) | `ZP Registered` | amber (var(--warning)) |
| No data / disabled | hidden | — |

When facets like `provisioned` or `delegated_autonomous` are also present, they appear in the popover; the badge text stays keyed to the fleet-lifecycle strongest facet for glance-level clarity.

**Hover popover (follows TEE popover pattern):**

```
┌─────────────────────────────┐
│ ⛨ ZeroPoint Governance     │
├─────────────────────────────┤
│ Facets                      │
│   ● registered              │
│   ● governed                │
│   ● hardened                │
├─────────────────────────────┤
│ Officer Attestations  4/4   │
│   steward   Jul 3, 14:22   │
│   sentinel  Jul 3, 14:22   │
│   forge     Jul 3, 14:22   │
│   cleo      Jul 3, 14:22   │
├─────────────────────────────┤
│ Warnings: none              │
└─────────────────────────────┘
```

Facet dots are green when present, gray when absent (showing the full vocabulary
teaches the operator what's possible). Attestation rows use relative timestamps
("2m ago", "1h ago") for at-a-glance freshness.

**Implementation in `gateway-tee.js` (or new `gateway-zp.js`):**

```javascript
// In fetchGatewayStatus callback, after existing popover rendering:
var zpGov = data.zp_governance;
if (zpGov) {
  renderGovernanceShield(zpGov);
} else {
  document.getElementById('zp-shield').style.display = 'none';
}
```

The shield element follows the same HTML structure as `#tee-shield`:

```html
<div class="zp-shield" id="zp-shield" style="display:none">
  <svg><!-- shield icon --></svg>
  <span id="zp-shield-label">ZP Hardened</span>
  <div class="zp-popover" id="zp-popover"></div>
</div>
```

CSS reuses the `.tee-shield` pattern with `--accent-zp-bg` / `--accent-zp-border`
variables for theming.

## Degradation

| Condition | Behavior |
|-----------|----------|
| ZP unreachable | Cache serves stale posture; badge stays. After 5min stale, badge dims (opacity 0.5) with tooltip "Last checked 5m ago" |
| ZP integration disabled | Shield hidden. No fetch attempted. |
| Posture drops (hardened → governed) | Badge color/text updates on next poll. No animation — absence is the signal. |
| New attestation lands | Badge updates on next poll (≤60s). |

## Non-goals

- **The popover is not a control surface.** It's read-only. Actions ("revoke
  delegation", "force re-attestation") belong in the ZP cockpit, not the tool's
  tile. The "pair conversational with reference" heuristic applies — the tile is
  reference-only for governance; control lives in ZP's own surfaces.

- **No per-request posture checks.** The badge reflects cached posture, not
  real-time gate status. The gate is already in the request path (via ZpHook);
  the badge is for operator awareness, not operational enforcement.

## Implementation Order

1. **ZP**: `tool_posture_handler` + route registration + `build_attestation_list` helper
2. **ZP**: Enrich `tools_list_handler` to use real posture (replace hardcoded `governance: "genesis-bound"`)
3. **Tenant backend**: `ZpClient::fetch_governance_posture()` + cache + gateway status enrichment
4. **Tenant frontend**: Shield HTML + CSS + JS rendering

Steps 1–2 are ZP-only. Steps 3–4 are tenant-only. No cross-project dependency
within either pair. Step 3 depends on step 1 being deployed.
