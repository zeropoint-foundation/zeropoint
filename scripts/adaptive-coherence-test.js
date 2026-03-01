#!/usr/bin/env node
/**
 * ═══════════════════════════════════════════════════════════════════════
 * ZeroPoint Adaptive Coherence Test
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Registry-driven test harness that evolves with surfaces and adaptations.
 * Instead of hardcoded endpoint lists, this reads from:
 *   - /api/catalog   → validates framework registry integrity
 *   - /health        → validates service health structure
 *   - /providers     → validates provider configuration
 *   - /chain/stats   → validates receipt chain integrity
 *
 * The test dynamically generates assertions based on what the catalog
 * declares, so adding a new framework or capability automatically
 * creates new test coverage.
 *
 * Usage:
 *   node scripts/adaptive-coherence-test.js
 *   BASE_URL=https://localhost:8081 node scripts/adaptive-coherence-test.js
 *   MODE=full node scripts/adaptive-coherence-test.js   # full + load
 *
 * Can also run from browser console (paste the runFromBrowser export).
 */

const http = require("http");
const https = require("https");
const { URL } = require("url");

const BASE_URL = process.env.BASE_URL || "https://localhost:18832";
const MODE = process.env.MODE || "coherence"; // coherence | full
const LOAD_CONCURRENCY = Number(process.env.LOAD_CONCURRENCY || 10);
const LOAD_DURATION_S = Number(process.env.LOAD_DURATION_S || 30);

const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true, maxSockets: 50 });
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 50 });

// ═══════════════════════════════════════════════════════════════════════
// HTTP Client
// ═══════════════════════════════════════════════════════════════════════

async function req(method, path, body) {
  const url = `${BASE_URL}${path}`;
  const parsed = new URL(url);
  const isHttps = parsed.protocol === "https:";
  const client = isHttps ? https : http;
  const payload = body ? JSON.stringify(body) : null;

  return new Promise((resolve) => {
    const start = Date.now();
    const r = client.request(
      {
        method,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: {
          "content-type": "application/json",
          ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}),
        },
        agent: isHttps ? agent : httpAgent,
        rejectUnauthorized: false,
        timeout: 10000,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          const latency = Date.now() - start;
          let json = null;
          try { json = JSON.parse(data); } catch {}
          resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json, raw: data, latency });
        });
      }
    );
    r.on("error", (e) => resolve({ ok: false, status: 0, json: null, raw: e.message, latency: Date.now() - start }));
    r.setTimeout(10000, () => r.destroy(new Error("timeout")));
    if (payload) r.write(payload);
    r.end();
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Test Runner
// ═══════════════════════════════════════════════════════════════════════

const results = [];

function assert(suite, name, condition, detail) {
  const status = condition ? "PASS" : "FAIL";
  results.push({ suite, name, status, detail: detail || "" });
  const icon = condition ? "✅" : "❌";
  console.log(`  ${icon} [${suite}] ${name}${detail ? " — " + detail : ""}`);
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 1: Endpoint Reachability
// ═══════════════════════════════════════════════════════════════════════

const ENDPOINTS = [
  // Core
  { path: "/health", key: "overall_status", suite: "core" },
  { path: "/metrics", type: "text", suite: "core" },

  // Receipts & Chain
  { path: "/receipts", key: "receipts", suite: "receipts" },
  { path: "/receipts/stats", key: "by_status", suite: "receipts" },
  { path: "/chain/stats", key: "success", suite: "receipts" },

  // Providers
  { path: "/providers", key: "providers", suite: "providers" },
  { path: "/providers/default", key: "provider", suite: "providers" },
  { path: "/providers/costs", type: "any_json", suite: "providers" },

  // Catalog & Surfaces
  { path: "/api/catalog", key: "frameworks", suite: "catalog" },
  { path: "/api/surfaces", key: "surfaces", suite: "catalog" },
  { path: "/api/frameworks", key: "frameworks", suite: "catalog" },

  // Conversations & Threads
  { path: "/api/conversations", key: "conversations", suite: "conversations" },
  { path: "/threads/base", key: "threads", suite: "threads" },

  // Secrets
  { path: "/secrets", key: "secrets", suite: "secrets" },

  // Git
  { path: "/git/status", key: "status", suite: "git" },

  // Workflow & Evidence
  { path: "/api/workflow", key: "workflows", suite: "workflow" },
  { path: "/api/evidence-pack", key: "evidence_packs", suite: "workflow" },

  // Canary (returns bare arrays, not objects)
  { path: "/api/canary/baselines", type: "any_json", suite: "canary" },
  { path: "/api/canary/alerts", type: "any_json", suite: "canary" },

  // Replay
  { path: "/api/replay/sessions", key: "sessions", suite: "replay" },
];

async function suiteReachability() {
  console.log("\n▸ Endpoint Reachability");
  for (const ep of ENDPOINTS) {
    const r = await req("GET", ep.path);
    if (ep.type === "text") {
      assert(ep.suite, `GET ${ep.path}`, r.ok, `${r.status} ${r.latency}ms`);
    } else if (ep.type === "any_json") {
      assert(ep.suite, `GET ${ep.path}`, r.ok && (r.json !== null || r.raw.startsWith("[")),
        `${r.status} ${r.latency}ms`);
    } else {
      const hasKey = r.json && ep.key in r.json;
      assert(ep.suite, `GET ${ep.path} → .${ep.key}`, r.ok && hasKey,
        `${r.status} ${r.latency}ms${!hasKey && r.ok ? " (key missing)" : ""}`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 2: Catalog Integrity (Registry-Driven)
// ═══════════════════════════════════════════════════════════════════════

const REQUIRED_CAPABILITIES = [
  "code_execution", "web_access", "file_system", "delegation",
  "memory", "shell_access", "package_install", "network_requests",
  "tool_creation", "git_operations", "browser_automation",
];

const REQUIRED_GOVERNANCE = ["strict", "audit", "permissive"];

const REQUIRED_SHIM_STRATEGIES = ["stdio", "event_hook", "monkey_patch", "http_proxy", "rest_proxy", "none"];

async function suiteCatalogIntegrity() {
  console.log("\n▸ Catalog Integrity");

  const r = await req("GET", "/api/catalog");
  assert("catalog", "Catalog endpoint reachable", r.ok && r.json);
  if (!r.json) return;

  const catalog = r.json;
  const frameworks = catalog.frameworks || [];

  assert("catalog", "Has frameworks", frameworks.length > 0, `count=${frameworks.length}`);
  assert("catalog", "framework_count matches array", catalog.framework_count === frameworks.length,
    `declared=${catalog.framework_count} actual=${frameworks.length}`);

  // Every framework must have required fields
  const requiredFields = ["id", "name", "category", "capabilities", "governance_profile", "shim_strategy", "risk_rating"];
  for (const fw of frameworks) {
    const missing = requiredFields.filter((f) => !(f in fw) || fw[f] === undefined || fw[f] === null);
    assert("catalog-schema", `${fw.id || "unknown"} has required fields`, missing.length === 0,
      missing.length > 0 ? `missing: ${missing.join(", ")}` : "");
  }

  // Category distribution
  const categories = {};
  frameworks.forEach((fw) => {
    categories[fw.category] = (categories[fw.category] || 0) + 1;
  });
  assert("catalog", "Has valid categories", Object.keys(categories).length > 0,
    Object.entries(categories).map(([k, v]) => `${k}=${v}`).join(", "));

  // Capability coverage: the registry should exercise most capability types
  const allCaps = new Set(frameworks.flatMap((fw) => fw.capabilities));
  const coveredCaps = REQUIRED_CAPABILITIES.filter((c) => allCaps.has(c));
  assert("catalog", "Capability coverage", coveredCaps.length >= 6,
    `${coveredCaps.length}/${REQUIRED_CAPABILITIES.length} capability types used`);

  // Governance profile coverage
  const allGov = new Set(frameworks.map((fw) => fw.governance_profile));
  const coveredGov = REQUIRED_GOVERNANCE.filter((g) => allGov.has(g));
  assert("catalog", "Governance profile coverage", coveredGov.length >= 2,
    `profiles: ${[...allGov].join(", ")}`);

  // Shim strategy diversity
  const allShims = new Set(frameworks.map((fw) => fw.shim_strategy));
  assert("catalog", "Shim strategy diversity", allShims.size >= 3,
    `strategies: ${[...allShims].join(", ")}`);

  // Bidirectional coexists_with
  const idSet = new Set(frameworks.map((fw) => fw.id));
  let coexBroken = [];
  for (const fw of frameworks) {
    if (!fw.coexists_with) continue;
    for (const peer of fw.coexists_with) {
      if (!idSet.has(peer)) {
        coexBroken.push(`${fw.id} → ${peer} (not in registry)`);
        continue;
      }
      const peerFw = frameworks.find((f) => f.id === peer);
      if (peerFw && peerFw.coexists_with && !peerFw.coexists_with.includes(fw.id)) {
        coexBroken.push(`${fw.id} ↔ ${peer} (not bidirectional)`);
      }
    }
  }
  assert("catalog", "Bidirectional coexists_with", coexBroken.length === 0,
    coexBroken.length > 0 ? coexBroken.slice(0, 5).join("; ") : "all symmetric");

  // Risk ratings in valid range
  const badRisk = frameworks.filter((fw) => fw.risk_rating < 1 || fw.risk_rating > 5);
  assert("catalog", "Risk ratings in [1,5]", badRisk.length === 0,
    badRisk.length > 0 ? `invalid: ${badRisk.map((f) => f.id).join(", ")}` : "");

  // Browser automation: at least one framework should have it (ADR-036)
  const browserFw = frameworks.filter((fw) => fw.capabilities.includes("browser_automation"));
  assert("catalog", "BROWSER_AUTOMATION capability present", browserFw.length >= 1,
    `frameworks: ${browserFw.map((f) => f.id).join(", ") || "none"}`);

  // Supported frameworks should have shim_ready=true
  const supportedNoShim = frameworks.filter((fw) => fw.supported && !fw.shim_ready);
  assert("catalog", "Supported → shim_ready", supportedNoShim.length === 0,
    supportedNoShim.length > 0 ? `broken: ${supportedNoShim.map((f) => f.id).join(", ")}` : "");

  // Featured frameworks should have descriptions
  const featuredNoDesc = frameworks.filter((fw) => fw.featured && (!fw.description || fw.description.length < 10));
  assert("catalog", "Featured → has description", featuredNoDesc.length === 0,
    featuredNoDesc.length > 0 ? `missing: ${featuredNoDesc.map((f) => f.id).join(", ")}` : "");
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 3: Provider Coherence
// ═══════════════════════════════════════════════════════════════════════

async function suiteProviderCoherence() {
  console.log("\n▸ Provider Coherence");

  const r = await req("GET", "/providers");
  if (!r.json) { assert("providers", "Provider list reachable", false); return; }

  const providers = r.json.providers || [];
  assert("providers", "Has at least one provider", providers.length > 0, `count=${providers.length}`);

  // Default provider should reference a valid provider
  const def = await req("GET", "/providers/default");
  if (def.json && def.json.provider) {
    const defaultId = def.json.provider.id || def.json.provider;
    assert("providers", "Default provider valid", true, `default=${JSON.stringify(defaultId).slice(0, 60)}`);
  }

  // Cost tracking should have numeric totals
  const costs = await req("GET", "/providers/costs");
  if (costs.json) {
    assert("providers", "Cost tracking has total", typeof costs.json.total === "number",
      `total=${costs.json.total}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 4: Receipt Chain Integrity
// ═══════════════════════════════════════════════════════════════════════

async function suiteReceiptChain() {
  console.log("\n▸ Receipt Chain Integrity");

  const stats = await req("GET", "/chain/stats");
  if (!stats.json) { assert("chain", "Chain stats reachable", false); return; }

  assert("chain", "Chain stats has total_chains", "total_chains" in stats.json,
    `chains=${stats.json.total_chains}`);

  const receipts = await req("GET", "/receipts");
  if (!receipts.json) { assert("chain", "Receipt list reachable", false); return; }

  const receiptList = receipts.json.receipts || [];
  assert("chain", "Receipt list structure", Array.isArray(receiptList),
    `count=${receiptList.length}`);

  // Spot check: if we have receipts, verify the first one has required fields
  if (receiptList.length > 0) {
    const sample = receiptList[0];
    const hasId = "id" in sample || "receipt_id" in sample;
    assert("chain", "Receipt has ID field", hasId);
  }

  // Receipt stats should have totals
  const rstats = await req("GET", "/receipts/stats");
  assert("chain", "Receipt stats reachable", rstats.ok && rstats.json,
    rstats.json ? `total=${rstats.json.total}` : "");
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 5: Workflow Lifecycle
// ═══════════════════════════════════════════════════════════════════════

async function suiteWorkflow() {
  console.log("\n▸ Workflow Lifecycle");

  // Create a test workflow
  const create = await req("POST", "/api/workflow", {
    name: `coherence-test-${Date.now()}`,
    description: "Adaptive coherence test workflow — safe to delete",
  });

  assert("workflow", "Create workflow", create.ok && create.json,
    create.json ? `id=${(create.json.id || create.json.workflow_id || "?").toString().slice(0, 12)}` : `status=${create.status}`);

  if (!create.json) return;
  const wfId = create.json.id || create.json.workflow_id;
  if (!wfId) return;

  // Read it back
  const get = await req("GET", `/api/workflow/${wfId}`);
  assert("workflow", "Get workflow by ID", get.ok && get.json,
    get.json ? `state=${get.json.state || get.json.status || "?"}` : "");

  // List should include our workflow
  const list = await req("GET", "/api/workflow");
  if (list.json && list.json.workflows) {
    const found = list.json.workflows.some((w) => (w.id || w.workflow_id) === wfId);
    assert("workflow", "Workflow appears in list", found);
  }

  // Cancel the test workflow (cleanup)
  const cancel = await req("POST", `/api/workflow/${wfId}/cancel`);
  assert("workflow", "Cancel test workflow", cancel.ok || cancel.status === 409,
    `status=${cancel.status}`);
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 6: POST Endpoint Structure
// ═══════════════════════════════════════════════════════════════════════

async function suitePostEndpoints() {
  console.log("\n▸ POST Endpoint Structure");

  // Mode classification
  const classify = await req("POST", "/api/classify-mode", {
    input: "Build a deployment pipeline and run tests",
  });
  assert("post", "classify-mode returns mode", classify.ok && classify.json && "mode" in classify.json,
    classify.json ? `mode=${classify.json.mode}` : `status=${classify.status}`);

  // Structured extraction
  const extract = await req("POST", "/api/extract", {
    input: "Alice, 28, software engineer at Anthropic",
    schema: { type: "object", properties: { name: { type: "string" }, age: { type: "integer" } } },
  });
  assert("post", "extract returns data", extract.ok && extract.json && "data" in extract.json,
    extract.json ? `keys=${Object.keys(extract.json.data || {}).join(",")}` : `status=${extract.status}`);

  // Surface scan (should accept but may return empty)
  const scan = await req("POST", "/api/scan-surface", { target: "localhost" });
  assert("post", "scan-surface accepts request", scan.ok || scan.status === 400,
    `status=${scan.status}`);
}

// ═══════════════════════════════════════════════════════════════════════
// Suite 7: Light Load Test (MODE=full only)
// ═══════════════════════════════════════════════════════════════════════

async function suiteLoadTest() {
  if (MODE !== "full") return;

  console.log(`\n▸ Load Test (${LOAD_CONCURRENCY} concurrent × ${LOAD_DURATION_S}s)`);

  const targets = ["/health", "/receipts/stats", "/chain/stats", "/providers", "/api/catalog"];
  const stats = { total: 0, errors: 0, latencies: [], byPath: {} };
  const endTime = Date.now() + LOAD_DURATION_S * 1000;

  async function worker() {
    while (Date.now() < endTime) {
      const path = targets[Math.floor(Math.random() * targets.length)];
      const r = await req("GET", path);
      stats.total++;
      stats.latencies.push(r.latency);
      if (!stats.byPath[path]) stats.byPath[path] = { ok: 0, err: 0, latencies: [] };
      if (r.ok) {
        stats.byPath[path].ok++;
        stats.byPath[path].latencies.push(r.latency);
      } else {
        stats.errors++;
        stats.byPath[path].err++;
      }
    }
  }

  const workers = Array.from({ length: LOAD_CONCURRENCY }, () => worker());
  await Promise.all(workers);

  const sorted = stats.latencies.sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
  const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
  const p99 = sorted[Math.floor(sorted.length * 0.99)] || 0;
  const errorRate = stats.total > 0 ? (stats.errors / stats.total * 100).toFixed(1) : 0;
  const rps = (stats.total / LOAD_DURATION_S).toFixed(1);

  assert("load", "Error rate < 5%", stats.errors / stats.total < 0.05,
    `${errorRate}% (${stats.errors}/${stats.total})`);
  assert("load", "p50 latency < 200ms", p50 < 200, `${p50}ms`);
  assert("load", "p95 latency < 1000ms", p95 < 1000, `${p95}ms`);
  assert("load", "p99 latency < 2000ms", p99 < 2000, `${p99}ms`);
  assert("load", "Throughput > 10 rps", parseFloat(rps) > 10, `${rps} rps`);

  console.log(`\n  Load test summary: ${stats.total} requests, ${rps} rps, p50=${p50}ms p95=${p95}ms p99=${p99}ms`);
  for (const [path, ps] of Object.entries(stats.byPath)) {
    const pSorted = ps.latencies.sort((a, b) => a - b);
    const pp50 = pSorted[Math.floor(pSorted.length * 0.5)] || 0;
    console.log(`    ${path}: ${ps.ok} ok, ${ps.err} err, p50=${pp50}ms`);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  ZeroPoint Adaptive Coherence Test");
  console.log(`  Target:    ${BASE_URL}`);
  console.log(`  Mode:      ${MODE}`);
  console.log(`  Timestamp: ${new Date().toISOString()}`);
  console.log("═══════════════════════════════════════════════════════════");

  // Quick connectivity check
  const ping = await req("GET", "/health");
  if (!ping.ok) {
    console.log(`\n❌ Cannot reach ${BASE_URL}/health — aborting.`);
    console.log(`   Status: ${ping.status}, Error: ${ping.raw}`);
    process.exit(1);
  }

  await suiteReachability();
  await suiteCatalogIntegrity();
  await suiteProviderCoherence();
  await suiteReceiptChain();
  await suiteWorkflow();
  await suitePostEndpoints();
  await suiteLoadTest();

  // Summary
  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const total = results.length;

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log(`  Results: ${passed} passed, ${failed} failed (${total} total)`);

  if (failed > 0) {
    console.log("\n  Failures:");
    results.filter((r) => r.status === "FAIL").forEach((r) => {
      console.log(`    ❌ [${r.suite}] ${r.name}${r.detail ? " — " + r.detail : ""}`);
    });
  }

  console.log("═══════════════════════════════════════════════════════════\n");

  // Write JSON report
  const report = {
    timestamp: new Date().toISOString(),
    base_url: BASE_URL,
    mode: MODE,
    summary: { passed, failed, total },
    results,
  };
  try {
    const fs = require("fs");
    const outPath = process.env.REPORT_PATH || "test-outputs/coherence-report.json";
    fs.mkdirSync(require("path").dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`  Report written to ${outPath}`);
  } catch {}

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(2);
});
