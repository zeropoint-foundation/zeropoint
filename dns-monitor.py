#!/usr/bin/env python3
"""
ZeroPoint DNS Shield — Real-time Traffic Monitor
Run on APOLLO-3: python3 dns-monitor.py
Dashboard: http://192.168.1.170:8080
"""

import http.server
import json
import re
import os
import time
from collections import Counter, defaultdict
from datetime import datetime

LOG_PATH = "/opt/homebrew/var/log/dnsmasq.log"
PORT = 8080

# === Domain Classification ===
CATEGORIES = {
    "blocked": {
        "color": "#ef4444",
        "label": "Blocked",
        "patterns": []  # detected by 0.0.0.0 response
    },
    "chinese_iot": {
        "color": "#f97316",
        "label": "Chinese IoT",
        "patterns": [
            r"tuya", r"tuyacn", r"tuyaus", r"alink", r"ai-link",
            r"smartlife", r"voluas", r"gizwits", r"espressif",
            r"iot\.mi\.com", r"xiaomi", r"bspapp"
        ]
    },
    "tracker": {
        "color": "#f59e0b",
        "label": "Tracker/Analytics",
        "patterns": [
            r"doubleclick", r"googlesyndication", r"googleadservices",
            r"facebook.*pixel", r"fbcdn.*tr", r"analytics",
            r"telemetry", r"tracking", r"metrics\.", r"sentry\.io",
            r"segment\.io", r"hotjar", r"fullstory", r"mixpanel",
            r"amplitude", r"appsflyer", r"adjust\.com", r"branch\.io",
            r"crashlytics", r"flurry", r"scorecardresearch",
            r"quantserve", r"taboola", r"outbrain"
        ]
    },
    "ads": {
        "color": "#d97706",
        "label": "Advertising",
        "patterns": [
            r"ads\.", r"ad\.", r"adserver", r"adservice",
            r"pagead", r"adsystem", r"adnxs", r"moatads",
            r"rubiconproject", r"openx\.net", r"pubmatic",
            r"criteo", r"serving-sys", r"2mdn\.net"
        ]
    },
    "streaming": {
        "color": "#3b82f6",
        "label": "Streaming",
        "patterns": [
            r"googlevideo", r"youtube", r"netflix", r"nflx",
            r"roku", r"hulu", r"disneyplus", r"disney",
            r"spotify", r"scdn\.co", r"akamai", r"cloudfront",
            r"twitch", r"plex", r"amazonvideo"
        ]
    },
    "apple": {
        "color": "#a78bfa",
        "label": "Apple",
        "patterns": [
            r"apple\.com", r"icloud", r"mzstatic", r"apple-dns",
            r"push\.apple", r"courier\.push", r"itunes",
            r"apple\.news", r"swcdn\.apple"
        ]
    },
    "infrastructure": {
        "color": "#6b7280",
        "label": "Infrastructure",
        "patterns": [
            r"ntp\.", r"time\.", r"ocsp\.", r"crl\.",
            r"captive\.apple", r"connectivitycheck",
            r"msftconnecttest", r"arpa$", r"in-addr\.arpa",
            r"_dns\.", r"local$", r"localdomain",
            r"gateway\.fe80", r"resolver"
        ]
    },
    "legitimate": {
        "color": "#22c55e",
        "label": "Legitimate",
        "patterns": [
            r"google\.com", r"googleapis", r"gstatic",
            r"github", r"cloudflare", r"brave\.com",
            r"mozilla", r"firefox", r"microsoft\.com",
            r"live\.com", r"office\.com", r"amazon\.com",
            r"aws\.amazon", r"anthropic", r"openai",
            r"zeropoint", r"thinkstreamlabs",
            r"substack", r"twitter", r"reddit"
        ]
    }
}

DEVICE_NAMES = {
    "192.168.1.170": "APOLLO-3 (Mac Mini)",
    "192.168.1.100": "kenrom-iPhone",
    "192.168.1.108": "iPad",
    "192.168.1.80": "iPad-2",
    "192.168.1.252": "Dalyns-iPad",
    "192.168.1.250": "HP Printer",
    "192.168.1.198": "Westinghouse TV",
    "192.168.1.239": "Roku Express",
    "192.168.1.137": "RokoMoko",
    "192.168.1.236": "Nintendo",
    "192.168.1.84": "TECNO Spark Go",
    "192.168.1.130": "Tuya Smart",
    "192.168.1.135": "AI-Link #1",
    "192.168.1.234": "AI-Link #2",
    "192.168.1.134": "Mac (mesh)",
    "192.168.1.254": "BGW210 Router",
}


def classify_domain(domain):
    """Classify a domain into a category."""
    domain_lower = domain.lower()
    for cat_id, cat in CATEGORIES.items():
        if cat_id == "blocked":
            continue
        for pattern in cat["patterns"]:
            if re.search(pattern, domain_lower):
                return cat_id
    return "unknown"


def parse_log(max_lines=2000):
    """Parse dnsmasq log and return structured entries."""
    entries = []
    blocked_domains = set()

    if not os.path.exists(LOG_PATH):
        return entries, {}

    with open(LOG_PATH, "r") as f:
        lines = f.readlines()

    # Take last N lines
    lines = lines[-max_lines:]

    # First pass: find blocked domains (replied with 0.0.0.0)
    for line in lines:
        m = re.match(r".+/opt/homebrew/etc/dnsmasq\.d/blocklist\.txt\s+(\S+)\s+is\s+0\.0\.0\.0", line)
        if m:
            blocked_domains.add(m.group(1).lower())

    # Second pass: parse queries
    for line in lines:
        # Match query lines: "query[A] domain from IP"
        m = re.match(
            r"(\w+\s+\d+\s+[\d:]+)\s+dnsmasq\[\d+\]:\s+query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)",
            line
        )
        if m:
            timestamp_str, qtype, domain, client_ip = m.groups()
            domain_lower = domain.lower()

            if domain_lower in blocked_domains:
                category = "blocked"
            else:
                category = classify_domain(domain)

            cat_info = CATEGORIES.get(category, {"color": "#94a3b8", "label": "Unknown"})
            device = DEVICE_NAMES.get(client_ip, client_ip)

            entries.append({
                "time": timestamp_str,
                "type": qtype,
                "domain": domain,
                "client": client_ip,
                "device": device,
                "category": category,
                "color": cat_info["color"],
                "label": cat_info["label"],
            })

    # Build stats
    stats = {
        "total_queries": len(entries),
        "blocked": sum(1 for e in entries if e["category"] == "blocked"),
        "unique_domains": len(set(e["domain"] for e in entries)),
        "unique_clients": len(set(e["client"] for e in entries)),
        "by_category": {},
        "top_domains": [],
        "top_clients": [],
        "top_blocked": [],
    }

    cat_counts = Counter(e["category"] for e in entries)
    for cat_id, count in cat_counts.most_common():
        cat_info = CATEGORIES.get(cat_id, {"color": "#94a3b8", "label": "Unknown"})
        stats["by_category"][cat_id] = {
            "count": count,
            "color": cat_info["color"],
            "label": cat_info["label"],
        }

    domain_counts = Counter(e["domain"] for e in entries)
    stats["top_domains"] = [
        {"domain": d, "count": c} for d, c in domain_counts.most_common(15)
    ]

    client_counts = Counter(e["device"] for e in entries)
    stats["top_clients"] = [
        {"device": d, "count": c} for d, c in client_counts.most_common(10)
    ]

    blocked_counts = Counter(
        e["domain"] for e in entries if e["category"] == "blocked"
    )
    stats["top_blocked"] = [
        {"domain": d, "count": c} for d, c in blocked_counts.most_common(10)
    ]

    return entries, stats


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroPoint DNS Shield</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1"></script>
    <style>
        :root {
            --bg: #0a0a0c;
            --bg-card: #111114;
            --bg-header: #0d0d10;
            --accent: #7eb8da;
            --text: #e4e4e7;
            --text-dim: #71717a;
            --border: #27272a;
            --red: #ef4444;
            --orange: #f97316;
            --amber: #f59e0b;
            --yellow: #d97706;
            --green: #22c55e;
            --blue: #3b82f6;
            --purple: #a78bfa;
            --gray: #6b7280;
            --slate: #94a3b8;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 16px; }

        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: var(--bg-header);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 16px;
        }
        .header h1 {
            font-size: 18px;
            font-weight: 600;
            color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
        }
        .header .status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: var(--text-dim);
        }
        .header .status .dot {
            width: 8px; height: 8px;
            border-radius: 50%;
            background: var(--green);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        /* KPI Row */
        .kpi-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }
        .kpi-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
        }
        .kpi-label {
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: 'JetBrains Mono', monospace;
        }
        .kpi-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
        }
        .kpi-sub {
            font-size: 12px;
            color: var(--text-dim);
            margin-top: 2px;
        }
        .kpi-value.accent { color: var(--accent); }
        .kpi-value.red { color: var(--red); }
        .kpi-value.green { color: var(--green); }

        /* Charts Row */
        .charts-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 16px;
        }
        .chart-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
        }
        .chart-card h3 {
            font-size: 12px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
            font-family: 'JetBrains Mono', monospace;
        }
        .chart-card canvas { max-height: 220px; }

        /* Live Feed */
        .feed-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 16px;
        }
        .feed-card h3 {
            font-size: 12px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
            font-family: 'JetBrains Mono', monospace;
            display: flex;
            justify-content: space-between;
        }
        .feed-filters {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
        }
        .feed-filters button {
            padding: 4px 12px;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: transparent;
            color: var(--text-dim);
            font-size: 11px;
            cursor: pointer;
            font-family: 'JetBrains Mono', monospace;
        }
        .feed-filters button.active {
            border-color: var(--accent);
            color: var(--accent);
            background: rgba(126, 184, 218, 0.1);
        }
        .feed-filters button:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .feed {
            max-height: 400px;
            overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }
        .feed::-webkit-scrollbar { width: 6px; }
        .feed::-webkit-scrollbar-track { background: var(--bg); }
        .feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        .feed-entry {
            display: grid;
            grid-template-columns: 70px 1fr 150px 80px;
            gap: 12px;
            padding: 6px 0;
            border-bottom: 1px solid rgba(39, 39, 42, 0.5);
            align-items: center;
        }
        .feed-entry:hover { background: rgba(126, 184, 218, 0.03); }
        .feed-time { color: var(--text-dim); }
        .feed-domain { color: var(--text); word-break: break-all; }
        .feed-device { color: var(--text-dim); font-size: 11px; text-align: right; }
        .feed-tag {
            display: inline-block;
            padding: 1px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            text-align: center;
        }

        /* Footer */
        .footer {
            text-align: center;
            font-size: 11px;
            color: var(--text-dim);
            padding: 12px;
            font-family: 'JetBrains Mono', monospace;
        }

        @media (max-width: 900px) {
            .kpi-row { grid-template-columns: repeat(2, 1fr); }
            .charts-row { grid-template-columns: 1fr; }
            .feed-entry { grid-template-columns: 60px 1fr 80px; }
            .feed-device { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ ZeroPoint DNS Shield</h1>
            <div class="status">
                <div class="dot"></div>
                <span>APOLLO-3 · 192.168.1.170 · Refreshing every 3s</span>
            </div>
        </div>

        <div class="kpi-row">
            <div class="kpi-card">
                <div class="kpi-label">Total Queries</div>
                <div class="kpi-value accent" id="kpi-total">—</div>
                <div class="kpi-sub" id="kpi-total-sub"></div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Blocked</div>
                <div class="kpi-value red" id="kpi-blocked">—</div>
                <div class="kpi-sub" id="kpi-blocked-sub"></div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Unique Domains</div>
                <div class="kpi-value" id="kpi-domains">—</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Active Devices</div>
                <div class="kpi-value green" id="kpi-clients">—</div>
            </div>
        </div>

        <div class="charts-row">
            <div class="chart-card">
                <h3>Traffic by Category</h3>
                <canvas id="category-chart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Top Talkers (Devices)</h3>
                <canvas id="clients-chart"></canvas>
            </div>
        </div>

        <div class="feed-card">
            <h3>
                <span>Live Query Feed</span>
                <span id="feed-count"></span>
            </h3>
            <div class="feed-filters">
                <button class="active" onclick="setFilter('all')">All</button>
                <button onclick="setFilter('blocked')" style="color:var(--red)">Blocked</button>
                <button onclick="setFilter('chinese_iot')" style="color:var(--orange)">IoT</button>
                <button onclick="setFilter('tracker')" style="color:var(--amber)">Trackers</button>
                <button onclick="setFilter('ads')" style="color:var(--yellow)">Ads</button>
                <button onclick="setFilter('streaming')" style="color:var(--blue)">Streaming</button>
                <button onclick="setFilter('legitimate')" style="color:var(--green)">Legit</button>
                <button onclick="setFilter('unknown')" style="color:var(--slate)">Unknown</button>
            </div>
            <div class="feed" id="feed"></div>
        </div>

        <div class="footer">
            ZeroPoint DNS Shield · APOLLO-3 · dnsmasq → Cloudflare 1.1.1.1 (DoH) · Last refresh: <span id="last-refresh">—</span>
        </div>
    </div>

    <script>
        let categoryChart = null;
        let clientsChart = null;
        let currentFilter = 'all';
        let allEntries = [];

        const CHART_DEFAULTS = {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { display: false },
            }
        };

        function setFilter(filter) {
            currentFilter = filter;
            document.querySelectorAll('.feed-filters button').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            renderFeed();
        }

        function renderFeed() {
            const feed = document.getElementById('feed');
            const filtered = currentFilter === 'all'
                ? allEntries
                : allEntries.filter(e => e.category === currentFilter);

            const recent = filtered.slice(-150).reverse();
            document.getElementById('feed-count').textContent = `${filtered.length} queries`;

            feed.innerHTML = recent.map(e => {
                const time = e.time.split(' ').pop();  // just HH:MM:SS
                const bgColor = e.color + '20';
                return `<div class="feed-entry">
                    <span class="feed-time">${time}</span>
                    <span class="feed-domain" style="color:${e.color}">${e.domain}</span>
                    <span class="feed-device">${e.device}</span>
                    <span class="feed-tag" style="background:${bgColor};color:${e.color}">${e.label}</span>
                </div>`;
            }).join('');
        }

        function updateKPIs(stats) {
            document.getElementById('kpi-total').textContent = stats.total_queries.toLocaleString();
            document.getElementById('kpi-blocked').textContent = stats.blocked.toLocaleString();
            document.getElementById('kpi-domains').textContent = stats.unique_domains.toLocaleString();
            document.getElementById('kpi-clients').textContent = stats.unique_clients;

            const blockPct = stats.total_queries > 0
                ? ((stats.blocked / stats.total_queries) * 100).toFixed(1)
                : '0.0';
            document.getElementById('kpi-blocked-sub').textContent = `${blockPct}% of all queries`;
        }

        function updateCategoryChart(stats) {
            const cats = Object.entries(stats.by_category)
                .sort((a, b) => b[1].count - a[1].count);

            const labels = cats.map(c => c[1].label);
            const data = cats.map(c => c[1].count);
            const colors = cats.map(c => c[1].color + 'CC');

            if (!categoryChart) {
                const ctx = document.getElementById('category-chart').getContext('2d');
                categoryChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: data,
                            backgroundColor: colors,
                            borderColor: '#111114',
                            borderWidth: 2,
                        }]
                    },
                    options: {
                        ...CHART_DEFAULTS,
                        cutout: '55%',
                        plugins: {
                            legend: {
                                display: true,
                                position: 'right',
                                labels: {
                                    color: '#71717a',
                                    font: { size: 11, family: 'JetBrains Mono, monospace' },
                                    usePointStyle: true,
                                    padding: 8,
                                }
                            }
                        }
                    }
                });
            } else {
                categoryChart.data.labels = labels;
                categoryChart.data.datasets[0].data = data;
                categoryChart.data.datasets[0].backgroundColor = colors;
                categoryChart.update('none');
            }
        }

        function updateClientsChart(stats) {
            const clients = stats.top_clients.slice(0, 8);
            const labels = clients.map(c => c.device.length > 18 ? c.device.slice(0, 18) + '…' : c.device);
            const data = clients.map(c => c.count);

            if (!clientsChart) {
                const ctx = document.getElementById('clients-chart').getContext('2d');
                clientsChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: data,
                            backgroundColor: '#7eb8da40',
                            borderColor: '#7eb8da',
                            borderWidth: 1,
                            borderRadius: 3,
                        }]
                    },
                    options: {
                        ...CHART_DEFAULTS,
                        indexAxis: 'y',
                        scales: {
                            x: {
                                grid: { color: '#27272a40' },
                                ticks: { color: '#71717a', font: { size: 10 } }
                            },
                            y: {
                                grid: { display: false },
                                ticks: { color: '#e4e4e7', font: { size: 10, family: 'JetBrains Mono, monospace' } }
                            }
                        }
                    }
                });
            } else {
                clientsChart.data.labels = labels;
                clientsChart.data.datasets[0].data = data;
                clientsChart.update('none');
            }
        }

        async function refresh() {
            try {
                const res = await fetch('/api/dns');
                const data = await res.json();

                allEntries = data.entries;
                updateKPIs(data.stats);
                updateCategoryChart(data.stats);
                updateClientsChart(data.stats);
                renderFeed();

                document.getElementById('last-refresh').textContent =
                    new Date().toLocaleTimeString();
            } catch (err) {
                console.error('Refresh failed:', err);
            }
        }

        // Initial load and auto-refresh
        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>
"""


class DNSMonitorHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())

        elif self.path == '/api/dns':
            entries, stats = parse_log()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(json.dumps({
                "entries": entries[-500:],  # last 500
                "stats": stats,
                "timestamp": datetime.now().isoformat(),
            }).encode())

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress HTTP logs


if __name__ == '__main__':
    print(f"⚡ ZeroPoint DNS Shield — Traffic Monitor")
    print(f"  Dashboard: http://192.168.1.170:{PORT}")
    print(f"  Log file:  {LOG_PATH}")
    print(f"  Press Ctrl+C to stop\n")

    server = http.server.HTTPServer(('0.0.0.0', PORT), DNSMonitorHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n⚡ Monitor stopped.")
        server.server_close()
