#!/usr/bin/env python3
"""
ZeroPoint Local Model Bench — Officer Inference Tier 2

Tests local Ollama models against the classification and scoring tasks
that officers will need for Tier 2 sweep analysis. Measures latency,
output quality, and tokens/sec for each model.

Usage:
    python3 scripts/bench-local-models.py
    python3 scripts/bench-local-models.py --models qwen3.6:35b-a3b
    python3 scripts/bench-local-models.py --task receipt_classify
"""

import argparse
import json
import os
import time
import sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

OLLAMA_URL = "http://localhost:11434"

# ── Config loading ───────────────────────────────────────────────────────────

# Minimal TOML parser for stdlib-only operation (no pip dependency).
# Handles the flat tables and string/int/bool values in officer-inference.toml.
# For anything more complex, swap in `import tomllib` (Python 3.11+).

def _parse_toml_minimal(text: str) -> dict:
    """Parse a simple TOML file into nested dicts. Handles [section], key = value."""
    result = {}
    current_section = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            result.setdefault(current_section, {})
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.split("#")[0].strip()  # strip inline comments
        # Parse value
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        elif val == "true":
            val = True
        elif val == "false":
            val = False
        else:
            try:
                val = int(val)
            except ValueError:
                try:
                    val = float(val)
                except ValueError:
                    pass
        if current_section:
            result[current_section][key] = val
        else:
            result[key] = val
    return result


def load_inference_config() -> dict:
    """Load officer-inference.toml from resolution chain.

    Search order:
      1. ./officer-inference.toml (cwd)
      2. ~/ZeroPoint/officer-inference.toml (runtime home)
      3. <repo>/officer-inference.toml (relative to this script)
    """
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent

    candidates = [
        Path.cwd() / "officer-inference.toml",
        Path.home() / "ZeroPoint" / "officer-inference.toml",
        repo_root / "officer-inference.toml",
    ]

    for path in candidates:
        if path.is_file():
            text = path.read_text()
            cfg = _parse_toml_minimal(text)
            cfg["_source"] = str(path)
            return cfg

    return {}  # No config found — use hardcoded defaults


def resolve_config() -> dict:
    """Resolve inference config into a flat operational dict."""
    raw = load_inference_config()
    models_sec = raw.get("models", {})
    prompts_sec = raw.get("prompts", {})
    timeout_sec = raw.get("timeout", {})
    routing_sec = raw.get("routing", {})

    format_sec = raw.get("format", {})
    think_sec = raw.get("think", {})

    return {
        "default_model": models_sec.get("default", "gemma4:26b-mlx"),
        "escalation_model": models_sec.get("escalation", "qwen3.6:35b-a3b"),
        "prompt_mode": prompts_sec.get("mode", "strict"),
        "timeout_s": timeout_sec.get("default_s", 30),
        "timeout_fallback": timeout_sec.get("fallback", "escalation"),
        "timeout_overrides": {k: v for k, v in timeout_sec.items()
                              if k not in ("default_s", "fallback")},
        "routing": routing_sec,
        "format_default": format_sec.get("default", True),
        "format_overrides": {k: v for k, v in format_sec.items() if k != "default"},
        "think_default": think_sec.get("default", False),
        "think_overrides": {k: v for k, v in think_sec.items() if k != "default"},
        "_source": raw.get("_source", "hardcoded defaults"),
    }


def resolve_model_for_task(config: dict, task_key: str) -> str:
    """Return the model to use for a given task, per routing config."""
    routing = config.get("routing", {})
    route = routing.get(task_key, "default")
    if route == "default":
        return config["default_model"]
    elif route == "escalation":
        return config["escalation_model"]
    else:
        return route  # Explicit model tag


def resolve_format_for_task(config: dict, task_key: str) -> bool:
    """Return whether to use native format for a given task."""
    overrides = config.get("format_overrides", {})
    return overrides.get(task_key, config.get("format_default", True))


def resolve_think_for_task(config: dict, task_key: str) -> bool:
    """Return whether to use think mode for a given task."""
    overrides = config.get("think_overrides", {})
    return overrides.get(task_key, config.get("think_default", False))


def resolve_timeout_for_task(config: dict, task_key: str) -> int:
    """Return timeout in seconds for a given task."""
    overrides = config.get("timeout_overrides", {})
    return overrides.get(task_key, config.get("timeout_s", 30))


# ── Models to bench ──────────────────────────────────────────────────────────

MODELS = [
    "gemma4:26b-mlx",     # primary: dense 26B, best classifier, fastest
    "qwen3.6:35b-a3b",    # escalation: MoE 3B active of 35B, best boundary detector
    # ── Candidates (bench pending) ──
    "nemotron-3-nano:30b-a3b-q4_K_M",  # NVIDIA MoE 30B, q4 quant
    "granite4.1:8b",                     # IBM dense 8B
    "qwen3:4b",                          # Alibaba dense 4B — smallest candidate
]

# ── Bench tasks ──────────────────────────────────────────────────────────────
# Each task has a system prompt, a user prompt, and a scoring function.
# Each task has both a default and a "strict" system prompt.  The strict
# variant constrains output shape without suppressing reasoning (which
# stays in the thinking field via the chat API).

TASKS = {}

# Task 1: Receipt classification
# Given a chain entry description, classify its domain and type.
TASKS["receipt_classify"] = {
    "name": "Receipt Classification",
    "system": (
        "You are a chain receipt classifier for a governance system. "
        "Given a description of a chain entry, respond with ONLY a JSON object: "
        '{"domain": "<governance|integrity|operations|system>", '
        '"type": "<specific_type>", "severity": "<ok|info|warning|critical>"}. '
        "No explanation, no markdown, just the JSON."
    ),
    "system_strict": (
        "You are a chain receipt classifier. Analyze the input, then respond "
        "with exactly one JSON object.\n\n"
        "Domain definitions:\n"
        "- governance: delegation grants/revocations, gate decisions (allowed/denied), "
        "authority policy, access control enforcement\n"
        "- integrity: chain health, missing signatures, chain silence, data completeness, "
        "cryptographic verification\n"
        "- operations: tool invocations, agent actions, task execution, workspace mutations\n"
        "- system: posture scores, officer heartbeats, sweep summaries, meta-status\n\n"
        "Severity definitions:\n"
        "- ok: routine success, background noise (tool completed, sweep found nothing)\n"
        "- info: notable event, no action needed (delegation granted, posture computed)\n"
        "- warning: investigate soon, something is off but not actively breaking "
        "(unsigned entries, chain silence, gate denial of unknown agent)\n"
        "- critical: operator attention now, active threat or systemic failure "
        "(repeated unauthorized access, chain integrity broken)\n\n"
        "Output format (nothing else — no confirmation, no verification, no narration):\n"
        '{"domain": "governance|integrity|operations|system", '
        '"type": "<specific_type>", '
        '"severity": "ok|info|warning|critical"}'
    ),
    "cases": [
        {
            "input": "A delegation was granted to agent 'ironclaw' for capabilities: chain_render, tool_invoke. Expires in 24 hours.",
            "expected": {"domain": "governance", "type": "delegation_granted", "severity": "info"},
        },
        {
            "input": "Gate denied agent 'unknown_bot' access to 'shell_exec': no delegation exists for this agent.",
            "expected": {"domain": "governance", "type": "gate_denied", "severity": "warning"},
        },
        {
            "input": "100% of 13000 chain entries lack cryptographic signatures.",
            "expected": {"domain": "integrity", "type": "unsigned_entries", "severity": "critical"},
        },
        {
            "input": "Tool 'memory_write' was invoked by agent ironclaw with arguments hash abc123.",
            "expected": {"domain": "operations", "type": "tool_invoked", "severity": "ok"},
        },
        {
            "input": "System posture computed: composite 0.90, integrity 0.90, security 1.00, operations 1.00, governance 0.95. Trend: Stable.",
            "expected": {"domain": "system", "type": "posture_computed", "severity": "info"},
        },
        {
            "input": "No chain entries recorded in the last 2700 minutes. Last activity was a tool health check.",
            "expected": {"domain": "integrity", "type": "chain_silence", "severity": "warning"},
        },
        # ── Edge cases (added for coverage) ──
        {
            "input": "Delegation to agent 'ironclaw' for shell_exec was revoked by operator. Reason: security review.",
            "expected": {"domain": "governance", "type": "delegation_revoked", "severity": "info"},
            "note": "Revocation is governance, not a threat — operator-initiated",
        },
        {
            "input": "Gate allowed agent 'ironclaw' to invoke 'memory_write' under delegation d-4f8a.",
            "expected": {"domain": "governance", "type": "gate_allowed", "severity": "ok"},
            "note": "Routine gate pass — background noise, not notable",
        },
        {
            "input": "Tool 'web_fetch' failed: connection timeout after 30s. Agent ironclaw, attempt 1 of 3.",
            "expected": {"domain": "operations", "type": "tool_failed", "severity": "ok"},
            "note": "Single tool failure is routine operational noise, not a warning",
        },
        {
            "input": "Officer steward sweep completed: 3 findings. Unsigned entries: 2, chain gap: 1. Next sweep in 30 minutes.",
            "expected": {"domain": "system", "type": "sweep_completed", "severity": "info"},
            "note": "Sweep result is system/meta — the findings themselves get separate receipts",
        },
    ],
}

# Task 2: Trajectory boundary detection
# Given a sequence of events, identify where one arc of work ends and another begins.
TASKS["trajectory_boundary"] = {
    "name": "Trajectory Boundary Detection",
    "system": (
        "You are analyzing a sequence of timestamped chain events to identify "
        "trajectory boundaries — points where one arc of work ends and another begins. "
        "Respond with ONLY a JSON object: "
        '{"boundaries": [<indices where a new trajectory starts>], '
        '"confidence": <0.0-1.0>, '
        '"reasoning": "<one sentence>"}. '
        "Index 0 is always the start of the first trajectory."
    ),
    "system_strict": (
        "You detect trajectory boundaries in timestamped chain events. "
        "A boundary is where one arc of work ends and another begins.\n\n"
        "Boundary signals (strongest to weakest):\n"
        "- Large time gaps (hours) between events\n"
        "- Actor/operator changes\n"
        "- Domain shifts (governance→operations) WITH time gaps\n\n"
        "NOT boundaries:\n"
        "- Consecutive tool calls by the same actor within minutes (same session)\n"
        "- Gate/delegation events followed by the tool they authorize\n"
        "- Officer heartbeats between active events\n\n"
        "Default to fewer boundaries. When in doubt, it's one trajectory.\n\n"
        "Output format (nothing else — no confirmation, no verification, no narration):\n"
        '{"boundaries": [0, ...], "confidence": 0.0-1.0, "reasoning": "<one sentence>"}\n\n'
        "Index 0 is always the start of the first trajectory."
    ),
    "cases": [
        {
            "input": (
                "Events:\n"
                "0. [09:00] delegation:granted:ironclaw for chain_render\n"
                "1. [09:01] gate:allowed:chain_render by ironclaw\n"
                "2. [09:02] gate:allowed:chain_render by ironclaw\n"
                "3. [09:03] officer:steward:heartbeat — 0 findings\n"
                "4. [17:30] tool:started:memory_write\n"
                "5. [17:31] tool:completed:memory_write success\n"
                "6. [17:32] tool:started:web_fetch\n"
                "7. [17:33] tool:completed:web_fetch success"
            ),
            "expected": {"boundaries": [0, 4]},
            "note": "8.5-hour gap + domain shift (governance→operations) = clear boundary",
        },
        {
            "input": (
                "Events:\n"
                "0. [14:00] delegation:granted:ironclaw for tool_invoke\n"
                "1. [14:01] gate:allowed:memory_write by ironclaw\n"
                "2. [14:02] tool:started:memory_write\n"
                "3. [14:03] tool:completed:memory_write success\n"
                "4. [14:05] gate:allowed:web_fetch by ironclaw\n"
                "5. [14:06] tool:started:web_fetch\n"
                "6. [14:07] tool:completed:web_fetch success"
            ),
            "expected": {"boundaries": [0]},
            "note": "Continuous activity, same actor, no time gap = single trajectory",
        },
        {
            "input": (
                "Events:\n"
                "0. [10:00] delegation:granted:ironclaw for chain_render\n"
                "1. [10:01] gate:allowed:chain_render\n"
                "2. [10:02] officer:cleo:governance:authority_gap — 5 ungoverned decisions\n"
                "3. [10:03] tool:started:shell_exec by operator\n"
                "4. [10:04] tool:completed:shell_exec success\n"
                "5. [10:05] delegation:granted:ironclaw for shell_exec\n"
                "6. [10:06] gate:allowed:shell_exec by ironclaw"
            ),
            "expected": {"boundaries": [0]},
            "note": "Mixed domains but continuous time, same session = single trajectory (governance driving operations)",
        },
        # ── Edge cases (added for coverage) ──
        {
            "input": (
                "Events:\n"
                "0. [08:00] delegation:granted:ironclaw for tool_invoke\n"
                "1. [08:01] gate:allowed:memory_write by ironclaw\n"
                "2. [08:02] tool:completed:memory_write success\n"
                "3. [08:03] officer:steward:heartbeat — 0 findings\n"
                "4. [14:00] delegation:granted:sage for chain_render\n"
                "5. [14:01] gate:allowed:chain_render by sage\n"
                "6. [14:02] tool:started:chain_render\n"
                "7. [14:03] tool:completed:chain_render success\n"
                "8. [22:30] officer:steward:heartbeat — 1 finding\n"
                "9. [22:31] officer:cleo:governance:authority_gap — 2 ungoverned"
            ),
            "expected": {"boundaries": [0, 4, 8]},
            "note": "Three sessions: morning ironclaw work, afternoon sage work, evening officer sweeps. Two large time gaps.",
        },
        {
            "input": (
                "Events:\n"
                "0. [11:00] tool:started:shell_exec by operator\n"
                "1. [11:01] tool:completed:shell_exec success\n"
                "2. [11:01] tool:started:file_write by operator\n"
                "3. [11:02] tool:completed:file_write success\n"
                "4. [11:02] tool:started:web_fetch by operator\n"
                "5. [11:03] tool:completed:web_fetch success\n"
                "6. [11:03] tool:started:memory_write by operator\n"
                "7. [11:04] tool:completed:memory_write success"
            ),
            "expected": {"boundaries": [0]},
            "note": "Rapid-fire tool burst by same actor — classic over-split trap. One trajectory.",
        },
        {
            "input": (
                "Events:\n"
                "0. [09:00] delegation:granted:ironclaw for tool_invoke\n"
                "1. [09:01] gate:allowed:shell_exec by ironclaw\n"
                "2. [09:02] tool:started:shell_exec\n"
                "3. [09:03] tool:completed:shell_exec success\n"
                "4. [09:10] delegation:granted:sage for chain_render\n"
                "5. [09:11] gate:allowed:chain_render by sage\n"
                "6. [09:12] tool:started:chain_render\n"
                "7. [09:13] tool:completed:chain_render success"
            ),
            "expected": {"boundaries": [0]},
            "note": "Actor change (ironclaw→sage) but only 7min gap — same session, one trajectory. Tests actor-change-without-time-gap.",
        },
    ],
}

# Task 3: Finding severity assessment
# Given an officer finding, assess its actual severity.
TASKS["severity_assess"] = {
    "name": "Finding Severity Assessment",
    "system": (
        "You are a governance system officer assessing the severity of findings. "
        "Given a finding description, respond with ONLY a JSON object: "
        '{"severity": "<ok|info|warning|critical>", '
        '"action_needed": <true|false>, '
        '"reasoning": "<one sentence>"}.'
    ),
    "system_strict": (
        "You assess the severity of governance system findings.\n\n"
        "Severity definitions:\n"
        "- ok: routine success, background noise (sweep found nothing)\n"
        "- info: notable event, no action needed (delegation renewed, config updated)\n"
        "- warning: investigate soon, something is off but not actively breaking "
        "(unsigned entries, chain silence, gate denial of unknown agent)\n"
        "- critical: operator attention now, active threat or systemic failure "
        "(repeated unauthorized access, chain integrity broken)\n\n"
        "Output format (nothing else — no confirmation, no verification, no narration):\n"
        '{"severity": "ok|info|warning|critical", "action_needed": true|false, '
        '"reasoning": "<one sentence>"}'
    ),
    "cases": [
        {
            "input": "100% of 13000 chain entries lack cryptographic signatures. The chain has been running for 30 days without signing enabled.",
            "expected": {"severity": "critical", "action_needed": True},
        },
        {
            "input": "Officer sweep completed with 0 findings. All domains healthy. Posture: 1.00.",
            "expected": {"severity": "ok", "action_needed": False},
        },
        {
            "input": "An agent 'unknown_external' attempted to invoke 'shell_exec' 47 times in the last 5 minutes, all denied by the gate.",
            "expected": {"severity": "critical", "action_needed": True},
        },
        {
            "input": "Delegation to 'ironclaw' for chain_render renewed automatically. Prior delegation was 23 hours old.",
            "expected": {"severity": "info", "action_needed": False},
        },
        {
            "input": "3 of 50 gate decisions in the last hour allowed tool access without a traceable delegation chain.",
            "expected": {"severity": "warning", "action_needed": True},
        },
        # ── Edge cases (added for coverage) ──
        {
            "input": "Chain has been running normally for 72 hours. All entries signed. No gate denials. Posture trending upward from 0.85 to 0.95.",
            "expected": {"severity": "ok", "action_needed": False},
            "note": "Unambiguously healthy — should not over-interpret positive trend as notable",
        },
        {
            "input": "Agent 'ironclaw' invoked 'memory_write' 340 times in the last hour. All authorized via valid delegation. No errors.",
            "expected": {"severity": "info", "action_needed": False},
            "note": "High volume but fully authorized — info at most, not warning. Tests volume-anxiety bias.",
        },
        {
            "input": "2 of 500 chain entries in the last 24 hours have mismatched content hashes. Both entries were officer heartbeat receipts.",
            "expected": {"severity": "warning", "action_needed": True},
            "note": "Hash mismatch is an integrity signal even at low rate — warning, not critical (2/500 is not systemic)",
        },
    ],
}

# Task 4: Receipt summarization (Cleo task)
# Given a batch of chain receipts, produce a one-paragraph narrative summary.
TASKS["receipt_summarize"] = {
    "name": "Receipt Summarization",
    "system": (
        "You are a governance chain narrator. Given a batch of chain receipts, "
        "produce a concise one-paragraph summary of what happened. "
        "Respond with ONLY a JSON object: "
        '{"summary": "<one paragraph>", "key_events": [<list of most important events>], '
        '"tone": "<routine|notable|concerning|urgent>"}. '
        "No explanation, no markdown, just the JSON."
    ),
    "system_strict": (
        "You narrate governance chain activity for operator awareness.\n\n"
        "Given a batch of chain receipts, produce a concise narrative summary.\n\n"
        "Tone definitions:\n"
        "- routine: normal operations, nothing requires attention\n"
        "- notable: something worth knowing but not worrying about\n"
        "- concerning: patterns that suggest investigation\n"
        "- urgent: active issues requiring operator response\n\n"
        "Output format (nothing else — no confirmation, no verification, no narration):\n"
        '{"summary": "<one paragraph, 2-4 sentences>", '
        '"key_events": ["<event1>", "<event2>"], '
        '"tone": "routine|notable|concerning|urgent"}'
    ),
    "cases": [
        {
            "input": (
                "Chain receipts (last 2 hours):\n"
                "- delegation:granted:ironclaw for tool_invoke (09:00)\n"
                "- gate:allowed:memory_write by ironclaw (09:01)\n"
                "- tool:completed:memory_write success (09:02)\n"
                "- gate:allowed:web_fetch by ironclaw (09:03)\n"
                "- tool:completed:web_fetch success (09:04)\n"
                "- officer:steward:heartbeat — 0 findings (09:30)\n"
                "- officer:cleo:heartbeat — 0 findings (09:30)"
            ),
            "expected": {"tone": "routine"},
            "note": "Completely normal session — delegation, tools, clean sweeps",
        },
        {
            "input": (
                "Chain receipts (last 6 hours):\n"
                "- gate:denied:unknown_bot access to shell_exec (14:00)\n"
                "- gate:denied:unknown_bot access to shell_exec (14:01)\n"
                "- gate:denied:unknown_bot access to file_write (14:01)\n"
                "- gate:denied:unknown_bot access to shell_exec (14:02)\n"
                "- gate:denied:unknown_bot access to memory_write (14:02)\n"
                "- officer:steward:heartbeat — 1 finding: 5 gate denials in 3 minutes (14:30)\n"
                "- delegation:granted:ironclaw for tool_invoke (17:00)\n"
                "- tool:completed:memory_write success (17:02)"
            ),
            "expected": {"tone": "concerning"},
            "note": "Burst of denials from unknown agent, then normal work resumed. Concerning, not urgent (attack stopped).",
        },
        {
            "input": (
                "Chain receipts (last 24 hours):\n"
                "- officer:steward:heartbeat — 0 findings (08:00)\n"
                "- officer:cleo:heartbeat — 0 findings (08:00)\n"
                "- officer:steward:heartbeat — 0 findings (08:30)\n"
                "- officer:cleo:heartbeat — 0 findings (08:30)\n"
                "- officer:steward:heartbeat — 0 findings (09:00)\n"
                "- officer:cleo:heartbeat — 0 findings (09:00)"
            ),
            "expected": {"tone": "routine"},
            "note": "Only heartbeats, no operator/agent activity — quiet chain, still routine",
        },
    ],
}

# Task 5: Pattern detection (Steward task)
# Given a batch of receipts, identify anomalous patterns.
TASKS["pattern_detect"] = {
    "name": "Anomaly Pattern Detection",
    "system": (
        "You are a security-focused governance officer analyzing chain receipts for anomalous patterns. "
        "Given a batch of receipts, identify any patterns that warrant attention. "
        "Respond with ONLY a JSON object: "
        '{"patterns": [{"type": "<pattern_type>", "severity": "<ok|info|warning|critical>", '
        '"description": "<one sentence>"}], '
        '"overall_assessment": "<clean|monitor|investigate|escalate>"}. '
        "No explanation, no markdown, just the JSON."
    ),
    "system_strict": (
        "You detect anomalous patterns in governance chain receipts.\n\n"
        "Pattern types to look for:\n"
        "- brute_force: repeated denied access attempts from same agent\n"
        "- privilege_escalation: agent requesting capabilities beyond its delegation\n"
        "- chain_drift: integrity indicators degrading over time\n"
        "- unusual_volume: tool invocation rates outside normal patterns\n"
        "- silence: unexpected gaps in expected activity\n"
        "- none: no anomalous patterns detected\n\n"
        "Overall assessment:\n"
        "- clean: no anomalous patterns\n"
        "- monitor: minor patterns worth watching\n"
        "- investigate: patterns that need operator review\n"
        "- escalate: active threat patterns requiring immediate response\n\n"
        "Output format (nothing else — no confirmation, no verification, no narration):\n"
        '{"patterns": [{"type": "<pattern_type>", "severity": "ok|info|warning|critical", '
        '"description": "<one sentence>"}], '
        '"overall_assessment": "clean|monitor|investigate|escalate"}'
    ),
    "cases": [
        {
            "input": (
                "Receipts (last 30 minutes):\n"
                "- gate:denied:agent_x access to shell_exec (10:00)\n"
                "- gate:denied:agent_x access to shell_exec (10:00)\n"
                "- gate:denied:agent_x access to file_write (10:01)\n"
                "- gate:denied:agent_x access to shell_exec (10:01)\n"
                "- gate:denied:agent_x access to memory_write (10:02)\n"
                "- gate:denied:agent_x access to shell_exec (10:02)\n"
                "- gate:denied:agent_x access to web_fetch (10:03)\n"
                "- gate:denied:agent_x access to shell_exec (10:03)"
            ),
            "expected": {"overall_assessment": "escalate"},
            "note": "Classic brute-force: same agent, multiple tools, rapid succession. Should escalate.",
        },
        {
            "input": (
                "Receipts (last 4 hours):\n"
                "- delegation:granted:ironclaw for tool_invoke (08:00)\n"
                "- tool:completed:memory_write success (08:05)\n"
                "- tool:completed:web_fetch success (08:10)\n"
                "- officer:steward:heartbeat — 0 findings (08:30)\n"
                "- tool:completed:memory_write success (09:00)\n"
                "- officer:steward:heartbeat — 0 findings (09:30)\n"
                "- tool:completed:file_read success (10:00)\n"
                "- officer:steward:heartbeat — 0 findings (10:30)\n"
                "- tool:completed:web_fetch success (11:00)\n"
                "- officer:steward:heartbeat — 0 findings (11:30)"
            ),
            "expected": {"overall_assessment": "clean"},
            "note": "Normal work pattern: authorized agent, varied tools, clean sweeps. No anomalies.",
        },
        {
            "input": (
                "Receipts (last 12 hours):\n"
                "- delegation:granted:ironclaw for chain_render (08:00)\n"
                "- gate:allowed:chain_render by ironclaw (08:01)\n"
                "- gate:denied:ironclaw access to shell_exec (08:05)\n"
                "- gate:denied:ironclaw access to file_write (08:06)\n"
                "- gate:denied:ironclaw access to memory_write (08:07)\n"
                "- delegation:granted:ironclaw for tool_invoke (08:30)\n"
                "- gate:allowed:shell_exec by ironclaw (08:31)\n"
                "- tool:completed:shell_exec success (08:32)"
            ),
            "expected": {"overall_assessment": "monitor"},
            "note": "Agent tried tools beyond delegation, then got proper delegation. Not malicious but worth monitoring — could be misconfiguration or probing.",
        },
    ],
}


# ── Ollama native structured output schemas ─────────────────────────────────
# Passed as the `format` parameter to /api/chat.  Ollama constrains output at
# the grammar/engine level — no hallucinated structure, ~6x faster.

TASK_SCHEMAS = {
    "receipt_classify": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "enum": ["governance", "integrity", "operations", "system"]},
            "type": {"type": "string"},
            "severity": {"type": "string", "enum": ["ok", "info", "warning", "critical"]},
        },
        "required": ["domain", "type", "severity"],
    },
    "trajectory_boundary": {
        "type": "object",
        "properties": {
            "boundaries": {"type": "array", "items": {"type": "integer"}},
            "confidence": {"type": "number"},
            "reasoning": {"type": "string"},
        },
        "required": ["boundaries", "confidence", "reasoning"],
    },
    "severity_assess": {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": ["ok", "info", "warning", "critical"]},
            "action_needed": {"type": "boolean"},
            "reasoning": {"type": "string"},
        },
        "required": ["severity", "action_needed", "reasoning"],
    },
    "receipt_summarize": {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "key_events": {"type": "array", "items": {"type": "string"}},
            "tone": {"type": "string", "enum": ["routine", "notable", "concerning", "urgent"]},
        },
        "required": ["summary", "key_events", "tone"],
    },
    "pattern_detect": {
        "type": "object",
        "properties": {
            "patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "severity": {"type": "string", "enum": ["ok", "info", "warning", "critical"]},
                        "description": {"type": "string"},
                    },
                    "required": ["type", "severity", "description"],
                },
            },
            "overall_assessment": {"type": "string", "enum": ["clean", "monitor", "investigate", "escalate"]},
        },
        "required": ["patterns", "overall_assessment"],
    },
}


# ── Ollama API ───────────────────────────────────────────────────────────────

# Models that don't support the think parameter (400 on think:true)
NO_THINK_MODELS = {"phi4-mini"}


def ollama_generate(model: str, system: str, prompt: str, temperature: float = 0.0,
                    timeout: int = 120, format_schema: dict | None = None,
                    think: bool | None = None) -> dict:
    """Call Ollama chat API, return response dict with timing.

    Uses /api/chat instead of /api/generate so thinking models (Qwen3,
    Gemma4) return their reasoning in a separate field rather than
    consuming all tokens invisibly.  Falls back to think:false for
    models that don't support it.

    When format_schema is provided, passes it as the `format` parameter
    to Ollama's /api/chat endpoint.  This constrains output at the
    grammar/engine level — guaranteed valid JSON matching the schema.

    think parameter: True/False to force think mode on/off. None (default)
    uses automatic detection — on unless the model is in NO_THINK_MODELS.
    """
    if think is None:
        use_think = model not in NO_THINK_MODELS
    else:
        use_think = think

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": 4096,
        },
    }
    if use_think:
        body["think"] = True
    else:
        body["think"] = False
    if format_schema is not None:
        body["format"] = format_schema

    payload = json.dumps(body).encode()

    req = Request(
        f"{OLLAMA_URL}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
    except (URLError, TimeoutError, OSError) as e:
        elapsed = time.monotonic() - start
        is_timeout = isinstance(e, TimeoutError) or elapsed >= (timeout - 1)
        return {"error": str(e), "elapsed": elapsed, "timed_out": is_timeout}

    elapsed = time.monotonic() - start
    message = result.get("message", {})

    return {
        "response": message.get("content", ""),
        "thinking": message.get("thinking", ""),
        "elapsed": elapsed,
        "eval_count": result.get("eval_count", 0),
        "eval_duration_ns": result.get("eval_duration", 0),
        "prompt_eval_count": result.get("prompt_eval_count", 0),
        "total_duration_ns": result.get("total_duration", 0),
        "timed_out": False,
    }


def extract_thinking_and_response(text: str) -> tuple[str | None, str]:
    """Separate <think>...</think> blocks from the answer portion.

    Returns (thinking_content, answer_text). If no thinking tags are
    present, thinking_content is None and answer_text is the full text.
    If the model hit the token limit mid-think (unclosed tag), the
    thinking content is what we got and answer_text is empty.
    """
    import re

    # Closed thinking block
    match = re.search(r"<think>(.*?)</think>(.*)", text, flags=re.DOTALL)
    if match:
        return match.group(1).strip(), match.group(2).strip()

    # Unclosed thinking block (hit token limit mid-reasoning)
    match = re.search(r"<think>(.*)", text, flags=re.DOTALL)
    if match:
        return match.group(1).strip(), ""

    return None, text.strip()


def parse_json_response(text: str) -> tuple[dict | None, str | None]:
    """Try to extract JSON from the answer portion of a model response.

    Returns (parsed_json, thinking_content). The thinking is preserved
    for logging — we don't discard it.
    """
    thinking, answer = extract_thinking_and_response(text)

    # Parse the answer portion
    answer = answer.strip()
    # Strip markdown fences if present
    if answer.startswith("```"):
        lines = answer.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        answer = "\n".join(lines).strip()

    # Try to find JSON object
    start = answer.find("{")
    end = answer.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(answer[start:end]), thinking
        except json.JSONDecodeError:
            return None, thinking
    return None, thinking


# ── Scoring ──────────────────────────────────────────────────────────────────

def score_classification(parsed: dict | None, expected: dict) -> tuple[float, str]:
    """Score a classification response. Returns (score 0-1, note)."""
    if parsed is None:
        return 0.0, "failed to parse JSON"

    score = 0.0
    notes = []

    # Domain match (most important)
    if parsed.get("domain", "").lower() == expected.get("domain", "").lower():
        score += 0.5
    else:
        notes.append(f"domain: got {parsed.get('domain')}, expected {expected.get('domain')}")

    # Severity match
    if parsed.get("severity", "").lower() == expected.get("severity", "").lower():
        score += 0.3
    else:
        notes.append(f"severity: got {parsed.get('severity')}, expected {expected.get('severity')}")

    # Has a type field
    if parsed.get("type"):
        score += 0.2
    else:
        notes.append("missing type field")

    return score, "; ".join(notes) if notes else "exact"


def score_boundary(parsed: dict | None, expected: dict) -> tuple[float, str]:
    """Score a trajectory boundary response."""
    if parsed is None:
        return 0.0, "failed to parse JSON"

    expected_boundaries = set(expected.get("boundaries", []))
    got_boundaries = set(parsed.get("boundaries", []))

    if not expected_boundaries:
        return 0.0, "no expected boundaries"

    # Intersection over union
    intersection = expected_boundaries & got_boundaries
    union = expected_boundaries | got_boundaries
    iou = len(intersection) / len(union) if union else 1.0

    notes = []
    if got_boundaries != expected_boundaries:
        notes.append(f"got {sorted(got_boundaries)}, expected {sorted(expected_boundaries)}")

    return iou, "; ".join(notes) if notes else "exact"


def score_severity(parsed: dict | None, expected: dict) -> tuple[float, str]:
    """Score a severity assessment response."""
    if parsed is None:
        return 0.0, "failed to parse JSON"

    score = 0.0
    notes = []

    if parsed.get("severity", "").lower() == expected.get("severity", "").lower():
        score += 0.6
    else:
        notes.append(f"severity: got {parsed.get('severity')}, expected {expected.get('severity')}")

    if parsed.get("action_needed") == expected.get("action_needed"):
        score += 0.4
    else:
        notes.append(f"action: got {parsed.get('action_needed')}, expected {expected.get('action_needed')}")

    return score, "; ".join(notes) if notes else "exact"


def score_summarize(parsed: dict | None, expected: dict) -> tuple[float, str]:
    """Score a receipt summarization response."""
    if parsed is None:
        return 0.0, "failed to parse JSON"

    score = 0.0
    notes = []

    # Has a summary field with actual content
    summary = parsed.get("summary", "")
    if summary and len(summary) > 20:
        score += 0.4
    else:
        notes.append("missing or trivial summary")

    # Tone match
    if parsed.get("tone", "").lower() == expected.get("tone", "").lower():
        score += 0.4
    else:
        notes.append(f"tone: got {parsed.get('tone')}, expected {expected.get('tone')}")

    # Has key_events list
    key_events = parsed.get("key_events", [])
    if isinstance(key_events, list) and len(key_events) > 0:
        score += 0.2
    else:
        notes.append("missing or empty key_events")

    return score, "; ".join(notes) if notes else "exact"


def score_pattern(parsed: dict | None, expected: dict) -> tuple[float, str]:
    """Score a pattern detection response."""
    if parsed is None:
        return 0.0, "failed to parse JSON"

    score = 0.0
    notes = []

    # Overall assessment match (most important)
    if parsed.get("overall_assessment", "").lower() == expected.get("overall_assessment", "").lower():
        score += 0.6
    else:
        notes.append(f"assessment: got {parsed.get('overall_assessment')}, expected {expected.get('overall_assessment')}")

    # Has patterns list with content
    patterns = parsed.get("patterns", [])
    if isinstance(patterns, list):
        if expected.get("overall_assessment") == "clean":
            # For clean: either empty list or list with type "none"
            if len(patterns) == 0 or all(p.get("type") == "none" for p in patterns):
                score += 0.4
            else:
                # Tolerate patterns if they're all ok/info severity
                if all(p.get("severity", "").lower() in ("ok", "info") for p in patterns):
                    score += 0.2
                    notes.append("found patterns in clean batch (minor)")
                else:
                    notes.append("false positive patterns in clean batch")
        else:
            # For non-clean: should have at least one pattern with description
            if len(patterns) > 0 and all(p.get("description") for p in patterns):
                score += 0.4
            elif len(patterns) > 0:
                score += 0.2
                notes.append("patterns missing descriptions")
            else:
                notes.append("no patterns detected in anomalous batch")
    else:
        notes.append("patterns is not a list")

    return score, "; ".join(notes) if notes else "exact"


SCORERS = {
    "receipt_classify": score_classification,
    "trajectory_boundary": score_boundary,
    "severity_assess": score_severity,
    "receipt_summarize": score_summarize,
    "pattern_detect": score_pattern,
}


# ── Runner ───────────────────────────────────────────────────────────────────

def run_bench(models: list[str], tasks: list[str], verbose: bool = False,
              strict: bool = True, config: dict | None = None,
              use_format: bool | None = None, use_think: bool | None = None):
    """Run the bench and print results.

    When config is provided and models list matches config's two models,
    task-based routing is used: each task runs on the model specified by
    [routing] in officer-inference.toml. When --models is overridden or
    --all-models is set, routing is ignored and every model runs every task.

    use_format / use_think: True/False to force globally (CLI override).
    None = per-task from config (default).
    """

    # Check Ollama is up
    try:
        urlopen(f"{OLLAMA_URL}/api/tags", timeout=5)
    except URLError:
        print(f"\n  ✗ Ollama not reachable at {OLLAMA_URL}")
        print("    Start it with: ollama serve")
        sys.exit(1)

    config = config or {}
    timeout_s = config.get("timeout_s", 30)
    timeout_fallback = config.get("timeout_fallback", "escalation")
    use_routing = config.get("_use_routing", False)

    prompt_mode = "strict" if strict else "default"
    format_label = "native" if use_format is True else "prompt-only" if use_format is False else "per-task"
    think_label = "on" if use_think is True else "off" if use_think is False else "per-task"
    results = {}
    thinking_log = []  # Collected for post-run review
    timeout_events = []  # Track timeouts for summary

    for model in models:
        print(f"\n{'═' * 70}")
        print(f"  Model: {model}  [prompt: {prompt_mode}, format: {format_label}, think: {think_label}]")
        print(f"{'═' * 70}")

        model_results = {}

        for task_key in tasks:
            # If routing is active and this model isn't routed to this task, skip
            if use_routing:
                routed_model = resolve_model_for_task(config, task_key)
                if model != routed_model:
                    continue

            task = TASKS[task_key]
            scorer = SCORERS[task_key]
            system_prompt = task.get("system_strict", task["system"]) if strict else task["system"]

            print(f"\n  ── {task['name']} ──")

            # Resolve per-task format and think (CLI flags override config)
            if use_format is not None:
                task_format = use_format
            else:
                task_format = resolve_format_for_task(config, task_key)

            if use_think is not None:
                task_think = use_think
            else:
                task_think = resolve_think_for_task(config, task_key)

            schema = TASK_SCHEMAS.get(task_key) if task_format else None
            # None means auto (per-model), True/False forces
            think_param = task_think if task_think is not None else None
            task_timeout = resolve_timeout_for_task(config, task_key)

            fmt_tag = "F" if task_format else "P"
            thk_tag = "T" if task_think else "·"
            print(f"  [{fmt_tag}{thk_tag}] timeout={task_timeout}s")

            case_results = []
            for i, case in enumerate(task["cases"]):
                result = ollama_generate(model, system_prompt, case["input"],
                                         timeout=task_timeout, format_schema=schema,
                                         think=think_param)

                # Timeout fallback
                if result.get("timed_out") and timeout_fallback == "escalation":
                    fallback_model = config.get("escalation_model", model)
                    if fallback_model != model:
                        print(f"    Case {i+1}: ⏱ timeout ({task_timeout}s), falling back to {fallback_model}")
                        timeout_events.append({"model": model, "task": task_key, "case": i + 1})
                        result = ollama_generate(fallback_model, system_prompt, case["input"],
                                                 timeout=120, format_schema=schema,
                                                 think=think_param)

                if "error" in result:
                    print(f"    Case {i+1}: ✗ Error: {result['error']}")
                    case_results.append({"score": 0, "latency": result["elapsed"], "error": True})
                    continue

                # Thinking comes from the API (chat endpoint) or from
                # <think> tags in the response (generate endpoint fallback).
                api_thinking = result.get("thinking", "")
                parsed, inline_thinking = parse_json_response(result["response"])
                thinking = api_thinking or inline_thinking
                score, note = scorer(parsed, case["expected"])

                # Tokens/sec
                eval_ns = result.get("eval_duration_ns", 0)
                eval_count = result.get("eval_count", 0)
                tps = (eval_count / (eval_ns / 1e9)) if eval_ns > 0 else 0

                # Track whether model used thinking
                thought = "🧠" if thinking else "  "
                truncated = " [truncated]" if thinking and parsed is None else ""

                icon = "✓" if score >= 0.8 else "△" if score >= 0.5 else "✗"
                print(
                    f"    Case {i+1}: {icon} {thought} score={score:.1f}  "
                    f"latency={result['elapsed']:.1f}s  "
                    f"tok/s={tps:.0f}  "
                    f"{note}{truncated}"
                )

                if verbose and thinking:
                    # Show first 200 chars of thinking in verbose mode
                    preview = thinking[:200] + ("…" if len(thinking) > 200 else "")
                    print(f"           think: {preview}")

                if verbose and parsed is None:
                    # Show raw response on parse failure
                    raw = result["response"][:300] + ("…" if len(result["response"]) > 300 else "")
                    print(f"           raw: {repr(raw)}")

                # Log thinking for post-run analysis
                if thinking:
                    thinking_log.append({
                        "model": model,
                        "task": task_key,
                        "case": i + 1,
                        "score": score,
                        "thinking": thinking,
                        "answer": parsed,
                        "expected": case["expected"],
                    })

                case_results.append({
                    "score": score,
                    "latency": result["elapsed"],
                    "tokens_per_sec": tps,
                    "eval_count": eval_count,
                    "used_thinking": thinking is not None,
                })

            # Task summary
            if case_results:
                avg_score = sum(r["score"] for r in case_results) / len(case_results)
                avg_latency = sum(r["latency"] for r in case_results) / len(case_results)
                avg_tps = sum(r.get("tokens_per_sec", 0) for r in case_results) / len(case_results)
                print(f"    ── avg: score={avg_score:.2f}  latency={avg_latency:.1f}s  tok/s={avg_tps:.0f}")

                model_results[task_key] = {
                    "avg_score": avg_score,
                    "avg_latency": avg_latency,
                    "avg_tokens_per_sec": avg_tps,
                    "cases": len(case_results),
                }

        results[model] = model_results

    # ── Summary table ────────────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print("  SUMMARY")
    print(f"{'═' * 70}")
    print(f"\n  {'Model':<25} {'Task':<25} {'Score':>6} {'Latency':>8} {'Tok/s':>6}")
    print(f"  {'─' * 25} {'─' * 25} {'─' * 6} {'─' * 8} {'─' * 6}")

    for model, task_results in results.items():
        for task_key, tr in task_results.items():
            print(
                f"  {model:<25} {TASKS[task_key]['name']:<25} "
                f"{tr['avg_score']:>5.2f} "
                f"{tr['avg_latency']:>7.1f}s "
                f"{tr['avg_tokens_per_sec']:>5.0f}"
            )

    # Overall per-model
    print(f"\n  {'Model':<25} {'Overall Score':>13} {'Avg Latency':>12} {'Avg Tok/s':>10}")
    print(f"  {'─' * 25} {'─' * 13} {'─' * 12} {'─' * 10}")
    for model, task_results in results.items():
        if task_results:
            overall = sum(tr["avg_score"] for tr in task_results.values()) / len(task_results)
            lat = sum(tr["avg_latency"] for tr in task_results.values()) / len(task_results)
            tps = sum(tr["avg_tokens_per_sec"] for tr in task_results.values()) / len(task_results)
            tier = "captain" if overall >= 0.85 else "utility" if overall >= 0.7 else "worker" if overall >= 0.5 else "skip"
            print(f"  {model:<25} {overall:>12.2f} {lat:>11.1f}s {tps:>9.0f}  [{tier}]")

    # ── Timeout events ──────────────────────────────────────────────────────
    if timeout_events:
        print(f"\n  Timeouts: {len(timeout_events)} calls exceeded {timeout_s}s")
        for evt in timeout_events:
            print(f"    {evt['model']} / {evt['task']} case {evt['case']}")

    # ── Thinking log ─────────────────────────────────────────────────────────
    if thinking_log:
        think_count = len(thinking_log)
        truncated = sum(1 for t in thinking_log if t["answer"] is None)
        print(f"\n  Thinking: {think_count} responses used <think> tags"
              f"{f', {truncated} truncated (no JSON after think)' if truncated else ''}")

        if verbose:
            print(f"\n{'═' * 70}")
            print("  THINKING LOG")
            print(f"{'═' * 70}")
            for entry in thinking_log:
                print(f"\n  [{entry['model']}] {entry['task']} case {entry['case']} (score={entry['score']:.1f})")
                print(f"  Expected: {json.dumps(entry['expected'])}")
                print(f"  Got:      {json.dumps(entry['answer'])}")
                print(f"  Thinking:")
                # Indent thinking content
                for line in entry["thinking"].split("\n"):
                    print(f"    {line}")
        else:
            print(f"  Run with --verbose to see full thinking traces.")

    # ── Config provenance ────────────────────────────────────────────────────
    if config.get("_source"):
        print(f"\n  Config: {config['_source']}")
    print(f"  Format: {format_label}  |  Think: {think_label}  [F=native, P=prompt-only, T=think, ·=no-think]")

    print()


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroPoint Local Model Bench")
    parser.add_argument(
        "--models",
        default=None,
        help="Comma-separated model names (overrides config routing)",
    )
    parser.add_argument(
        "--task",
        choices=list(TASKS.keys()),
        help="Run only this task (default: all)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show thinking traces inline and in full log",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="Use default (non-strict) prompts instead of strict",
    )
    parser.add_argument(
        "--routed",
        action="store_true",
        help="Use task-based model routing from officer-inference.toml",
    )
    parser.add_argument(
        "--no-format",
        action="store_true",
        help="Disable Ollama native structured output (prompt-only JSON)",
    )
    parser.add_argument(
        "--no-think",
        action="store_true",
        help="Disable thinking mode (think:false). Use with --no-format for prompt-only baseline.",
    )
    args = parser.parse_args()

    # Load config
    config = resolve_config()
    strict = not args.no_strict  # strict is now the default

    # If prompt mode is set in config, use it (unless --no-strict overrides)
    if not args.no_strict and config.get("prompt_mode"):
        strict = config["prompt_mode"] == "strict"

    # Model selection
    if args.models:
        # Explicit --models overrides routing
        models = [m.strip() for m in args.models.split(",")]
        config["_use_routing"] = False
    elif args.routed:
        # Routed mode: both models run, but each only on its assigned tasks
        models = [config["default_model"], config["escalation_model"]]
        config["_use_routing"] = True
    else:
        # Default: all models, all tasks (bench comparison mode)
        models = [config["default_model"], config["escalation_model"]]
        config["_use_routing"] = False

    tasks = [args.task] if args.task else list(TASKS.keys())

    # None = per-task from config; True/False = CLI override
    use_format = False if args.no_format else None
    use_think = False if args.no_think else None
    prompt_mode = "STRICT" if strict else "DEFAULT"
    format_label = "PROMPT-ONLY" if use_format is False else "PER-TASK"
    think_label = "OFF" if use_think is False else "PER-TASK"
    routing_mode = "ROUTED" if config.get("_use_routing") else "ALL×ALL"
    print("\n  ZeroPoint Local Model Bench — Officer Inference Tier 2")
    print(f"  Models: {', '.join(models)}")
    print(f"  Tasks:  {', '.join(TASKS[t]['name'] for t in tasks)}")
    print(f"  Prompt: {prompt_mode}  |  Format: {format_label}  |  Think: {think_label}  |  Routing: {routing_mode}")
    print(f"  Timeout: {config.get('timeout_s', 30)}s → {config.get('timeout_fallback', 'escalation')}")
    if config.get("_source"):
        print(f"  Config: {config['_source']}")

    run_bench(models, tasks, verbose=args.verbose, strict=strict, config=config,
              use_format=use_format, use_think=use_think)
