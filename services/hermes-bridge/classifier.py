"""
Hermes stdout → AG-UI event classifier.

Hermes (run_agent.py) prints structured telemetry with emoji-prefix markers
mixed with the actual model response. Streaming every line verbatim as
TEXT_MESSAGE_CONTENT bleeds tool-registry lists, cache stats, and API-call
timings into the chat body. This classifier maps each line to the right
AG-UI event type so the cockpit can render chat separately from telemetry,
and the governance layer gets semantically-meaningful receipt claims
instead of a flat wall of message.stream beads.

State machine:
    PRE_FINAL  — default; emoji-prefix lines → STEP_* / CUSTOM events.
    IN_FINAL   — entered after `🎯 FINAL RESPONSE:\\n----...\\n`;
                 every line becomes a TEXT_MESSAGE_CONTENT delta until
                 `👋 Agent execution completed!` ends it.
    POST_FINAL — emoji-prefix lines continue as CUSTOM events.

Why this shape — Hermes prints the real model response TWICE: once
inline after `🤖 Assistant:` (often truncated with `...`), and once
fully inside the `🎯 FINAL RESPONSE:` block. Only the second is
complete, so that's what we lift into the chat body.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

# Leading-emoji → CUSTOM event name. Names are namespaced as `agent.<...>`
# so proxy claim_type stays legible (`agent.init`, `agent.cache`, etc.).
_EMOJI_NAME: dict[str, str] = {
    "🤖": "agent.init",
    "🛠": "agent.tools",            # may include U+FE0F variation selector
    "⚠": "agent.warning",
    "🔑": "agent.credential",
    "💾": "agent.cache",
    "📊": "agent.stats",
    "📝": "agent.query_echo",
    "💬": "agent.conversation_start",
    "🔄": "agent.api_call_start",
    "⏱": "agent.api_call_end",
    "🎉": "agent.conversation_done",
    "📋": "agent.summary_header",
    "✅": "agent.outcome",
    "📞": "agent.api_calls_count",
    "🎯": "agent.final_response_marker",
    "👋": "agent.done",
    "❌": "agent.error",
    "🔧": "agent.tools_detail",
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _match_emoji(s: str) -> Optional[str]:
    """Return the agent.<name> label for the line's leading emoji, else None.
    Emoji match is whitespace-insensitive (handles indented children like
    `   📊 Request size: ...`) and tolerates the VS-16 variation selector."""
    stripped = s.lstrip()
    for emoji, name in _EMOJI_NAME.items():
        if stripped.startswith(emoji):
            return name
    return None


@dataclass
class StdoutClassifier:
    message_id: str
    thread_id: str
    run_id: str
    in_final_response: bool = False
    _saw_final_marker: bool = False

    def classify(self, raw_line: str) -> list[dict]:
        """Classify one line of Hermes stdout. Returns 0..N AG-UI event dicts.

        The caller is responsible for wrapping these in `data: ...\\n\\n`.
        Empty list means the line was swallowed (dividers, redundant blanks).
        """
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        ts = _now_ms()
        out: list[dict] = []

        # Blank line — preserve inside final response for paragraph breaks.
        if not stripped:
            if self.in_final_response:
                out.append(self._content("\n", ts))
            return out

        # `====...` section dividers — always drop.
        if all(c == "=" for c in stripped):
            return out

        # `----...` dashes — either the content divider inside the 🎯 block,
        # or horizontal-rule dividers elsewhere. Either way, drop from output.
        if all(c == "-" for c in stripped):
            if self._saw_final_marker:
                self.in_final_response = True
                self._saw_final_marker = False
            return out

        # --- IN_FINAL_RESPONSE: every line becomes chat-body content ---
        if self.in_final_response:
            # 👋 terminates the block even before an explicit end marker.
            if stripped.startswith("👋"):
                self.in_final_response = False
                out.append(self._custom("agent.done", stripped, ts))
                return out
            out.append(self._content(line + "\n", ts))
            return out

        # --- PRE_FINAL or POST_FINAL: classify by prefix ---

        # 🎯 FINAL RESPONSE: arms the dashes-follow-up transition.
        if stripped.startswith("🎯"):
            self._saw_final_marker = True
            out.append(self._custom("agent.final_response_marker", stripped, ts))
            return out

        # 🔄 / ⏱ are step boundaries — emit first-class AG-UI STEP events
        # alongside the CUSTOM (so cockpit can render a timeline AND governance
        # receives the step claim separately).
        if stripped.startswith("🔄"):
            out.append(
                {"type": "STEP_STARTED", "stepName": "api_call", "timestamp": ts}
            )
            out.append(self._custom("agent.api_call_start", stripped, ts))
            return out

        if stripped.startswith("⏱"):
            out.append(
                {"type": "STEP_FINISHED", "stepName": "api_call", "timestamp": ts}
            )
            out.append(self._custom("agent.api_call_end", stripped, ts))
            return out

        # Any other known emoji → CUSTOM with the mapped name.
        name = _match_emoji(stripped)
        if name is not None:
            out.append(self._custom(name, stripped, ts))
            return out

        # Unknown line (no emoji, non-empty, non-divider). Keep it — don't
        # silently drop — but tag as trace so the governance layer can filter.
        out.append(self._custom("agent.trace", stripped, ts))
        return out

    def _content(self, text: str, ts: int) -> dict:
        return {
            "type": "TEXT_MESSAGE_CONTENT",
            "messageId": self.message_id,
            "delta": text,
            "timestamp": ts,
        }

    def _custom(self, name: str, value: str, ts: int) -> dict:
        return {
            "type": "CUSTOM",
            "name": name,
            "value": {"text": value},
            "timestamp": ts,
        }
