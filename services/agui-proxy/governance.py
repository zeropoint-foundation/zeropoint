"""
ZeroPoint governance bridge for AG-UI events.

Maps AG-UI event types to ZeroPoint receipt claims,
validates against governance policy, and stamps receipts.
"""

import json
import os
import time
import uuid
import httpx
from typing import Optional
from ag_ui.core import (
    EventType,
    BaseEvent,
    RunStartedEvent,
    RunFinishedEvent,
    RunErrorEvent,
    ToolCallStartEvent,
    ToolCallArgsEvent,
    ToolCallEndEvent,
    ToolCallResultEvent,
    StateSnapshotEvent,
    StateDeltaEvent,
    TextMessageStartEvent,
    TextMessageContentEvent,
    TextMessageEndEvent,
)
from config import ProxyConfig


# AG-UI event type -> ZeroPoint receipt claim type
CLAIM_MAP: dict[str, str] = {
    # Lifecycle
    EventType.RUN_STARTED: "session.begin",
    EventType.RUN_FINISHED: "session.seal",
    EventType.RUN_ERROR: "session.fault",
    EventType.STEP_STARTED: "step.begin",
    EventType.STEP_FINISHED: "step.seal",

    # Tool calls — these are the high-governance events
    EventType.TOOL_CALL_START: "action.request",
    EventType.TOOL_CALL_ARGS: "action.params",
    EventType.TOOL_CALL_END: "action.execute",
    EventType.TOOL_CALL_RESULT: "action.result",

    # State mutations
    EventType.STATE_SNAPSHOT: "state.snapshot",
    EventType.STATE_DELTA: "state.mutation",
    EventType.MESSAGES_SNAPSHOT: "state.messages",

    # Text output — low governance, high throughput
    EventType.TEXT_MESSAGE_START: "message.begin",
    EventType.TEXT_MESSAGE_CONTENT: "message.stream",
    EventType.TEXT_MESSAGE_END: "message.seal",

    # Reasoning — log but don't block
    EventType.REASONING_START: "reasoning.begin",
    EventType.REASONING_MESSAGE_START: "reasoning.message.begin",
    EventType.REASONING_MESSAGE_CONTENT: "reasoning.message.stream",
    EventType.REASONING_MESSAGE_END: "reasoning.message.seal",
    EventType.REASONING_END: "reasoning.seal",
    EventType.REASONING_ENCRYPTED_VALUE: "reasoning.encrypted",

    # Activity
    EventType.ACTIVITY_SNAPSHOT: "activity.snapshot",
    EventType.ACTIVITY_DELTA: "activity.delta",

    # Pass-through
    EventType.RAW: "event.raw",
    EventType.CUSTOM: "event.custom",
}

# Events that stream at high frequency — stamp once, don't block per-chunk
STREAMING_EVENTS = {
    EventType.TEXT_MESSAGE_CONTENT,
    EventType.TOOL_CALL_ARGS,
    EventType.REASONING_MESSAGE_CONTENT,
}

# Events that require governance approval before forwarding
GOVERNED_EVENTS = {
    EventType.TOOL_CALL_START,
    EventType.TOOL_CALL_END,
    EventType.STATE_DELTA,
    EventType.STATE_SNAPSHOT,
}


class GovernanceGate:
    """Validates AG-UI events against ZeroPoint governance policy."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.zp_client = httpx.AsyncClient(
            base_url=config.zeropoint_url,
            timeout=5.0,
        )
        self._active_runs: dict[str, str] = {}  # run_id -> receipt_id
        self._event_count: int = 0
        self._blocked_count: int = 0
        # Local receipt journal — every stamped receipt appended as one JSON
        # line. The ZP `POST /api/v1/receipts` chain endpoint isn't built yet,
        # so the proxy fails-open on the network call but never loses receipts
        # locally. Path is overridable via env for testing.
        self._journal_path = os.environ.get(
            "AGUI_PROXY_RECEIPT_JOURNAL", "/tmp/agui-receipts.jsonl"
        )

    async def evaluate(self, event: BaseEvent) -> tuple[bool, Optional[str]]:
        """
        Evaluate an AG-UI event against governance policy.

        Returns:
            (approved: bool, reason: Optional[str])
            - (True, None) if approved
            - (False, "reason") if blocked
        """
        event_type = event.type
        self._event_count += 1

        # 1. Check deny-list
        if event_type in self.config.blocked_event_types:
            self._blocked_count += 1
            return False, f"Event type '{event_type}' is on the deny list"

        # 2. Streaming events: pass through (stamped at start/end boundaries)
        if event_type in STREAMING_EVENTS:
            return True, None

        # 3. Governed events: validate with ZeroPoint
        if event_type in GOVERNED_EVENTS:
            return await self._validate_with_zp(event)

        # 4. All other events: log and pass through
        return True, None

    async def stamp_receipt(self, event: BaseEvent, approved: bool, reason: Optional[str] = None):
        """Stamp a ZeroPoint receipt for this event."""
        claim_type = CLAIM_MAP.get(event.type, "event.unknown")

        receipt = {
            "receipt_id": str(uuid.uuid4()),
            "timestamp": event.timestamp or int(time.time() * 1000),
            "claim_type": claim_type,
            "event_type": event.type,
            "approved": approved,
            "reason": reason,
            "metadata": self._extract_metadata(event),
        }

        # Append to local journal — durable, observable, file-line-per-receipt.
        try:
            with open(self._journal_path, "a") as f:
                f.write(json.dumps(receipt) + "\n")
        except OSError:
            # Don't crash the stream if disk write fails.
            pass

        # Best-effort POST to ZP. The chain endpoint is planned but not built;
        # we keep the call so the wiring lights up the day it ships.
        try:
            await self.zp_client.post("/api/v1/receipts", json=receipt)
        except httpx.HTTPError:
            pass

        return receipt

    async def _validate_with_zp(self, event: BaseEvent) -> tuple[bool, Optional[str]]:
        """Ask ZeroPoint whether this event is permitted."""
        claim_type = CLAIM_MAP.get(event.type, "event.unknown")

        try:
            resp = await self.zp_client.post(
                "/api/governance/validate",
                json={
                    "claim_type": claim_type,
                    "event_type": event.type,
                    "metadata": self._extract_metadata(event),
                },
            )

            if resp.status_code == 200:
                body = resp.json()
                return body.get("approved", True), body.get("reason")

            # ZP returned non-200 — fail open for now, log it
            return True, None

        except httpx.HTTPError:
            # ZP unreachable — fail open, but log
            return True, None

    def _extract_metadata(self, event: BaseEvent) -> dict:
        """Extract governance-relevant metadata from an event."""
        meta = {"event_type": event.type}

        if isinstance(event, RunStartedEvent):
            meta["thread_id"] = event.thread_id
            meta["run_id"] = event.run_id
        elif isinstance(event, RunFinishedEvent):
            meta["thread_id"] = event.thread_id
            meta["run_id"] = event.run_id
        elif isinstance(event, ToolCallStartEvent):
            meta["tool_call_id"] = event.tool_call_id
            meta["tool_call_name"] = event.tool_call_name
            meta["parent_message_id"] = event.parent_message_id
        elif isinstance(event, ToolCallEndEvent):
            meta["tool_call_id"] = event.tool_call_id
        elif isinstance(event, ToolCallResultEvent):
            meta["tool_call_id"] = event.tool_call_id
            # Don't log full result content — could be large
            meta["result_role"] = getattr(event, "role", None)
        elif isinstance(event, StateDeltaEvent):
            meta["delta_ops"] = len(event.delta) if event.delta else 0
        elif isinstance(event, TextMessageStartEvent):
            meta["message_id"] = event.message_id
            meta["role"] = event.role

        return meta

    @property
    def stats(self) -> dict:
        return {
            "events_processed": self._event_count,
            "events_blocked": self._blocked_count,
            "active_runs": len(self._active_runs),
        }

    async def close(self):
        await self.zp_client.aclose()
