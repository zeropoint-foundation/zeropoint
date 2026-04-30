"""Unit tests for the receipts sub-namespace (c)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from zeropoint import (
    AuditEntry,
    ChainError,
    ChainHead,
    Receipt,
    ReceiptAck,
    VerifyResult,
    ZeroPointClient,
    ZeroPointError,
)


# ── success — typed response parsing ─────────────────────────────────


@respx.mock
def test_generate_returns_typed_receipt(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/receipts/generate").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "rcpt-001",
                "receipt_type": "execution",
                "content_hash": "deadbeef",
                "signature": "sig-base64",
                "claims": {"k": "v"},
            },
        )
    )
    rcpt = client.receipts.generate("execution", {"k": "v"})
    assert isinstance(rcpt, Receipt)
    assert rcpt.id == "rcpt-001"
    assert rcpt.signature == "sig-base64"


@respx.mock
def test_chain_head_and_entries_parse_typed(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/audit/chain-head").mock(
        return_value=httpx.Response(
            200,
            json={
                "entry_hash": "h-tip",
                "sequence": 401,
                "timestamp": "2026-04-26T00:00:00Z",
            },
        )
    )
    respx.get(f"{base_url}/api/v1/audit/entries").mock(
        return_value=httpx.Response(
            200,
            json={
                "entries": [
                    {
                        "entry_hash": "h1",
                        "prev_hash": None,
                        "timestamp": "2026-04-26T00:00:00Z",
                    },
                    {
                        "entry_hash": "h2",
                        "prev_hash": "h1",
                        "timestamp": "2026-04-26T00:00:01Z",
                    },
                ]
            },
        )
    )
    head = client.receipts.chain_head()
    entries = client.receipts.chain_entries(limit=2)
    assert isinstance(head, ChainHead)
    assert head.entry_hash == "h-tip"
    assert head.sequence == 401
    assert len(entries) == 2
    assert all(isinstance(e, AuditEntry) for e in entries)
    assert entries[1].prev_hash == "h1"


@respx.mock
def test_verify_chain_passed_returns_verify_result(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/audit/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "passed": True,
                "entries_checked": 401,
                "signature_checks": 11,
                "signature_failures": 0,
                "findings": [],
                "rules_checked": ["P1", "P2", "M3", "M4", "S1"],
                "chain_head": "h-tip",
            },
        )
    )
    r = client.receipts.verify_chain()
    assert isinstance(r, VerifyResult)
    assert r.passed is True
    assert r.entries_checked == 401
    assert r.signature_failures == 0


# ── error response handling ──────────────────────────────────────────


@respx.mock
def test_verify_chain_failed_with_raise_raises_chain_error(
    client: ZeroPointClient, base_url: str
) -> None:
    payload = {
        "passed": False,
        "entries_checked": 12,
        "signature_checks": 12,
        "signature_failures": 1,
        "findings": [
            {"rule": "S1", "entry_id": "h-broken", "description": "bad sig"}
        ],
        "rules_checked": ["P1", "P2", "M3", "M4", "S1"],
    }
    respx.get(f"{base_url}/api/v1/audit/verify").mock(
        return_value=httpx.Response(200, json=payload)
    )
    with pytest.raises(ChainError) as excinfo:
        client.receipts.verify_chain(raise_on_failure=True)
    assert excinfo.value.body == payload


@respx.mock
def test_submit_external_500_raises_zeropoint_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/receipts").mock(
        return_value=httpx.Response(500, json={"error": "store unavailable"})
    )
    with pytest.raises(ZeroPointError) as excinfo:
        client.receipts.submit_external({"id": "rcpt-x", "receipt_type": "external"})
    assert excinfo.value.status_code == 500


# ── request payload / construction ───────────────────────────────────


@respx.mock
def test_generate_sends_receipt_type_and_claims_in_body(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.post(f"{base_url}/api/v1/receipts/generate").mock(
        return_value=httpx.Response(
            200, json={"id": "rcpt-001", "receipt_type": "execution"}
        )
    )
    client.receipts.generate("execution", {"action": "tool_call", "tool": "x"})
    body = json.loads(route.calls[0].request.content)
    assert body == {
        "receipt_type": "execution",
        "claims": {"action": "tool_call", "tool": "x"},
    }


@respx.mock
def test_submit_external_round_trips_ack(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/receipts").mock(
        return_value=httpx.Response(
            200,
            json={"accepted": True, "receipt_id": "rcpt-x", "entry_hash": "h-x"},
        )
    )
    ack = client.receipts.submit_external({"id": "rcpt-x"})
    assert isinstance(ack, ReceiptAck)
    assert ack.accepted is True
    assert ack.entry_hash == "h-x"


@respx.mock
def test_chain_entries_sends_limit_and_offset_query(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.get(f"{base_url}/api/v1/audit/entries").mock(
        return_value=httpx.Response(200, json={"entries": []})
    )
    client.receipts.chain_entries(limit=50, offset=200)
    qp = dict(route.calls[0].request.url.params)
    assert qp == {"limit": "50", "offset": "200"}
