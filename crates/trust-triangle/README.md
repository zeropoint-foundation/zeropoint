# trust-triangle

ZeroPoint reference implementation — cross-domain cryptographic governance in action.

Demonstrates the complete trust model with three autonomous nodes from different trust domains communicating over plain HTTPS.

## Scenario

A patient asks their personal AI assistant: *"Why is my prescription late?"*

To answer, the patient's agent must coordinate with two foreign organizations:

- **MediCare Clinic** — holds appointment scheduling data
- **QuickRx Pharmacy** — holds prescription fulfillment data

Each organization runs its own ZeroPoint genesis key. Every data exchange is policy-gated, sanitized, and produces a signed cryptographic receipt. The patient receives their answer along with a full provenance chain proving exactly what data was accessed, by whom, and under what authority.

## What This Demonstrates

- **Key hierarchy** — Three independent genesis keys → operator keys → agent keys
- **Introduction protocol** — Cross-genesis trust establishment (policy-gated)
- **Graduated policy** — Sanitize decisions strip other patients' data
- **Signed receipts** — Every query produces a verifiable receipt
- **Transport agnosticism** — All governance runs over plain HTTPS

## Running

```bash
cargo run -p trust-triangle
```

This starts three HTTP servers representing the patient, clinic, and pharmacy nodes, then runs the full "Why is my prescription late?" scenario with receipt chain output.
