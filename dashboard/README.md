# ZeroPoint Development Dashboard

Local dev tool for tracking inference spend and project build status in real time. Working notes quality — for us, not public.

## Files

- `index.html` — the dashboard
- `data/spend.jsonl` — inference spend log (append-only)
- `data/status.json` — current project state (updated manually or by tooling)
- `serve.sh` — one-liner local HTTP server

## Usage

```
cd ~/projects/zeropoint/dashboard
./serve.sh
```

Opens on `http://localhost:8090/` by default. Dashboard auto-refreshes every 30 seconds; manual refresh via the button.

## Spend logging

Inference wrappers append one JSON line per completed call to `data/spend.jsonl`:

```json
{"ts":"2026-07-10T14:30:00Z","provider":"abacus","model":"glm-5.2","input_tokens":1523,"output_tokens":847,"total_cost_usd":0.00278,"context":"regent-tool-dispatch"}
```

Fields:
- `ts` — ISO 8601 timestamp
- `provider` — `anthropic` | `abacus` | `openai` | `local` | ...
- `model` — model identifier
- `input_tokens` / `output_tokens` — integers
- `total_cost_usd` — float (optional; dashboard computes from its price map if absent)
- `context` — optional short label

Dashboard rolls up: session total, today's total, all-time total, per-model breakdown, recent-window burn rate ($/hr and tok/min over last 5 minutes), and last 10 calls.

## Status updates

`data/status.json` is hand-edited (or updated by future tooling) with:

```json
{
  "updated_at": "2026-07-10T14:00:00Z",
  "current_phase": "...",
  "focus": "...",
  "substrate_binary_status": "running on APOLLO",
  "in_progress": ["item 1", "item 2"],
  "next": ["item 1", "item 2"],
  "recent_completions": ["item 1", "item 2"]
}
```

`substrate_binary_status` — dashboard color-codes the indicator dot based on whether the string contains `running` (green), `stop` or `down` (red), or anything else (gray).

## Extension notes

Recent commits, test status, and file-modification tracking aren't wired in yet. Could be added by:
- A cron/watch script that updates `status.json` with git log tail and test results
- A pre-commit hook that appends completions
- The Regent, once operational, maintaining status via chain-anchored receipts

For now, hand-edit `status.json` as work advances.
