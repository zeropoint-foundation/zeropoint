# ZeroPoint AG-UI Governance Proxy

Intercepts the AG-UI event stream between Hermes and its dashboard.
Every event passes through ZeroPoint's receipt system before reaching the UI.

## Architecture

```
Dashboard  <--SSE-->  [Proxy :8900]  <--SSE-->  Hermes :9119
                          |
                     ZeroPoint :3000
                     (receipt API)
```

## Quick start

```bash
cd ~/projects/zeropoint/services/agui-proxy
pip install -r requirements.txt
python proxy.py
```

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| /agent | POST | Main proxy — forwards to Hermes, governs stream |
| /health | GET | Proxy + upstream health |
| /governance/stats | GET | Event counts, blocked counts |
| /governance/block/{type} | POST | Add event type to deny list |
| /governance/block/{type} | DELETE | Remove from deny list |

## How governance works

1. Dashboard POSTs `RunAgentInput` to proxy
2. Proxy forwards to Hermes `/agent`
3. Hermes streams SSE events back
4. For each event:
   - Parse via `ag_ui.core.Event` (discriminated union)
   - Evaluate against governance policy
   - Stamp ZeroPoint receipt
   - If approved: forward to dashboard
   - If blocked: emit `CUSTOM` event with reason
5. All events logged as signed receipts in ZeroPoint
