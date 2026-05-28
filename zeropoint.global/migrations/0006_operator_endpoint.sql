-- ZeroPoint Workspace — Foundation Worker Edge Proxy Routing
-- Task #143, Cut A.1.
--
-- Adds zp_server_endpoint to the operators table so the Foundation worker
-- knows where to forward receipt-intents for each operator. NULL means
-- "operator hasn't yet registered an endpoint" — Foundation actions for
-- that operator cannot be relayed until they do.
--
-- See docs/handoffs/foundation-worker-edge-proxy-2026-05.md for the
-- architecture this column supports: worker is a thin edge proxy with no
-- chain, operator's zp-server (reached at this endpoint via Cloudflare
-- Tunnel from APOLLO or equivalent) is the canonical chain holder and
-- signer.

ALTER TABLE operators ADD COLUMN zp_server_endpoint TEXT;
