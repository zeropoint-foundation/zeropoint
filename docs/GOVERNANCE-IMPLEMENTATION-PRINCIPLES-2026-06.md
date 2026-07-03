# Notes from Building Inference Governance — June 2026

**Context:** Things that came up while implementing `ZpGovernedLlmProvider` and the inference receipt chain (Steps 1–4 of `docs/design/routellm-inference-governance-2026-06.md`). Fresh observations — worth revisiting after the next arc to see which ones hold.

---

**On config vs chain for governed values.**
`selected_model` in `~/.ironclaw/config.toml` was the concrete problem case. Config values are unsigned, unwitnessed, and invisible to the chain — you can't query what the model was set to last Tuesday, or attribute when it changed. For any value where auditability matters, the chain is the right home. We replaced `selected_model` with `preference:llm:policy:set`. Step 5 (retiring the TOML field and reading from chain at startup) finishes that migration. The rough heuristic: if you're reading from config to decide what governed behavior to permit, the chain should probably be authoritative instead.

**On what belongs in policy vs delegation.**
We started with `InferencePolicyData` carrying `model_allowlist`, `schema_compat`, and `circuit_breaker_threshold`. These are constraints on how a capability is used — they ended up in the wrong layer. The revised architecture stripped them all; the policy receipt now carries only the backend and routing strategy. Restrictions belong in delegation, where they can be narrowed per-operator without touching shared policy. The rough test: policy declares that a capability exists; delegation constrains how it may be used. If a field in a policy receipt is a constraint rather than a declaration, it probably belongs one layer down.

**On capturing both what was asked and what actually happened.**
RouteLLM routes `route-llm` to a real backend and reports which one in the response body. Initially `inference:completed` only recorded token counts — not which model actually ran. That's most of the governance signal gone. We added `model_used` to `ToolCompletionResponse` as a first-class field and receipted both `model_requested` and `model_used`. The general observation: the gap between intent and outcome is often where the interesting governance data is. You can't reconstruct it later if you didn't capture both sides at the time.

**On keeping governance out of the agent's business logic.**
`ZpGovernedLlmProvider` wraps the `LlmProvider` trait. Gate evaluation, policy fetch, receipt emission — all of it happens in the wrapper. IronClaw's `agent_loop.rs`, `dispatcher.rs`, and `commands.rs` didn't change; governance was wired at `app.rs` in a single substitution. The alternative — spreading governance calls through the agent's dispatch logic — would make governance something the agent participates in and has opinions about, which makes it harder to test and easier to bypass. Finding the natural seam and putting governance there seems like the right pattern.

**On calling the gate even when the answer is predetermined.**
With restrictions moved to delegation, the gate's allowlist is empty and it will always say yes to well-formed requests. The tempting shortcut: skip the gate call. But the gate call is what produces `gate:allowed:inference` or `gate:denied:inference`. Without those receipts, there's no chain evidence that governance ran — the chain can't distinguish "governance cleared this" from "governance was skipped." The gate is the record of what happened, not just the thing that makes the decision. Even when delegation has effectively decided already, the gate needs to run so there's a receipt.

---

These mostly feel like the eight design principles getting concrete in a specific context rather than anything new. P1, P7, and P8 show up repeatedly. The two that felt least obvious going in: governance should be structurally separate from the agent (not just a good idea, it changes what you can test and bypass), and the gate runs for its receipts as much as for its decisions. Worth watching whether those generalize.
