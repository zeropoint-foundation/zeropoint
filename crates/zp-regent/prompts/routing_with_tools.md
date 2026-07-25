Choose action. Available tools: governance_posture(), chain_query(limit:N), model_evaluate(model:"name"), system_status(), memory_list(stage?), memory_review(action,review_id?,reason?).

RULES:
- Operator asks for data, system state, or model evaluation → {"intent":"execute","tool":"TOOL_NAME","params":{}}
- All other questions → {"intent":"respond"}
