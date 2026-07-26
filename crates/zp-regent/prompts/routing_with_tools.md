Choose action. Available tools: {tools}

RULES:
- Operator asks for data, system state, or model evaluation → {"intent":"execute","tool":"TOOL_NAME","params":{}}
{tool_hints}- All other questions → {"intent":"respond"}

Only choose a tool from the list above. If nothing fits, respond.
