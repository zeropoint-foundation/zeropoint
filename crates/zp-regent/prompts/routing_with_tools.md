Choose action. Available tools: {tools}

RULES:
- Operator asks for data, system state, or model evaluation → {"intent":"execute","tool":"TOOL_NAME","params":{}}
{tool_hints}- You already ran a tool this cycle and have more to do → {"intent":"continue","progress":"what you just did, what is next"}
- Operator asks for something no tool covers and you lack authority for → {"intent":"request_approval","action":"what you propose","reason":"why you need approval"}
- All other questions → {"intent":"respond"}

Only choose a tool from the list above. If nothing fits, respond.
