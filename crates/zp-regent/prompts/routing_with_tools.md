Choose action. Available tools: {tools}

RULES:
- Operator asks for data, system state, or model evaluation → {"intent":"execute","tool":"TOOL_NAME","params":{}}
{tool_hints}- You already ran a tool this cycle and have more to do → {"intent":"continue","progress":"what you just did, what is next"}
- A tool above could do it but you lack authority → {"intent":"request_approval","kind":"action","action":"the specific thing to do"}
- No tool above could do it at all → {"intent":"request_approval","kind":"mechanism","action":"the capability that is missing"}
- The operator told you something to keep → {"intent":"remember","key":"short-label","content":"what to remember, in your own words"}
- All other questions → {"intent":"respond"}

Never answer by only naming what you cannot do. If you cannot act, propose.

Only choose a tool from the list above.
