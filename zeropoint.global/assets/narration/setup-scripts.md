# ZeroPoint Setup — Narration Scripts

Paste each script into ElevenLabs, export as MP3, and save with the filename shown.

---

## setup-discovery.mp3

Discovery. When you run zp secure, ZeroPoint begins by understanding your environment. It scans for the shells you use — bash, zsh, fish — and checks for existing configuration like oh-my-zsh or custom rc files. It detects AI tools in your path — Claude Code, Cursor, Copilot, Aider — anything that acts on your behalf. It finds running services like Docker containers and development servers. It identifies sensitive directories — your SSH keys, cloud credentials, GPG keyrings — places where unauthorized access matters. And it checks your network posture — active interfaces, VPN status, firewall configuration. None of this is intrusive. ZeroPoint reads. It doesn't touch. The goal is to build a complete picture of your compute space — every interface that could benefit from governance — and present it to you with a clear recommendation. You decide what gets wrapped.

---

## setup-shell.mp3

Shell Integration. Your shell is the primary governance surface. Every command you type — and every command an agent executes — passes through it. ZeroPoint installs a lightweight preexec hook that evaluates commands before they run. Safe commands like ls, git status, and pwd pass through instantly — sub-millisecond overhead. Dangerous commands — credential exfiltration, recursive deletion of system paths, piping untrusted code to a shell — are blocked outright. Everything in between is logged with a signed receipt. You choose the posture. Permissive mode logs everything but blocks nothing — good for observation. Balanced mode warns on risky operations and blocks critical threats — the recommended default. Strict mode requires explicit approval for anything beyond a curated safe list. And you choose the actor mode — human gets the most trust, supervised mode adds guardrails for AI assistants, and locked mode applies agent-level restrictions. The hook is a single source line in your shell config. Remove it, and ZeroPoint steps back. It's your shell.

---

## setup-ai.mp3

AI Tool Wrapping. This is where ZeroPoint's value becomes most visible. Your AI tools — Claude Code, Cursor, Copilot, Aider — they're powerful, but they act on your behalf with broad permissions. Wrapping them means every action they take produces a signed receipt. For Claude Code, ZeroPoint installs as an MCP governance server — it sees every tool call before execution and evaluates it against your policy set. For Cursor and VS Code, terminal commands are routed through the guard. For other tools, ZeroPoint creates PATH-priority wrapper shims — lightweight scripts that sit between your command and the real binary. The AI tool doesn't know it's being governed. It doesn't need to cooperate. It just becomes accountable. When you launch the dashboard after setup, you can see every action your AI tools have taken, every policy decision, every receipt in the chain. That's the difference between deploying agents on faith and deploying them with proof.

---

## setup-network.mp3

Network and API. The outer perimeter. ZeroPoint watches your sensitive directories — SSH keys, cloud credentials, GPG keyrings — using filesystem events. If something touches those files, you get a receipt. Docker containers can be governed too — container actions produce receipts just like shell commands. For those who want it, ZeroPoint offers a lightweight API proxy that logs outbound requests with full provenance. And network monitoring can track connections from wrapped processes. Not all of this needs to be active on day one. ZeroPoint installs the watchers for sensitive directories by default — that's the minimum responsible posture. Everything else is available when you're ready. Run zp proxy start for the API layer. Run zp net watch for network monitoring. Each piece extends the governance surface without requiring a full reconfiguration.

---

## setup-confirm.mp3

Confirmation. With every interface wrapped, ZeroPoint closes the circle. The confirmation screen shows you exactly what's been secured — your identity, the policy gates that are active, which shells are hooked, which AI tools are wrapped, which directories are watched, and your overall security posture. From this moment forward, every action in your compute space produces a signed receipt. Every receipt chains to its predecessor. The chain becomes proof. Run zp status at any time to verify that everything is active. Run zp secure with the wizard flag to reconfigure. Or open the dashboard at localhost three thousand to see the full picture — your governance surface, visualized. ZeroPoint is now your guardian. It runs transparently in the background, standing watch until needed. Your compute space is secured.
