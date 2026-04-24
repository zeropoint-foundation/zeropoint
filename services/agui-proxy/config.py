"""Configuration for the AG-UI governance proxy."""

from dataclasses import dataclass, field


@dataclass
class ProxyConfig:
    """Proxy configuration with sensible defaults."""

    # Proxy listens here
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 17020

    # Hermes agent endpoint (upstream)
    hermes_url: str = "http://127.0.0.1:17030"

    # ZeroPoint receipt API
    zeropoint_url: str = "http://127.0.0.1:17010"

    # Governance policy
    # Events in this list are blocked outright (deny-list)
    blocked_event_types: list[str] = field(default_factory=list)

    # If true, unknown/custom events require explicit approval
    strict_mode: bool = False

    # Logging
    log_all_events: bool = True
    log_blocked_events: bool = True

    # Vault credentials to fetch from ZeroPoint and inject into upstream
    # requests as `X-Provider-Key-<name>` headers. The bridge translates these
    # into env vars on the agent subprocess. Empty list disables injection.
    inject_credentials: list[str] = field(default_factory=lambda: ["anthropic", "openai"])

    # Path to ZP session token file. The proxy reads this at startup.
    # Override with env var ZP_SESSION_FILE.
    zp_session_file: str = "~/ZeroPoint/session.json"
