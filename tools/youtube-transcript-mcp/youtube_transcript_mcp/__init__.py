"""youtube_transcript_mcp — resilient YouTube transcript retrieval as an MCP tool.

Public surface for reuse (e.g. ZeroPoint phase 2):
    from youtube_transcript_mcp.core import get_transcript, list_transcripts
"""

from .core import (  # noqa: F401
    cache_info,
    clear_cache,
    get_transcript,
    list_transcripts,
)

__version__ = "0.1.0"
