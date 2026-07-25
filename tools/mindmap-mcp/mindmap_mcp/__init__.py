"""mindmap-mcp — structured mindmap generation + rendering.

Public API (importable without any MCP dependency):

    from mindmap_mcp.core import extract_mindmap, render_mindmap, from_transcript
    from mindmap_mcp.common import Mindmap, validate_mindmap

The MCP surface (server.py) is a thin wrapper over these functions, mirroring
the shape of youtube-transcript-mcp so ZeroPoint can consume the same core
without the MCP dependency.
"""

__version__ = "0.1.0"
