"""Theme presets — color palettes for the renderer.

Each theme resolves the six palette identifiers (teal, coral, lavender,
saffron, sage, rose) to concrete colors, plus canvas/center/text colors.
Renderers pick a theme; mindmaps carry only palette *identifiers*, so the
same mindmap renders honestly in any theme without editing.

ZeroPoint palette is authoritative — pulled directly from the CSS variables
in `zeropoint.global/tools/mindgraph.html` and matched across the branch
palette against actual colors used in the ZP web surfaces.

    --bg: #0a0a0c;              /* canvas */
    --bg-elevated: #1a1a1f;     /* pill surface */
    --bg-hover: #222228;        /* pill border */
    --accent: #7eb8da;          /* primary — center + connectors */
    --accent-dim: #4a7a96;      /* dimmed accent (used for light-theme conn.) */
    --accent-bright: #a8d4ee;   /* raised accent */
    --text-primary: #e8e8ec;    /* pill text */
    --text-secondary: #8888a0;  /* muted */
"""

from __future__ import annotations

from typing import Dict, TypedDict


class Theme(TypedDict):
    name: str
    bg: str            # canvas background
    center_bg: str     # center pill fill
    center_fg: str     # center pill text
    pill_bg: str       # branch/sub pill fill
    pill_border: str   # branch/sub pill border
    pill_fg: str       # branch/sub pill text
    connector: str     # connector line stroke
    text_muted: str    # subtitle / footnote text
    palette: Dict[str, str]  # branch accent colors keyed by identifier
    font: str          # css font stack


# ---------------------------------------------------------------------------
# ZP palette (the six branch identifiers → concrete ZP colors used across
# the project's HTML/CSS surfaces). Same map is used by both zp-light and
# zp-dark so the color-coded taxonomy is stable across themes.
# ---------------------------------------------------------------------------
_ZP_BRANCH_PALETTE: Dict[str, str] = {
    "teal":     "#94e2d5",
    "coral":    "#f87171",
    "lavender": "#a78bfa",
    "saffron":  "#fbbf24",
    "sage":     "#34d399",
    "rose":     "#fb923c",
}


ZP_DARK: Theme = {
    "name": "zp-dark",
    "bg": "#0a0a0c",
    "center_bg": "#7eb8da",
    "center_fg": "#0a0a0c",
    "pill_bg": "#1a1a1f",
    "pill_border": "#222228",
    "pill_fg": "#e8e8ec",
    "connector": "#7eb8da",
    "text_muted": "#8888a0",
    "palette": _ZP_BRANCH_PALETTE,
    "font": "'Inter','SF Pro Text',system-ui,-apple-system,sans-serif",
}


ZP_LIGHT: Theme = {
    "name": "zp-light",
    "bg": "#f7f7f4",
    "center_bg": "#0a0a0c",
    "center_fg": "#7eb8da",
    "pill_bg": "#ffffff",
    "pill_border": "#d8d8d0",
    "pill_fg": "#0a0a0c",
    "connector": "#4a7a96",
    "text_muted": "#5a5a5e",
    "palette": _ZP_BRANCH_PALETTE,
    "font": "'Inter','SF Pro Text',system-ui,-apple-system,sans-serif",
}


# ---------------------------------------------------------------------------
# Non-ZP presets — retained for callers that want the MyLens-warm or plain-
# monochrome look. Never the default; kept so nothing that already picked
# one of these silently breaks.
# ---------------------------------------------------------------------------
MYLENS: Theme = {
    "name": "mylens",
    "bg": "#f8f4ec",
    "center_bg": "#1d2836",
    "center_fg": "#f4ead2",
    "pill_bg": "#f0e9d9",
    "pill_border": "#d9cdb3",
    "pill_fg": "#2a2a2a",
    "connector": "#333333",
    "text_muted": "#4a4a4a",
    "palette": {
        "teal":     "#3d8f8b",
        "coral":    "#d76b5a",
        "lavender": "#8a7ab8",
        "saffron":  "#c99a2f",
        "sage":     "#7a9070",
        "rose":     "#c1668e",
    },
    "font": "'Inter','SF Pro Text',system-ui,-apple-system,sans-serif",
}


MONOCHROME: Theme = {
    "name": "monochrome",
    "bg": "#ffffff",
    "center_bg": "#1a1a1a",
    "center_fg": "#ffffff",
    "pill_bg": "#ffffff",
    "pill_border": "#1a1a1a",
    "pill_fg": "#1a1a1a",
    "connector": "#1a1a1a",
    "text_muted": "#4a4a4a",
    "palette": {k: "#4a4a4a" for k in _ZP_BRANCH_PALETTE},
    "font": "'Inter',system-ui,-apple-system,sans-serif",
}


_THEMES: Dict[str, Theme] = {
    "zp-dark":    ZP_DARK,
    "zp-light":   ZP_LIGHT,
    "mylens":     MYLENS,
    "monochrome": MONOCHROME,
    # legacy alias — `dark` was the pre-ZP name for the dark theme.
    "dark":       ZP_DARK,
    "brand":      ZP_DARK,
}


DEFAULT_THEME = "zp-dark"


def get_theme(name: str) -> Theme:
    """Look up a theme by name, defaulting to ZP-dark on unknown."""
    return _THEMES.get((name or "").lower(), ZP_DARK)


def list_themes() -> list[str]:
    """Return the built-in theme names, ZP first."""
    return ["zp-dark", "zp-light", "mylens", "monochrome"]


def companion_theme(name: str) -> str:
    """Return the natural light/dark counterpart of a theme, for toggling."""
    n = (name or "").lower()
    if n == "zp-light":
        return "zp-dark"
    if n == "zp-dark":
        return "zp-light"
    if n == "mylens":
        return "zp-dark"
    if n == "monochrome":
        return "zp-dark"
    return "zp-dark"
