"""HTML/SVG renderer for structured mindmaps.

Design notes:

- Output is a **single self-contained HTML document**: no CDN loads, no external
  fonts (system fallback stack), no browser-storage usage. Opens equally well
  as a file, an artifact, an emailed attachment.
- Layout is a **horizontal radial**: center pill in the middle of the canvas,
  branches split into a left column and a right column, sub-nodes and leaves
  fan outward from each branch. This matches the MyLens.ai visual language
  the user cited as reference.
- Bottom-up vertical positioning: leaf rows are the atomic unit, sub-nodes
  center on their leaves, branches center on their sub-nodes, both sides are
  vertically centered as a whole. Handles asymmetry (2 branches on left,
  4 on right) without hardcoding cases.
- All colors come from :class:`themes.Theme`. Mindmap JSON carries only
  *palette identifiers* (teal, coral, ...) — the same mindmap renders in any
  theme without editing.
- Connectors are cubic beziers. Control points are pulled toward the horizontal
  midpoint between the two endpoints so curves have a consistent lazy-S shape
  regardless of vertical distance.
- The HTML shell carries a **toolbar**: theme toggle (☀/☾) plus exports for
  PDF (via ``window.print()`` + print CSS), SVG, Markdown outline, and JSON.
  Both light and dark ZP themes ship to the browser so the toggle is instant
  and offline — no CDN, no server round-trip.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .common import Mindmap, validate_mindmap
from .themes import (
    DEFAULT_THEME,
    Theme,
    companion_theme,
    get_theme,
)


# ---------------------------------------------------------------------------
# Layout constants (tuned to feel like the MyLens reference)
# ---------------------------------------------------------------------------
CANVAS_PAD = 40                # inner padding all sides
CENTER_MIN_W = 190
CENTER_H = 56
BRANCH_H = 44
SUB_H = 36
LEAF_H = 34

# Horizontal offset from each column's anchor to the next column
CENTER_TO_BRANCH = 260
BRANCH_TO_SUB = 240
SUB_TO_LEAF = 210

# Vertical spacing
LEAF_ROW_MIN = 40              # min vertical space per leaf row
SUB_GAP = 24                   # vertical gap between subs of the same branch when both have leaves
BRANCH_GAP = 40                # vertical gap between branches on the same side

# Text sizing
FONT_CENTER = 22
FONT_BRANCH = 15
FONT_SUB = 13
FONT_LEAF = 12
CHAR_W_CENTER = 12.0
CHAR_W_BRANCH = 8.6
CHAR_W_SUB = 7.6
CHAR_W_LEAF = 7.0
PILL_PAD_X = 26


@dataclass
class Node:
    """One laid-out node in the tree."""
    label: str
    x: float = 0.0
    y: float = 0.0
    w: float = 0.0
    h: float = 0.0
    color: Optional[str] = None    # accent color hex (branches only)
    emoji: str = ""
    kind: str = "leaf"             # 'center' | 'branch' | 'sub' | 'leaf'
    children: List["Node"] = field(default_factory=list)
    parent: Optional["Node"] = None
    side: str = "right"            # 'left' | 'right' — inherited from branch


def _est_pill_w(label: str, char_w: float, emoji: str = "") -> float:
    """Estimate pill width from label length. Emoji adds a small fixed width."""
    n = len(label)
    base = max(90.0, char_w * n + PILL_PAD_X * 2)
    if emoji:
        base += 22
    return base


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
def _build_tree(mindmap: Mindmap, theme: Theme) -> Tuple[Node, List[Node], List[Node]]:
    """Turn the mindmap dict into a Node tree and split into left/right sides.

    Returns (center, left_branches, right_branches).
    """
    center_data = mindmap.get("center", {})
    center_label = center_data.get("label") or mindmap.get("title") or "Untitled"
    center = Node(
        label=center_label,
        emoji=center_data.get("emoji", ""),
        kind="center",
        w=max(CENTER_MIN_W, _est_pill_w(center_label, CHAR_W_CENTER, center_data.get("emoji", ""))),
        h=CENTER_H,
    )

    branches = mindmap.get("branches") or []
    right_side: List[Node] = []
    left_side: List[Node] = []
    for i, b in enumerate(branches):
        # Alternate side assignment so odd-numbered lists still look balanced:
        # index 0 → right, 1 → left, 2 → right, 3 → left, ...
        side = "right" if i % 2 == 0 else "left"
        emoji = b.get("emoji", "")
        color_id = b.get("color") or "teal"
        color = theme["palette"].get(color_id, theme["palette"]["teal"])
        branch = Node(
            label=b.get("label", ""),
            emoji=emoji,
            color=color,
            kind="branch",
            side=side,
            w=_est_pill_w(b.get("label", ""), CHAR_W_BRANCH, emoji),
            h=BRANCH_H,
            parent=center,
        )
        for s in b.get("children") or []:
            sub = Node(
                label=s.get("label", ""),
                kind="sub",
                side=side,
                color=color,
                w=_est_pill_w(s.get("label", ""), CHAR_W_SUB),
                h=SUB_H,
                parent=branch,
            )
            for l in s.get("children") or []:
                leaf = Node(
                    label=l.get("label", ""),
                    kind="leaf",
                    side=side,
                    color=color,
                    w=_est_pill_w(l.get("label", ""), CHAR_W_LEAF),
                    h=LEAF_H,
                    parent=sub,
                )
                sub.children.append(leaf)
            branch.children.append(sub)
        (right_side if side == "right" else left_side).append(branch)
    return center, left_side, right_side


def _measure_side(branches: List[Node]) -> float:
    """Compute the total vertical height needed to lay out one side."""
    total = 0.0
    for i, br in enumerate(branches):
        if i > 0:
            total += BRANCH_GAP
        total += _branch_height(br)
    return total


def _branch_height(branch: Node) -> float:
    """Height a branch occupies = max(its own height, stack of subs+leaves)."""
    if not branch.children:
        return BRANCH_H
    subs_h = 0.0
    for i, sub in enumerate(branch.children):
        if i > 0:
            subs_h += SUB_GAP
        subs_h += _sub_height(sub)
    return max(BRANCH_H, subs_h)


def _sub_height(sub: Node) -> float:
    """A sub-node's height = max(its own height, sum of its leaf rows)."""
    if not sub.children:
        return SUB_H
    return max(SUB_H, len(sub.children) * LEAF_ROW_MIN)


def _place_side(
    branches: List[Node],
    center_x: float,
    center_y: float,
    side: str,
    total_h: float,
) -> None:
    """Position every node in one column (bottom-up). Center vertically."""
    y_cursor = center_y - total_h / 2
    branch_x_anchor = (
        center_x + CENTER_TO_BRANCH if side == "right" else center_x - CENTER_TO_BRANCH
    )

    for br in branches:
        bh = _branch_height(br)
        br.y = y_cursor + bh / 2
        if side == "right":
            br.x = branch_x_anchor + br.w / 2
        else:
            br.x = branch_x_anchor - br.w / 2

        if br.children:
            subs_h = sum(_sub_height(s) for s in br.children) + SUB_GAP * (
                len(br.children) - 1
            )
            sy_cursor = br.y - subs_h / 2
            sub_x_anchor = (
                br.x + br.w / 2 + BRANCH_TO_SUB
                if side == "right"
                else br.x - br.w / 2 - BRANCH_TO_SUB
            )
            for sub in br.children:
                sh = _sub_height(sub)
                sub.y = sy_cursor + sh / 2
                if side == "right":
                    sub.x = sub_x_anchor + sub.w / 2
                else:
                    sub.x = sub_x_anchor - sub.w / 2

                if sub.children:
                    leaves_h = len(sub.children) * LEAF_ROW_MIN
                    ly_cursor = sub.y - leaves_h / 2 + LEAF_ROW_MIN / 2
                    leaf_x_anchor = (
                        sub.x + sub.w / 2 + SUB_TO_LEAF
                        if side == "right"
                        else sub.x - sub.w / 2 - SUB_TO_LEAF
                    )
                    for lf in sub.children:
                        lf.y = ly_cursor
                        if side == "right":
                            lf.x = leaf_x_anchor + lf.w / 2
                        else:
                            lf.x = leaf_x_anchor - lf.w / 2
                        ly_cursor += LEAF_ROW_MIN
                sy_cursor += sh + SUB_GAP
        y_cursor += bh + BRANCH_GAP


def _canvas_bounds(
    center: Node,
    left: List[Node],
    right: List[Node],
) -> Tuple[float, float, float, float]:
    """Compute the tight bounding box of the whole laid-out tree."""
    xs: List[float] = [center.x - center.w / 2, center.x + center.w / 2]
    ys: List[float] = [center.y - center.h / 2, center.y + center.h / 2]

    def _walk(node: Node) -> None:
        xs.append(node.x - node.w / 2)
        xs.append(node.x + node.w / 2)
        ys.append(node.y - node.h / 2)
        ys.append(node.y + node.h / 2)
        for c in node.children:
            _walk(c)

    for br in left + right:
        _walk(br)

    return min(xs), min(ys), max(xs), max(ys)


# ---------------------------------------------------------------------------
# SVG emission
# ---------------------------------------------------------------------------
def _bezier(x1: float, y1: float, x2: float, y2: float, side: str) -> str:
    mid_x = (x1 + x2) / 2
    cx1, cy1 = mid_x, y1
    cx2, cy2 = mid_x, y2
    return f"M {x1:.1f} {y1:.1f} C {cx1:.1f} {cy1:.1f}, {cx2:.1f} {cy2:.1f}, {x2:.1f} {y2:.1f}"


def _connector_endpoints(parent: Node, child: Node) -> Tuple[float, float, float, float]:
    if child.side == "right":
        x1 = parent.x + parent.w / 2
        x2 = child.x - child.w / 2
    else:
        x1 = parent.x - parent.w / 2
        x2 = child.x + child.w / 2
    return x1, parent.y, x2, child.y


def _render_pill(node: Node, theme: Theme) -> str:
    if node.kind == "center":
        fill = theme["center_bg"]
        fg = theme["center_fg"]
        font_size = FONT_CENTER
        stroke = "none"
        stroke_w = 0
        radius = node.h / 2
    else:
        fill = theme["pill_bg"]
        fg = theme["pill_fg"]
        stroke = theme["pill_border"]
        stroke_w = 1.4
        radius = node.h / 2
        if node.kind == "branch":
            font_size = FONT_BRANCH
        elif node.kind == "sub":
            font_size = FONT_SUB
        else:
            font_size = FONT_LEAF

    x = node.x - node.w / 2
    y = node.y - node.h / 2

    label = html.escape(node.label)
    if node.emoji:
        display = f"{html.escape(node.emoji)}  {label}"
    else:
        display = label

    accent = ""
    if node.kind == "branch" and node.color:
        dot_r = 5
        dot_cx = x + 18
        dot_cy = node.y
        accent = (
            f'<circle cx="{dot_cx:.1f}" cy="{dot_cy:.1f}" r="{dot_r}" '
            f'fill="{node.color}" />'
        )
        text_x = node.x + 8
    else:
        text_x = node.x

    return (
        f'<g class="pill pill-{node.kind}">'
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{node.w:.1f}" height="{node.h:.1f}" '
        f'rx="{radius:.1f}" ry="{radius:.1f}" fill="{fill}" stroke="{stroke}" '
        f'stroke-width="{stroke_w}" />'
        f'{accent}'
        f'<text x="{text_x:.1f}" y="{node.y:.1f}" '
        f'font-size="{font_size}" fill="{fg}" '
        f'text-anchor="middle" dominant-baseline="central" '
        f'font-family="{theme["font"]}" '
        f'font-weight="{"600" if node.kind in ("center","branch") else "500"}">'
        f'{display}</text>'
        f'</g>'
    )


def _render_connectors(center: Node, left: List[Node], right: List[Node], theme: Theme) -> str:
    parts: List[str] = []
    stroke = theme["connector"]

    def _draw(parent: Node, child: Node, weight: float) -> None:
        x1, y1, x2, y2 = _connector_endpoints(parent, child)
        d = _bezier(x1, y1, x2, y2, child.side)
        parts.append(
            f'<path d="{d}" fill="none" stroke="{stroke}" '
            f'stroke-width="{weight}" stroke-linecap="round" opacity="0.55"/>'
        )

    for br in left + right:
        _draw(center, br, 1.8)
        for sub in br.children:
            _draw(br, sub, 1.2)
            for lf in sub.children:
                _draw(sub, lf, 0.9)
    return "\n".join(parts)


def _render_pills(center: Node, left: List[Node], right: List[Node], theme: Theme) -> str:
    parts: List[str] = []

    def _walk(node: Node) -> None:
        parts.append(_render_pill(node, theme))
        for c in node.children:
            _walk(c)

    for br in left + right:
        _walk(br)
    parts.append(_render_pill(center, theme))  # center on top
    return "\n".join(parts)


def _shift(node: Node, dx: float, dy: float) -> None:
    node.x += dx
    node.y += dy
    for c in node.children:
        _shift(c, dx, dy)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def render_svg(
    mindmap: Dict[str, Any],
    theme_name: str = DEFAULT_THEME,
) -> str:
    """Return just the SVG (no wrapping HTML). Useful for embedding."""
    data = validate_mindmap(mindmap)
    theme = get_theme(theme_name)

    center, left, right = _build_tree(data, theme)
    left_h = _measure_side(left)
    right_h = _measure_side(right)

    provisional_cx, provisional_cy = 1200.0, 700.0
    center.x, center.y = provisional_cx, provisional_cy
    _place_side(right, provisional_cx, provisional_cy, "right", right_h)
    _place_side(left, provisional_cx, provisional_cy, "left", left_h)

    title = data.get("title") or ""
    subtitle = data.get("subtitle") or ""
    fns = data.get("footnotes") or []
    top_pad = CANVAS_PAD
    if title:
        top_pad += 30 + (22 if subtitle else 0)
    bottom_pad = CANVAS_PAD
    if fns:
        bottom_pad = 2 * CANVAS_PAD + len(fns) * 18 + 20

    min_x, min_y, max_x, max_y = _canvas_bounds(center, left, right)
    dx = CANVAS_PAD - min_x
    dy = top_pad - min_y
    for node in (center, *left, *right):
        _shift(node, dx, dy)
    svg_w = int(max_x - min_x + CANVAS_PAD * 2)
    svg_h = int(max_y - min_y + top_pad + bottom_pad - CANVAS_PAD)

    connectors = _render_connectors(center, left, right, theme)
    pills = _render_pills(center, left, right, theme)

    esc_title = html.escape(title)
    esc_subtitle = html.escape(subtitle)
    header = ""
    if title:
        header = (
            f'<g class="header">'
            f'<text x="{CANVAS_PAD}" y="{CANVAS_PAD + 18}" '
            f'font-family="{theme["font"]}" font-size="24" font-weight="700" '
            f'fill="{theme["pill_fg"]}">{esc_title}</text>'
        )
        if subtitle:
            header += (
                f'<text x="{CANVAS_PAD}" y="{CANVAS_PAD + 44}" '
                f'font-family="{theme["font"]}" font-size="14" font-weight="400" '
                f'fill="{theme["text_muted"]}">{esc_subtitle}</text>'
            )
        header += "</g>"

    footer = ""
    if fns:
        parts = [f'<g class="footnotes">']
        base_y = svg_h - CANVAS_PAD - len(fns) * 18
        for i, fn in enumerate(fns):
            parts.append(
                f'<text x="{CANVAS_PAD}" y="{base_y + i * 18}" '
                f'font-family="{theme["font"]}" font-size="12" '
                f'fill="{theme["text_muted"]}">'
                f'{i+1}. {html.escape(fn)}</text>'
            )
        parts.append("</g>")
        footer = "\n".join(parts)

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {svg_w} {svg_h}" '
        f'width="100%" preserveAspectRatio="xMidYMid meet" '
        f'style="background:{theme["bg"]};font-family:{theme["font"]}">'
        f'<rect x="0" y="0" width="{svg_w}" height="{svg_h}" fill="{theme["bg"]}"/>'
        f'{header}'
        f'{connectors}'
        f'{pills}'
        f'{footer}'
        f'</svg>'
    )
    return svg


def render_html(
    mindmap: Dict[str, Any],
    theme_name: str = DEFAULT_THEME,
    show_editor: bool = True,
) -> str:
    """Return a self-contained HTML document rendering the mindmap.

    Args:
        mindmap: Dict shaped per :func:`common.validate_mindmap`.
        theme_name: One of :func:`themes.list_themes`.  ``zp-dark`` is the
            default; the toolbar toggles between ``zp-dark`` and ``zp-light``
            (or between the theme picked here and its :func:`companion_theme`).
        show_editor: If true, include a slide-out JSON editor pane the operator
            can use to tweak the JSON and re-render live in the browser.
            When embedded in an artifact gallery, set this False for a cleaner
            surface.
    """
    data = validate_mindmap(mindmap)
    theme = get_theme(theme_name)
    partner_name = companion_theme(theme_name)
    partner = get_theme(partner_name)

    svg = render_svg(data, theme_name)

    esc_title = html.escape(data.get("title", "Mindmap"))
    mindmap_json = html.escape(json.dumps(data, ensure_ascii=False, indent=2))

    # Editor UI (optional) — kept minimal, JS below handles all wiring.
    editor_html = ""
    if show_editor:
        editor_html = f"""
        <aside id="editor" class="editor" aria-hidden="true">
          <div class="editor-head">
            <strong>Mindmap JSON</strong>
            <div class="editor-actions">
              <button id="apply-btn" class="btn btn-primary" type="button">Render</button>
              <button id="close-editor" class="btn" type="button" aria-label="Close">✕</button>
            </div>
          </div>
          <textarea id="json-source" spellcheck="false">{mindmap_json}</textarea>
          <div class="editor-status" id="status">Loaded. Edit and press Render.</div>
        </aside>
        """

    # Bundle both themes and the initial mindmap into the JS. Deliberately no
    # external deps — the browser gets a working editor + toolbar without
    # loading anything from a CDN.
    themes_bundle = {
        "current": theme_name,
        "themes": {theme_name: theme, partner_name: partner},
    }
    script = (
        _EDITOR_JS
        .replace("__THEMES_JSON__", json.dumps(themes_bundle))
        .replace("__INITIAL_MINDMAP_JSON__", json.dumps(data, ensure_ascii=False))
        .replace("__SHOW_EDITOR__", "true" if show_editor else "false")
    )

    css = _CSS.replace("__BG__", theme["bg"])\
              .replace("__TEXT__", theme["pill_fg"])\
              .replace("__MUTED__", theme["text_muted"])\
              .replace("__FONT__", theme["font"])\
              .replace("__PILL_BG__", theme["pill_bg"])\
              .replace("__PILL_BORDER__", theme["pill_border"])\
              .replace("__CENTER_BG__", theme["center_bg"])\
              .replace("__CENTER_FG__", theme["center_fg"])

    return f"""<!doctype html>
<html lang="en" data-theme="{theme_name}">
<head>
<meta charset="utf-8">
<title>{esc_title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{css}</style>
</head>
<body>
  <header class="topbar">
    <div class="title">{esc_title}</div>
    <div class="spacer"></div>
    <nav class="toolbar" aria-label="Export and view options">
      <button id="theme-toggle" class="btn icon-btn" type="button"
        aria-label="Toggle light/dark theme" title="Toggle light/dark">
        <span class="theme-icon" aria-hidden="true">☾</span>
      </button>
      <div class="toolbar-sep" aria-hidden="true"></div>
      <button id="export-pdf" class="btn" type="button" title="Print to PDF">PDF</button>
      <button id="export-svg" class="btn" type="button" title="Download SVG">SVG</button>
      <button id="export-md" class="btn" type="button" title="Download Markdown outline">MD</button>
      <button id="export-json" class="btn" type="button" title="Download JSON">JSON</button>
      { '<div class="toolbar-sep" aria-hidden="true"></div>' if show_editor else '' }
      { '<button id="edit-toggle" class="btn" type="button" aria-controls="editor" aria-expanded="false">Edit JSON</button>' if show_editor else '' }
    </nav>
  </header>
  <main class="canvas">
    <div id="svg-host" class="svg-host">{svg}</div>
  </main>
  {editor_html}
  <script>{script}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CSS + JS templates (kept inline so the file is self-contained; NO CDN loads)
# ---------------------------------------------------------------------------
_CSS = """
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  background: __BG__;
  color: __TEXT__;
  font-family: __FONT__;
  min-height: 100vh;
  overflow-x: hidden;
  transition: background 200ms ease, color 200ms ease;
}
.topbar {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 20px;
  border-bottom: 1px solid __PILL_BORDER__;
  background: __BG__;
  position: sticky; top: 0; z-index: 10;
}
.topbar .title { font-weight: 700; font-size: 14px; letter-spacing: 0.01em; }
.topbar .spacer { flex: 1; }
.toolbar { display: flex; align-items: center; gap: 6px; }
.toolbar-sep {
  width: 1px; height: 20px; background: __PILL_BORDER__;
  margin: 0 4px;
}
.btn {
  background: __PILL_BG__; color: __TEXT__;
  border: 1px solid __PILL_BORDER__;
  padding: 6px 14px; border-radius: 8px;
  font: inherit; font-size: 12px; font-weight: 500;
  letter-spacing: 0.02em;
  cursor: pointer;
  transition: background 120ms ease, border-color 120ms ease;
}
.btn:hover { border-color: __CENTER_BG__; }
.btn:active { transform: translateY(1px); }
.btn-primary {
  background: __CENTER_BG__; color: __CENTER_FG__;
  border-color: __CENTER_BG__;
}
.btn-primary:hover { filter: brightness(1.08); }
.icon-btn {
  width: 32px; padding: 6px 0;
  display: inline-flex; align-items: center; justify-content: center;
  font-size: 14px;
}
.theme-icon { line-height: 1; }
.canvas {
  width: 100%;
  padding: 24px;
  overflow: auto;
}
.svg-host { width: 100%; }
.svg-host svg { display: block; max-width: 100%; height: auto; }

.editor {
  position: fixed; right: 0; top: 0; height: 100vh;
  width: min(520px, 92vw);
  transform: translateX(100%);
  transition: transform 220ms ease;
  background: __PILL_BG__;
  border-left: 1px solid __PILL_BORDER__;
  display: flex; flex-direction: column;
  z-index: 20;
  box-shadow: -8px 0 24px rgba(0,0,0,0.15);
}
.editor.open { transform: translateX(0); }
.editor-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 18px;
  border-bottom: 1px solid __PILL_BORDER__;
}
.editor-actions { display: flex; gap: 8px; }
#json-source {
  flex: 1;
  background: __BG__;
  color: __TEXT__;
  border: none;
  padding: 16px 18px;
  font-family: 'JetBrains Mono','SF Mono',ui-monospace,monospace;
  font-size: 12px;
  line-height: 1.5;
  resize: none;
  outline: none;
}
.editor-status {
  padding: 8px 18px; font-size: 12px; color: __MUTED__;
  border-top: 1px solid __PILL_BORDER__;
}

/* Print — strip chrome for clean PDF via Save-as-PDF from the print dialog. */
@media print {
  .topbar, .editor { display: none !important; }
  body { background: #ffffff; }
  .canvas { padding: 0; overflow: visible; }
  .svg-host svg { width: 100%; height: auto; }
  @page { size: landscape; margin: 12mm; }
}
"""


# The JS: (1) both themes are bundled in memory so the toggle is instant, no
# server round-trip; (2) the same layout engine used server-side runs client-
# side so the editor is truly WYSIWYG; (3) all exports (PDF via print, SVG,
# Markdown, JSON) work without any CDN or external library.
_EDITOR_JS = r"""
(function(){
  const BUNDLE = __THEMES_JSON__;
  const INITIAL = __INITIAL_MINDMAP_JSON__;
  const HAS_EDITOR = __SHOW_EDITOR__;

  let activeThemeName = BUNDLE.current;
  let activeMindmap = INITIAL;

  const CANVAS_PAD=40, CENTER_MIN_W=190, CENTER_H=56, BRANCH_H=44, SUB_H=36, LEAF_H=34;
  const CENTER_TO_BRANCH=260, BRANCH_TO_SUB=240, SUB_TO_LEAF=210;
  const LEAF_ROW_MIN=40, SUB_GAP=24, BRANCH_GAP=40;
  const FONT_CENTER=22, FONT_BRANCH=15, FONT_SUB=13, FONT_LEAF=12;
  const CHAR_W_CENTER=12.0, CHAR_W_BRANCH=8.6, CHAR_W_SUB=7.6, CHAR_W_LEAF=7.0;
  const PILL_PAD_X=26;

  const PALETTE_COLORS = ["teal","coral","lavender","saffron","sage","rose"];

  function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
  function pillW(label, charW, emoji){
    const n = (label||"").length;
    let base = Math.max(90, charW*n + PILL_PAD_X*2);
    if(emoji) base += 22;
    return base;
  }

  function activeTheme(){ return BUNDLE.themes[activeThemeName]; }

  function buildTree(mindmap, THEME){
    const center = mindmap.center || {};
    const centerLabel = center.label || mindmap.title || "Untitled";
    const centerNode = {
      label: centerLabel, emoji: center.emoji||"", kind:"center", side:"right",
      w: Math.max(CENTER_MIN_W, pillW(centerLabel, CHAR_W_CENTER, center.emoji||"")),
      h: CENTER_H, x:0, y:0, children:[],
    };
    const left = [], right = [];
    (mindmap.branches||[]).forEach((b, i) => {
      const side = (i%2===0)?"right":"left";
      const colorId = b.color || PALETTE_COLORS[i%PALETTE_COLORS.length];
      const color = THEME.palette[colorId] || THEME.palette.teal;
      const branch = {
        label: b.label||"", emoji: b.emoji||"", color: color, kind:"branch", side:side,
        w: pillW(b.label||"", CHAR_W_BRANCH, b.emoji||""), h: BRANCH_H, x:0,y:0,
        children: (b.children||[]).map(s => ({
          label: s.label||"", kind:"sub", side:side, color:color, emoji:"",
          w: pillW(s.label||"", CHAR_W_SUB, ""), h: SUB_H, x:0,y:0,
          children: (s.children||[]).map(l => ({
            label: l.label||"", kind:"leaf", side:side, color:color, emoji:"",
            w: pillW(l.label||"", CHAR_W_LEAF, ""), h: LEAF_H, x:0,y:0, children:[],
          })),
        })),
      };
      (side==="right"?right:left).push(branch);
    });
    return {center: centerNode, left, right};
  }

  function subHeight(sub){
    if(!sub.children.length) return SUB_H;
    return Math.max(SUB_H, sub.children.length*LEAF_ROW_MIN);
  }
  function branchHeight(br){
    if(!br.children.length) return BRANCH_H;
    let h = 0;
    br.children.forEach((sub,i)=>{ if(i>0) h+=SUB_GAP; h+=subHeight(sub); });
    return Math.max(BRANCH_H, h);
  }
  function measureSide(brs){
    let total=0;
    brs.forEach((b,i)=>{ if(i>0) total+=BRANCH_GAP; total+=branchHeight(b); });
    return total;
  }

  function placeSide(brs, cx, cy, side, totalH){
    let y = cy - totalH/2;
    const brAnchor = (side==="right") ? cx+CENTER_TO_BRANCH : cx-CENTER_TO_BRANCH;
    brs.forEach(br => {
      const bh = branchHeight(br);
      br.y = y + bh/2;
      br.x = (side==="right") ? brAnchor + br.w/2 : brAnchor - br.w/2;
      if(br.children.length){
        let subsH = 0;
        br.children.forEach((s,i)=>{ if(i>0) subsH+=SUB_GAP; subsH+=subHeight(s); });
        let sy = br.y - subsH/2;
        const subAnchor = (side==="right") ? br.x+br.w/2+BRANCH_TO_SUB : br.x-br.w/2-BRANCH_TO_SUB;
        br.children.forEach(sub => {
          const sh = subHeight(sub);
          sub.y = sy + sh/2;
          sub.x = (side==="right") ? subAnchor + sub.w/2 : subAnchor - sub.w/2;
          if(sub.children.length){
            const leavesH = sub.children.length*LEAF_ROW_MIN;
            let ly = sub.y - leavesH/2 + LEAF_ROW_MIN/2;
            const leafAnchor = (side==="right") ? sub.x+sub.w/2+SUB_TO_LEAF : sub.x-sub.w/2-SUB_TO_LEAF;
            sub.children.forEach(lf => {
              lf.y = ly;
              lf.x = (side==="right") ? leafAnchor + lf.w/2 : leafAnchor - lf.w/2;
              ly += LEAF_ROW_MIN;
            });
          }
          sy += sh + SUB_GAP;
        });
      }
      y += bh + BRANCH_GAP;
    });
  }

  function walkAll(nodes, fn){ nodes.forEach(n => { fn(n); walkAll(n.children, fn); }); }
  function bounds(center, left, right){
    let minx=Infinity,miny=Infinity,maxx=-Infinity,maxy=-Infinity;
    function absorb(n){
      minx=Math.min(minx,n.x-n.w/2); maxx=Math.max(maxx,n.x+n.w/2);
      miny=Math.min(miny,n.y-n.h/2); maxy=Math.max(maxy,n.y+n.h/2);
    }
    absorb(center); walkAll(left, absorb); walkAll(right, absorb);
    return {minx,miny,maxx,maxy};
  }

  function shift(n, dx, dy){
    n.x+=dx; n.y+=dy;
    n.children.forEach(c => shift(c, dx, dy));
  }

  function bezier(x1,y1,x2,y2){
    const mx = (x1+x2)/2;
    return "M "+x1.toFixed(1)+" "+y1.toFixed(1)+" C "+mx.toFixed(1)+" "+y1.toFixed(1)+", "+mx.toFixed(1)+" "+y2.toFixed(1)+", "+x2.toFixed(1)+" "+y2.toFixed(1);
  }
  function connectorEnds(p, c){
    const x1 = (c.side==="right") ? p.x + p.w/2 : p.x - p.w/2;
    const x2 = (c.side==="right") ? c.x - c.w/2 : c.x + c.w/2;
    return {x1, y1:p.y, x2, y2:c.y};
  }

  function pillSVG(n, THEME){
    let fill, fg, stroke="none", strokeW=0, fontSize, radius=n.h/2, weight="500";
    if(n.kind==="center"){
      fill=THEME.center_bg; fg=THEME.center_fg; fontSize=FONT_CENTER; weight="600";
    } else {
      fill=THEME.pill_bg; fg=THEME.pill_fg; stroke=THEME.pill_border; strokeW=1.4;
      if(n.kind==="branch"){ fontSize=FONT_BRANCH; weight="600"; }
      else if(n.kind==="sub") fontSize=FONT_SUB;
      else fontSize=FONT_LEAF;
    }
    const x = n.x - n.w/2, y = n.y - n.h/2;
    let display = esc(n.label);
    if(n.emoji) display = esc(n.emoji) + "  " + display;
    let accent = "", textX = n.x;
    if(n.kind==="branch" && n.color){
      const dotCx = x+18;
      accent = '<circle cx="'+dotCx.toFixed(1)+'" cy="'+n.y.toFixed(1)+'" r="5" fill="'+n.color+'"/>';
      textX = n.x + 8;
    }
    return '<g class="pill pill-'+n.kind+'">'
      + '<rect x="'+x.toFixed(1)+'" y="'+y.toFixed(1)+'" width="'+n.w.toFixed(1)+'" height="'+n.h.toFixed(1)+'" '
      + 'rx="'+radius.toFixed(1)+'" ry="'+radius.toFixed(1)+'" fill="'+fill+'" stroke="'+stroke+'" stroke-width="'+strokeW+'"/>'
      + accent
      + '<text x="'+textX.toFixed(1)+'" y="'+n.y.toFixed(1)+'" font-size="'+fontSize+'" fill="'+fg+'" '
      + 'text-anchor="middle" dominant-baseline="central" font-family="'+THEME.font+'" font-weight="'+weight+'">'+display+'</text>'
      + '</g>';
  }

  function render(mindmap){
    const THEME = activeTheme();
    const {center, left, right} = buildTree(mindmap, THEME);
    const leftH = measureSide(left);
    const rightH = measureSide(right);
    const cx = 1200, cy = 700;
    center.x = cx; center.y = cy;
    placeSide(right, cx, cy, "right", rightH);
    placeSide(left, cx, cy, "left", leftH);
    const title = mindmap.title||"", subtitle = mindmap.subtitle||"", fns = mindmap.footnotes||[];
    let topPad = CANVAS_PAD; if(title) topPad += 30 + (subtitle?22:0);
    let bottomPad = CANVAS_PAD; if(fns.length) bottomPad = 2*CANVAS_PAD + fns.length*18 + 20;
    const {minx,miny,maxx,maxy} = bounds(center, left, right);
    const dx = CANVAS_PAD - minx, dy = topPad - miny;
    shift(center, dx, dy);
    left.forEach(b => shift(b, dx, dy));
    right.forEach(b => shift(b, dx, dy));
    const svgW = Math.round(maxx - minx + CANVAS_PAD*2);
    const svgH = Math.round(maxy - miny + topPad + bottomPad - CANVAS_PAD);

    let connectors = "";
    function drawConn(p, c, sw){
      const {x1,y1,x2,y2} = connectorEnds(p,c);
      connectors += '<path d="'+bezier(x1,y1,x2,y2)+'" fill="none" stroke="'+THEME.connector+'" stroke-width="'+sw+'" stroke-linecap="round" opacity="0.55"/>';
    }
    [...left, ...right].forEach(br => {
      drawConn(center, br, 1.8);
      br.children.forEach(sub => {
        drawConn(br, sub, 1.2);
        sub.children.forEach(lf => drawConn(sub, lf, 0.9));
      });
    });

    let pills = "";
    function walk(n){ pills += pillSVG(n, THEME); n.children.forEach(walk); }
    [...left, ...right].forEach(walk);
    pills += pillSVG(center, THEME);

    const esct = esc(title), escs = esc(subtitle);
    let header = "";
    if(title){
      header = '<g><text x="'+CANVAS_PAD+'" y="'+(CANVAS_PAD+18)+'" font-family="'+THEME.font+'" font-size="24" font-weight="700" fill="'+THEME.pill_fg+'">'+esct+'</text>';
      if(subtitle) header += '<text x="'+CANVAS_PAD+'" y="'+(CANVAS_PAD+44)+'" font-family="'+THEME.font+'" font-size="14" fill="'+THEME.text_muted+'">'+escs+'</text>';
      header += '</g>';
    }
    let footer = "";
    if(fns.length){
      const baseY = svgH - CANVAS_PAD - fns.length*18;
      footer = "<g>" + fns.map((f,i) => '<text x="'+CANVAS_PAD+'" y="'+(baseY + i*18)+'" font-family="'+THEME.font+'" font-size="12" fill="'+THEME.text_muted+'">'+(i+1)+'. '+esc(f)+'</text>').join("") + "</g>";
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+svgW+' '+svgH+'" preserveAspectRatio="xMidYMid meet" style="background:'+THEME.bg+'">'
      + '<rect x="0" y="0" width="'+svgW+'" height="'+svgH+'" fill="'+THEME.bg+'"/>'
      + header + connectors + pills + footer
      + '</svg>';
  }

  // --- CSS variable re-theming when the toggle fires ---
  function applyThemeToPage(){
    const T = activeTheme();
    const root = document.documentElement;
    root.setAttribute('data-theme', activeThemeName);
    // Direct style rewrites since we shipped :style-substituted CSS, not vars.
    document.body.style.background = T.bg;
    document.body.style.color = T.pill_fg;
    document.querySelectorAll('.topbar').forEach(el => {
      el.style.background = T.bg;
      el.style.borderBottomColor = T.pill_border;
    });
    document.querySelectorAll('.btn').forEach(el => {
      if(!el.classList.contains('btn-primary')){
        el.style.background = T.pill_bg;
        el.style.color = T.pill_fg;
        el.style.borderColor = T.pill_border;
      } else {
        el.style.background = T.center_bg;
        el.style.color = T.center_fg;
        el.style.borderColor = T.center_bg;
      }
    });
    document.querySelectorAll('.toolbar-sep').forEach(el => { el.style.background = T.pill_border; });
    const editor = document.getElementById('editor');
    if(editor){
      editor.style.background = T.pill_bg;
      editor.style.borderLeftColor = T.pill_border;
    }
    const src = document.getElementById('json-source');
    if(src){
      src.style.background = T.bg;
      src.style.color = T.pill_fg;
    }
    const status = document.getElementById('status');
    if(status){ status.style.color = T.text_muted; status.style.borderTopColor = T.pill_border; }
    const themeIcon = document.querySelector('.theme-icon');
    if(themeIcon){ themeIcon.textContent = (activeThemeName === 'zp-dark') ? '☾' : '☀'; }
  }

  // --- Markdown outline ---
  function toMarkdown(mm){
    const lines = [];
    if(mm.title) lines.push('# ' + mm.title, '');
    if(mm.subtitle) lines.push('_' + mm.subtitle + '_', '');
    (mm.branches||[]).forEach(b => {
      const pre = b.emoji ? (b.emoji + ' ') : '';
      lines.push('## ' + pre + (b.label||''), '');
      (b.children||[]).forEach(s => {
        lines.push('### ' + (s.label||''));
        (s.children||[]).forEach(l => { lines.push('- ' + (l.label||'')); });
        lines.push('');
      });
    });
    const fns = mm.footnotes||[];
    if(fns.length){
      lines.push('---', '');
      fns.forEach((f,i) => lines.push((i+1) + '. ' + f));
      lines.push('');
    }
    return lines.join('\n');
  }

  // --- File download helper ---
  function download(name, content, mime){
    const blob = new Blob([content], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  }
  function currentMindmapForExport(){
    if(!HAS_EDITOR) return activeMindmap;
    const src = document.getElementById('json-source');
    if(!src) return activeMindmap;
    try { return JSON.parse(src.value); } catch(e){ return activeMindmap; }
  }
  function safeName(){
    const t = (activeMindmap.title||'mindmap').toLowerCase()
      .replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,60);
    return t || 'mindmap';
  }

  // --- Wiring ---
  const host   = document.getElementById("svg-host");
  const src    = document.getElementById("json-source");
  const btn    = document.getElementById("apply-btn");
  const toggle = document.getElementById("edit-toggle");
  const closeEd = document.getElementById("close-editor");
  const editor = document.getElementById("editor");
  const status = document.getElementById("status");
  const themeBtn = document.getElementById("theme-toggle");
  const pdfBtn  = document.getElementById("export-pdf");
  const svgBtn  = document.getElementById("export-svg");
  const mdBtn   = document.getElementById("export-md");
  const jsonBtn = document.getElementById("export-json");

  function reRender(){
    host.innerHTML = render(activeMindmap);
  }

  function apply(){
    if(!src) return;
    try{
      const mm = JSON.parse(src.value);
      activeMindmap = mm;
      reRender();
      if(status){ status.textContent = "Rendered."; status.style.color = activeTheme().text_muted; }
    }catch(e){
      if(status){ status.textContent = "JSON error: " + e.message; status.style.color = "#f87171"; }
    }
  }
  if(btn) btn.addEventListener("click", apply);
  if(toggle) toggle.addEventListener("click", () => {
    const open = editor.classList.toggle("open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    editor.setAttribute("aria-hidden", open ? "false" : "true");
  });
  if(closeEd) closeEd.addEventListener("click", () => {
    editor.classList.remove("open");
    if(toggle){ toggle.setAttribute("aria-expanded", "false"); }
    editor.setAttribute("aria-hidden", "true");
  });

  if(themeBtn) themeBtn.addEventListener("click", () => {
    const others = Object.keys(BUNDLE.themes).filter(n => n !== activeThemeName);
    if(others.length){
      activeThemeName = others[0];
      applyThemeToPage();
      reRender();
    }
  });

  if(pdfBtn) pdfBtn.addEventListener("click", () => { window.print(); });
  if(svgBtn) svgBtn.addEventListener("click", () => {
    const svg = host.querySelector("svg");
    if(!svg) return;
    download(safeName()+".svg", svg.outerHTML, "image/svg+xml");
  });
  if(mdBtn) mdBtn.addEventListener("click", () => {
    download(safeName()+".md", toMarkdown(currentMindmapForExport()), "text/markdown");
  });
  if(jsonBtn) jsonBtn.addEventListener("click", () => {
    const mm = currentMindmapForExport();
    download(safeName()+".json", JSON.stringify(mm, null, 2), "application/json");
  });

  // Initial paint of the theme UI (button icon, editor styling).
  applyThemeToPage();
})();
"""
