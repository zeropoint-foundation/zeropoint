#!/usr/bin/env python3
"""
Phase 3: Split onboard.html into CSS, HTML, and JS.

Before:  crates/zp-server/assets/onboard.html  (3,058 lines — everything)
After:   crates/zp-server/assets/onboard.html   (HTML structure + <link>/<script> refs)
         crates/zp-server/assets/onboard.css    (styles)
         crates/zp-server/assets/onboard.js     (all JS logic)

The split files are also deployed to ~/.zeropoint/assets/ for the hot-reload
path (`./zp-dev.sh html` copies them there).

Run from repo root:  python3 scripts/phase3-split-onboard-html.py
"""

import os
import sys
import shutil

SRC = "crates/zp-server/assets/onboard.html"
CSS_OUT = "crates/zp-server/assets/onboard.css"
JS_OUT  = "crates/zp-server/assets/onboard.js"
HTML_OUT = SRC  # overwrite in place (after backup)


def main():
    if not os.path.exists(SRC):
        print(f"✗ Source file not found: {SRC}")
        sys.exit(1)

    if os.path.exists(CSS_OUT) or os.path.exists(JS_OUT):
        print(f"⚠ Split files already exist — aborting to avoid data loss")
        print(f"  {CSS_OUT}: {'exists' if os.path.exists(CSS_OUT) else 'missing'}")
        print(f"  {JS_OUT}: {'exists' if os.path.exists(JS_OUT) else 'missing'}")
        sys.exit(1)

    with open(SRC, "r") as f:
        content = f.read()

    lines = content.split('\n')
    total = len(lines)
    print(f"Source: {SRC} ({total} lines)\n")

    # ── Find boundaries ──
    style_start = None   # line of <style>
    style_end = None     # line of </style>
    script_start = None  # line of <script>
    script_end = None    # line of </script>

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == '<style>' and style_start is None:
            style_start = i
        elif stripped == '</style>' and style_end is None:
            style_end = i
        elif stripped == '<script>' and script_start is None:
            script_start = i
        elif stripped == '</script>' and script_end is None:
            script_end = i

    if None in (style_start, style_end, script_start, script_end):
        print(f"✗ Could not find all boundaries:")
        print(f"  <style>:  line {style_start}")
        print(f"  </style>: line {style_end}")
        print(f"  <script>: line {script_start}")
        print(f"  </script>: line {script_end}")
        sys.exit(1)

    print(f"Boundaries (0-indexed):")
    print(f"  CSS:  lines {style_start+1}–{style_end+1}  ({style_end - style_start - 1} lines)")
    print(f"  HTML: lines {style_end+2}–{script_start}   ({script_start - style_end - 1} lines)")
    print(f"  JS:   lines {script_start+1}–{script_end+1} ({script_end - script_start - 1} lines)")
    print()

    # ── Extract CSS ──
    # Lines between <style> and </style> (exclusive of the tags)
    css_lines = lines[style_start + 1 : style_end]
    css_content = '\n'.join(css_lines) + '\n'

    # ── Extract JS ──
    # Lines between <script> and </script> (exclusive of the tags)
    js_lines = lines[script_start + 1 : script_end]
    js_content = '\n'.join(js_lines) + '\n'

    # ── Build new HTML ──
    # Everything before <style>, replace <style>...</style> with <link>,
    # keep HTML body, replace <script>...</script> with <script src>
    html_parts = []

    # Head up to (not including) the <style> tag
    html_parts.extend(lines[:style_start])

    # Link to external CSS
    html_parts.append('<link rel="stylesheet" href="/assets/onboard.css">')

    # Everything between </style> and <script> (the </head>, <body>, HTML content)
    html_parts.extend(lines[style_end + 1 : script_start])

    # Also grab the comment block before <script> if it's part of the section
    # Actually the lines between </style> and <script> already include the
    # </head> <body> and all HTML. We just need to add the external script ref.

    # Link to external JS
    html_parts.append('<script src="/assets/onboard.js"></script>')

    # Everything after </script> (closing body/html)
    html_parts.extend(lines[script_end + 1 :])

    html_content = '\n'.join(html_parts)

    # ── Backup ──
    bak = SRC + ".monolith.bak"
    shutil.copy2(SRC, bak)
    print(f"✓ Backed up original → {bak}")

    # ── Write files ──
    with open(CSS_OUT, "w") as f:
        f.write(css_content)
    css_count = len(css_lines)
    print(f"✓ {CSS_OUT} ({css_count} lines)")

    with open(JS_OUT, "w") as f:
        f.write(js_content)
    js_count = len(js_lines)
    print(f"✓ {JS_OUT} ({js_count} lines)")

    with open(HTML_OUT, "w") as f:
        f.write(html_content)
    html_count = html_content.count('\n') + 1
    print(f"✓ {HTML_OUT} ({html_count} lines)")

    print(f"""
══════════════════════════════════════
Phase 3 complete — HTML split done.

Before: {total} lines in one file
After:
  onboard.html  {html_count:>5} lines  (structure + <link>/<script> refs)
  onboard.css   {css_count:>5} lines  (all styles)
  onboard.js    {js_count:>5} lines  (all JS logic)

The HTML references CSS/JS via /assets/ paths, which are served by
the existing ServeDir at ~/.zeropoint/assets/ or the dev source tree.

To hot-reload CSS/JS without rebuilding:
  ./zp-dev.sh html
══════════════════════════════════════""")


if __name__ == "__main__":
    main()
