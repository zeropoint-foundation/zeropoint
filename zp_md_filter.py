"""
zp_md_filter — strip Markdown syntax for clean TTS output.

Used by voice-tuner-server.py (Piper) and kokoro-tuner-server.py (Kokoro).
Import: from zp_md_filter import strip_markdown
"""

import re


def strip_markdown(text: str) -> str:
    """Return text with Markdown syntax removed, suitable for TTS.

    Processing order matters: block elements before inline, fenced code
    before inline code, links/images before bare URLs.
    """
    # ── Fenced code blocks ────────────────────────────────────────
    text = re.sub(r'```[\s\S]*?```', ' code block ', text)
    text = re.sub(r'~~~[\s\S]*?~~~', ' code block ', text)

    # ── Inline code → content ────────────────────────────────────
    text = re.sub(r'`([^`\n]+)`', r'\1', text)
    text = text.replace('`', '')

    # ── Setext heading underlines (=== / ---) → drop ─────────────
    text = re.sub(r'^[=\-]{3,}\s*$', '', text, flags=re.MULTILINE)

    # ── ATX headers → text only ──────────────────────────────────
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)

    # ── Horizontal rules (--- / *** / ___) → drop ────────────────
    text = re.sub(r'^(\*{3,}|-{3,}|_{3,})\s*$', '', text, flags=re.MULTILINE)

    # ── Blockquotes → content ────────────────────────────────────
    text = re.sub(r'^>\s?', '', text, flags=re.MULTILINE)

    # ── Bold-italic ***text*** / ___text___ ──────────────────────
    text = re.sub(r'\*{3}([^*\n]+)\*{3}', r'\1', text)
    text = re.sub(r'_{3}([^_\n]+)_{3}', r'\1', text)

    # ── Bold **text** / __text__ ─────────────────────────────────
    text = re.sub(r'\*{2}([^*\n]+)\*{2}', r'\1', text)
    text = re.sub(r'_{2}([^_\n]+)_{2}', r'\1', text)

    # ── Italic *text* — guard against mid-word matches ───────────
    text = re.sub(r'(?<!\w)\*([^*\n]+)\*(?!\w)', r'\1', text)

    # ── Italic _text_ — word-boundary guard preserves snake_case ─
    text = re.sub(r'(?<!\w)_([^_\n]+)_(?!\w)', r'\1', text)

    # ── Strikethrough ~~text~~ ───────────────────────────────────
    text = re.sub(r'~~([^~\n]+)~~', r'\1', text)

    # ── Images → alt text (or "image" if no alt) ─────────────────
    text = re.sub(
        r'!\[([^\]]*)\]\([^)]*\)',
        lambda m: m.group(1) if m.group(1).strip() else 'image',
        text,
    )

    # ── Links → link text ────────────────────────────────────────
    text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)

    # ── Bare URLs → "link" ───────────────────────────────────────
    # Catches http/https URLs that remain after link stripping.
    # Long URLs confuse phonemizers and explode phoneme budgets.
    text = re.sub(r'https?://\S+', 'link', text)

    # ── Table separator rows (| --- | :---: |) → drop ────────────
    text = re.sub(r'^\|[-| :]+\|\s*$', '', text, flags=re.MULTILINE)

    # ── Table rows → strip pipes, keep cell content ───────────────
    text = re.sub(
        r'^\|(.+)\|\s*$',
        lambda m: re.sub(r'\|', '  ', m.group(1)),
        text,
        flags=re.MULTILINE,
    )

    # ── List markers ─────────────────────────────────────────────
    text = re.sub(r'^[-*+]\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\d+[.)]\s+', '', text, flags=re.MULTILINE)

    # ── HTML tags ────────────────────────────────────────────────
    text = re.sub(r'<[^>]+>', '', text)

    # ── Stray markdown punctuation the above didn't consume ───────
    # * # | are never meaningful in plain prose after the passes above.
    # \ is a markdown escape character. ~ left over from incomplete ~~.
    text = re.sub(r'[*#|\\~]', ' ', text)

    # ── Whitespace normalization ──────────────────────────────────
    text = re.sub(r'\n{2,}', '. ', text)   # paragraph gap → sentence pause
    text = text.replace('\n', ' ')
    text = re.sub(r'\.{2,}', '.', text)    # collapse double-periods
    text = re.sub(r'\s+', ' ', text).strip()

    return text
