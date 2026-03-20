#!/usr/bin/env python3
"""
ZeroPoint Identity System — Eye mark inspired by Substack auto-generated logo.

Key characteristics of the reference:
  - 3 concentric rings (not 6), bold and visible
  - Strong horizontal eye/almond shape
  - Bright solid center circle (not a glow — a dot)
  - Rings are thick, high contrast against dark background
  - Blue accent (#4A9FD9-ish from the Substack version)
  - Clean, logo-grade simplicity — reads at any size

Assets:
  1. Logo mark (512x512)
  2. Social preview (1280x640)
  3. Banner (1500x500)
  4. Favicon (64x64)
"""

from PIL import Image, ImageDraw, ImageFont, ImageFilter
import math
import os

BG = (10, 10, 12)
RING_BLUE = (74, 159, 217)     # Brighter blue matching Substack version
RING_MID = (60, 130, 185)      # Slightly darker mid ring
RING_OUTER = (45, 100, 150)    # Darkest outer ring
WHITE = (240, 240, 243)
MUTED = (100, 100, 110)

FONTS_DIR = "/sessions/pensive-tender-johnson/mnt/.skills/skills/canvas-design/canvas-fonts"
OUT_DIR = "/sessions/pensive-tender-johnson/mnt/zeropoint/assets/logo"
os.makedirs(OUT_DIR, exist_ok=True)


def draw_eye_mark(draw, cx, cy, scale):
    """
    Draw the eye mark — 3 bold concentric ellipses + solid center dot.

    Landscape orientation: wider than tall. The vertical compression
    creates pointed tips at left and right — the eye silhouette.
    """
    # 3 rings: outer, middle, inner — each progressively brighter and thicker
    # (rx_factor, ry_factor, width, color)
    rings = [
        (1.00, 0.62, max(3, scale * 0.030), RING_OUTER),   # Outer ring
        (0.72, 0.42, max(4, scale * 0.040), RING_MID),      # Middle ring
        (0.46, 0.26, max(5, scale * 0.055), RING_BLUE),     # Inner ring — boldest
    ]

    for rx_f, ry_f, width, color in rings:
        rx = scale * rx_f
        ry = scale * ry_f
        draw.ellipse(
            [cx - rx, cy - ry, cx + rx, cy + ry],
            outline=color,
            width=int(width)
        )

    # Center dot — solid, bright, prominent
    dot_r = scale * 0.075
    draw.ellipse(
        [cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r],
        fill=RING_BLUE
    )
    # Bright core within the dot
    inner_r = dot_r * 0.55
    draw.ellipse(
        [cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
        fill=WHITE
    )


def draw_wordmark(draw, cx, y, size, tracking=0, color=None):
    """Draw 'zeropoint' in Jura Light with wide tracking."""
    font_path = os.path.join(FONTS_DIR, "Jura-Light.ttf")
    if color is None:
        color = (*WHITE, 180)
    try:
        font = ImageFont.truetype(font_path, size)
    except:
        font = ImageFont.load_default()

    text = "zeropoint"
    char_widths = []
    for ch in text:
        bbox = font.getbbox(ch)
        char_widths.append(bbox[2] - bbox[0])
    total_width = sum(char_widths) + tracking * (len(text) - 1)
    x = cx - total_width / 2
    for i, ch in enumerate(text):
        draw.text((x, y), ch, fill=color, font=font)
        x += char_widths[i] + tracking


def generate_logo_mark(size=512):
    """512x512 — GitHub avatar, app icon."""
    # Render at 2x for anti-aliasing
    big = size * 2
    img = Image.new('RGB', (big, big), BG)
    draw = ImageDraw.Draw(img)

    cx, cy = big // 2, big // 2 - 30
    scale = big * 0.40

    draw_eye_mark(draw, cx, cy, scale)
    draw_wordmark(draw, big // 2, big - 130, size=42, tracking=16, color=WHITE)

    img = img.resize((size, size), Image.LANCZOS)
    return img


def generate_social_preview(w=1280, h=640):
    """1280x640 — GitHub social card, Open Graph."""
    img = Image.new('RGB', (w, h), BG)
    draw = ImageDraw.Draw(img)

    mark_cx = int(w * 0.33)
    mark_cy = int(h * 0.48)
    scale = h * 0.40

    draw_eye_mark(draw, mark_cx, mark_cy, scale)

    # Text
    text_x = int(w * 0.58)
    try:
        title_font = ImageFont.truetype(os.path.join(FONTS_DIR, "Jura-Light.ttf"), 52)
        sub_font = ImageFont.truetype(os.path.join(FONTS_DIR, "Jura-Light.ttf"), 18)
        mono_font = ImageFont.truetype(os.path.join(FONTS_DIR, "JetBrainsMono-Regular.ttf"), 13)
    except:
        title_font = sub_font = mono_font = ImageFont.load_default()

    # Title with tracking
    tx = text_x
    for ch in "zeropoint":
        draw.text((tx, int(h * 0.34)), ch, fill=WHITE, font=title_font)
        bbox = title_font.getbbox(ch)
        tx += (bbox[2] - bbox[0]) + 7

    draw.text((text_x, int(h * 0.52)), "portable trust for the agentic age",
              fill=MUTED, font=sub_font)
    draw.text((text_x, int(h * 0.63)), "zeropoint.global",
              fill=RING_BLUE, font=mono_font)

    return img


def generate_banner(w=1500, h=500):
    """1500x500 — X/LinkedIn header."""
    img = Image.new('RGB', (w, h), BG)
    draw = ImageDraw.Draw(img)

    draw_eye_mark(draw, w // 2, h // 2 - 10, h * 0.38)
    draw_wordmark(draw, w // 2, h - 70, size=18, tracking=10, color=MUTED)

    return img


def generate_favicon(size=64):
    """64x64 — browser tab."""
    big = size * 4
    img = Image.new('RGB', (big, big), BG)
    draw = ImageDraw.Draw(img)

    draw_eye_mark(draw, big // 2, big // 2, big * 0.40)

    return img.resize((size, size), Image.LANCZOS)


if __name__ == '__main__':
    print("Generating ZeroPoint identity assets...\n")

    for filename, fn, args, desc in [
        ("zp-mark-512.png", generate_logo_mark, (512,), "GitHub avatar, app icon"),
        ("zp-social-1280x640.png", generate_social_preview, (1280, 640), "GitHub social card"),
        ("zp-banner-1500x500.png", generate_banner, (1500, 500), "X/LinkedIn header"),
        ("zp-favicon-64.png", generate_favicon, (64,), "Browser tab"),
    ]:
        result = fn(*args)
        result.save(os.path.join(OUT_DIR, filename), 'PNG')
        print(f"  ✓ {filename} ({desc})")

    generate_logo_mark(512).save('/sessions/pensive-tender-johnson/mnt/zeropoint/zp-mark-512.png', 'PNG')
    print(f"\nAll assets saved to {OUT_DIR}/")
