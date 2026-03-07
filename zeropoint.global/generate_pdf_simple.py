#!/usr/bin/env python3
"""
Generate ZeroPoint Whitepaper PDF using system reportlab if available,
or fall back to a pre-generated binary PDF template.
"""

import sys
import os
from datetime import datetime

# Try to import reportlab - if it fails, we'll create a minimal PDF manually
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("Warning: reportlab not available, creating minimal PDF manually", file=sys.stderr)

OUTPUT_PATH = "/sessions/hopeful-sweet-hypatia/mnt/zeropoint/zeropoint.global/ZeroPoint_Whitepaper_v1.0.pdf"

def create_pdf_with_reportlab():
    """Create PDF using reportlab canvas."""
    c = canvas.Canvas(OUTPUT_PATH, pagesize=letter)
    width, height = letter

    # Colors
    bg_color = HexColor("#0a0a0c")
    accent_color = HexColor("#7eb8da")
    text_color = HexColor("#e0ded9")

    # Set background (approximate with a filled rectangle)
    c.setFillColor(bg_color)
    c.rect(0, 0, width, height, fill=1, stroke=0)

    # Title Page
    c.setFillColor(accent_color)
    c.setFont("Helvetica-Bold", 48)
    c.drawString(1*inch, height - 2.5*inch, "ZeroPoint")

    c.setFont("Helvetica", 14)
    c.setFillColor(text_color)
    c.drawString(1*inch, height - 3.2*inch, "Portable Proof Infrastructure for")
    c.drawString(1*inch, height - 3.5*inch, "Autonomous Agent Systems")

    c.setFont("Helvetica", 12)
    c.drawString(1*inch, height - 4.2*inch, "Cryptographic Proof Primitives for the Agentic Age")

    c.setFont("Courier", 8)
    c.setFillColor(HexColor("#5a5a5e"))
    y_pos = height - 5.5*inch
    c.drawString(1*inch, y_pos, "Version 1.0 — February 2026")
    y_pos -= 0.2*inch
    c.drawString(1*inch, y_pos, "Author: Ken Romero, Founder, ThinkStream Labs")
    y_pos -= 0.2*inch
    c.drawString(1*inch, y_pos, "Website: zeropoint.global")
    y_pos -= 0.2*inch
    c.drawString(1*inch, y_pos, "License: CC BY 4.0 (text); MIT/Apache-2.0 (code)")

    c.setFont("Helvetica-Oblique", 11)
    c.setFillColor(accent_color)
    c.drawString(1*inch, height - 7.5*inch, "Proof produces trust. Trust is infrastructure.")

    c.showPage()
    c.save()
    return True

def create_minimal_pdf():
    """Create a minimal valid PDF manually without reportlab."""
    # This is a minimal PDF structure
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 2500 >>
stream
BT
/F1 48 Tf
72 700 Td
(ZeroPoint) Tj
0 -36 Td
/F1 14 Tf
(Portable Proof Infrastructure for Autonomous Agent Systems) Tj
0 -18 Td
/F1 12 Tf
(Cryptographic Proof Primitives for the Agentic Age) Tj
0 -54 Td
/F1 10 Tf
(Version 1.0 — February 2026) Tj
0 -14 Td
(Author: Ken Romero, Founder, ThinkStream Labs) Tj
0 -14 Td
(Website: zeropoint.global) Tj
0 -14 Td
(License: CC BY 4.0 text; MIT/Apache-2.0 code) Tj
0 -72 Td
/F1 11 Tf
(Proof produces trust. Trust is infrastructure.) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000229 00000 n
0000002778 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
2867
%%EOF
"""

    try:
        with open(OUTPUT_PATH, 'wb') as f:
            f.write(pdf_content)
        return True
    except Exception as e:
        print(f"Error writing PDF: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    try:
        if HAS_REPORTLAB:
            success = create_pdf_with_reportlab()
        else:
            success = create_minimal_pdf()

        if success and os.path.exists(OUTPUT_PATH):
            file_size = os.path.getsize(OUTPUT_PATH)
            if file_size > 0:
                print(f"Success: PDF created at {OUTPUT_PATH}")
                print(f"File size: {file_size} bytes")
                sys.exit(0)

        print(f"Error: PDF file not created properly", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
