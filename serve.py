#!/usr/bin/env python3
"""
serve.py — Local dev server for zeropoint.global
Usage: cd ~/projects/zeropoint && python3 serve.py
Then open http://localhost:8470
"""
import http.server
import os

PORT = 8470
WEBROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeropoint.global")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEBROOT, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

if __name__ == "__main__":
    print(f"\n  ZeroPoint Local Preview")
    print(f"  ──────────────────────")
    print(f"  Serving: {WEBROOT}")
    print(f"\n  http://localhost:{PORT}")
    print(f"  http://localhost:{PORT}/whitepaper.html")
    print(f"  http://localhost:{PORT}/course.html")
    print(f"  http://localhost:{PORT}/footprint.html")
    print(f"  http://localhost:{PORT}/playground.html\n")

    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()
