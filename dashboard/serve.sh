#!/bin/bash
# ZeroPoint Development Dashboard — local HTTP server
# Usage: ./serve.sh [port]  (default port: 8090)

PORT="${1:-8090}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "ZeroPoint dashboard serving from: $DIR"
echo "Open http://localhost:$PORT/ in your browser"
echo "(Ctrl+C to stop)"
echo ""

cd "$DIR" && python3 -m http.server "$PORT" --bind 127.0.0.1
