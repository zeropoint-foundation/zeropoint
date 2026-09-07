#!/usr/bin/env bash
#
# install-dflash-mlx.sh — install DFlash for Apple Silicon into a
# project-local venv under ~/projects/zeropoint/.venvs/dflash-mlx.
#
# Per docs/design/MODEL-DOSSIER-2026-07.md §"Two serializations, one
# artifact" and MODEL-DOSSIER's drafter adoption ceremony — this is
# Step 1 (install the runtime that can host a drafter).
#
# Idempotent — safe to re-run. Refuses to run on non-Darwin / non-arm64.

set -euo pipefail

# ── Preflight ────────────────────────────────────────────────────────

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: DFlash MLX backend requires macOS (Apple Silicon). Detected: $(uname -s)" >&2
    exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
    echo "error: DFlash MLX backend requires Apple Silicon (arm64). Detected: $(uname -m)" >&2
    exit 1
fi

REPO_ROOT="${REPO_ROOT:-$HOME/projects/zeropoint}"
VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venvs/dflash-mlx}"
PY="${PY:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "error: python3 not found in PATH" >&2
    exit 1
fi

PY_VERSION=$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$("$PY" -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$("$PY" -c 'import sys; print(sys.version_info.minor)')

if (( PY_MAJOR < 3 )) || (( PY_MAJOR == 3 && PY_MINOR < 10 )); then
    echo "error: dflash-mlx requires Python >= 3.10. Found $PY_VERSION at $(command -v "$PY")" >&2
    echo "hint: try 'brew install python@3.12' or set PY=/path/to/python3.10+" >&2
    exit 1
fi

echo "== DFlash MLX install =="
echo "  repo root : $REPO_ROOT"
echo "  venv dir  : $VENV_DIR"
echo "  python    : $(command -v "$PY") (v$PY_VERSION)"
echo

# ── Venv ─────────────────────────────────────────────────────────────

if [[ ! -d "$VENV_DIR" ]]; then
    echo "[1/4] creating venv..."
    mkdir -p "$(dirname "$VENV_DIR")"
    "$PY" -m venv "$VENV_DIR"
else
    echo "[1/4] venv exists, reusing"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# ── Pip upgrade ──────────────────────────────────────────────────────

echo "[2/4] upgrading pip..."
python -m pip install --upgrade pip >/dev/null

# ── DFlash install ───────────────────────────────────────────────────

echo "[3/4] installing dflash-mlx (+ bench extras)..."
python -m pip install 'dflash-mlx[bench]'

# ── Verify ───────────────────────────────────────────────────────────

echo "[4/4] verifying install..."
if ! command -v dflash >/dev/null 2>&1; then
    echo "error: 'dflash' not on PATH after install" >&2
    exit 1
fi

echo
echo "== install ok =="
echo "  dflash version : $(dflash --version 2>&1 || echo 'unknown')"
echo "  mlx version    : $(python -c 'import mlx; print(mlx.__version__)' 2>&1 || echo 'unknown')"
echo "  venv path      : $VENV_DIR"
echo
echo "next steps:"
echo "  1. Activate the venv:"
echo "       source $VENV_DIR/bin/activate"
echo "  2. Launch the drafter-accelerated server (auto-resolves drafter):"
echo "       dflash serve --model Qwen/Qwen3-8B"
echo "  3. Verify with curl:"
echo "       curl -s http://127.0.0.1:8000/v1/chat/completions \\"
echo "         -H 'Content-Type: application/json' \\"
echo "         -d '{\"model\":\"Qwen/Qwen3-8B\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}'"
echo "  4. Point Regent's inference base URL at http://127.0.0.1:8000/v1"
echo
echo "See scripts/README-dflash-mlx.md for the drafter-adoption ceremony."
