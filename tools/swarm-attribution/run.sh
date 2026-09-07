#!/usr/bin/env bash
# Paired run: identical swarm, identical task, unsigned vs signed blackboard.
set -euo pipefail

MODEL="${SWARM_MODEL:-qwen3.6:27b-mlx}"
export SWARM_MODEL

echo "model: $MODEL"
echo "reminder: start the server with"
echo "  OLLAMA_NUM_PARALLEL=3 OLLAMA_FLASH_ATTENTION=1 \\"
echo "  OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_MAX_LOADED_MODELS=1 ollama serve"
echo

echo "=== condition A: unsigned blackboard ==="
SWARM_SIGNED=0 SWARM_WORKDIR=./run-unsigned python3 swarm.py
python3 analyze.py ./run-unsigned > /dev/null
echo

echo "=== condition B: signed blackboard ==="
SWARM_SIGNED=1 SWARM_WORKDIR=./run-signed python3 swarm.py
python3 analyze.py ./run-signed > /dev/null
echo

python3 - <<'PY'
import json

def load(p):
    with open(p) as fh:
        return json.load(fh)

rows = []
for label, path in (("unsigned", "./run-unsigned"), ("signed", "./run-signed")):
    rep = load(f"{path}/attribution_report.json")
    met = load(f"{path}/_truth/metrics.json")
    for r in rep["reports"]:
        if "accuracy" not in r:
            continue
        rows.append((label, r["analyzer"], r["boundary_recovery"],
                     r["accuracy"], r["accuracy_multi_author_files"]))
    print(f"{label:9} decode {met['decode_tokens_per_sec']} tok/s  "
          f"wall {met['total_wall_seconds']}s  calls {met['calls']}")

print()
print(f"{'condition':10} {'analyzer':13} {'boundary':>9} {'acc':>7} {'multi':>7}")
for label, an, b, a, m in rows:
    print(f"{label:10} {an:13} {b:>9} {a:>7} {str(m):>7}")
PY
