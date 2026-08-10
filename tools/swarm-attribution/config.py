"""Configuration for the swarm attribution experiment."""
import os

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

# Swarm tier by default. Override with SWARM_MODEL=qwen3.6:27b-q8_0 for the
# capability tier (much slower on bandwidth-bound hardware).
MODEL = os.environ.get("SWARM_MODEL", "qwen3.6:27b-mlx")

# Thinking off for coordination runs -- it multiplies wall clock without
# changing the attribution result. Turn on for scope-adherence work.
THINK = os.environ.get("SWARM_THINK", "0") == "1"

NUM_CTX = int(os.environ.get("SWARM_NUM_CTX", "16384"))
TEMPERATURE = float(os.environ.get("SWARM_TEMP", "0.7"))
REQUEST_TIMEOUT = int(os.environ.get("SWARM_TIMEOUT", "900"))

# Distinct personas exist to give the stylometric analyzer a fighting chance.
# A swarm of identical agents would make the null result trivial and
# uninteresting; we want attribution to fail even when the agents are
# deliberately differentiated.
AGENTS = [
    {
        "id": "kepler",
        "style": (
            "You write in short declarative sentences. You prefer numbered "
            "steps. You avoid adjectives. You never use bullet points."
        ),
    },
    {
        "id": "noether",
        "style": (
            "You write in flowing prose paragraphs. You favour precise "
            "technical vocabulary and occasional subordinate clauses. You "
            "never use numbered lists."
        ),
    },
    {
        "id": "lovelace",
        "style": (
            "You write tersely using bullet points. You lead with the risk. "
            "You use sentence fragments where they are clearer."
        ),
    },
]

WORKDIR = os.environ.get("SWARM_WORKDIR", "./run")
SHARED_DIRNAME = "blackboard"     # what the analyzer is allowed to see
GROUNDTRUTH_DIRNAME = "_truth"    # out of band; analyzer never reads this
KEYS_DIRNAME = "_keys"

# When True, every append carries an Ed25519 attestation trailer.
SIGNED = os.environ.get("SWARM_SIGNED", "0") == "1"

# Offline pipeline check with canned agent output -- no Ollama required.
MOCK = os.environ.get("SWARM_MOCK", "0") == "1"

N_FINDINGS = int(os.environ.get("SWARM_N_FINDINGS", "6"))
