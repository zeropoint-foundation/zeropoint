# swarm-attribution

Can you tell which agent wrote what, from a filesystem blackboard alone?

The Moonshot episode described the coordination substrate that makes agent
swarms viable as "a unified global store, which is the file system" — agents
post-trained to pass messages and share mutable state. That works for an
attack swarm, which has no insider-threat model: every member is cooperative
by construction, so nobody ever needs to verify anybody. A *defence* swarm
running on your own infrastructure has to answer "is this agent mine, and what
did it just do" continuously, under adversarial pressure.

This harness tests whether the same substrate can carry that weight. It runs
the same three-agent task twice — once over a plain shared directory, once
where every write carries an Ed25519 attestation — and measures how well
authorship can be reconstructed afterwards.

## What it does

Three agents work through one shared directory over four rounds:

| Round | What happens | Why |
|---|---|---|
| 0 | each agent writes a labelled sample | training data for the stylometric analyzer |
| 1 | each claims findings, writes a remediation | single-author files |
| 2 | each amends a finding written by someone else | **multi-author files** |
| 3 | all agents append to one running summary | **every-author file, interleaved** |

Rounds 2 and 3 are the experiment. Round 1 is the easy case.

Ground truth is written to `_truth/` outside the blackboard. The analyzer
never reads it except to score itself.

## The three analyzers

- **mechanical** — filesystem metadata only. Every agent runs as the same uid
  in the same process; the file carries one mtime for the last write and no
  per-chunk owner. This analyzer abstains, because there is nothing to read.
  That abstention *is* the finding.
- **stylometric** — the steelman. The model is shown labelled writing samples
  for each agent and asked to attribute each passage. The agents are given
  deliberately distinct prose styles so this has a real chance; if attribution
  fails even with differentiated authors and known exemplars, it fails harder
  with a homogeneous swarm.
- **attested** — verifies the Ed25519 trailer on each chunk. Only available in
  the signed condition.

Scoring reports **boundary recovery** separately from accuracy, because
attribution presupposes you recovered the right chunk boundaries. A blackboard
where you cannot tell how many writes occurred has already failed, and
unrecovered writes are counted as misses rather than quietly dropped.

## Running it

```bash
pip install requests cryptography

OLLAMA_NUM_PARALLEL=3 OLLAMA_FLASH_ATTENTION=1 \
OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_MAX_LOADED_MODELS=1 ollama serve

./run.sh
```

Offline pipeline check with canned output, no model required:

```bash
SWARM_MOCK=1 SWARM_WORKDIR=./run-unsigned python3 swarm.py
SWARM_MOCK=1 python3 analyze.py ./run-unsigned
```

### Configuration

Everything is environment variables, see `config.py`:

| Variable | Default | Notes |
|---|---|---|
| `SWARM_MODEL` | `qwen3.6:27b-mlx` | try `27b-mtp-q4_K_M` for faster decode |
| `SWARM_THINK` | `0` | leave off for coordination runs |
| `SWARM_NUM_CTX` | `16384` | not the 256K default — KV cache multiplies per slot |
| `SWARM_SIGNED` | `0` | set by `run.sh` for condition B |
| `SWARM_N_FINDINGS` | `6` | up to 8 |

## Reading the output

The mock run gives a floor, not a prediction — canned text has no section
headings, so segmentation collapses further than it will with a real model.
With a real model the findings files should segment reasonably (the agents
emit `## Remediation` / `## Review` headings) while `summary.md` stays hostile,
since six appends with no structure leave no boundary to find.

What matters is the shape of the comparison:

- If **mechanical** abstains on everything, the filesystem carries no
  authorship. Expected, and worth having as a measurement rather than an
  assertion.
- If **stylometric** lands near the 0.333 chance baseline on multi-author
  files, then content-based attribution does not rescue you either — and note
  this is the generous case, with distinct styles and labelled exemplars.
- If **attested** is 1.0 while the others are at chance, the difference is not
  the model, the task, or the hardware. It is one signature per write.

The throughput numbers in `_truth/metrics.json` are a second result. On
bandwidth-bound hardware — an M4 Pro is 273 GB/s — three parallel slots share
one memory bus, so per-agent decode is roughly a third of single-stream. That
speaks to a claim the episode passes over: "a capable model runs on consumer
hardware" and "a capable model runs *usefully fast* on consumer hardware" are
different statements.

## Caveats

- Ollama serves parallel requests from one loaded model, so the agents share
  weights. This is realistic for a single-host swarm and understates memory
  cost for a distributed one.
- Stylometric attribution here is single-pass and zero-shot. A dedicated
  forensic pipeline with more exemplars would do better. If you want the
  strong version of the claim, raise the exemplar count and re-run before
  citing the number.
- The signed condition proves authorship of *bytes*, not correctness of the
  claim those bytes make. A signed lie is still a lie — it is just an
  attributable one.
