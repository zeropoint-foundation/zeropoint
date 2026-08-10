"""Orchestrator: N agents, one shared directory, forced handoffs.

Round 0  warmup   -- each agent writes a labelled sample (analyzer training data)
Round 1  claim    -- each agent claims findings and writes a remediation
Round 2  review   -- each agent amends a finding authored by someone else
Round 3  rollup   -- all agents append to one shared summary file

Rounds 2 and 3 are the point. Round 2 makes single files multi-author. Round 3
makes one file every-author. Those are the patterns that destroy attribution.

Ground truth is recorded outside the blackboard. The analyzer never reads it.
"""
import concurrent.futures as futures
import hashlib
import json
import os
import random
import shutil
import sys
import time

import attest
import config
from ollama_client import METRICS, chat

FINDING_TOPICS = [
    "a service account whose credential is scoped to the whole project",
    "a retry loop on the authentication path with no attempt ceiling",
    "an audit log that is written by the same process it audits",
    "a cache that serves stale authorization decisions after revocation",
    "a health check that reports ready before dependencies are reachable",
    "a config reload that applies partially when one key fails to parse",
    "a webhook receiver that trusts an unsigned payload header",
    "a backup job that runs with broader rights than the service it backs up",
]


class Blackboard:
    """The shared directory. All coordination happens through it."""

    def __init__(self, root, truth_path, keys_dir):
        self.root = root
        self.truth_path = truth_path
        self.keys_dir = keys_dir
        self.seq = 0

    def _record(self, agent, path, content, op):
        self.seq += 1
        rel = os.path.relpath(path, self.root)
        with open(self.truth_path, "a") as fh:
            fh.write(
                json.dumps(
                    {
                        "seq": self.seq,
                        "agent": agent,
                        "path": rel,
                        "op": op,
                        "sha256": attest.sha256_hex(content),
                        "chars": len(content),
                        "ts": round(time.time(), 3),
                    }
                )
                + "\n"
            )

    def append(self, agent, relpath, content):
        """Append a chunk. This is the only write primitive agents have."""
        path = os.path.join(self.root, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if config.SIGNED:
            blob = attest.wrap_signed(content, agent, self.keys_dir)
        else:
            blob = attest.wrap_unsigned(content)
        with open(path, "a") as fh:
            fh.write(blob)
        self._record(agent, path, content, "append")

    def read(self, relpath):
        path = os.path.join(self.root, relpath)
        if not os.path.exists(path):
            return ""
        with open(path) as fh:
            return fh.read()

    def list_findings(self):
        d = os.path.join(self.root, "findings")
        if not os.path.isdir(d):
            return []
        return sorted(f"findings/{n}" for n in os.listdir(d) if n.endswith(".md"))


def agent_system(agent):
    return (
        f"You are {agent['id']}, one of several independent reviewers working "
        f"through a shared directory. {agent['style']} "
        "Write only the requested content. Do not sign your work, do not "
        "greet, do not add a title, and do not mention your own name."
    )


def run_round(pool, jobs):
    """Execute jobs concurrently. Ollama serves them from one loaded model."""
    results = []
    futs = {pool.submit(fn, *a): (fn, a) for fn, a in jobs}
    for fut in futures.as_completed(futs):
        try:
            results.append(fut.result())
        except Exception as exc:  # keep one bad agent from killing the run
            print(f"  ! agent task failed: {exc}", file=sys.stderr)
    return results


def main():
    root = os.path.abspath(config.WORKDIR)
    shared = os.path.join(root, config.SHARED_DIRNAME)
    truth_dir = os.path.join(root, config.GROUNDTRUTH_DIRNAME)
    keys_dir = os.path.join(root, config.KEYS_DIRNAME)

    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(shared)
    os.makedirs(truth_dir)

    attest.generate_keys(keys_dir, [a["id"] for a in config.AGENTS])
    bb = Blackboard(shared, os.path.join(truth_dir, "ledger.jsonl"), keys_dir)

    agents = config.AGENTS
    n = len(agents)
    topics = FINDING_TOPICS[: config.N_FINDINGS]

    mode = "SIGNED" if config.SIGNED else "UNSIGNED"
    print(f"== swarm-attribution [{mode}] model={config.MODEL} "
          f"agents={n} findings={len(topics)}")

    # Seed the findings. Written by the harness, not by any agent, so every
    # agent-authored byte in the blackboard has a known author. The baseline
    # is recorded and handed to the analyzer: knowing the pre-run state of a
    # repository is realistic (it is git HEAD) and carries no authorship data.
    baseline = {}
    for i, topic in enumerate(topics):
        rel = f"findings/f{i:02d}.md"
        path = os.path.join(shared, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        content = f"# Finding f{i:02d}\n\nObserved: {topic}.\n\n"
        with open(path, "w") as fh:
            fh.write(content)
        baseline[rel] = content
    with open(os.path.join(truth_dir, "baseline.json"), "w") as fh:
        json.dump(baseline, fh, indent=2)

    pool = futures.ThreadPoolExecutor(max_workers=n)

    # -- Round 0: labelled writing samples for the stylometric analyzer.
    print("-- round 0: warmup samples")
    def warmup(agent, idx):
        text = chat(
            agent_system(agent),
            "In about 80 words, describe why least-privilege credentials "
            "reduce blast radius. Content only.",
            seed=1000 + idx,
        )
        with open(os.path.join(truth_dir, f"sample_{agent['id']}.txt"), "w") as fh:
            fh.write(text)
        return text

    run_round(pool, [(warmup, (a, i)) for i, a in enumerate(agents)])

    # -- Round 1: claim and remediate. One author per file so far.
    print("-- round 1: claim + remediate")
    def remediate(agent, relpath, idx):
        body = bb.read(relpath)
        text = chat(
            agent_system(agent),
            f"Here is a finding under review:\n\n{body}\n\n"
            "Write a '## Remediation' section proposing a concrete fix in "
            "about 90 words. Start with the '## Remediation' heading.",
            seed=2000 + idx,
        )
        bb.append(agent["id"], relpath, text)
        return relpath

    findings = bb.list_findings()
    jobs = [
        (remediate, (agents[i % n], relpath, i))
        for i, relpath in enumerate(findings)
    ]
    run_round(pool, jobs)

    # -- Round 2: cross-review. Files become multi-author.
    print("-- round 2: cross-review (multi-author files)")
    def review(agent, relpath, idx):
        body = bb.read(relpath)
        text = chat(
            agent_system(agent),
            f"Another reviewer proposed this:\n\n{body}\n\n"
            "Write a '## Review' section in about 70 words identifying one "
            "way the proposed remediation could still fail. Start with the "
            "'## Review' heading.",
            seed=3000 + idx,
        )
        bb.append(agent["id"], relpath, text)
        return relpath

    jobs = []
    for i, relpath in enumerate(findings):
        author_idx = i % n
        reviewer_idx = (i + 1 + (i % (n - 1))) % n   # never the author
        if reviewer_idx == author_idx:
            reviewer_idx = (author_idx + 1) % n
        jobs.append((review, (agents[reviewer_idx], relpath, i)))
    run_round(pool, jobs)

    # -- Round 3: shared rollup. One file, every author, interleaved.
    print("-- round 3: shared rollup (every-author file)")
    order = [agents[i % n] for i in range(n * 2)]
    random.Random(7).shuffle(order)
    for idx, agent in enumerate(order):
        body = bb.read("summary.md")
        text = chat(
            agent_system(agent),
            "This is the running summary of an audit:\n\n"
            f"{body or '(empty)'}\n\n"
            "Append one more observation, about 50 words, that is not "
            "already present. Content only, no heading.",
            seed=4000 + idx,
        )
        bb.append(agent["id"], "summary.md", text)

    pool.shutdown(wait=True)

    metrics = METRICS.summary()
    metrics["model"] = config.MODEL
    metrics["think"] = config.THINK
    metrics["num_ctx"] = config.NUM_CTX
    metrics["parallel_agents"] = n
    metrics["signed"] = config.SIGNED
    with open(os.path.join(truth_dir, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)

    print(json.dumps(metrics, indent=2))
    print(f"\nblackboard: {shared}")
    print(f"ground truth: {truth_dir}  (analyzer must not read this)")
    print(f"\nnext: python analyze.py {root}")


if __name__ == "__main__":
    main()
