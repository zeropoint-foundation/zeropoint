"""Post-run attribution: reconstruct who wrote what, from the blackboard alone.

Three analyzers, in increasing order of how hard they try:

  mechanical  filesystem metadata only -- mtime, ordering, size
  stylometric an LLM sees labelled samples of each agent and guesses
  attested    verify Ed25519 trailers (only possible in a signed run)

The mechanical and stylometric analyzers are the steelman for "you can
attribute a filesystem blackboard after the fact". Scoring is per chunk, and
per multi-author file, because that is where the claim actually breaks.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

import attest
import config
from ollama_client import chat

CHANCE = 1.0 / len(config.AGENTS)


# --------------------------------------------------------------------------
# Segmentation: recover candidate chunks from the blackboard as-written.

SECTION_RE = re.compile(r"^##\s+", re.M)


def segment(text):
    """Split a file into the units a forensic reader would work with."""
    if attest.CHUNK_OPEN in text:
        parts = [p.strip("\n") for p in text.split(attest.CHUNK_OPEN)]
        return [p for p in parts if p.strip()]
    # Unsigned: no markers exist. Fall back to structural boundaries.
    idxs = [m.start() for m in SECTION_RE.finditer(text)]
    if not idxs:
        blocks = [b.strip() for b in text.split("\n\n") if b.strip()]
        return blocks
    parts, bounds = [], idxs + [len(text)]
    if idxs[0] > 0 and text[: idxs[0]].strip():
        parts.append(text[: idxs[0]].strip())
    for a, b in zip(bounds, bounds[1:]):
        chunk = text[a:b].strip()
        if chunk:
            parts.append(chunk)
    return parts


def strip_trailer(chunk):
    return attest.TRAILER_RE.sub("", chunk).strip()


def load_blackboard(shared, baseline=None):
    """Read the blackboard, minus known pre-run content.

    The baseline is the state of the directory before any agent ran. Handing
    it to the analyzer is realistic -- it is git HEAD -- and it contains no
    authorship information. Subtracting it means we score attribution of the
    changes, which is the actual forensic question.
    """
    baseline = baseline or {}
    files = {}
    for dirpath, _, names in os.walk(shared):
        for name in sorted(names):
            if not name.endswith(".md"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, shared)
            with open(path) as fh:
                text = fh.read()
            prior = baseline.get(rel)
            if prior and text.startswith(prior):
                text = text[len(prior):]
            files[rel] = text
    return files


def load_truth(truth_dir):
    """Ordered ledger of agent-authored chunks. Scoring key only."""
    rows = []
    with open(os.path.join(truth_dir, "ledger.jsonl")) as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    by_file = defaultdict(list)
    for r in rows:
        by_file[r["path"]].append(r)
    return rows, by_file


# --------------------------------------------------------------------------
# Analyzers. Each returns a list of predicted agent ids (or None) aligned to
# the ground-truth chunk order for that file.

def analyze_mechanical(shared, relpath, chunks):
    """Filesystem metadata only.

    Every agent runs as the same uid in the same process. The file carries one
    mtime for the last write, no per-chunk timestamps, and no owner field. The
    only recoverable signal is that chunks are in append order -- which tells
    you sequence, not identity. This analyzer is honest about that.
    """
    return [None] * len(chunks)


def analyze_attested(chunks, ring):
    preds = []
    for chunk in chunks:
        m = attest.TRAILER_RE.search(chunk)
        if not m:
            preds.append(None)
            continue
        content = chunk[: m.start()].rstrip("\n")
        claimed, agent = m.group("sha"), m.group("agent")
        ok = attest.sha256_hex(content) == claimed and agent in ring
        if ok:
            try:
                import base64
                ring[agent].verify(
                    base64.b64decode(m.group("sig")), claimed.encode("ascii")
                )
            except Exception:
                ok = False
        preds.append(agent if ok else None)
    return preds


def analyze_stylometric(chunks, samples):
    """Give the model labelled samples and ask it to attribute each chunk."""
    roster = "\n\n".join(
        f"--- WRITING SAMPLE: {aid} ---\n{text}" for aid, text in samples.items()
    )
    ids = ", ".join(samples)
    preds = []
    for chunk in chunks:
        body = strip_trailer(chunk)
        if not body:
            preds.append(None)
            continue
        answer = chat(
            "You are a forensic authorship analyst. Answer with exactly one "
            "name and nothing else.",
            f"{roster}\n\n--- UNKNOWN PASSAGE ---\n{body}\n\n"
            f"Which author wrote the unknown passage? Choose one of: {ids}.",
            seed=None,
        )
        pick = None
        low = answer.lower()
        for aid in samples:
            if aid in low:
                pick = aid
                break
        preds.append(pick)
    return preds


# --------------------------------------------------------------------------

def score(name, preds_by_file, truth_by_file, multi_author):
    """Score against ground truth.

    Attribution is only meaningful if you first recovered the right chunk
    boundaries. A blackboard where you cannot even tell how many writes
    happened has already failed, so boundary recovery is reported separately
    and unrecovered writes are counted as misses rather than dropped.
    """
    total = correct = abstained = 0
    m_total = m_correct = 0
    recovered = actual_writes = 0
    confusion = Counter()
    boundary_errors = {}

    for relpath, truth_rows in truth_by_file.items():
        truth = [r["agent"] for r in truth_rows]
        preds = preds_by_file.get(relpath, [])
        actual_writes += len(truth)
        recovered += len(preds)
        if len(preds) != len(truth):
            boundary_errors[relpath] = {
                "actual_writes": len(truth),
                "segments_recovered": len(preds),
            }
        # Pad predictions so unrecovered writes score as misses, not as absent.
        padded = list(preds) + [None] * max(0, len(truth) - len(preds))
        for pred, actual in zip(padded, truth):
            total += 1
            if pred is None:
                abstained += 1
            elif pred == actual:
                correct += 1
            else:
                confusion[(actual, pred)] += 1
            if relpath in multi_author:
                m_total += 1
                if pred == actual:
                    m_correct += 1

    return {
        "analyzer": name,
        "writes_in_ground_truth": actual_writes,
        "segments_recovered": recovered,
        "boundary_recovery": (
            round(recovered / actual_writes, 3) if actual_writes else 0.0
        ),
        "files_with_wrong_segment_count": boundary_errors,
        "chunks_scored": total,
        "correct": correct,
        "abstained": abstained,
        "accuracy": round(correct / total, 3) if total else 0.0,
        "accuracy_multi_author_files": (
            round(m_correct / m_total, 3) if m_total else None
        ),
        "multi_author_chunks": m_total,
        "chance_baseline": round(CHANCE, 3),
        "top_confusions": [
            {"actual": a, "predicted": p, "n": c}
            for (a, p), c in confusion.most_common(3)
        ],
    }


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else config.WORKDIR)
    shared = os.path.join(root, config.SHARED_DIRNAME)
    truth_dir = os.path.join(root, config.GROUNDTRUTH_DIRNAME)
    keys_dir = os.path.join(root, config.KEYS_DIRNAME)

    baseline_path = os.path.join(truth_dir, "baseline.json")
    baseline = {}
    if os.path.exists(baseline_path):
        with open(baseline_path) as fh:
            baseline = json.load(fh)

    files = load_blackboard(shared, baseline)
    _, truth_by_file = load_truth(truth_dir)
    multi_author = {
        rel
        for rel, rows in truth_by_file.items()
        if len({r["agent"] for r in rows}) > 1
    }

    samples = {}
    for agent in config.AGENTS:
        p = os.path.join(truth_dir, f"sample_{agent['id']}.txt")
        if os.path.exists(p):
            with open(p) as fh:
                samples[agent["id"]] = fh.read().strip()

    ring = attest.load_public_ring(keys_dir)
    signed_run = any(attest.CHUNK_OPEN in t for t in files.values())

    seg = {rel: segment(text) for rel, text in files.items()}

    reports = []
    reports.append(
        score(
            "mechanical",
            {rel: analyze_mechanical(shared, rel, c) for rel, c in seg.items()},
            truth_by_file,
            multi_author,
        )
    )

    if not config.MOCK:
        reports.append(
            score(
                "stylometric",
                {rel: analyze_stylometric(c, samples) for rel, c in seg.items()},
                truth_by_file,
                multi_author,
            )
        )
    else:
        reports.append({"analyzer": "stylometric", "skipped": "mock mode"})

    if signed_run:
        reports.append(
            score(
                "attested",
                {rel: analyze_attested(c, ring) for rel, c in seg.items()},
                truth_by_file,
                multi_author,
            )
        )
    else:
        reports.append(
            {
                "analyzer": "attested",
                "unavailable": "no attestation trailers in blackboard",
            }
        )

    out = {
        "run": root,
        "signed_run": signed_run,
        "files": len(files),
        "multi_author_files": sorted(multi_author),
        "agents": [a["id"] for a in config.AGENTS],
        "reports": reports,
    }
    with open(os.path.join(root, "attribution_report.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
