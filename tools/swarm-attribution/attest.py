"""Ed25519 attestation for blackboard writes.

This is the control condition. In the unsigned run the blackboard is exactly
what a filesystem-coordinated swarm produces today: shared mutable state with
no authorship record. In the signed run every appended chunk carries a
detached attestation covering that chunk's bytes.

The trailer format is deliberately in-band and human readable so the analyzer
reads the same file the agents wrote, with no side channel.
"""
import base64
import hashlib
import os
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

CHUNK_OPEN = "<!-- zp:chunk -->"
TRAILER_RE = re.compile(
    r"<!--\s*zp:attest\s+agent=(?P<agent>[a-z0-9_-]+)\s+"
    r"sha256=(?P<sha>[0-9a-f]{64})\s+sig=(?P<sig>[A-Za-z0-9+/=]+)\s*-->"
)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate_keys(keys_dir, agent_ids):
    """Create a keypair per agent. Private keys never leave this directory."""
    os.makedirs(keys_dir, exist_ok=True)
    for agent_id in agent_ids:
        priv_path = os.path.join(keys_dir, f"{agent_id}.priv")
        if os.path.exists(priv_path):
            continue
        priv = Ed25519PrivateKey.generate()
        with open(priv_path, "wb") as fh:
            fh.write(
                priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(os.path.join(keys_dir, f"{agent_id}.pub"), "wb") as fh:
            fh.write(
                priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )


def load_private(keys_dir, agent_id):
    with open(os.path.join(keys_dir, f"{agent_id}.priv"), "rb") as fh:
        return Ed25519PrivateKey.from_private_bytes(fh.read())


def load_public_ring(keys_dir):
    """Map of agent_id -> public key. This is the verifier's whole world."""
    ring = {}
    if not os.path.isdir(keys_dir):
        return ring
    for name in os.listdir(keys_dir):
        if not name.endswith(".pub"):
            continue
        with open(os.path.join(keys_dir, name), "rb") as fh:
            ring[name[:-4]] = Ed25519PublicKey.from_public_bytes(fh.read())
    return ring


def wrap_signed(content, agent_id, keys_dir):
    """Return the chunk as it should be appended, with an attestation."""
    digest = sha256_hex(content)
    sig = load_private(keys_dir, agent_id).sign(digest.encode("ascii"))
    sig_b64 = base64.b64encode(sig).decode("ascii")
    trailer = (
        f"<!-- zp:attest agent={agent_id} sha256={digest} sig={sig_b64} -->"
    )
    return f"{CHUNK_OPEN}\n{content}\n{trailer}\n"


def wrap_unsigned(content):
    """The realistic blackboard write: content, and nothing else."""
    return f"{content}\n"


def parse_signed_chunks(text, ring):
    """Recover (agent_id, content, verified) for each attested chunk."""
    out = []
    for raw in text.split(CHUNK_OPEN):
        raw = raw.strip("\n")
        if not raw:
            continue
        m = TRAILER_RE.search(raw)
        if not m:
            out.append((None, raw, False))
            continue
        content = raw[: m.start()].rstrip("\n")
        agent = m.group("agent")
        claimed = m.group("sha")
        verified = False
        # Bind the signature to the bytes, not to the claim about the bytes.
        if sha256_hex(content) == claimed and agent in ring:
            try:
                ring[agent].verify(
                    base64.b64decode(m.group("sig")), claimed.encode("ascii")
                )
                verified = True
            except InvalidSignature:
                verified = False
        out.append((agent if verified else None, content, verified))
    return out
