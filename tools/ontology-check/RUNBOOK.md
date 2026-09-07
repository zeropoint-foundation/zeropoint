# Runbook — first Cartographer catchup (S2 step 2)

Enables the Cartographer for the first time and confirms it processed the
whole chain without silently dropping any of it.

Everything here is reversible. The ontology database is disposable by design
(`crates/zp-ontology/migrations/schema-v1.sql`, KEEL §II.13 P5): it is
rebuildable from the receipt chain, so a bad catchup is recovered by deleting
it and running again, not by repair.

---

## Before you start

**A restart is required.** `ZP_CARTOGRAPHER_ENABLED` is read once, when
`ServerConfig` is built (`crates/zp-server/src/lib.rs:208`), and
`spawn_cartographer_task` returns `None` and never spawns if the flag was
false at boot. There is no runtime toggle — that is the "P3.2 follow-up" the
comment refers to.

**`zp serve` daemonizes, and its log is not where you put it.** The command
forks and returns your prompt; `spawn_serve_daemon` redirects the child's
stdio to `<ZP_HOME>/logs/zp-serve.log` (`crates/zp-cli/src/main.rs:1713`).
Anything you `tee` on the launching command captures only the handful of lines
printed before the fork — sovereignty unlock, and the `zp serve started` line.
Everything after, including every Cartographer line, goes to the daemon's log.

`RUST_LOG` is handled for you *on that path only*: the daemon spawner sets it
to `info` when unset (`main.rs:1736`). Every other path builds the subscriber
from `EnvFilter::from_default_env()` with no fallback (`main.rs:1797`), where
unset means `error`. Setting `RUST_LOG=info` explicitly costs nothing and
removes the distinction.

You do not *need* the log at all: step 4 reads the Cartographer's own cursor
out of the database. The log is corroboration, and useful when something goes
wrong.

---

## 1 — Build and install the current tree

```sh
cd ~/projects/zeropoint
just build && just install
```

`just deploy` also restarts, but its `zp restart` is the tool-targeted path,
not the server. Restart explicitly in step 3 instead.

## 2 — Stop the running server

Find any running server first. `just status` only probes :17770, and a server
on another port will not show up there — nor will it stop, and you will end up
with two.

```sh
pgrep -fl "zp serve"
lsof -nP -iTCP -sTCP:LISTEN | grep -i zp
```

If either prints something, stop it. If both are empty there is nothing
running and you can go straight to step 3.

```sh
pkill -f "zp serve"
sleep 1
pgrep -fl "zp serve"
```

The last line should print nothing.

**Do not paste trailing `#` comments into this shell.** zsh on macOS has
`interactive_comments` off by default, so `#` is not a comment — it is passed
to the command as an argument. `just status # expect: no server` fails with
*"Justfile does not contain recipe `#`"*. Every command block in this runbook
is comment-free for that reason.

## 3 — Start it with the Cartographer on, in the foreground

Own terminal. Foreground so it owns a terminal you can watch and stop with
Ctrl-C; `zp serve` blocks on `run_server(...).await`.

```sh
cd ~/projects/zeropoint
RUST_LOG=info ZP_CARTOGRAPHER_ENABLED=1 zp serve
```

It returns immediately — that is the fork, not a failure. Watch the daemon's
own log instead:

```sh
tail -f ~/ZeroPoint/logs/zp-serve.log
```

The environment survives the fork: `spawn_serve_daemon` uses
`Command::new(current_exe)`, which inherits the parent's environment, so
`ZP_CARTOGRAPHER_ENABLED=1` reaches the daemon.

**Sovereignty first.** Before any of this the binary unlocks Genesis through
whatever provider the machine is configured for, and on a Trezor that means a
physical confirmation:

```
INFO trezor: Requesting CipherKeyValue from Trezor — confirm on device
INFO trezor: Waiting for user confirmation on Trezor...
INFO trezor: Genesis secret decrypted via Trezor CipherKeyValue
```

If it fails with *"Trezor support requires the hw-trezor feature flag"*, the
binary was built without it — `just build` is a plain `cargo build --release`
and `zp-cli`'s defaults do not include `hw-trezor`. Rebuild:

```sh
cargo build --release -p zp-cli --features hw-trezor
```

`-p` is required because the root is a virtual workspace. `--features` adds to
the defaults rather than replacing them, so `biometric-keychain` stays on;
do not substitute `--features full`, which omits it from its own list and
adds `policy-wasm`. No reinstall needed — `/usr/local/bin/zp` is a symlink to
the rebuilt file.

Expect within the first seconds:

```
Cartographer starting                        last_processed_sequence=0
Regent attached ontology read handle (consumer for L4)
```

The second line is S2 step 1 confirming itself.

**Expect a stall here.** `run_catchup`'s batch loop contains no `.await`, so
it never yields: one tokio worker is monopolised for the whole pass while
contending for the same blocking audit mutex the HTTP handlers use. Tens of
seconds on a ~10k chain, visible, not an outage. The server will feel
unresponsive and then recover.

## 4 — Watch it, in a second terminal

```sh
cd ~/projects/zeropoint
python3 tools/ontology-check/catchup_reconcile.py --watch
```

**Check the first line it prints.** It reports the data directory it resolved
and how, mirroring `zp-config` — `ZP_DATA_DIR`, else `ZP_HOME/data`, else
`~/ZeroPoint/data`, with `data_dir` from `<zp_home>/config.toml` if set there.
A wrong path reports "no ontology database" indefinitely, which is
indistinguishable from the flag never having taken, and sends you restarting a
server that was working. Override with `--data-dir` if it disagrees with the
server.

Start it whenever — before the server if you like. It waits up to two minutes
for `ontology.db` to appear, since the Cartographer creates the file on first
open.

```
RUNNING       1,400/10,018    200/s  eta 0m43s [####........................]  14.0%
COMPLETE     10,018/10,018    187/s            [############################] 100.0%
```

Progress is the Cartographer's own `last_processed_sequence` against the
chain's max rowid. No log needed.

| exit | meaning | what to do |
|------|---------|------------|
| 0 | clean — every entry the cursor claims is linked to an object | go to step 5 |
| 1 | entries unlinked, or the view disagrees with itself | step 6 |
| 2 | no ontology database yet | the flag did not take; check step 3 |
| 3 | cursor stopped moving with entries remaining | step 7 |

**The unlinked count is cumulative, not a verdict on this run.** It is the
difference between the cursor and the links across every run the database has
ever had. A store that was damaged weeks ago reports the same number after a
flawless catchup as before it. `--watch` takes a baseline on its first sample
and reports what *this* run processed, linked and lost, separately from what
was already broken — which is the difference between "your last action
destroyed something" and "something was already broken". For a one-shot
before/after, `--snapshot` persists the same baseline to a file.

## 5 — Confirm the Regent can see it

```sh
python3 tools/ontology-check/catchup_reconcile.py
python3 tools/ecosystem-state/ecosystem_state.py
```

Expect `trajectories` above zero from the first, and `zp-ontology` still
reported live by the second.

Then drive one cognitive cycle — put a question to the Regent through
whichever cockpit surface you normally use. In the server log:

```sh
grep -i "trajectory\|ontology" ~/ZeroPoint/logs/zp-serve.log
```

**The S2 exit is two things, and the second is the one that is easy to skip:**
a `cognitive:input:composed` receipt carrying a non-empty ontology class, *and*
a Regent response that demonstrably used it. A populated field is not the exit.
Something has to change because of it.

Note the composition receipt does **not** yet carry an ontology class hash —
that was deliberately left out of `CompositionSummary` while the field was
always empty, because adding it moves the matrix version and would anchor
nothing. Adding it is the next commit, and it is what makes the first half of
the exit checkable.

## 6 — If entries were silently skipped

The catchup error path continues past a failed entry and lets later entries
advance the high-water mark. The code says so:

> "failed entry stays unprocessed but subsequent entries advance the HWM
> (which will look like the failed one was processed). Acceptable for P3."

Those entries will never be revisited — the cursor says they are done. Find
what failed, then rebuild:

```sh
grep "per-entry failure" ~/ZeroPoint/logs/zp-serve.log | head -40
grep -c "per-entry failure" ~/ZeroPoint/logs/zp-serve.log

# rebuild: the database is disposable, the chain is the source of truth
pkill -f "zp serve"
ZP_DATA=$(python3 tools/ontology-check/catchup_reconcile.py --json \
          | python3 -c 'import json,sys;print(json.load(sys.stdin).get("data_dir",""))')
rm "$ZP_DATA"/ontology.db*
# then step 3 again
```

If the same count fails on the second pass it is systematic — a receipt shape
`project_to_boundary_input` cannot handle — and worth fixing before a third.

## 7 — If it stalls

Remaining entries are **unprocessed, not skipped**: the cursor never claimed
them, so a restart resumes from where it stopped rather than losing them.

```sh
grep -E "catchup failed|task exiting|failed to open" ~/ZeroPoint/logs/zp-serve.log
```

`Cartographer failed to open ontology store` or `catchup failed` both exit the
task while leaving the server running — the substrate keeps working and simply
has no Cartographer. Fix the cause, then step 3 again.

## Backing out

```sh
pkill -f "zp serve"
zp serve
```

Without the env var the Cartographer does not spawn.

Deleting `ontology.db` is optional and harmless either way — it is rebuildable
from the chain, and an orphaned one is simply never read.

Nothing in S2 step 1 depends on the Cartographer running. The Regent's
ontology handle opens an empty store, every read returns `None`, and the
composed prompt is byte-identical to one composed with no handle at all.
