# landings

Manifests for `scripts/land.sh`. One directory per landing; the driver
supplies the logic, the manifest supplies the lists.

```
scripts/landings/<name>/
  01-first-step.files    one path per line — what this commit contains
  01-first-step.msg      the commit message, passed to git commit -F as-is
  02-second-step.files
  02-second-step.msg
  deferred               dirty on purpose, committed by nobody (optional)
  after                  manual steps to run once this lands (optional)
```

Steps run in filename order. Blank lines and `#` comments are ignored in
`.files` and `deferred`; in `deferred` a comment line is *printed*, which is
where the reason a path is being left alone belongs.

Run it:

```
bash scripts/land.sh scripts/landings/<name> --dry-run
bash scripts/land.sh scripts/landings/<name>
```

Manifests are gitignored. They are working state — the message text lands in
git history, and keeping a second copy in the tree would be one more pair of
hand-maintained lists for one fact.

## The guard

`land.sh` refuses to run if any dirty path is claimed by neither a step nor
`deferred`. This is deliberately the inverse of the obvious design.

On 2026-08-16 a commit defined as *everything dirty minus this list* swept 357
lines of a scheduled task's output into a commit whose message described a
mechanical formatting sweep. Nothing lied; the definition was open at one end.
Since inverting it the guard has caught a regenerated derived artifact whose
self-stamp would have been false, an unrelated in-flight edit by another
session, and a landing script that failed to account for its own existence.

Claiming a path is a decision about what a commit means. Adding a line to make
the script run is the failure mode this is built against.

## Derived artifacts go in their own step, after their source

Anything that stamps the commit it was generated from — `connections.json`,
`DISCIPLINE-PINS-MAP.md` — must be regenerated *after* the commit it
describes, then committed alone. Generating first produces an artifact whose
stamp names a commit that does not contain what the artifact lists. Use
`after` for the regeneration command so the next reader does not have to
remember the ordering. This decided commit order three separate times on
2026-08-17.
