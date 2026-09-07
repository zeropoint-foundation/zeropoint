# Review Sources — provenance manifest

Pinned copies of external documents the review corpus cites. **Review artifact,
not canonical corpus** — same tier as `docs/review/ai-landscape-log.md`. Do not
add to `CANONICAL-CORPUS-INDEX-2026-07.md`.

## Why copies exist

Link rot, demonstrated. The CACR guideline below sits on a Chinese CMS host that
is unreachable to automated fetch and unindexed by every search engine tried on
2026-08-18; the file only reached us because the operator downloaded it by hand.
A corpus citation to a URL that cannot be re-fetched is a citation that cannot be
re-verified, which defeats *verify before commit* and rule 5 of the sweep task
(*"a foreign-language instrument is not verified until someone reads it in its
own language"* — impossible if the instrument is gone).

## Why the manifest exists

**A committed copy without provenance is a document of unknown authenticity that
looks authoritative because it is in our repo.** For a substrate whose subject is
provenance, that would be a poor joke. Every file here carries its source URL,
retrieval date, retrieval path, SHA-256, and whether anyone has checked it
against the publisher's copy.

The hash is the load-bearing field. It lets a future reader confirm that the file
they are reading is the file the log entry was written from, and — if the
original ever becomes reachable again — whether the two match.

## Policy

- **Commit:** government works not subject to copyright (NIST SPs state this on
  their face), standards-body Internet-Drafts, freely-published guidance from
  professional societies, and preprints under permissive licences.
- **Do not commit, cite by URL and hash only:** national standards sold for a fee
  (the GB/Z 185 series is the live example), paywalled research, and full
  transcripts of copyrighted video. For those, record the hash of what was read
  and quote only what the log needs.
- **Always:** attribution in this manifest, and a note of the publisher's stated
  terms where they are known.
- Not legal advice. Where terms are unclear, the conservative option is to record
  the hash and quote narrowly rather than to commit the artifact.

---

## Manifest

### CACR-genai-cryptography-guide-2026-08-v1.0.pdf

| Field | Value |
|---|---|
| Title | 《生成式人工智能系统密码应用指引》 v1.0 |
| English | *Cryptography application guide for generative artificial intelligence systems* |
| Publisher | 中国密码学会密评联委会 (CACR Cryptographic Application Security Assessment Joint Committee) |
| Date | 2026-08 (PDF `CreationDate` 2026-08-04) |
| Pages | 26 |
| Source URL | `https://cmsfiles.zhongkefu.com.cn/cmsmima/backend_upload/file/20260807/1786096412171088.pdf` |
| Announcement | https://www.secrss.com/articles/92943 (安全内参, 2026-08-07) |
| Retrieved | 2026-08-18, **by the operator by hand** — `web_fetch` refused the URL on its provenance check and no search engine indexes it |
| SHA-256 | `d6e996b2926c934fed5c36c531a511279462fd548a5203781f85214fa87208cd` |
| Verified against publisher copy | **No.** Metadata, drafting list and internal cross-references are self-consistent; no independent check that this matches what is served at the source URL |
| Stated terms | Publisher page carries 版权归作者所有 (copyright belongs to the author); document is 供行业参考使用 ("for industry reference") |
| Cited by | `docs/review/ai-landscape-log.md` 2026-08-18 fifth addendum; `docs/handoffs/external-convergence-evaluation-2026-08.md` |

Figures: **`CACR-figures/page-NN.png`** — full-page renders at scale 3
(1786×2526) of the seven pages carrying embedded images, produced with
`pypdfium2` 5.12.1. Full-page rather than cropped so captions and surrounding
clause text stay attached to the diagram.

| File | Contains | SHA-256 (short) |
|---|---|---|
| `page-10.png` | §5 概述 — system layer model | `835e61e7…` |
| `page-13.png` | **图2 密码应用技术框架** — the four-part cryptographic application framework | `0cef598e…` |
| `page-14.png` | **图3 密码防护措施** — layered protection measures over GB/T 39786-2021 | `98c3afcb…` |
| `page-19.png` | Appendix A.1 — training-system example | `0a6e7b7b…` |
| `page-20.png` | Appendix A.2 — application-system example | `77644db8…` |
| `page-21.png` | **图A.3 智能体密码应用架构** — the five-layer agent architecture | `b34c38d3…` |
| `page-23.png` | Appendix B — model lifecycle example | `011f7302…` |

**All seven read 2026-08-18** (extracted the same day; the day's earlier log
entries were written from text alone). The read is recorded in
`docs/review/ai-landscape-log.md`, **sixth addendum** — including what each figure
adds over the extracted text, one internal inconsistency in the document (the
third layer of the agent architecture is named 工具调用与执行层 in A.3's prose and
工具调用与决策层 in the figure), and two placement corrections to the fifth
addendum. **A future session does not need to re-open these**; the addendum is the
record.

**English rendering of 图3.** `CACR-figures/page-14.en.svg` (and `.en.png`) is an
unofficial bilingual redraw of Figure 3 — English primary, original Chinese
retained under every term so the diagram stays citable against the source. It is
a derived artifact made in this repo, **not** a reproduction of the publisher's
file, and carries its own provenance line in the footer. The source PDF's terms
are unresolved (see the CACR entry above), so treat the redraw as commentary on
the figure rather than a substitute for it.

One finding worth surfacing at manifest level, because it bears on how the
document is cited: 图3 is a **concentric** model, not a stack. GB/T 39786-2021's
requirement set is the innermost ellipse, 基础密码防护 the middle ring, 增强密码防护
the outer. 智能体安全 sits in the **baseline** ring; 零知识证明 appears only in the
**enhanced** ring. The guideline's own tiering therefore places §8.5.2.4(a)'s
zero-knowledge plan-verification — the clause the fifth addendum called the most
striking in the document — at the enhanced tier, not the baseline.

Companion: **`CACR-genai-cryptography-guide-2026-08-v1.0.extracted.txt`**
(SHA-256 `17d5bd55f9ece524af3cb6ac0bdae343d6a7acc99a75676a2e0c1ac4e28c6a62`) —
full text extracted with `pypdf` 6.15.0, page-delimited, greppable. **Figures are
not captured**: §7 figures 2 and 3 (the cryptographic application technical
framework, and the layered protection measures) and Appendix A.3's agent
architecture diagram exist only in the PDF.

---

## Candidates — terms verified 2026-08-18, files not yet pinned

Cited by the log, currently URL-only. **Publisher terms were read at source on
2026-08-18** rather than assumed; the previous version of this section recorded
beliefs about IETF and arXiv licensing that had explicitly not been checked. Three
of the four are safe to commit and are not yet committed — see *Pinning status*
below for why.

### NIST SP 800-239 ipd — SAFE TO COMMIT

| Field | Value |
|---|---|
| Title | *AI Data Center Security Analysis: A High-Performance Computing (HPC) Driven Approach* |
| Publisher | NIST — Yang Guo (ITL, Computer Security Division) and Bennett Tomlinson (CAISI) |
| Date | Published **2026-07-27**; comment period closes 2026-09-25 |
| Status | Initial Public Draft. **Current — not superseded, not finalised** (checked 2026-08-18) |
| URL | `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-239.ipd.pdf` |
| Landing | `https://csrc.nist.gov/pubs/sp/800/239/ipd` |
| Stated terms | Verbatim: *"This publication may be used by nongovernmental organizations on a voluntary basis and is not subject to copyright in the United States. Attribution would, however, be appreciated by NIST."* |
| Cited by | `ai-landscape-log.md` 2026-08-18 entry and second addendum (read at primary) |

Attribution is requested, not required. Commit the full PDF with attribution.

### draft-niyikiza-oauth-attenuating-agent-tokens-01 — SAFE TO COMMIT (unmodified only)

| Field | Value |
|---|---|
| Title | *Attenuating Authorization Tokens for Agentic Delegation Chains* |
| Date | 2026-06-15; **expires 2026-12-17** |
| Status | Individual Internet-Draft, no WG adoption, no standing in the IETF process. **-01 is the latest revision** (only -00 and -01 exist) |
| URL | `https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` |
| Datatracker | `https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/` |
| Stated terms | *"Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved."* — subject to BCP 78 and the IETF Trust Legal Provisions |

### draft-nelson-agent-delegation-receipts-10 — SAFE TO COMMIT (unmodified only)

| Field | Value |
|---|---|
| Title | *Delegation Receipt Protocol for AI Agent Authorization* |
| Date | 2026-06-13; **expires 2026-12-15** |
| Status | Individual Internet-Draft, sole author. Revisions -00 through -10 exist; **-10 confirmed latest** |
| URL | `https://www.ietf.org/archive/id/draft-nelson-agent-delegation-receipts-10.txt` |
| Datatracker | `https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/` |
| Stated terms | Same BCP 78 / TLP boilerplate as above |

**What the IETF Trust Legal Provisions actually say** — read at
`https://trustee.ietf.org/wp-content/uploads/Corrected-TLP-5.0-legal-provsions.pdf`
on 2026-08-18. (Note: the guessable filename `TLP-5.pdf` 404s; that is the working
canonical URL, reached from the trustee's TLP landing page.)

- **§3.c** grants a non-exclusive, royalty-free right *"to copy, publish, display
  and distribute IETF Contributions and IETF Documents **in full and without
  modification**"*, plus translation, plus copying and distributing **unmodified
  portions** with proper attribution.
- **§3.d.i** grants no licence *"to modify IETF Contributions or IETF Documents …
  in any context outside the IETF Standards Process."*
- **§6.c.i**, carried in every I-D: *"This document may not be modified, and
  derivative works of it may not be created, except to format it for publication
  as an RFC or to translate it into languages other than English."*

So: **unmodified full copies with the Copyright Notice retained are permitted.**
Excerpting is permitted for unmodified portions with attribution. Derivative works
are not. The prior belief recorded here was correct; it is now checked.

### arXiv 2603.14332 v2 — HASH ONLY, do not commit

| Field | Value |
|---|---|
| Title | *Governing Dynamic Capabilities: Cryptographic Binding and Reproducibility Verification for AI Agent Tool Use* |
| Note on the name | **"A2Auth" is not the title.** It is the name of the software artifact, used in §7 and §9 prose. The log and `external-convergence-evaluation-2026-08.md` both refer to the paper as "A2Auth"; that is shorthand, not a citation |
| Author | Ziling Zhou (single author) |
| Affiliation | **Genupixel Technology Pte. Ltd.** (`ziling@genupixel.com`) — shown in the paper header, **not** on the abs page |
| Dates | v1 2026-03-15 11:46:57 UTC; **v2 2026-03-19 19:46:56 UTC**. No v3 (checked 2026-08-18) |
| URL | `https://arxiv.org/abs/2603.14332` · PDF **`https://arxiv.org/pdf/2603.14332v2`** (version-pinned — the unversioned URL follows `latest` and would not hash reproducibly if a v3 ever appears) |
| Stated terms | Verbatim, from the paper's own header: **"License: arXiv.org perpetual non-exclusive license"** (abs page renders only `view license` → `http://arxiv.org/licenses/nonexclusive-distrib/1.0/`) |
| Competing interests | **None declared.** No funding statement, no acknowledgements, no competing-interest declaration. The paper releases `agent-trust-kit` as an SDK and describes `a2auth` as a credential-governance application without disclosing the company's relationship to either |

**Verdict: hash only.** The arXiv default non-exclusive distribution licence grants
arXiv the right to distribute; it does **not** grant third parties a redistribution
licence for the full text. This differs materially from CC BY, which several arXiv
papers carry and this one does not. Cite and quote narrowly under fair use.

**Provenance fact that must travel with any citation of this paper:** the Bounded
Divergence Theorem was **stated differently in v1 and silently replaced in v2 four
days later**. v1 gave ε ≤ exp(−2nθ²), keyed on the pass threshold θ, with a proof
sketch whose derived bound and stated bound were different objects; v2 gives
ε ≤ 1 − α^(1/n), the standard one-sided Clopper–Pearson bound, which is correct.
v1's headline numeric claim was wrong by roughly eight orders of magnitude at
n = 12. The Chain Verifiability Theorem statement is byte-identical between
versions (renumbered only). Detail in
`docs/handoffs/external-convergence-evaluation-2026-08.md`, inputs section.

### Not to be pinned, by policy

| Document | Reason |
|---|---|
| GB/Z 185.1–185.7-2026 | Chinese national standards, sold. **Never read** — the log characterises the series from its announcement alone. Do not commit; record a hash only if ever obtained |
| OpenAI Black Hat talk `87DyyMV0kCY` | Copyrighted video. The log's quotes in the third addendum are the record |

---

## Pinning status — 2026-08-18

**Terms verified for all four candidates. No file committed.** Three of the four
are safe to commit and were not committed for a tooling reason, recorded here so
it is not rediscovered:

`web_fetch` results are not reachable from the bash sandbox — the two filesystems
are separate — so "fetch it and hash it" is not one operation. The standing
content restriction forbids retrieving URLs with `curl`, `wget` or an HTTP library
in any language. Both constraints are structural, not incidental, and routing
around the second would be worse than leaving the gap open.

**`docs/review/sources/fetch-pending-sources.sh`** does the job in one pass from
Ken's own shell: downloads the three committable documents into
`docs/review/sources/`, prints SHA-256 for all four (fetching the arXiv PDF to a
temp path, hashing it, and deleting it — since that one is hash-only), and emits
the manifest rows ready to paste. Run it from the repo root. Once run, replace the
SHA-256 placeholders below and move these entries into the main Manifest section.

| File to land | SHA-256 |
|---|---|
| `NIST.SP.800-239.ipd.pdf` | *pending* |
| `draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` | *pending* |
| `draft-nelson-agent-delegation-receipts-10.txt` | *pending* |
| arXiv 2603.14332 v2 (**hash only, not committed**) | *pending* |
