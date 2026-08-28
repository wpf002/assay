# Phase 1 exit gate

The roadmap makes Phase 1 a kill gate: if precision at `CONFIRMED` cannot clear 90% after two rounds of rule tuning, the AST approach is under-specified and the project stops. This records the run.

**Result: passed.** One round of tuning, two disjoint hand-verified samples.

Run date 2026-08-28. Reproduce with `apps/cli/tools/analyze.mjs` and `apps/cli/tools/sample.mjs`.

---

## Corpus

Three real repositories, shallow-cloned at HEAD, all well over the 50k LOC threshold.

| Repo | Language | LOC (ts/js/py) | Files scanned | Scan time |
|---|---|---|---|---|
| `django/django` | Python | 554,557 | 2,972 | 3.6 s |
| `TryGhost/Ghost` | JS/TS | 758,874 | 6,361 | 9.9 s |
| `n8n-io/n8n` | TS | 834,838 | 20,182 | 45.9 s |

---

## Criterion 1 — precision at `CONFIRMED` above 90%

Sampling is deterministic and stratified: `CONFIRMED` evidence records are sorted by (repo, rule, locator) and every *n*th row is taken, so no single repo or rule can dominate the sample. Each sampled record was verified by reading the source at the reported `file:line` and checking the primitive, the parameters and the purpose.

**Sample 1 — population 447, stride 14, offset 0. 29/30 correct = 96.7%.**

The single defect: `django/utils/cache.py:356`, `md5(usedforsecurity=False)`. The primitive and location were right; the purpose was wrong. Python 3.9's `usedforsecurity=False` is the developer stating the digest is a cache key, not a security control, and Assay ranked it as an integrity finding on the authenticity worklist. Django carries ten of these.

**Fix (one round of tuning, three changes):**

1. `usedforsecurity=False` now enters as a detector **assumption**. This required a small extension to the model — `Finding.assumptions`, folded into the confidence `Factor` tree by `assemble()` — so a detector can taint provenance without touching the number. The numeric confidence is unchanged, because the evidence really is a resolved AST call site; but under I6 the finding can no longer reach `CONFIRMED`. It stays in the inventory as `OBSERVED` and out of the worklist. This is the provenance gate doing exactly the job it was designed for: a claim nobody can verify from source does not become a fact.
2. Added a rule for Python's `hmac` module. Its absence was a recall gap, not a precision one — Django centralizes HMAC in `django/utils/crypto.py`, so the miss was one call site, but every Python webhook-verification codebase lives there.
3. Tightened the coverage-gap pattern in `detect-deps`. It was matching `design-system` (sign), `ajv-keywords` (key) and `alien-signals`, burying the real gaps under noise.

**Sample 2 — same population, stride 14, offset 7. Fully disjoint from sample 1. 30/30 correct = 100%.**

Drawn after the fix and deliberately disjoint, so it is a check on the rules rather than on the tuning. It spans `hashlib.pbkdf2_hmac` with an unresolvable iteration count (correctly omitted rather than guessed), JOSE `alg` resolution across multi-line call sites in four codebases, `createCipheriv('aes-256-gcm')`, and `generateKeyPairSync('rsa', { modulusLength: 2048 })`.

---

## Criterion 2 — the `CONFIRMED` set is short enough that a human would read it

This is the criterion the field fails, and it passes decisively.

| Repo | Raw detections | Occurrences | Worklist rows (`CONFIRMED`) | Hints held back |
|---|---|---|---|---|
| django | 24 | 9 | 2 | 0 |
| Ghost | 148 | 27 | 4 | 12 |
| n8n | 426 | 40 | 11 | 13 |

n8n: 834k LOC and 20,182 files reduce to **eleven** work items. Three things do the compression, and each is a design invariant rather than a filter:

- **Grouping.** An Occurrence is one (system, asset, control class) triple. 151 `createHmac` call sites in n8n are one work item, because you migrate them together with one decision. Every individual `file:line` survives inside `evidence`.
- **Ceilings.** 106 dependency findings sit at 0.35 and cannot confirm, so they land in `hints` instead of leading the page.
- **Vulnerability filter.** SHA-256 and AES-256 are inventory, not work. They export; they do not rank.

---

## What the run exposed beyond the gate

- **Reachability is the next real constraint.** Twelve of the thirty records in sample 1 were in `test/`, `__tests__/` or `e2e/` paths. They are correct findings and they are not work. This is exactly I5, and Phase 3 is where it gets fixed; until then the CLI reports them as `unanalyzed` rather than pretending they are reached.
- **Coverage gaps worth catalog entries**, now that the pattern is tight enough to see them: `browserify-aes`, `browserify-rsa`, `browserify-sign`, `cipher-base`, `create-hmac`, `bcrypt-pbkdf`, `@aws-crypto/sha256-js`, `@smithy/signature-v4`, `cookie-signature`, `aws-ssl-profiles`.
- **Low recall on Django is correct, not a miss.** 24 findings from 554k LOC looks alarming until you notice Django deliberately depends on nothing but `hashlib`, `hmac` and `secrets`, and centralizes them in `django/utils/crypto.py`. A well-factored codebase should produce a small CBOM. A scanner that returned hundreds of rows here would be wrong.
- **n8n at 46 seconds** is acceptable but is the slowest thing in the pipeline. Parsing is single-threaded; a worker pool is the obvious fix if it becomes a problem.

---

## What this does not establish

- **Recall is unmeasured.** Precision was sampled; recall was not. There is no ground-truth crypto inventory for these repos to measure against, and constructing one is a larger exercise than the gate requires.
- **Three repos, two languages.** Nothing here says anything about Go, Java, C or Rust — that is Phase 6.
- **No binary, network or PKI evidence** was involved, so the noisy-OR across independent modality groups was never exercised against real data. Only the within-group ceilings were. Phase 2 is the first real test of the combination rule.
