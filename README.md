# Assay

Cryptographic bill of materials. Find where RSA and ECC actually live, prove it, and rank what to fix first with a number you can defend in an audit.

Post-quantum migration is now a procurement line item with a date attached. **EO 14412** (signed 2026-06-22) requires federal high-value and high-impact systems to be on PQC for key establishment by **2030-12-31** and for digital signatures by **2031-12-31**, extends the obligation to covered contractors through the FAR, and directs CISA to publish minimum elements for a cryptographic bill of materials enabling *automated assessment of cryptographic assets*.

The blocker is not the replacement algorithms — those are standardized. The blocker is that nobody can produce a credible inventory of what they're running, because the classical crypto is buried in firmware, TLS terminators, signing pipelines, and vendor SDKs that were never documented.

Assay produces that inventory with provenance attached to every claim.

---

## What makes this not a grep script

**1. Confidence has a ceiling per detection modality, and same-modality repetition can't raise it.**

An AST-parsed call site with resolved arguments is a different kind of fact than a string match in a stripped binary. Four hundred string matches is one weak observation repeated, not four hundred observations. Assay assigns a hard confidence ceiling per modality and combines only across *independent* modality groups, via noisy-OR. Source, dependency and config evidence are correlated with each other and do not stack. Source evidence plus a network handshake plus a parsed certificate — those are independent, and those do.

CycloneDX has a confidence *field* (0–100) and a six-value technique enum. It has no notion of a per-technique ceiling and no notion of correlated versus independent evidence. That gap is the reason this project exists.

**2. Confidentiality urgency and authenticity urgency are ranked separately.**

Harvest-now-decrypt-later applies to key establishment and data encryption. That traffic is being recorded today and decrypted later; the clock started before you read this. It does **not** apply to signatures. A signature that becomes forgeable in 2033 is a 2033 problem, not a retroactive compromise.

EO 14412 splits its own deadlines the same way, a year apart. Tools that put both on one severity scale are misaligned with the mandate they claim to serve. Assay emits two ranked tracks and never pools them.

**3. Ranking is Mosca's inequality *and* the regulatory deadline — whichever binds first.**

```
physics:     X + Y > Z         =>  already late
regulation:      Y > D - now   =>  already late
```

- **X** — years the data must stay confidential (zero on the authenticity track)
- **Y** — years to complete migration, derived from control class
- **Z** — years until a cryptographically relevant quantum computer
- **D** — a fixed completion date. X does not appear: a regulator setting 2030-12-31 does not care how long your data stays secret.

For anyone in federal or contractor scope, D lands four to five years ahead of any credible Z. Ranking on the CRQC horizon alone — as most of the field still does — understates urgency by about half a decade. Assay computes both and tells you which one bound.

Y is the interesting term. It comes from who actually controls the code:

| Control class | Meaning |
|---|---|
| `SELF` | our source, our deploy |
| `VENDOR_UPGRADEABLE` | dependency with a PQ-capable version shipping |
| `VENDOR_LOCKED` | closed vendor, no roadmap — this is a procurement problem, not an engineering one |
| `HARDWARE` | HSM, TPM, smartcard, silicon — bounded by replacement cycle |
| `PROTOCOL_BILATERAL` | both endpoints must move together — the slowest thing in the estate |

Every slack figure carries a recursive `Factor` tree back to the raw evidence and the policy pack that supplied Z and D. There are no bare numbers.

**4. Deadline policy is versioned data, never constants.**

CNSA 2.0, NIST IR 8547, EU financial-sector timelines and EO 14412 disagree, and they move. Policy packs are inputs; every ranked finding records which pack version produced it, so a re-rank under a new pack is a diff instead of a rewrite.

```bash
pnpm assay policy list
```

**5. Presence is not exposure.**

RSA in a dev dependency's test fixture and RSA on the payment API key exchange are not the same work item. Occurrences carry a reachability determination, and unreached findings are reported separately rather than padding the count. "Not yet analyzed" is a third state, never collapsed into "not reached."

Competitors claim reachability. Assay ships the **path**, in CycloneDX `evidence.callstack`, where someone who does not trust us can check it — and it says *how* it concluded reachability, because "a request handler calls this" and "this module is published, so somebody's handler might" are different claims: `OBSERVED`, `ENTRY_POINT`, `DEPLOYED_CONFIG`, `LIBRARY_SURFACE`, or `NONE`.

---

## Provenance gate

An occurrence exports at `CONFIRMED` only when its confidence `Factor` tree contains no `ASSUMPTION` node anywhere in its dependency path *and* clears the threshold. Otherwise it downgrades to `OBSERVED` or `SUSPECTED`, with the reason attached.

A guess does not launder itself into a fact by passing through a serializer.

The "binary strings never confirm alone" rule needs no special case: a 0.30 ceiling cannot arithmetically reach 0.85 without independent corroboration. The invariant is enforced by the algebra, not by a check that can be forgotten.

---

## Reproducibility

Same evidence set, byte-identical CBOM — including the serial number, which is a content hash rather than a random UUID. `@assay/core` performs no I/O, reads no clock, and has zero runtime dependencies; SHA-256 and canonical JSON are implemented in-package so asset identity is the same in Node and in the browser.

Post-EO, with auditors and FAR clauses in play, "re-run it and diff the file" is an argument, not a nicety.

---

## Authorization

Active network probing runs only inside a signed `ScopeGrant` naming the targets and the time window. Detectors take the grant as an explicit argument — no ambient authority, no default-allow, no environment variable that quietly turns scanning on.

Repo, artifact and cloud-KMS scanning of your own estate needs no grant. Touching a host does.

The gate is enforced by the type system, not by a check someone can forget to call. `probeTls` and `probeSsh` accept only an `AuthorizedTarget`, whose brand is not exported; the only way to construct one is `authorize(verifiedGrant, host, port, now)`, which throws unless a verified, in-window grant covers that exact host and port. An out-of-scope probe does not compile.

```bash
pnpm assay scope keygen --out-dir ./grants
pnpm assay scope sign --key ./grants/assay-scope.key.pem \
  --issued-by security@example.com --targets '*.example.com,10.0.0.0/24' \
  --ports 443 --not-after 2026-12-31T00:00:00Z --out ./grants/q3.json
pnpm assay probe api.example.com:443 --grant ./grants/q3.json --pubkey ./grants/assay-scope.pub.pem
```

---

## Architecture

```
packages/
  core/            pure. types, confidence algebra, Mosca + regulatory ranking,
                   worklists, CycloneDX export. no I/O, no clock, no deps.
  policy/          versioned deadline/CRQC packs
  scope/           signed authorization grants for network detectors
  detect-source/   tree-sitter AST + config parsing (nginx, openssl.cnf, java.security)
  detect-deps/     manifest -> known crypto capability surface
  detect-network/  TLS/SSH capability enumeration. scope-gated at the type level.
  detect-pki/      X.509 inventory, lifetime vs migration window
  detect-kms/      cloud KMS / HSM key inventory. metadata only, never key material.
  correlate/       joins modalities into Asset -> Occurrence edges, resolves conflicts
apps/
  api/             Fastify + Prisma + Postgres. Ranks on read; never re-derives confidence.
  web/             Next.js. Two worklists, live policy switcher, derivation drill-down.
  cli/             primary interface. CI-integrable.
```

**Conflict resolution:** when source says a service supports X25519 and RSA but the network says RSA was negotiated, both are true and they answer different questions. Deployment reality wins for "what is running." Source wins for "what is possible." `correlate` keeps them distinct rather than picking one.

---

## Quickstart

```bash
pnpm install
pnpm typecheck && pnpm test && pnpm build
```

Bring up the API and the web surface:

```bash
cp .env.example .env && docker compose up -d && pnpm db:migrate
```

```bash
pnpm dev
```

Compose binds Postgres to host port **5433**. Many machines already run a local Postgres on 5432, and a shadowed port fails as an authentication error rather than as a conflict.

Scan a repo and push the evidence:

```bash
pnpm assay push ./path/to/repo --system payments-api
```

Then open http://localhost:3000. Only evidence is stored; the ranking is computed on read, so switching policy packs re-ranks live and marks every row that moved.

Inspect the deadline policy in force:

```bash
pnpm assay policy show eo-14412
```

Scan a repo (Phase 1):

```bash
pnpm assay scan ./path/to/repo --policy eo-14412 --out cbom.json
```

Probe an endpoint you are authorized to touch (Phase 2):

```bash
pnpm assay probe api.example.com:443 --grant ./grants/prod-q3.json
```

---

## Output

CycloneDX 1.7 cryptographic assets (ECMA-424 2nd edition; 1.6 emitter retained for consumers that lag), plus an Assay-native report carrying the full `Factor` trees that CycloneDX has no field for. A `cisa-min-elements` profile is stubbed against the guidance EO 14412 directs CISA to publish, and marks itself provisional rather than pretending to a schema nobody has seen.

The CBOM is for the auditor. The `Factor` trees are for the engineer who has to argue with the auditor.

---

## Prior art

IBM Quantum Safe Explorer and `cbomkit`, SandboxAQ AQtive Guard, Keyfactor (InfoSec Global + CipherInsights), Fortanix PQC Central, AppViewX, CryptoNext, Quantum Xchange, ISARA, Tychon, AWS `cryptobom-forge`.

Discovery is table stakes and several of these do it competently. The gap Assay targets is everything after discovery: correlation across modalities, reachability with a checkable path, and a migration ranking whose derivation is inspectable rather than asserted. Full review in [COMPETITIVE.md](COMPETITIVE.md).

---

## Status

Phases 0 through 4 complete. The engine is implemented and tested, and `assay scan` runs end to end from a directory to two ranked worklists and a CycloneDX 1.7 document.

Phase 1's exit gate was a kill condition, and it passed: two disjoint hand-verified samples across django, Ghost and n8n scored 96.7% and 100% precision at `CONFIRMED`, and 834k LOC of n8n reduced to eleven work items. Details, including what the run does *not* establish, are in [VALIDATION.md](VALIDATION.md). Phase 2 added the scope gate, certificate inventory with a lifetime-vs-deadline check, TLS/SSH capability enumeration, and cloud key-store classification. Its exit gate — that an out-of-scope probe fails at the type level rather than at runtime — is asserted by a compile-time test that runs under `tsc` in CI.

Phase 4 added the API, Postgres persistence, scan diff, ticket export, and the web surface: two worklists that are never merged, one derived headline, and a policy pack switcher that re-ranks live and badges every row that moved. Its exit gate — any slack figure to raw evidence in under three clicks — lands in one.

Next is Phase 5, binary analysis — see [ROADMAP.md](ROADMAP.md).
