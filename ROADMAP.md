# Assay — Roadmap

Cryptographic bill of materials. Discovery, inventory, and defensible migration ranking for post-quantum transition.

This is the single planning document. Design invariants, phase sequence, exit gates, kill conditions, and unresolved decisions all live here.

---

## 1. Thesis

Post-quantum migration is a procurement requirement now, not a research topic. The replacement algorithms are standardized. The blocker is that nobody can produce a credible inventory of where classical crypto actually runs, because it's buried in firmware, TLS terminators, signing pipelines, and vendor SDKs nobody documented.

As of **EO 14412 (signed 2026-06-22)** this stopped being a matter of prudence. Federal HVAs and high-impact systems must be on PQC for key establishment by **2030-12-31** and for digital signatures by **2031-12-31**; a FAR rule extends the obligation to covered contractors; and CISA is directed to publish **minimum elements for a cryptographic bill of materials** enabling *automated assessment of cryptographic assets*. The category acquired a mandate and a schema deadline in the same document.

**Discovery is table stakes.** IBM Quantum Safe Explorer, `cbomkit`, SandboxAQ AQtive Guard, Keyfactor, and AWS `cryptobom-forge` all do discovery competently. Assay does not win by scanning harder.

**The bet is on everything after discovery:** correlation across detection modalities, reachability, and a migration ranking whose derivation is inspectable rather than asserted. The deliverable a CISO pays for is a worklist short enough to read and defensible enough to survive an audit — not a 40,000-row CSV.

If Phase 1 can't produce that on a real repo, the project stops. See §5.

Competitive and regulatory source review: [COMPETITIVE.md](COMPETITIVE.md).

---

## 2. Design invariants

These constrain every phase. Violating one is a redesign, not a bug fix.

### I1 — Confidence has a per-modality ceiling; same-modality repetition never raises it

An AST-parsed call site with resolved arguments is a categorically different fact from a string match in a stripped binary. Four hundred string matches are one weak observation repeated, not four hundred observations.

| Modality | Ceiling | Notes |
|---|---|---|
| `PKI_CERTIFICATE` | 0.99 | parsed X.509 / SSH host key |
| `NETWORK_ACTIVE` | 0.98 | negotiated handshake — ground truth for *deployed*, silent on *capability* |
| `RUNTIME_HOOK` | 0.97 | instrumented process observed calling the primitive |
| `CLOUD_KMS_API` | 0.97 | authenticated KMS/HSM/KMIP enumeration — the provider names the key spec |
| `SOURCE_AST` | 0.95 | resolved call site |
| `SOURCE_CONFIG` | 0.90 | nginx, openssl.cnf, java.security, sshd_config |
| `BINARY_CONSTANT` | 0.90 | byte-exact S-box / round constants / curve params |
| `HOST_AGENT` | 0.90 | endpoint agent / EDR telemetry |
| `BINARY_SYMBOL` | 0.85 | imported symbol table |
| `NETWORK_PASSIVE` | 0.80 | pcap |
| `ASSERTED` | 0.40 | vendor questionnaire, unverified |
| `DEPENDENCY` | 0.35 | **a search hint, not a finding — see D1, resolved** |
| `BINARY_STRING` | 0.30 | never a sole basis for `CONFIRMED` |

Combination is noisy-OR across **independent** groups only. Source, config, and dependency evidence are correlated and do not stack with each other. Source + network handshake + parsed certificate are independent and do. `RUNTIME_HOOK` is its own group: observing a live process call the primitive is causally independent of having read the source that compiled into it.

The `BINARY_STRING` rule needs no special case in the exporter — a 0.30 ceiling is arithmetically incapable of reaching 0.85 alone. The invariant is enforced by the algebra, not by a check that can be forgotten.

This is the reason existing CBOM output is unusable at scale. Everything else is downstream.

### I2 — Confidentiality and authenticity are ranked on separate tracks and never pooled

Harvest-now-decrypt-later applies to key establishment and data encryption. That traffic is being recorded today. It does **not** apply to signatures — a signature forgeable in 2033 is a 2033 problem, not a retroactive compromise.

EO 14412 splits its own deadlines the same way, one year apart. The two tracks are the regulator's model, not an Assay idiosyncrasy, and a pooled "quantum readiness %" is now misaligned with the mandate it claims to serve rather than merely imprecise.

### I3 — Ranking is Mosca's inequality *and* the regulatory deadline, whichever binds first

```
physics:     X + Y > Z         =>  already late
regulation:      Y > D - now   =>  already late
```

- **X** — years the data must stay confidential. Collapses to zero on the authenticity track.
- **Y** — years to complete migration, derived from control class.
- **Z** — years until a cryptographically relevant quantum computer. Supplied by policy pack.
- **D** — a fixed completion date. X does not appear: a regulator setting 2030-12-31 does not care how long your data stays secret.

Both are computed; `bindingConstraint` names which produced the answer. "We are late because of the EO" and "we are late because of Shor" are different conversations with different people.

Y is the load-bearing term:

| Control class | Meaning | Default Y |
|---|---|---|
| `SELF` | our source, our deploy | 0.5 |
| `VENDOR_UPGRADEABLE` | dependency with a PQ-capable release shipping | 1.5 |
| `VENDOR_LOCKED` | closed vendor, no roadmap — a procurement problem, not engineering | 4.0 |
| `HARDWARE` | HSM / TPM / smartcard / silicon, bounded by replacement cycle | 6.0 |
| `PROTOCOL_BILATERAL` | both endpoints must move together — slowest thing in the estate | 5.0 |

### I4 — Deadline policy is versioned data, never constants

CNSA 2.0, NIST IR 8547, EU financial-sector timelines and now EO 14412 disagree and move. Hardcoding a year makes the tool silently wrong on a schedule. Every ranked finding records the pack version that produced it, so a re-rank under a new pack is a diff instead of a rewrite.

Shipped pack figures are **inputs, not truth claims.**

### I5 — Presence is not exposure

RSA in a dev dependency's test fixture and RSA on the payment API key exchange are not the same work item. Unreached findings report separately and never pad the headline count.

"Not yet analyzed" and "analyzed and not reached" are distinct states and are never collapsed.

Reachability is no longer an unclaimed differentiator — competitors claim it. The differentiator is **shipping the path**, in `evidence.callstack`, where a third party can check it.

### I6 — Provenance gate

An occurrence exports at `CONFIRMED` only when its confidence `Factor` tree contains no `ASSUMPTION` node anywhere in its dependency path *and* clears threshold. Otherwise it downgrades to `OBSERVED` or `SUSPECTED`.

The gate reads the **confidence** tree, which answers "is this crypto really here". Ranking assumptions — an operator's guess at data retention — taint the ranking derivation without downgrading the assertion, because conflating them would make every ranked finding unconfirmable.

### I7 — Engine purity

`@assay/core` performs no I/O and reads no clock. Detectors emit `Evidence[]`; core turns evidence into rankings. Same evidence set produces a byte-identical CBOM, always — including the serial number, which is derived from content rather than randomness. Reproducibility is an audit argument, not a nicety.

### I8 — No ambient authority for network access

Active probing runs only inside a signed `ScopeGrant` naming targets and a time window, passed as an explicit argument. No default-allow, no environment variable that quietly enables scanning. Scanning your own artifacts needs no grant; touching a host does.

### I9 — Never touch key material

Assay records that a key exists, its algorithm, and its size. It never reads, stores, or transmits private key material. Non-negotiable, and it's what makes the tool deployable inside a bank.

---

## 3. Phase sequence at a glance

| Phase | Scope | Why here |
|---|---|---|
| 0 | Substrate + core engine | done |
| 1 | Source + dependency, TS/Python | **the whole bet** — done, gate passed |
| 2 | Scope gate, KMS, PKI, network | done — adds the independent modalities I1 needs |
| 3 | Correlation + reachability | done — where it becomes worth money |
| 4 | API, persistence, web | done — makes the derivation clickable |
| 5 | Binary analysis | done — last on purpose |
| 6 | Language expansion + CI | done — breadth after depth |
| 7 | Vendor attestation | done — now a FAR compliance artifact, not an upsell |

---

## 4. Phase 0 — Substrate and engine ✅

Monorepo, Prisma schema, CI, Docker Postgres. Core types committed as the architectural contract, with the confidence algebra, Mosca ranking, worklists and the CycloneDX exporter implemented and tested rather than stubbed.

**Exit gate:** `pnpm typecheck && pnpm test && pnpm build` green. `@assay/core` has zero runtime dependencies — SHA-256 and canonical JSON are implemented in-package so asset identity is identical in Node and the browser.

---

## 5. Phase 1 — Source + dependency detection (TypeScript, Python)

**Status: complete. Exit gate passed** — see [VALIDATION.md](VALIDATION.md). Two disjoint hand-verified samples over django, Ghost and n8n: 96.7% then 100% precision at `CONFIRMED`, and 834k LOC of n8n reduces to eleven work items. Recall is unmeasured.

The beachhead. Every later phase is an expansion of this surface.

**Deliverables**

- tree-sitter grammars for TS/JS and Python
- Rule set mapping call sites to `CryptoAsset` with resolved parameters. `crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })` must yield RSA/2048/`KEY_ESTABLISHMENT` — not "RSA somewhere in this file."
- Config parsers: `openssl.cnf`, nginx ssl directives, `java.security`, `sshd_config`
- Manifest ingestion: `package.json`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock` → known crypto capability surface per library version, emitted as `implements` and never `uses`
- CLI `scan` wired end to end: evidence → confidence → rank → CBOM

**Exit gate**

Scan three real open-source repos of >50k LOC. Hand-verify a 30-finding sample.

1. Precision at `CONFIRMED` exceeds 90%.
2. The `CONFIRMED` set is small enough a human would actually read it. If it returns 800 items, the ceilings are wrong — fix them before proceeding.

**Kill condition**

If precision at `CONFIRMED` can't clear 90% after two rounds of rule tuning, the AST approach is under-specified and the project stops here. Shipping a noise generator into a CISO's inbox is worse than not shipping. A kill at Phase 1 is a valid outcome and costs two weeks instead of six months.

---

## 6. Phase 2 — Cloud KMS, PKI, and network

**Status: complete.** The scope gate shipped before any probing code existed, as required.

**Ship the scope gate before any probing code exists.**

Reordered from the original plan: cloud KMS/HSM/KMIP enumeration lands *before* active network probing. It is higher confidence (the provider names the key spec), lower effort, needs no grant machinery beyond IAM, and it is the single largest coverage gap against the commercial field.

**Deliverables**

- `@assay/detect-kms`: AWS KMS, Azure Key Vault, GCP KMS, KMIP. Key spec, rotation state, HSM-vs-software backing. Never key material (I9).
- `@assay/scope`: Ed25519 grant signing, verification, target matching (CIDR / hostname glob), time-window enforcement
- Certificate inventory: parse chains, extract key algorithm and size, compare cert lifetime against the migration window. A ten-year CA cert issued today under RSA-4096 is a finding with a hard date attached.
- TLS capability enumeration via repeated handshakes — record what was *offered* and what was *selected*. Different facts, stored separately.
- SSH host key and KEX algorithm enumeration
- Passive PCAP ingest for environments where active probing is off the table

**Exit gate: passed.** `AuthorizedTarget` and `VerifiedGrant` are branded with unexported symbols, so the only way to obtain either is through `authorize()` / `verifyGrant()`. `packages/scope/test/types.compile-test.ts` asserts this with `@ts-expect-error` and runs under `tsc` in CI: if the brands were ever removed, the *typecheck* fails, not a test. 27 adversarial runtime tests cover expired and not-yet-valid grants, wrong key, targets/ports/expiry widened after signing, truncated and non-base64 signatures, a public key smuggled into the grant body, inverted windows, capped clock skew, glob escape across dots, non-canonical IPv4 octets, and IPv6 prefixes that are not byte-aligned.

**What shipped, and one honest gap.** Cloud KMS ships as the normalized `KeyRecord` model plus pure adapters from each provider's metadata response (`fromAwsKms`, `fromAzureKeyVault`, `fromGcpKms`) and `importInventory` for a customer-supplied export. The SDK calls that would feed those adapters live credentials are *not* implemented: they cannot be verified here, and an unverifiable integration is worse than an absent one. The classification layer — the part that is easy to get subtly wrong, and where a real bug was caught (Azure states RSA size only as an unpadded base64url modulus, and the padded-length formula reported 2048-bit keys as 2052) — is implemented and tested. The import path is also the only path that ever exists in an air-gapped estate.

---

## 7. Phase 3 — Correlation and reachability

**Status: complete. Exit gate passed** — on a fixture with a known dev/prod split, every test-only and orphaned finding is marked unreached and nothing is falsely reached.

Where the product becomes worth money.

**Deliverables**

- Join across modalities into `System → Occurrence → CryptoAsset` edges
- Deterministic dedupe by asset content hash
- Conflict resolution: when source says a service supports X25519 *and* RSA but the network says RSA was negotiated, both are true and they answer different questions. Deployment reality wins for "what is running," source wins for "what is possible," and `correlate` keeps them distinct rather than picking one. (Resolves §14.3: separate evidence on one asset, not separate asset records — separate records would break dedupe by content hash.)
- Reachability: call-graph analysis from network entry points (I5), emitting `CallFrame[]` paths
- Control-class inference: our code, upgradeable dependency, or vendor blob

**Exit gate: passed.** On `fixtures/sample-repo`: the RC4 and MD5 in `tests/` are unreached, the 3DES in the module nothing imports is unreached, and the MD5 in a helper that is neither exported nor called from an exported function is unreached *inside a file that is itself live* — the case import-only analysis gets wrong. Nothing from a test or orphaned path is reported reached.

**Reachability answers with a `via`, not a boolean.** "A request handler calls this" and "this module is published, so somebody's handler might" justify different urgency, and one bit cannot tell them apart:

| `via` | Meaning |
|---|---|
| `OBSERVED` | seen on the wire; not an inference at all |
| `ENTRY_POINT` | a static path exists from a server, `main`, or framework route |
| `DEPLOYED_CONFIG` | configuration describing a running deployment |
| `LIBRARY_SURFACE` | inside a package that declares a public surface, so reachable by consumers outside this tree |
| `NONE` | analyzed, no path |

`LIBRARY_SURFACE` exists because the alternative is worse in the dangerous direction. Django loads its password hashers from a dotted string in settings and n8n discovers its nodes at runtime; no static import edge exists, and calling that code dead retires real work. It carries an explicit `ASSUMPTION` node saying so.

**Three defects the real repos exposed, each of which had silently collapsed the graph:**

1. NodeNext TypeScript imports `./x.js` and means `./x.ts`. Resolving only the literal specifier made every modern TS service look like it imported nothing.
2. Workspace package names are bare specifiers, indistinguishable from `express`. Without resolving them a monorepo has no edges at all — n8n reported 983 of 19,747 files reachable.
3. Python absolute imports (`django.utils.crypto`) and TypeScript path aliases (`@/crypto/signer`) are the norm at scale. Aliases resolve by unique-suffix match, preferring the importing package; an ambiguous match creates no edge, because a wrong edge marks unrelated code reachable.

---

## 8. Phase 4 — API, persistence, web surface

**Status: complete. Exit gate passed** — clicking a slack figure opens the full derivation, ending at `conf/nginx.conf:4` with the literal directive, in **one** click against a budget of three.

**Two decisions carry the phase.** Ranking is computed *on read*, with the policy pack as a query parameter, which is what makes the switcher a live control rather than a re-scan: the evidence does not change when the deadline does, only the arithmetic over it. Confidence is *not* recomputed on read — it is stored verbatim and returned verbatim, because a second implementation is a second chance to disagree with the CLI, and the whole claim is that the same evidence yields the same answer everywhere. A Postgres round-trip test asserts that a CBOM exported from a stored scan is byte-identical to one exported before it was ever written.

**Deliverables**

- Fastify routes: scans, systems, occurrences, CBOM export
- Scan diff — what appeared, what got remediated, what regressed. Versioned report slots as the diff primitive.
- Web (Vite + React, static build): two ranked worklists (confidentiality, authenticity), `Factor`-tree drill-down on every number, confidence panel showing what was suppressed, deadline timeline per row against the EO markers, policy pack switcher that re-ranks live with per-row diff badges
- Exactly one headline number, derived and clickable
- Jira / ServiceNow export — a worklist that cannot leave the tool does not get worked
- `assay push` ships evidence to the API; only evidence crosses the wire, never a ranking

**On the web framework.** It is a plain Vite + React SPA, not a framework with a hosting vendor attached. `vite build` produces static files any web server can serve, and the API base URL is resolved at runtime rather than baked into the bundle, so one build works against localhost, staging, or an air-gapped internal host. The first cut used Next.js as the roadmap originally specified; the Vercel GitHub App detected it and emailed the repository owner offering to deploy it, which is the wrong default for a tool whose whole point is running inside someone's perimeter.

**Not done, deliberately:** hosting. This is a pre-alpha tool with a kill gate two phases back; putting it behind a URL is not a development step. The Docker Compose file and the Prisma migration are the deployment surface for now.

**Exit gate: passed.** One click from a slack figure to `file:line`. The budget is also enforced in code rather than by eye — `derivationDepth()` measures the tree, and a test fails if a refactor buries evidence a level deeper.

**One environment note worth keeping.** Compose binds Postgres to host port **5433**, not 5432. A developer machine very often already has a local Postgres on 5432, and the resulting shadowed port fails as an *authentication* error rather than as a conflict, which is a bad afternoon.

---

## 9. Phase 5 — Binary analysis

**Status: complete. Exit gate passed** — `BINARY_STRING` cannot reach `CONFIRMED` without independent corroboration, verified at 1, 10, 500 and 5,000 repetitions and with every other binary modality piled on.

Deliberately last. Highest effort, lowest confidence, and shipping it early buries the good signal under noise.

**Deliverables**

- ELF / PE / Mach-O parsing
- Imported symbol tables — the strong signal (`RSA_sign`, `EVP_PKEY_CTX_new_id`, `ECDSA_do_sign`)
- Byte-exact constant detection: AES S-box, SHA-256 round constants, P-256/P-384 curve parameters. These survive stripping and are near-unambiguous.
- Embedded key and certificate detection via DER structure parsing, not string matching
- Static library version fingerprinting

**Exit gate: passed**, and it needed no special case. A 0.30 ceiling cannot reach 0.85 by noisy-OR within its own group however many matches there are, and `BINARY_SYMBOL` and `BINARY_CONSTANT` are in that *same* correlated group — three views of one artefact, not three independent facts. Adding a genuinely independent modality (a negotiated handshake) does confirm it. The invariant is arithmetic, not a check someone can forget.

**Verified against a real 114 MB runtime**, which produced 18 work items: 3DES, RC4 and X25519 on the confidentiality track, ECDSA P-256/P-384, Ed25519, SHA-1 and an embedded RSA certificate on the authenticity track — all `VENDOR_LOCKED`, which is a four-year Y and puts them near the top of the list where they belong.

**Two defects the first real run exposed:**

1. **SHA-2 constants were invisible.** A `uint32` round-constant table compiles to the *target's* byte order, and every signature was written big-endian from the specification. Both orders are now generated automatically for word-table constants. A big-endian-only scanner finds SHA-2 in essentially nothing that ships.
2. **The file-size cap skipped the files worth scanning.** 64 MB excluded the Node binary itself at 114 MB, and firmware images are routinely larger. Now 512 MB.

**On I9 in this phase specifically:** embedded private keys are found by DER structure parsing, and the parser returns `bytes: null` for them by construction. A test asserts that a distinctive 16-byte window of a real PKCS#8 key appears nowhere in the emitted report, in hex or in base64.

---

## 10. Phase 6 — Language expansion and CI integration

**Status: complete.**

**Ten languages.** Go, Java, C, C++, Rust and C# join TypeScript, TSX, JavaScript and Python. Each library family gets rules shaped to its own idiom rather than one generic pattern that half-works everywhere: Go names the algorithm in the package path, Java in a transformation string passed to a factory (`"AES/CBC/PKCS5Padding"`, where the mode and padding are half the security story), OpenSSL in the function name, .NET in the class. Import gating is per-language and is the single largest lever on precision — a local class called `Cipher` is not `javax.crypto.Cipher`.

This is where the estate actually lives. A TypeScript-only scanner reports on the layer a company rewrote last year and says nothing about the payments core or the twelve-year-old Java service that signs everything.

**The build gate fails on what is NEW.** A gate that fails on the existing estate fails on day one in every repository and is switched off by Friday, which protects nothing. Only `CONFIRMED` + reachable + quantum-vulnerable findings absent from the committed baseline can fail a build; `OBSERVED` evidence is not certain enough to block a merge, and an unreached finding is not exposure.

**Suppressions carry a mandatory expiry, and it is enforced three ways.** The schema will not parse one without a date. A suppression may not run longer than 365 days — anything longer is a decision never to fix it and should be recorded as one. And `--update-baseline` *drops* expired suppressions rather than renewing them, because silently rolling one forward is how a temporary exception becomes permanent without anyone deciding to make it so. An expired suppression is reported as its own outcome: a lapsed decision to remake, not a mysterious new finding.

Ships as a composite GitHub Action (`.github/actions/assay-scan`), a `.pre-commit-hooks.yaml` entry, and `assay ci`.

**Assay gates itself**, and its own estate is one finding: the Ed25519 keypair `@assay/scope` uses to sign grants. Shor-broken, on the authenticity track, found by the tool in its own source. It is in the committed baseline rather than hidden, and migrating it to ML-DSA is the obvious first use of this project on itself.

---

## 11. Phase 7 — Vendor attestation

**Status: complete.**

**The date is the product, not the questionnaire.** A questionnaire response is ingested at the `ASSERTED` ceiling (0.40) and cannot confirm anything on its own — a vendor saying their product uses AES-256 is not an observation of AES-256. What is worth collecting is the roadmap date: a class average says `VENDOR_LOCKED` is "four years, probably", while a vendor saying *2030-09-01, and you must replace the HSM line to get it* yields **Y = 6.52 years**, which blows the 2031 deadline by two years. That is a procurement conversation with a number in it rather than a shrug, and the number carries its provenance — the vendor's date enters the Mosca derivation as an `ASSUMPTION` node, with the class default it replaced still shown beside it.

`"evaluating"` is deliberately not treated as a commitment. It is a vendor declining to give a date, and ranking it as though one existed is exactly the optimism this tool exists to remove.

**The reconciliation cell that pays for the exercise is `UNDISCLOSED`:** cryptography observed in a product whose attestation never mentions it. Not because the vendor lied, but because a CBOM assembled from vendor claims alone would have a hole exactly there. The four verdicts are `CORROBORATED`, `UNDISCLOSED`, `UNVERIFIED` (claimed and untested — which may simply be true) and `CONTRADICTED_ROADMAP` (the vendor claims post-quantum support is available and the wire still negotiates a Shor-broken key exchange).

An attestation carries a mandatory `validUntil`, for the same reason a suppression does: a response with no expiry is a claim about a product that has shipped four releases since.

`VENDOR_LOCKED` and `HARDWARE` are the classes that actually blow the timeline, and they're unresolvable by scanning.

The FAR rule directed by EO 14412 sec. 6 makes contractor attestation a compliance artifact due 2030-12-31, which moves this earlier than originally planned.

- Structured questionnaire ingestion under the `ASSERTED` modality at its 0.40 ceiling
- Diff between what the vendor claims and what the network says

---

## 12. Decision log

**D1 — `DEPENDENCY` ceiling. RESOLVED: 0.35.**
A library *supporting* RSA is not evidence RSA is *used*. Dropped from 0.55 to 0.35 and treated as a search hint that directs AST scanning. Emitted as CycloneDX `implements`, never `uses` — the schema already encodes the distinction, so the caveat travels with the data.

**D2 — Policy pack figures. RESOLVED, and the answer changed the model.**
The packs weren't merely stale. `crqcYear: 2035` measures the wrong clock for a paying customer: EO 14412's 2030/2031 deadlines bind 4–5 years earlier for anyone in federal or contractor scope. Ranking now computes both constraints and reports which binds. Two packs ship: `eo-14412` (regulatory + physics) and `nist-ir-8547-draft` (physics only, asserts no deadline). Verify both against current published revisions before a real ranking.

**D3 — Policy pack governance.**
If customers author their own Z values, rankings stop being comparable across organizations. Likely split: signed vendor packs for Z and D, locally overridable Y. Not blocking for Phase 1, blocking for Phase 4.

**D4 — CISA minimum elements (new).**
EO 14412 sec. 5(d) directs CISA to publish CBOM minimum elements ~2026-12-20. The exporter is profile-pluggable; `cisa-min-elements` currently emits CycloneDX 1.7 and marks itself `PROVISIONAL` rather than pretending to a schema nobody has seen. Fill it in when it publishes.

---

## 13. Out of scope, permanently

- **Automated remediation.** Rewriting crypto call sites automatically is how you ship a subtly broken key exchange. Assay recommends and never edits. (This also keeps the project clear of InfoSec Global's US 12,340,262, which covers runtime crypto-engine replacement.)
- **Key material handling.** See I9.
- **Crypto implementation.** No PQ algorithms are implemented here. Assay is inventory.
- **Certificate lifecycle management.** Export cleanly into a CLM rather than competing with one.

---

## 14. Open questions

1. **Reachability across process boundaries.** A service calling a signing microservice over gRPC — static call-graph analysis stops at the network edge. Probably needs distributed-trace ingestion. Phase 8 conversation.
2. **GTM.** This is a CISO budget product with an enterprise sales cycle. Phase 6's CI integration is the only plausible self-serve wedge; the consultancy/MSP channel (which implies multi-tenancy) is the realistic near-term route. Worth deciding which is the entry point.
3. ~~Whether "capability" and "deployment" should be separate asset records.~~ Resolved in §7: separate evidence on one asset.
