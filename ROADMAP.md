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
| 4 | API, persistence, web | makes the derivation clickable |
| 5 | Binary analysis | last on purpose |
| 6 | Language expansion + CI | breadth after depth |
| 7 | Vendor attestation | now a FAR compliance artifact, not an upsell |

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

**Deliverables**

- Fastify routes: scans, systems, occurrences, CBOM export
- Scan diff — what appeared, what got remediated, what regressed. Versioned report slots as the diff primitive.
- Web: two ranked worklists (confidentiality, authenticity), `Factor`-tree drill-down on every number, confidence panel showing what was suppressed, deadline timeline per row against the EO markers, policy pack switcher that re-ranks live with per-row diff badges
- Exactly one headline number, derived and clickable
- Jira / ServiceNow export — a worklist that cannot leave the tool does not get worked
- Railway deploy

**Exit gate:** clicking any slack figure walks the full recursive derivation to raw evidence in under three clicks.

---

## 9. Phase 5 — Binary analysis

Deliberately last. Highest effort, lowest confidence, and shipping it early buries the good signal under noise.

**Deliverables**

- ELF / PE / Mach-O parsing
- Imported symbol tables — the strong signal (`RSA_sign`, `EVP_PKEY_CTX_new_id`, `ECDSA_do_sign`)
- Byte-exact constant detection: AES S-box, SHA-256 round constants, P-256/P-384 curve parameters. These survive stripping and are near-unambiguous.
- Embedded key and certificate detection via DER structure parsing, not string matching
- Static library version fingerprinting

**Exit gate:** on a corpus of binaries with known crypto composition, `BINARY_STRING` findings never reach `CONFIRMED` without independent corroboration. Verify the ceiling holds under adversarial input.

---

## 10. Phase 6 — Language expansion and CI integration

- Go, Java, C/C++, Rust, C# AST rules
- GitHub Action and pre-commit hook: fail the build on a new `CONFIRMED` quantum-vulnerable occurrence in reachable code
- Baseline and suppression **with mandatory expiry** — a suppression that never expires is a lie

---

## 11. Phase 7 — Vendor attestation

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
