# Assay — Competitive & Regulatory Review
Source review of all 30 supplied URLs, as of 2026-08-28. Ordered by impact on the roadmap.

---

## 0. The headline: the roadmap's ranking math is now wrong

**EO 14412, "Securing the Nation Against Advanced Cryptographic Attacks," signed 2026-06-22.**

| Deadline | Requirement |
|---|---|
| 2026-07-22 (30d) | Agencies name a PQC migration lead to OMB + ONCD |
| 2026-09-20 (90d) | OMB guidance: agencies review HVA / high-impact inventories, produce transition plans |
| ~2026-12-20 (180d) | **CISA publishes "minimum elements for a cryptographic bill of materials"** enabling *automated assessment of cryptographic assets*; NIST starts PQC pilot; NIST revises CMVP |
| ~2027-03-19 (270d) | FAR Council proposed rule — covered-contractor compliance / vulnerability disclosure |
| 2027-12-31 | NIST pilot complete |
| **2030-12-31** | All HVAs + high-impact systems on PQC for **key establishment**; covered contractors comply via FAR |
| **2031-12-31** | Same systems on PQC for **digital signatures** |

Sections: 1 Background · 2 Definitions · 3 Coordinating · 4 Accelerating · 5 Leading · 6 Procurement · 7 General. Named: OMB, ONCD, NSA, DHS/CISA, Commerce/NIST, State, Dept. of War, NASA, GSA, DNI. Cites FIPS 199, 140-3, 186-5, 203. **Does not name CNSA 2.0 or NIST IR 8547.**

### What this does to Assay

1. **`crqcYear: 2035` is no longer the binding constraint.** For anyone in federal or contractor scope, the binding date is a *regulatory* one — 2030 or 2031 — arriving 4–5 years before the pack's CRQC horizon. Mosca still models the physics; it no longer models the deadline the buyer is actually being held to. Ranking must take `min(slack_crqc, slack_regulatory)` and say which one bound.
   - This resolves **D2**. The pack figures aren't merely stale; they're measuring the wrong clock for the paying customer.
2. **The EO independently validates invariant I2.** The government split key establishment (2030) from digital signatures (2031) — one year apart, two separate deadlines. Assay's two-track ranking is now the *regulator's* model, not an idiosyncratic design choice. Every competitor that pools both into one "quantum readiness %" is now provably misaligned with the mandate. This is the single strongest marketing fact in this document.
3. **CISA's "minimum elements" guidance lands ~Dec 2026** — inside Phase 1's window. The phrase mirrors NTIA's SBOM minimum elements, so expect a required-field list, not a new schema. Build the exporter as a *pluggable profile* now (`cyclonedx-1.7`, `cisa-min-elements`), ship the stub, fill it in December.
4. **FAR contractor rule pulls Phase 7 forward.** Vendor attestation stops being an upsell and becomes a compliance artifact contractors must produce by 2030-12-31.
5. FDD's March 2026 analysis — "no formal regulatory requirement, no mandated schema, no federal minimum data elements" — went obsolete three months later. Useful narrative: *the category had no mandate until June, and now has a hard one with a CISA schema arriving in December.*

**Source discrepancy — verify before quoting.** The three EO sources disagree on which FAR rule is 180d vs 270d, and hillgraph adds an NSA status report at 270d that the others don't. Read the Federal Register text (2026-12909) before any of these dates appear in product output or a policy pack.

---

## 1. Standards: two concrete corrections

**CycloneDX 1.7 is current, not 1.6.** ECMA-424, 2nd edition, December 2025, standardizes CycloneDX **v1.7** (1st ed., June 2024, was 1.6). The roadmap targets 1.6 throughout. Target 1.7; keep a 1.6 emitter for tools that lag.

**CycloneDX's own confidence model is far weaker than Assay's — and that's the moat.**

| CycloneDX 1.6/1.7 `evidence` | What Assay needs |
|---|---|
| `identity.confidence` — integer 0–100 | a derived value with a recursive derivation |
| `identity.methods[].technique` — enum: `hash`, `signature`, `fingerprint`, `attestation`, `manifest`, `other` | a 10-value modality taxonomy with per-modality ceilings |
| no notion of correlated vs independent methods | noisy-OR over independent groups only |
| no provenance / taint tracking | the `ASSUMPTION` gate (I6) |

So: the standard has a confidence *field* and no confidence *discipline*. Six techniques, none of which distinguish a resolved AST call site from a string match in a stripped binary. **The `Factor` tree has no native home in CycloneDX** — it must ride in namespaced `properties` (`assay:factor:*`) plus the Assay-native report, exactly as the README already says. Make that concrete in Phase 1 rather than deferring.

Two free wins hiding in the schema:

- **`evidence.occurrences`** (`location`, `line`, `offset`, `symbol`, `additionalContext`) and **`evidence.callstack.frames`** (`package`, `module`, `function`, `parameters`, `line`, `column`, `fullFilename`) already exist and are essentially unused by the field. Assay's Phase 3 reachability analysis should **emit call paths into `callstack`**. Every competitor claims reachability; none of them ship the path in a standard field a third party can check.
- **`implements` vs `uses` dependency semantics.** CycloneDX already encodes the exact distinction behind **D1** — a library *implementing* RSA is not an application *using* it. Resolve D1 as recommended (0.55 → **0.35**) *and* emit dependency findings as `implements`, never `uses`. The schema then carries the caveat for you.

---

## 2. Competitor map

| Vendor | Primary modality | Notable | Weakness (per Encryption Consulting) |
|---|---|---|---|
| **IBM** Quantum Safe Explorer / Advisor / Remediator; CBOMkit (Apache-2.0, ~134★) | Source + object code static; runtime TLS; hybrid proxy | Explorer=discover, Advisor=operational view + risk priority, Remediator=patterns. CBOMkit = hyperion (Sonar Cryptography plugin) + theia (container/filesystem) + coeus (viewer) + OPA/Rego compliance | Java 100% (JCA, BouncyCastle), Python 100% (pyca), Go partial. **Does not build repos before scanning** — no class files/JARs, so Java symbol resolution degrades |
| **SandboxAQ** AQtive Guard | Passive network + **runtime hooking** + filesystem | $1.45B raised, ~$14B valuation, FedRAMP Ready Jul 2026. **$250k/yr, 12-mo enterprise contract on AWS Marketplace.** Entity model: Issues → Instances → Reports → **Slots** (versioned report containers). CrowdStrike/Palo Alto/Jira/GitHub integrations, GenAI assistant | Runtime instrumentation overhead; needs taps/SPAN; premium price; support gaps in reviews |
| **Keyfactor** (acq. InfoSec Global + CipherInsights, May 2025) | **Agent/EDR-based** (CrowdStrike, Tanium), filesystem/registry/**memory**; CipherInsights passive network | US Pat. **12,340,262** (Oct 2025): pluggable crypto engines, runtime algorithm offload | Agents ⇒ legacy blind spots; weak on network appliances and embedded/IoT; misses custom app code |
| **Encryption Consulting** CBOM Secure | Widest: cloud KMS, HSM, KMIP, DB, network, source, filesystem — "20+ sensors" | Claims **7 languages, 70+ libraries, 880+ function patterns, call-graph reachability across files**; 4-band risk; key-reuse detection; HSM-vs-software key separation; multi-tenant | Vendor's own comparison page — treat claims as marketing |
| **Fortanix** PQC Central (in Key Insight) | KMS/service discovery | Quantum-readiness %; **ServiceNow / Jira roadmap export** | Tied to Fortanix DSM/Armor |
| **AppViewX** AVX ONE | Static code + deps + certs + config | "Crypto Resilience Scorecards", exec + technical dashboards, CI/CD | No dynamic/network analysis; weak on third-party estates |
| **CryptoNext** COMPASS | 100% passive network, **100+ IT/OT protocols** | Safe for OT; ~1 Gbps/probe | Wire only; no at-rest |
| **Quantum Xchange** CipherInsights | Passive network | NCCoE-referenced | **Can't say where the algorithm is implemented** |
| **ISARA** Advance | Agentless, ingests NDR/EDR telemetry | Fast deploy, multi-tenant | Only as good as existing telemetry; high-level, not deep |
| **Tychon** ACDI | Agent/agentless endpoint | NSM-10 / HR 7535 federal framing | No source analysis; not for OT |
| **PQStation** QVision, **QryptoCyber** | Sensors / 5-pillar orchestration | CBOM output + PQC scores | New entrants |
| **Cycode, Checkmarx, Sectigo** | SBOM/SCA and CLM adjacency | Checkmarx: CBOM as an ASPM extension of SCA + reachability. Cycode: *"dedicated CBOM generation is not a settled product category yet."* Sectigo: CBOM only pays off paired with automated CLM | All position CBOM as a feature of an existing platform, not a product |

---

## 3. What they do that Assay does not

Ranked by how much it costs Assay to be missing.

1. **Cloud KMS / HSM / KMIP inventory.** AWS KMS, Azure Key Vault, GCP KMS list key specs directly over authenticated APIs — near-`PKI_CERTIFICATE`-grade confidence, no scope grant beyond IAM, days of work. CBOM Secure and Fortanix both lead with it. **This is the highest value-per-effort modality Assay is missing, and it belongs in Phase 2 ahead of network probing.**
2. **Host/agent and EDR-derived discovery** (Keyfactor, Tychon, ISARA). Assay has no host modality at all. ISARA's model — ingest what the customer's EDR/NDR already collects — needs no agent of your own and is a cheap `HOST_AGENT` evidence source.
3. **Runtime hooking** (SandboxAQ). Catches dynamically generated keys and config-driven algorithm selection that AST provably cannot. Genuinely independent of source evidence, so it *stacks* under I1's noisy-OR.
4. **Ticketing / ITSM egress** (Fortanix → ServiceNow/Jira; SandboxAQ → Jira/GitHub). A defensible worklist that can't leave the tool doesn't get worked. Cheap; Phase 4.
5. **Declarative policy engine.** CBOMkit runs compliance through OPA/Rego with a standardized JSON findings format. Assay's policy packs should be OPA-expressible, or at minimum declarative enough that a customer's auditor can read them.
6. **Executive scorecard.** Fortanix's readiness %, AppViewX's Resilience Scorecard, QryptoCyber's PQC score. Assay's design correctly refuses heuristic scores — but the CISO buyer needs one number for the board. **Resolution: ship exactly one headline number, and make it derived and clickable** — e.g. *"% of reachable confidentiality-track occurrences whose projected completion misses 2030-12-31."* That is a defensible number, not a severity heuristic.
7. **OT/ICS protocol coverage** (CryptoNext, 100+ protocols). Out of scope for now; note it as a partner surface.
8. **Multi-tenancy** (CBOM Secure, ISARA) — the consultancy/MSP channel, which for a CISO-budget product is the realistic route to market ahead of self-serve.
9. **FedRAMP** (SandboxAQ, Ready as of Jul 2026). Post-EO, this is the federal gate. Not now; know it exists.
10. Certificate *lifecycle* — issuance, rotation, CLM (Keyfactor, Sectigo, AppViewX, Fortanix). Correctly excluded by §13 and I9. Mitigate by exporting cleanly into a CLM rather than competing with one.

---

## 4. What Assay does that none of them do

Each of these is absent from every one of the twelve products reviewed.

1. **Per-modality confidence ceilings with same-modality repetition suppressed.** CycloneDX permits per-method confidence; no shipping tool disciplines it. This is the moat, and it's the reason the roadmap's Phase 1 exit gate ("small enough a human would read it") is the right gate.
2. **Noisy-OR across *independent* groups only.** Every competitor that combines evidence treats source + dependency + config as additive corroboration. They're correlated; stacking them manufactures confidence.
3. **The provenance gate (I6).** No `ASSUMPTION` anywhere in the derivation, or it can't export `CONFIRMED`. Nobody else gates export tier on taint.
4. **Two ranked tracks, never pooled — now backed by the EO's 2030/2031 split.**
5. **Mosca with Y derived from control class**, rather than an unexplained severity score. `VENDOR_LOCKED` and `PROTOCOL_BILATERAL` correctly reframe items as procurement problems; no competitor models who *can actually change the thing*.
6. **Versioned policy packs with the pack version recorded on every finding**, making a re-rank a diff. AppViewX and Fortanix bake deadlines in.
7. **Determinism.** Same evidence set ⇒ byte-identical CBOM. Nobody claims reproducibility. Post-EO, with auditors and FAR clauses in play, "you can re-run this and get the same file" is an audit argument, not a nicety.
8. **Capability vs deployment kept as distinct facts.** Source says X25519+RSA supported; network says RSA negotiated. Both true, different questions. Every competitor picks one and loses the other. (This also answers open question §14.3: keep them as separate evidence on one asset, and let `correlate` project the two views — separate asset records would break dedupe by content hash.)
9. **Signed `ScopeGrant` as a type-level gate on active probing.** CryptoNext and Quantum Xchange went *fully passive* specifically to dodge this problem; nobody offers authorized active probing under a verifiable grant. For banks and OT this is a deployment unlock, not a compliance checkbox.
10. **Never touching key material.** Keyfactor and Fortanix are key-management platforms and hold key material by design. Assay is deployable in places they need a much longer security review.

**One claim to stop making unqualified: reachability.** CBOM Secure claims call-graph reachability across files today, and Checkmarx claims CBOM-to-reachability linkage. Assay's edge is no longer *having* reachability — it's **shipping the evidence for it** (`evidence.callstack` frames, drill-down to the path). Reframe I5 accordingly.

**Patent note (not legal advice):** InfoSec Global's US 12,340,262 covers *replacing* crypto engines at runtime via a pluggable API. Assay's §13 "recommends and never edits" scope decision keeps it clear of that estate. Worth a look from counsel before anyone proposes an auto-remediation feature.

---

## 5. UI/UX direction

### What competitors actually show

| Product | Pattern | Verdict |
|---|---|---|
| Fortanix PQC Central | **Sunburst chart** — root "All Connections" → concentric rings → assets; hover shows parent + counts; green/red/mixed; `Group By: Keys / Services / Certificates / Crypto Asset Types`; readiness % as `((total − vulnerable)/total)×100`; right-side summary panels; click count → filtered list; Back | Sunburst optimizes for *look at the estate*, not *what do I do Monday*. **Steal the group-by + click-through-to-filtered-list. Skip the sunburst.** The readiness formula is exactly the pooled single score I2 forbids |
| SandboxAQ AQtive Guard | Issues → Instances; Reports; **Slots** = versioned report containers; filterable tables | Issue/Instance ≙ Asset/Occurrence — independent validation of the core model. **Slots ≙ Assay's scan diff**; adopt versioned report slots as the diff primitive |
| CBOMkit | Scan-a-repo-by-URL, **WebSocket live scan progress**, viewer with stats, per-policy compliance status | Live progress is a genuinely good pattern for a scan that takes minutes. Steal it |
| AppViewX | Milestone/deadline table, dual dashboards (exec + technical), Crypto Resilience Scorecard | The **milestone table** is the right shape post-EO. Two audiences, two views |
| IBM | Discover → Assess → Remediate as three products | Three-verb workflow is the category's mental model; match the vocabulary even though Assay stops before remediate |

### The screen nobody has built

None of the twelve exposes a derivation. **That absence is the product.**

- **Two worklists, side by side, never merged.** `Confidentiality` | `Authenticity`. Sorted by slack ascending. Each capped at a readable length by construction (I1), with the overflow reachable but not shown. Row: asset · system · control class · slack · assertion chip · reachability chip.
- **Click the slack number → "Why this number."** X, Y and Z rendered as three terms, each expanding into its `Factor` tree, leaves being raw evidence: `file:line`, the handshake transcript, the cert fingerprint. Roadmap gate is three clicks to raw evidence — hold it.
- **Click the confidence chip → the modality breakdown**, showing which groups were independent, which collapsed, and — explicitly — *"412 `BINARY_STRING` matches, counted once, ceiling 0.30."* Showing the suppression is more persuasive than showing the result.
- **Policy pack switcher in the header. Changing it re-ranks live and puts a diff badge on every row that moved.** With EO 14412 vs CNSA 2.0 vs an internal pack, this turns the argument about deadlines into a control, and it is the single most demo-able thing in the product.
- **Deadline timeline per row.** A bar from today through projected completion (`Y` by control class) against a 2030-12-31 / 2031-12-31 marker. Overshoot renders red. This is the picture a procurement conversation needs, and it is strictly more useful than a sunburst.
- **Unreached findings in a separate tab with their own count** (I5). Never in the headline.
- **Suppressions render as chips that visibly decay toward expiry** (Phase 6). A suppression that never expires is a lie; make the lie visible.
- **Live scan progress** (from CBOMkit) so a multi-minute scan isn't a spinner.

### Anti-patterns, all observed in the reviewed field

Single pooled readiness % · sunburst as primary navigation · 40k-row exports · a GenAI assistant standing in for a derivation · heat-map severity with no arithmetic behind it · dashboards that show the estate but never a next action.

---

## 6. Roadmap deltas, ordered

1. **Add a regulatory-deadline term to the policy pack and to `scoreMosca`.** `deadlineByPurpose: { keyEstablishment: 2030-12-31, digitalSignature: 2031-12-31 }`. Rank on `min(slack_crqc, slack_regulatory)` and record which bound. Ship an `eo-14412` pack alongside `nist-ir-8547-draft`. **Closes D2.**
2. **Resolve D1 → `DEPENDENCY: 0.35`**, and emit dependency findings with CycloneDX `implements`, never `uses`. Do it before rule authoring, as the roadmap says.
3. **Target CycloneDX 1.7** (ECMA-424 2nd ed.); keep the 1.6 emitter.
4. **Make the exporter profile-pluggable now** — `cyclonedx-1.7`, `cyclonedx-1.6`, `cisa-min-elements` (stub until ~Dec 2026).
5. **Add modalities:** `CLOUD_KMS_API` ≈ 0.97 (own independent group with PKI), `RUNTIME_HOOK` ≈ 0.97 (independent of source — it stacks), `HOST_AGENT` ≈ 0.90 (correlated with binary evidence).
6. **Phase 2 reorder:** cloud KMS/HSM/KMIP inventory *before* active network probing. Higher confidence, lower effort, no grant machinery required.
7. **Phase 3: emit reachability paths into `evidence.callstack`.** Ship the evidence, not the claim.
8. **Phase 4:** policy-pack switcher with live re-rank + row diffs; versioned report "slots" as the diff primitive; Jira/ServiceNow export; exactly one derived headline number.
9. **Phase 7 moves earlier** — the FAR rule makes contractor attestation a 2030 compliance artifact, not a renewal upsell.

---

## 7. Sources not retrieved

Honest gaps in this review:

- Three Business Wire URLs (`20250422013160`, `20250423931888`, `20240717483673`) and the Fortanix release timed out repeatedly behind bot protection. Their subject matter is covered via Keyfactor, SandboxAQ, and Fortanix primary sources — but the specific pages were not read.
- `ibm.com` Quantum Safe Explorer product blog and docs, and `g2.com/sellers/sandboxaq`, returned HTTP 403. Covered via IBM newsroom, the IBM partner directory, and secondary review aggregators.
- Three `researcher.ibm.com` blog URLs (cbomkit, Linux Foundation, original CBOM) now 307 → `research.ibm.com/404`; IBM retired that host. Covered via the `IBM/cbomkit` repo.
- The ECMA-424 PDF is the **1st edition (June 2024 = CycloneDX 1.6)**; the current standard is the 2nd edition (Dec 2025 = v1.7). Schema detail was taken from the CycloneDX 1.6 JSON reference instead. A 4.9 MB copy of the 1st-edition PDF is cached in this session's tool-results directory.
