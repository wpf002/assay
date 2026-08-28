# Assay — Roadmap II: from engine to product

[ROADMAP.md](ROADMAP.md) is finished. Its eight phases built a working engine and every exit gate passed. This document asks the question that one never did: *would anyone buy this.*

A first draft was reviewed by four adversarial critics — a sceptical CISO at a federal contractor, a competitor planning to kill it, an engineering leader attacking the sequencing, and an honesty audit. Fourteen fatal objections came back. This version is the answer to them, and it retracts most of the first draft's plan.

---

## 0. Three things established the hard way

**The engine is good.** Assay reduces n8n's 834k lines to ten confirmed work items, each walkable to a `file:line`, with a byte-identical re-export. That is genuinely better than what the field ships.

**My quality claims could not be trusted.** An adversarial audit of the claims made while building it found **82 confirmed defects, 15 critical**, and established that only 18 of 26 "fixed" items fully held. A CIDR with an empty prefix (`10.0.0.0/`) matched every address on the internet. A stated invariant was being laundered. All are fixed and mutation-tested; the record is commit `bcf792e`.

**And the thesis is aimed at the wrong problem.** This is the finding that reorganises everything below. Put to a CISO at the buyer profile this project named:

> Ranking is the last 5% of my work and the easiest 5%. My problem is acquisition of the inventory in the first place: I cannot get source for the COTS I run, the appliance in the SCIF, the ERP, the subcontractor deliverable.

Assay is strongest at source analysis. Source is the part of that estate the buyer already sees best. **The product's centre of gravity and the buyer's pain are in different places**, and no amount of improving the ranking closes that gap.

---

## 1. What follows from that

The no-source modalities are already built — binary analysis, network probing, PKI, cloud KMS classification, vendor attestation. They are the four phases that were validated least: KMS ships adapters but no SDK calls, binary analysis has been run against exactly one file, network probing against a localhost fixture, and attestation has never seen a real vendor response.

So the work is not "measure how well we read TypeScript". It is **prove the modalities that reach an estate nobody has source for**, and be honest in public about what remains unreachable.

Two corrections to the pitch, both from the competitor review:

**The 40,000-row CSV is not incompetence.** It is a requested deliverable serving a different obligation: the CBOM a regulator receives should be exhaustive. The short list is the *plan*, not the *inventory*. Assay already produces both — the CycloneDX export is complete, the worklist is ranked — and presenting them as opposed was a mistake. Sell the pair.

**The real advantages are commercial, not technical.** The two-track split, the ceilings, the derivation drill-down and the pack switcher are one quarter of work for a competent team of six, and any incumbent can copy them. What they cannot easily copy:

| Advantage | Why it is structural |
|---|---|
| Willing to report ten findings | An incumbent's contract value is metered on asset counts, and their counsel will not let them hold the customer's prioritisation risk |
| Never touches key material | Keyfactor and Fortanix are key-management platforms; key custody is the charter |
| Determinism | Easy on a pure static engine, hard on a sampling or runtime path |

That advantage has a shelf life measured in quarters, which is an argument for moving on the market now rather than for building more engine.

---

## 2. Phase 9 — Authentication, this week

An API that serves an inventory of an organization's weakest cryptography to any caller that can reach the port. It is days of work and the first draft put it behind a multi-month gate.

- Authentication and authorization on every route; the estate view scoped to what the caller may see.
- An audit log of who read what.
- Treat the CBOM as the sensitive artifact it is: at a federal contractor it is very likely CUI, which constrains where it may be stored and processed. **This decides whether a pilot is possible at all** (see D7), so it is not a Phase 13 concern.

Nothing else in this document matters if a pilot cannot be run.

---

## 3. Phase 10 — Five buyer conversations, in parallel with Phase 9

Nothing in this project has ever been shown to a buyer. Every strategic claim in it — including the ones in §1 — is inference from published competitor material, and [COMPETITIVE.md §7](COMPETITIVE.md) records that several of those sources could not even be retrieved.

Five conversations, structured to falsify rather than to pitch:

- What fraction of your estate do you have source for?
- What did the last inventory attempt cost you, and where did it stop?
- Who signs the CBOM, and what do they need in order to sign it?
- What system of record does a finding have to land in before it gets funded? (eMASS, Xacta, ServiceNow, with a POA&M identifier, milestone and owner.)
- Would you buy a short defensible list, or is that not the problem?

**This is the real kill gate.** If five buyers say ranking is the easy part, the differentiator this whole project is built on is not a business, and the right outcome is to stop — or to pivot onto the acquisition problem, which is Phase 11.

---

## 4. Phase 11 — Coverage, stated and signed

The first draft proposed measuring recall against a hand-built ground truth and killing the project below 80%. Three reviewers dismantled that, correctly:

- [VALIDATION.md](VALIDATION.md) already judged building that ground truth "a larger exercise than the gate requires". The first draft reversed that without explaining what changed.
- Recall has no well-defined denominator here. Call sites is the wrong unit — the product's claim is that 151 `createHmac` sites are *one* work item. Deciding whether a miss counted requires reproducing Assay's own grouping and reachability semantics by hand, which is not independent measurement.
- **The gate cannot fire.** Recall gaps close by writing more rules. The realistic outcome is not "40%, unrecoverable" but "58%, and twelve more rules to write", which is a backlog wearing a gate's clothes.
- And 80% does not help the buyer anyway: *"I cannot attest an inventory to a regulator on a tool that silently misses one in five call sites."*

What the buyer actually asked for is not a recall percentage. It is **a coverage attestation they can sign**: a per-estate-class statement of what Assay saw, what it could not see, and why.

**Deliverables**

- A machine-generated coverage report per scan: for each class of the estate — application source, deployed configuration, certificates, managed keys, vendor binaries, appliances, network endpoints, third-party SaaS — did Assay look, with what modality, and what did it explicitly not reach.
- The trace-derived blind-spot list (`GET /estate/coverage`) generalised: every service, host and product observed that has no inventory.
- Signed, so it is an artifact rather than a screenshot.
- Recall measured only where a real ground truth is cheap: purpose-built corpora with known composition, per rule, in unit tests — not by hand-inventorying 2.1M lines.

**This gate can fire.** If the honest answer is "we saw 15% of your estate and here is the list of what we did not touch", that is a real result, it is publishable, and it tells you whether to build Phase 12 or stop.

---

## 5. Phase 12 — Reach the estate that has no source

Ordered by what Phase 10 and 11 say, but on present evidence:

**Host and endpoint ingest, first.** Read what the customer's EDR and NDR already collect rather than deploying another agent. The CISO review called this the single highest-value item in the roadmap. It is also the biggest — per-vendor integrations against CrowdStrike, SentinelOne, Defender and whatever else they run, each with its own schema and its own approval — and describing it in one line was the first draft's largest under-estimate. It inherits ISARA's weakness, recorded in [COMPETITIVE.md §2](COMPETITIVE.md): *only as good as the existing telemetry, high-level rather than deep.* That caveat belongs in the pitch, not buried.

**Live cloud KMS.** Adapters and classification exist and are tested; only the SDK calls are missing. COMPETITIVE.md §3 ranked this the highest value-per-effort gap in the product and it remains unwired.

**Binary analysis at scale.** It works on one file. A corpus of real firmware and vendor binaries is what would show whether it works at all.

**Vendor attestation with a real vendor.** The schema, the reconciliation and the date-driven Y term are built and have never met a real questionnaire response.

---

## 6. Phase 13 — Sell something

The realistic first transaction is not a licence. It is **a paid, scoped assessment on three programs**: Assay's authors run the tool, hand-verify the output, and deliver a CBOM plus a ranked plan plus a signed coverage statement.

It is the only motion that works today, and it does four things at once: revenue, five more estates to test against, the ground truth that Phase 11 cannot otherwise afford, and the reference a later licence sale needs.

**On the free CI gate.** The first draft made it the primary wedge. That is structurally impossible for the buyer it named: at a federal contractor developers cannot install from the public npm registry, and everything arrives through an internal mirror after a supply-chain review. The gate is still worth publishing, but it serves a *different* audience — product and SaaS engineering organizations whose estate really is mostly source — and pretending one funnels into the other was wishful. **Pick one deliberately (D5).**

---

## 7. Phase 14 — Be procurable

The competitor review is blunt about where this sale dies: *"it does not reach the technical evaluation — it dies in third-party risk management."*

- SOC 2 Type II, cyber insurance, indemnification, an escrow arrangement, a support SLA, and a credible answer to "will you exist in 2031". The bus factor is one, and a supply-chain risk team scores that.
- A price and a licensing model. Neither exists.
- **Resolve the FedRAMP contradiction.** The first draft named federal contractors as the primary buyer and filed FedRAMP under "not now". Those cannot both stand: either commit to the authorisation path and its cost, or name a buyer for whom it is not a gate (D9).
- Output that lands in a system of record — eMASS, Xacta or ServiceNow, with a POA&M identifier, milestone, resource estimate and responsible party. A finding that does not reach the system of record does not get funded.
- A one-page board answer. The single derived headline number exists in the engine; it has never been shaped into something a CISO can put in front of a board.

---

## 8. Phase 15 — Standards, and someone else's evaluation

**CISA's minimum-elements guidance for CBOMs lands around December 2026** (EO 14412 §5(d)). Whoever is in that working group shapes the required-field list. Treating it as an integration task — which is what [ROADMAP.md D4](ROADMAP.md) does — is, in the competitor's words, the cheapest way to lose the category: if the required fields are what an incumbent's exporter already emits, the `Factor` tree stays a proprietary extension nobody's auditor asks for.

**And commission an independent evaluation.** Every number this project has ever published is self-measured on a self-chosen corpus by the author whose self-assessments an audit found 82 defects in. §0 says a tool whose pitch is *defensible* cannot ask a buyer to take its word for anything; that applies to its own precision figure first.

---

## 9. Decisions

| | Decision | Blocking |
|---|---|---|
| **D5** | CI gate as a free product for source-heavy engineering orgs, or drop it and focus wholly on the enterprise assessment motion. They are different businesses. | Phase 13 |
| **D6** | What does the coverage attestation have to say for a buyer to sign it? Ask them (Phase 10) rather than inventing a threshold. | Phase 11 |
| **D7** | Self-hosted or hosted. Regulated buyers will require self-hosted, which rules out usage pricing, telemetry and every standard expansion signal. This decides whether a pilot is possible, so it is needed now. | Phase 9 |
| **D8** | Who publishes policy packs long-term, and what happens when CISA's guidance forces a reissue. | Phase 15 |
| **D9** | Federal contractors with the FedRAMP cost, or a buyer for whom it is not a gate. | Phase 14 |

---

## 10. Corrections to the record

Found by the honesty review and worth keeping visible:

- **The published figures were stale.** "11 work items" and the 96.7%/100% precision samples were measured at commit `c7d189a`. Commit `bcf792e` then changed the exact rules and the exact `CONFIRMED`-set logic those numbers are computed over. Re-measured after the fixes: django 2 confirmed, Ghost 2, **n8n 10** (was 11). **The precision figures have not been re-verified and must be treated as unmeasured until they are.**
- **No competitor has ever been run.** COMPETITIVE.md is a review of vendor marketing and secondary sources, several of which could not be retrieved. Every comparative claim in it is an inference about published material, not a benchmark.
- **The three-click gate was demonstrated on one path**, not proven for every finding.
- **The audit that produced the 82 defects was self-run** and its only artifact is a commit message. That is the same conflict §8 objects to in others.

---

## 11. Still open from the audit

- `java.security` disabled-lists do not resolve `MD2` or `SSLv3`.
- SSH and TLS mint different asset ids for the same hybrid KEM; `detect-network` was outside the fix scope.
- The Rust rule misses `SigningKey::random`, the common p256 constructor.
- `latestPerSystem` still loads every occurrence of every system to merge them.

---

## 12. Permanently out of scope

Unchanged from [ROADMAP.md §13](ROADMAP.md), each restated because each will be asked for: **automated remediation**, **key material handling** (I9), **implementing cryptography**, **certificate lifecycle management**.

And one addition: **telemetry**. Not now, not anonymised, not opt-out. It is incompatible with the self-hosted deployment a regulated buyer requires, and with the trust the product is selling.

---

## 13. What was cut from the first draft, and why

Kept visible so the same mistakes are not made twice.

- **"Measure recall, 80% or kill."** The gate could not fire, the denominator was undefined, the ground truth would have been built by the tool's own author to the tool's own definitions, and 80% would not have satisfied the buyer anyway. Replaced by the coverage attestation.
- **The free npm CI gate as the primary wedge.** Structurally impossible at the buyer the same document named.
- **Migrating Assay's own Ed25519 signing to ML-DSA, described as "the most credible demo this project will ever have".** It is the least credible: it demonstrates migrating a signing utility we wrote, own end-to-end and can deploy at will — the `SELF` control class, the case nobody doubts. Worth doing as hygiene; worthless as evidence. It is now a line in Phase 12, not a headline.
- **Opening with the 82 defects.** Honest internally, and it ends a procurement conversation. The record stays in the repository; it does not go in a deck.
