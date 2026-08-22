# The Chakra attack taxonomy — thirteen families across Indian payment rails

**Pillar: Identify.** The challenge asks for breadth and depth of emerging
GenAI-powered payment fraud, grounded in how real payment systems actually
work. This is that map.

Two tiers, fixed by the pre-registered experiment contract:

- **Executable (5): F5, F6, F8, F10, F11.** Simulated end to end as
  parameterised raw-event emitters; they enter the adaptive loop and receive
  quantitative evaluation. Each has a dossier in `chakra/generate/attacks/`.
- **Mapped (8): F1–F4, F7, F9, F12, F13.** Specified here with mechanism,
  GenAI delta and signal shape; not simulated. They receive no performance
  claims — saying so is part of the contract (§1), because a taxonomy entry
  with a made-up detection number attached is worse than one without.

Evidence discipline: every external figure in this document was carried
through the claim review recorded in `EXPERIMENT_CONTRACT.md §11`. Claims that
did not survive it are listed there as retired and do not appear here. Where a
statement is a modelling choice rather than a sourced fact, it says ASSUMPTION.

---

## Why GenAI changes the economics before it changes the techniques

Almost nothing below is new *as fraud*. What generative models changed is the
cost structure of three inputs every scam needs:

1. **Content** — lures, scripts, documents, selfies, QR stickers, dispute
   narratives. Previously scarce per-language/per-target; now effectively free
   at any scale and any Indian language.
2. **Personalisation** — researching a victim well enough to sound legitimate
   used to select for high-value targets. It now scales down-market.
3. **Operation** — one operator can run many concurrent conversations,
   onboardings and disputes where each once needed a person.

The consequence for defence is the thesis of this whole system: static rules
cannot keep pace with an adversary whose marginal cost of variation is zero.
Only a loop that regenerates attacks faster than defenders can write rules —
and measures itself honestly while doing so — stays calibrated.

---

## Tier 1 — executable families

| Code | Family | Rail | Signal shape |
|---|---|---|---|
| F11 | Enumeration / card testing | card | velocity + entropy |
| F5 | UPI authorised-push deception | UPI | authorised, credentials genuine |
| F6 | Mule networks / layering | UPI | graph structure |
| F8 | Credit nurture & bust-out | card | slow temporal escalation |
| F10 | Agentic checkout manipulation | agentic | mandate-integrity residue |

Full dossiers live in the emitter source files; the short form:

- **F11** — batch card validation through weakly-limited endpoints. Many
  unknown instruments, concentrated, mostly declining. Implemented first
  because it is the *loud* baseline; its honest result (zero evasion on every
  seed) is recorded in FINDINGS F-001.
- **F5** — the victim's own VPA, device and PIN; authentication legitimately
  succeeds. Collect impersonation, QR substitution, screen-share direction.
  The family the loop exists for: evasion levers trade directly against yield.
- **F6** — every hop unremarkable, the convergence shape damning. Tests
  whether the detector learned structure rather than row anomalies. RBI's own
  Innovation Hub operates MuleHunter.AI against this class, and ~1.33 million
  mule accounts were reported frozen in 2025 — the strongest feasibility
  argument available for building it.
- **F8** — one compromised instrument nurtured like a good customer, then
  burst out into cash-equivalents. The mirror image of F11: all history, no
  novelty. Time-compressed openly in simulation; the escalation shape is what
  transfers.
- **F10** — prompt injection rewrites what an agent *declares*, upstream of
  the signed mandate, so intent/cart/payment stay internally consistent and
  every deterministic policy check passes. Only behavioural residue remains:
  fan-out across principals, delegate age, pacing. Registered fake agents are
  entity-indistinguishable from genuine ones by construction.

## Tier 2 — mapped families

### F1 · Real-time deepfake impersonation of trusted counterparties
**Mechanism:** a video call from a "known" executive, relative or merchant —
face and voice cloned from social-media footage — directs an urgent payment:
vendor account updates, emergency family transfer, salary redirection.
Payment authorisation itself is genuine authorised push; the fraud lives
entirely in the identity layer in front of it.
**GenAI delta:** real-time face/voice swap crossed the quality threshold for
casual verification ("it looked and sounded like him on a video call") only
recently; per-call cost keeps falling.
**Rail:** UPI/IMPS/RTGS push. **Signal shape:** none at transaction level —
the network sees an ordinary push to possibly-known payee. Detectable only at
the counterparty-graph layer (new beneficiary, value outlier vs relationship
history) or with issuer/app telemetry (session context), which is why it is
mapped rather than simulated under network-surface-only rules: the honest
network-only detector *cannot* separate it, and pretending otherwise would be
exactly the overclaim this project refuses.
**What simulation would require:** an issuer/app telemetry lane and
relationship-history features; specified, not built.

### F2 · Synthetic identity onboarding
**Mechanism:** fabricated KYC packets — generated documents, generated selfie
passing liveness, plausible address/utility trail — open accounts or credit
lines that behave perfectly while building history, then default or serve as
mule infrastructure.
**GenAI delta:** document forgery and face generation beat most remote-onboarding
liveness checks; the bottleneck moved from forging one identity to orchestrating thousands.
**Rail:** account/credit-card issuance. **Signal shape:** cold-start graph
(instrument, device fingerprint reuse across applications), bureau-thin files,
dormancy then activation. Overlaps F8's slow-temporal tail but originates at
onboarding, which the simulator's population model treats as pre-existing.
**Why not executable yet:** requires an application/onboarding event schema
distinct from transaction streams — designed in EVENT_SCHEMA terms but not emitted.

### F3 · Voice-clone vishing against OTP/approval flows
**Mechanism:** cloned voice of a bank official or family member walks a victim
through OTP sharing or in-app approval. Distinct from F5's screen-share
direction: the deception channel is telephony, and the payload is often just
one approval the victim performs willingly.
**GenAI delta:** seconds of sample audio suffice; conversational scripts can
be generated per dialect and per bank, removing the accent/tell barrier.
**Rail:** telco surface → UPI/card outcome. **Signal shape:** telco-side
(call metadata) plus issuer-side approval anomaly. Under the labelled-ablation
rule this family is precisely the case where network-only signals fail and the
ablation gap is the finding.

### F4 · LLM-generated phishing at industrial scale
**Mechanism:** per-victim smishing/email/WhatsApp lures — correct bank name,
correct language, correct recent-event reference — harvesting credentials or
planting malicious APKs. Downstream misuse looks like F5/F8 depending on rail.
**GenAI delta:** the marginal lure cost went to zero and typo-ridden scam
grammar — long a usable signal — disappeared with it.
**Rail:** delivery telco/app; misuse card/UPI. **Signal shape:** content-side
(URL reputation, APK provenance) more than flow-side. Content inspection is
out of scope for a payment-network simulator; the *downstream* misuse of
harvested credentials is already covered by executing families, which is why
this tier-2 entry maps the delivery layer rather than duplicating them.

### F5b→F7 · Fake merchant onboarding and settlement abuse
*(coded F7)*
**Mechanism:** merchant accounts registered with generated KYB packs, real
transaction flow at first (to build acquirer trust), then used to launder F5/F13
proceeds or run bust-out-style settlement flight.
**GenAI delta:** KYB documents, website presence, and review footprints all
generate convincingly.
**Rail:** acquiring/settlement. **Signal shape:** early-settlement velocity,
MCC-vs-behaviour mismatch, rapid descriptor churn. Requires a settlement-ledger
schema the simulator does not yet emit. Note the deliberate interplay: F10's
mule merchants already exercise the *behavioural* half of this in simulation.

### F9 · Fabricated-dispute and refund abuse
**Mechanism:** genuine goods received, then chargeback/UPD narratives generated
at scale — synthetic receipts, AI-written dispute letters, deepfake proof-of-
non-delivery — reversing legitimate spends or extracting goodwill refunds.
**GenAI delta:** evidence fabrication quality and throughput; per-case customisation
defeats template-matching reviewers.
**Rail:** card chargeback / UPI dispute. **Signal shape:** cross-case narrative
similarity collapse (each story unique), dispute-history graphs, claim-vs-
delivery telemetry gaps. Needs the dispute event chain (schema defines
DISPUTE_RAISED/EVIDENCE/RESOLVED) populated with content artefacts — future work.

### F12 · AePS biometric fraud
**Mechanism:** business-correspondent collusion with skimmed or replayed
fingerprints draining benefit accounts; victims are precisely the population
least able to absorb losses.
**GenAI delta:** synthetic/replayable fingerprint presentation research keeps
improving; the regulator treats operator due-diligence as the control point
(RBI/2025-26/63 direction). The retired-claims table records exactly which
widely-circulated AePS statistics failed verification — and stands as the
example of why this project cites primary sources or marks assumptions.
**Rail:** AePS. **Signal shape:** operator-centric fan-in (many accounts per
terminal per day), withdrawal-after-credit patterns, dormancy breaks.
Requires AePS background emission (BC-operator entities exist in the entity
model); the rail mix reserves its share until then.

### F13 · Personalised investment/task scams ("pig butchering") at scale
**Mechanism:** long-horizon romance/investment grooming, now with
LLM-maintained personas that remember months of conversation, escalating to
repeated authorised pushes through mule layers (which is F6's receiving side)
under digital-arrest urgency variants.
**GenAI delta:** persona maintenance across hundreds of simultaneous victims;
script depth previously limited staffing.
**Rail:** IMPS/UPI push → mule networks. **Signal shape:** the push side is
F5-shaped; the distinctive residue is repeated-value cadence per victim
(escalating "investment" tranches). Officially tracked at scale — MHA reported
1,23,672 cyber-fraud incidents with ₹1,935.51 crore losses in 2024, the
category containing these schemes — but no public row-level labelled data
exists, hence simulation rather than curve-fitting to someone's aggregate.

---

## Coverage matrix — what each tier tests about the defender

| Family | Credentials wrong? | Behaviour loud at t0? | Structure needed? | Network-only detectable? |
|---|---|---|---|---|
| F11 | yes (unknown instruments) | very | endpoint/device | strongly yes — the easy tier |
| F5 | no | no | payee fan-in | partially — the core case |
| F6 | no | no | yes (graph) | only structurally |
| F8 | no | late | per-instrument history | yes, after nurture |
| F10 | no (mandate valid) | no | agent-principal bipartite | residue only |
| F1–F4, F7, F9, F12, F13 | varies | varies | varies | mapped, not claimed |

The five executable families were chosen to span the matrix's corners: loud
(F11), quiet-but-authorised (F5), purely structural (F6), slow (F8), and
policy-passing (F10). A detector set that handles those five shapes generalises
to most of the mapped eight *by analogy*, but this document claims that only
as design intent — never as measured performance.

---

*This file is taxonomy, not results. Every number this project publishes comes
from a seeded run artifact under `runs/`, produced under the procedure fixed in
`docs/EXPERIMENT_CONTRACT.md` — or it does not get published.*
