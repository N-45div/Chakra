# Chakra — Experiment Contract

**Status: pre-registered. Written before any result exists. Nothing in this document may be edited to match an outcome.**

Mastercard Innovation Challenge @ GFF 2026. This file fixes what will be measured, on what data, under what splits, before the experiments run. If a number in the final submission is not produced by a procedure described here, it does not go in the submission.

---

## 1. Scope (this exact sentence, used everywhere)

> Thirteen evidence-backed families are mapped. Five — F5, F6, F8, F10 and F11 — are executable, enter the adaptive loop and receive quantitative evaluation. The remaining eight receive no performance claims.

| Code | Family | Signal shape it tests |
|---|---|---|
| F11 | Enumeration / card testing | Velocity and entropy |
| F5 | UPI authorised-push deception | Authorised, credentials genuine |
| F6 | Mule networks | Graph structure |
| F8 | Credit nurture and bust-out | Slow temporal |
| F10 | Agentic checkout manipulation | Mandate integrity |

## 2. Data lanes — never conflated

**Lane A — real-data (card).** IEEE-CIS split chronologically into development and locked test partitions. An IEEE-compatible generator is fitted **only** on the development partition. Two classifiers — one trained on generated IEEE-schema rows, one on real IEEE rows — are evaluated on the identical locked labelled real test partition. ULB is evaluated independently in its own schema as an extreme-imbalance sanity check only.

Lane A validates **dataset-native synthetic utility**. It does not validate any Indian attack family, and no claim to that effect may be made.

**Lane B — Chakra simulator.** Indian-payment event streams: transactions, authentication events, entities and devices, account relationships, disputes, labels. Separate schemas per rail linked by the common event ontology (`docs/EVENT_SCHEMA.md`). This is where the five executable families live.

**Lane C — calibration.** Official NPCI and RBI aggregates constrain Lane B's volumes, values, merchant and state mixes, and approval rates. Aggregates only. Never used as detection ground truth.

**Disclosure sentence, verbatim, in the deck and README:**

> No official public row-level labelled UPI or AePS dataset was located. Our Indian simulation is official-aggregate-calibrated, while synthetic-to-real validation is performed separately on native public card schemas.

## 3. The generation rule

Attacks emit **raw actions**. Never engineered features.

An attack simulates five rapid payments so that `velocity_10m` is *derived* by the same feature pipeline that runs on real data. An attack that writes `velocity_10m = 5` is a bug, and any result produced by one is void. This applies to every feature: fan-in degree, dwell time, escalation curves, all of them.

Enforced by test: `tests/test_no_feature_injection.py` asserts that no attack module imports from or writes to the feature layer.

## 4. Signal availability

Every feature declares three attributes:

- `decision_surface` — which system could observe it: `network` | `issuer` | `psp_app` | `telco`
- `decision_timestamp` — when the decision is made
- `available_at` — when this information first becomes observable to that surface

The training pipeline enforces `available_at < decision_timestamp`. Violations raise, they do not warn.

**Default model is `decision_surface == network` only.** Features on other surfaces (`screen_share_active`, call duration, app telemetry) run as a **labelled ablation**, reported separately: "network-only signals give X; adding issuer-app telemetry gives Y."

For F10, cryptographic signature validation and Intent↔Cart mandate consistency are **deterministic policy checks, not model features**. The model judges only the ambiguous behavioural residue after those checks pass.

## 5. Loop protocol — four streams per generation

| Stream | Used for | May the detector train on it? |
|---|---|---|
| Feedback batch | Attacker receives caught/missed outcomes | No |
| Training batch | Detector update | Yes |
| Monitor batch | Pre- and post-retrain recall | **Never** |
| Locked audit | Final scoring, once | **Never** |

The improvement claim comes from the monitor batch only. The locked audit stream is scored exactly once, at the end, and its result is reported whatever it says.

## 6. Pre-registered run parameters

- **Seeds:** 20 seeds, values `1000..1019`, fixed now.
- **Generations:** 10.
- **Mutation bounds:** declared per family in `chakra/loop/bounds.py` before the first run. Bounded mutation is a *realism constraint* (attackers face budget limits), not a tuning knob.
- **Reporting:** median and interquartile range across all 20 seeds. No seed is selected for presentation. No run is discarded.
- **Replays:** any recorded run shown in the demo is labelled `REPLAY` on screen.

Prohibited, explicitly: handicapping the detector to produce a more dramatic curve; tuning step size until curves look smooth; selecting a run by its outcome.

## 7. The two claims, kept separate

These answer different questions and are never merged into one sentence.

**Zero-shot (LOFO).** Detector frozen. Target family used nowhere in its training — not in data, not in tuning, not in threshold selection. One number, generation zero. Hold-out varies **entities, seeds, parameter ranges and renderer version** as well as the family, so the detector cannot recognise the generator's fingerprint instead of the fraud.

**Adaptive recovery.** Detector has received labelled feedback on the family. Trajectory across generations, measured on fresh monitor batches. This is a learning-speed claim, not a generalisation claim.

> "Never trained on this family and caught N% by generation five" is logically impossible and must never be written. After generation one the detector has seen the family.

## 8. Metrics

Primary, on the locked audit stream:

1. **AUPRC** — headline. Not AUC-ROC: under fraud-level imbalance true negatives swamp FPR.
2. Recall @ 0.1% FPR and @ 0.5% FPR
3. False alerts per million transactions
4. **Value-weighted recall** — a ₹40 lakh fraud is not a ₹400 fraud
5. **Worst-family recall** across the five executable families
6. Logistic-regression baseline alongside every figure

Lane A additionally reports TRTR vs TSTR on the identical locked real test partition, and the gap between them.

## 9. Fidelity gates (Lane B must pass before training on it)

| Check | Target |
|---|---|
| KSComplement / TVComplement | > 0.90 |
| CorrelationSimilarity / ContingencySimilarity | > 0.85 |
| BoundaryAdherence / NewRowSynthesis | > 0.95 / > 0.90 |
| Real-vs-synthetic discriminator AUC | ≈ 0.50 |
| Behavioural: velocity, inter-arrival, escalation, fan-in/out (KS vs real) | > 0.85 |

The last row is the one a 2026 preprint says off-the-shelf synthesizers fail. It is reported either way.

## 10. Pre-committed failure disclosures

Reported in the deck regardless of outcome:

- Any family the detector solves in one generation (a finding about the family, not a bug).
- Any family where zero-shot recall is at or below the base rate.
- Any fidelity gate not met, and what was done about it.
- The gap between network-only and full-telemetry ablations.
- Every claim carried without a primary source.

## 11. Claims retired during review — do not reintroduce

| Retired claim | Why |
|---|---|
| "RBI is phasing out SMS OTP" | False. Directions effective 1 Apr 2026 **retain** OTP as a valid factor; it may no longer be the *only* factor. |
| AePS "340% rise / ₹1,200 crore" | Secondary reporting; conflicts with RBI FY26 category data. Cite RBI/2025-26/63 operator due-diligence direction instead. |
| AePS biometric-lock adoption % | From a search summary, not a verified NPCI circular. |
| Digital arrest "₹22,495 crore in 2025" | That is total across **all** cyber fraud. Official MHA figure: 1,23,672 incidents, ₹1,935.51 crore in 2024. |
| Digital arrest "86% decline in 2025" | No primary source located. |
| MuleHunter "19 patterns / 4.7 lakh flagged / ₹5,489 cr recovered" | Recovery figure belongs to a broader total. Officially reported: live in 26 banks. |
| "40% of FY26 UPI fraud value in QR-swap/fake-collect" | Unsupported. |
| Benchmark names TabDDPM | The 2026 work is a **preprint** and benchmarks **TabularARGN**. |
| Selfie → usable fingerprint reconstruction | Unvalidated research hypothesis, not established capability. |
| Any illustrative result (71%, 81%, evolution table) | Placeholders get quoted as findings. All cells read TBD until produced. |

---

*Amendments to this contract are permitted only before the first locked-audit scoring, must be dated, and must state what changed and why. Amendments after seeing audit results are not permitted.*
