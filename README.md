# Chakra — An Adversarial Fraud Range for Indian Payment Rails

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-78%20passing-brightgreen)](https://github.com/N-45div/Chakra/actions)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Status](https://img.shields.io/badge/registered%20protocol-100%2F100%20runs-9cf)](https://github.com/N-45div/Chakra/tree/main/runs)

A closed-loop adversarial simulation environment for studying fraud on Indian
payment rails. An attacker generates fraud, a detector scores it, the attacker
mutates on what slipped through, the detector retrains on independent data,
and the improvement is measured on batches neither of them trained on.

**Mastercard Innovation Challenge @ GFF 2026 — AI Defense Lab for Payment
Security.**

---

## Abstract

We present Chakra, an adversarial range for payment fraud research built
around a single design commitment: *no published number may be produced by a
procedure that could silently flatter it*. The system instantiates three
research pillars — **Identify** (a thirteen-family taxonomy of emerging
GenAI-enabled attack vectors, five executable), **Generate** (parameterised
attackers that emit raw events into an officially-calibrated simulator of
Indian payment traffic), and **Defend** (a rail-scoped detector retrained
each generation against an attacker that mutates on its own failures).
Results are produced only under a pre-registered protocol — 20 seeds, 10
generations, sealed audits, medians with interquartile range — and three
claims produced during development were retracted before submission; each
retraction, with the mechanism that caused it, is part of the artifact
(`docs/FINDINGS.md`).

## Findings at a glance

**Registered protocol (20 seeds × 10 generations per family), locked audits,
thresholds frozen on calibration data:**

| Family | AUPRC med [IQR] | Recall @ frozen cut | Value-weighted recall | False alerts /M |
|---|---|---|---|---|
| F10 · agentic checkout manipulation | 0.985 [0.967 – 0.998] | 0.961 | 0.965 | 67 |
| F11 · enumeration / card testing | 0.948 [0.922 – 0.955] | 0.940 | 0.929 | 959 |
| F5 · UPI authorised-push deception | 0.878 [0.849 – 0.937] | 0.620 | 0.359 | ~0 |
| F6 · mule networks / layering | 0.977 [0.849 – 0.998] | 0.496 | 0.581 | ~0 |
| F8 · credit nurture & bust-out | 0.376 [0.302 – 0.457] | 0.404 | 0.903 | 2,932 |

**Zero-shot (leave-one-family-out, within rail):** a detector trained only on
bust-out catches 98.3% of enumeration it has never seen; one trained only on
enumeration catches 5.5% of bust-out. On mule networks the logistic baseline
(AUPRC 0.979) transfers better than the boosted model (0.636) — a
methodological finding recorded rather than hidden.

Full analysis: `docs/FINDINGS.md` (F-010), generated dashboard, and
`docs/Walkthrough.docx`.

## Scope

> Five families are executable and enter the adaptive loop: **F11**
> (enumeration / card testing), **F5** (UPI authorised-push deception), **F6**
> (mule networks / layering), **F8** (credit nurture & bust-out), **F10**
> (agentic checkout manipulation). Eight further families — deepfake
> impersonation, synthetic-identity onboarding, voice-clone vishing,
> industrial phishing, fake-merchant acquiring, fabricated disputes, AePS
> biometric fraud, personalised investment scams — are specified with
> mechanism, GenAI delta and signal shape in
> [`docs/ATTACK_TAXONOMY.md`](docs/ATTACK_TAXONOMY.md) and receive no
> performance claims.

## Data disclosure

> No official public row-level labelled UPI or AePS dataset was located. Our
> Indian simulation is official-aggregate-calibrated, while synthetic-to-real
> validation is performed separately on native public card schemas.

Three data lanes, never conflated:

- **Lane A — real card data.** IEEE-CIS, chronologically split, validates
  dataset-native synthetic utility. It validates nothing about the Indian
  families.
- **Lane B — Chakra simulator.** Indian-payment event streams (UPI, card,
  agentic) where the five executable families live.
- **Lane C — calibration.** Official NPCI/RBI aggregates constrain volumes,
  values, merchant mixes and approval rates. Aggregates only; never detection
  ground truth.

## Method

### Two invariants that decide whether any result means anything

1. **Attacks emit raw actions, never engineered features.** An attack
   simulates five rapid payments so `velocity_10m` is *derived* by the same
   feature pipeline that runs on real data. An attack that wrote
   `velocity_10m = 5` would be teaching the detector rules its author wrote.
   Enforced by `tests/test_no_feature_injection.py`.
2. **Every feature declares when it becomes observable, and to whom.**
   `decision_surface`, `decision_timestamp`, `available_at`. The default
   model uses network-surface signals only; issuer/app/telco telemetry runs
   as a labelled ablation. The training pipeline enforces
   `available_at < decision_timestamp`; violations raise, they do not warn.

### The four-stream adaptive loop

Each generation builds four independent event streams: **feedback** (attacker
sees caught/missed outcomes; detector may not train on it), **training**
(detector update), **monitor** (a frozen batch scored before and after
retraining — the only place the improvement claim is read), and a **locked
audit stream**, sealed and hash-verified before the loop starts, scored
exactly once at the end. Attacker fitness is episode-level, yield-aware and
in rupees on both sides of the ledger (`docs/ARCHITECTURE.md`, F-007).

### Two claims, never merged

- **Zero-shot (LOFO)** — detector frozen, target family used nowhere in
  training, tuning or threshold selection. One number, generation zero.
  Rail-scoped: a family with no within-rail sibling (F10) receives no
  zero-shot number rather than a fudged one.
- **Adaptive recovery** — detector has received labelled feedback; trajectory
  across generations on fresh monitor batches. A learning-speed claim, not a
  generalisation claim.

> "Never trained on this family and caught N% by generation five" is
> logically impossible. After generation one, the detector has seen the
> family.

### Metrics

AUPRC is the headline (not AUC-ROC: at fraud prevalence, true negatives swamp
the false-positive rate). Recall is read at thresholds frozen on separate
calibration data, with the *achieved* FPR reported beside it. Value-weighted
recall counts money, not rows. Worst-family recall refuses to let an average
hide an open family. A logistic baseline accompanies every figure.

## Reproducibility

```bash
pip install -e .[dev]
pytest -q                    # 78 checks

python scripts/run_registered.py --workers 5   # 20 seeds × 10 gens × 5 families
python scripts/run_lofo.py                     # zero-shot protocol
python scripts/build_dashboard.py              # dashboard/index.html
python scripts/build_walkthrough.py            # docs/Walkthrough.docx
```

Every number on the dashboard and in the walkthrough is read from a seeded
run artifact under `runs/` — one sealed directory per (family, seed), named
with the code-version and config hashes that produced it, so a score can
never be attributed to different source than the audit beside it. Missing
artifacts render as missing; nothing is invented at render time.

## Repository layout

```
chakra/
  schema/     event ontology, entities, feature registry
  generate/   population model, genuine background, attack families
  detect/     LightGBM + isolation forest + logistic baseline
  loop/       four-stream orchestrator, evolutionary proposer, bounds
  evaluate/   audit sealing, metrics, LOFO harness
  lanes/      Lane A synthetic-to-real validation (ULB, chronological split)
docs/         EXPERIMENT_CONTRACT · ATTACK_TAXONOMY · FINDINGS · ARCHITECTURE · EVENT_SCHEMA
runs/         one sealed directory per seeded run
dashboard/    self-contained web prototype
```

## Web prototype

`dashboard/index.html` is a self-contained static page generated from the run
artifacts: headline results, an interactive REPLAY explorer (generation
scrubber, per-seed drill-down, aggregate-first per the contract), taxonomy,
LOFO, Lane A and the honesty ledger. No server, no CDN; deployment is a
folder upload. A live in-browser run mode and episode-level drill-down are
marked as future work rather than implied.

## Documentation index

| Document | Purpose |
|---|---|
| [`docs/EXPERIMENT_CONTRACT.md`](docs/EXPERIMENT_CONTRACT.md) | pre-registered protocol; read before changing anything |
| [`docs/ATTACK_TAXONOMY.md`](docs/ATTACK_TAXONOMY.md) | the thirteen-family Identify pillar |
| [`docs/FINDINGS.md`](docs/FINDINGS.md) | results, and the retractions with their mechanisms |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | end-to-end system blueprint (Mermaid) |
| [`docs/EVENT_SCHEMA.md`](docs/EVENT_SCHEMA.md) | the event ontology |

## Limitations, stated in advance

Lane A's synthetic-to-real fidelity is weak (real-vs-synthetic discriminator
AUC 0.998) and is reported as such; F8's slow-temporal signal is simulated at
compressed timescale (the escalation *shape* transfers, the clock does not);
and no claim in this repository reaches beyond what the pre-registered
protocol measures. Pre-committed failure disclosures are listed in the
contract and reported in the walkthrough regardless of outcome.

## License

MIT. See [LICENSE](LICENSE).
