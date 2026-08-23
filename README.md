# Chakra

A closed-loop adversarial fraud range for Indian payment rails.

An attacker generates fraud, a detector scores it, the attacker reads what slipped through and mutates, the detector retrains on independent data, and the improvement is measured on batches neither of them trained on.

**Mastercard Innovation Challenge @ GFF 2026.**

---

## The three pillars, anywhere in this repo

- **Identify** — [`docs/ATTACK_TAXONOMY.md`](docs/ATTACK_TAXONOMY.md): thirteen families mapped; five are executable, the rest are specified with mechanism, GenAI delta and signal shape, and receive no performance claims.
- **Generate** — `chakra/generate/`: the population model, genuine background traffic and the attack families, each a parameterised *raw-event* emitter.
- **Defend** — `chakra/detect/`: rail-scoped LightGBM + isolation-forest scorer with a logistic baseline, inside the four-stream adaptive loop (`chakra/loop/`).

## Scope

> Five families are executable and enter the adaptive loop: **F11** (card enumeration), **F5** (UPI authorised push), **F6** (mule networks), **F8** (credit nurture and bust-out), **F10** (agentic checkout manipulation). Three railroads are implemented with genuine background traffic: UPI, card, agentic. See the taxonomy for the remaining eight.

## Data disclosure

> No official public row-level labelled UPI or AePS dataset was located. Our Indian simulation is official-aggregate-calibrated, while synthetic-to-real validation is performed separately on native public card schemas.

Three lanes, never conflated:

- **Lane A — real card data.** IEEE-CIS, chronologically split. Validates dataset-native synthetic utility. Validates nothing about the Indian families.
- **Lane B — Chakra simulator.** Indian-payment event streams. Where the five executable families live.
- **Lane C — calibration.** Official NPCI/RBI aggregates constrain Lane B's distributions. Aggregates only, never detection ground truth.

## Two rules that decide whether any result means anything

**Attacks emit raw actions, never engineered features.** An attack simulates five rapid payments so `velocity_10m` is *derived*. An attack that sets `velocity_10m = 5` teaches the detector rules its author wrote, and every hold-out number becomes meaningless. Enforced by test, not by discipline.

**Every feature declares when it becomes observable, and to whom.** `decision_surface`, `decision_timestamp`, `available_at`. The default model uses network-surface signals only; app and telco telemetry run as a labelled ablation.

## Two claims, never merged

- **Zero-shot (LOFO)** — frozen detector, family used nowhere in training, one number. [`chakra/evaluate/lofo.py`](chakra/evaluate/lofo.py). Rail-scoped: a family with no within-rail sibling receives *no* zero-shot number rather than a fudged one.
- **Adaptive recovery** — detector has had labelled feedback; trajectory measured on fresh monitor batches.

"Never trained on this family and caught N% by generation five" is logically impossible. After generation one, it has seen the family.

## Results

The registered protocol is fixed in [`docs/EXPERIMENT_CONTRACT.md`](docs/EXPERIMENT_CONTRACT.md): 20 seeds (1000–1019), 10 generations, five families, median and interquartile range across all seeds, no seed selected for presentation, no run discarded. Execute it with:

```
python scripts/run_registered.py --workers 5
```

Every number flows from the sealed run artifacts into the [dashboard](dashboard/index.html) and the walkthrough document:

```
python scripts/build_dashboard.py          # dashboard/index.html (static, self-contained)
python scripts/build_walkthrough.py        # docs/Walkthrough.docx
python scripts/run_lofo.py                 # zero-shot protocol
```

The current aggregate results live in the generated dashboard and in `runs/`; the honesty ledger in [`docs/FINDINGS.md`](docs/FINDINGS.md) records the claims this project withdrew before any of them reached a submission.

## Web prototype

The challenge requires a working web prototype with a presentable UI. That is
[`dashboard/index.html`](dashboard/index.html) — a single self-contained static
page generated from the run artifacts (`python scripts/build_dashboard.py`),
deployed statically via `render.yaml`. It contains the full report (loop
mechanics, per-family panels, Lane A, LOFO, taxonomy, honesty ledger) plus an
interactive generation scrubber that replays the recorded runs — labelled
REPLAY per the contract, aggregate-first so no seed is selected for
presentation.

Marked as future work, deliberately: a live in-browser run mode (running the
loop on demand behind a small API), episode-level drill-down into the sealed
audit streams, and the full-telemetry ablation panels. The current page never
invents a number and never needs a server — the two properties that matter
most on demo day.

## Research extension path

The mapped tier of the taxonomy (F1 deepfake impersonation, F2 synthetic
onboarding, F3 voice-clone vishing, F4 industrial phishing, F7 fake-merchant
acquiring, F9 fabricated disputes, F12 AePS biometric fraud, F13 personalised
investment scams) is specified, not simulated. Each entry states the event
schema and features it would need; implementing any of them is a
well-bounded extension of the same loop. Zero-shot across rails is likewise
left as future work because a cross-rail model's baseline is meaningless
under the rail-scoping rule (FINDINGS F-004).

## Layout

```
chakra/
  schema/     event ontology, entities, feature registry
  generate/   population model, attack families (raw-action emitters)
  detect/     LightGBM + isolation forest + logistic baseline
  loop/       orchestrator, proposer, pre-registered bounds
  evaluate/   fidelity gates, LOFO harness, metrics, audit sealing
  lanes/      Lane A synthetic-to-real validation on real ULB data
docs/
  EXPERIMENT_CONTRACT.md   pre-registered; read before changing anything
  ATTACK_TAXONOMY.md       the Identify pillar
  FINDINGS.md              results and, more importantly, retractions
  EVENT_SCHEMA.md          the ontology
data/
  raw/ interim/ locked/    locked/ is write-once
runs/                      one sealed directory per seeded run
```

## Development

```
pip install -e .[dev]
pytest -q
```

76 checks cover the load-bearing guarantees: no feature injection by attacks, truth isolation, availability discipline, stream separation, threshold honesty, determinism, and per-family mechanics for F5, F6, F8, F10 and F11.