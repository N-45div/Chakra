# Chakra

A closed-loop adversarial fraud range for Indian payment rails.

An attacker generates fraud, a detector scores it, the attacker reads what slipped through and mutates, the detector retrains on independent data, and the improvement is measured on batches neither of them trained on.

**Mastercard Innovation Challenge @ GFF 2026.**

---

## Scope

> Thirteen evidence-backed families are mapped. Three — **F11** (card enumeration), **F5** (UPI authorised push) and **F6** (mule networks) — are implemented and enter the adaptive loop. F8 and F10 are specified but **not yet implemented**. The remaining eight are taxonomy only. No family receives a performance claim until the registered 20-seed, 10-generation run.

## Data disclosure

> No official public row-level labelled UPI or AePS dataset was located. Our Indian simulation is official-aggregate-calibrated, while synthetic-to-real validation is performed separately on native public card schemas.

Three lanes, never conflated:

- **Lane A — real card data.** IEEE-CIS, chronologically split. Validates dataset-native synthetic utility. Validates nothing about the Indian families.
- **Lane B — Chakra simulator.** Indian-payment event streams. Where the five executable families live.
- **Lane C — calibration.** Official NPCI/RBI aggregates constrain Lane B's distributions. Aggregates only, never detection ground truth.

## Two rules that decide whether any result means anything

**Attacks emit raw actions, never engineered features.** An attack simulates five rapid payments so `velocity_10m` is *derived*. An attack that sets `velocity_10m = 5` teaches the detector rules its author wrote, and every hold-out number becomes meaningless.

**Every feature declares when it becomes observable, and to whom.** `decision_surface`, `decision_timestamp`, `available_at`. The default model uses network-surface signals only; app and telco telemetry run as a labelled ablation.

## Two claims, never merged

- **Zero-shot** — frozen detector, family used nowhere in training, one number at generation zero.
- **Adaptive recovery** — detector has had labelled feedback; trajectory measured on fresh monitor batches.

"Never trained on this family and caught N% by generation five" is logically impossible. After generation one, it has seen the family.

## Layout

```
chakra/
  schema/     event ontology, entities, feature registry
  generate/   population model, attack families (raw-action emitters)
  detect/     LightGBM + isolation forest + logistic baseline
  loop/       orchestrator, proposers, pre-registered bounds
  evaluate/   fidelity gates, LOFO harness, metrics
docs/
  EXPERIMENT_CONTRACT.md   pre-registered; read before changing anything
  EVENT_SCHEMA.md          the ontology
data/
  raw/ interim/ locked/    locked/ is write-once
runs/                      one directory per seeded run
```

## Status

Three families implemented (F11, F5, F6). No reportable result exists: every run so far is a development pilot below the registered 20-seed, 10-generation contract. `docs/EXPERIMENT_CONTRACT.md` is pre-registered — it fixes what will be measured before results exist, and may not be edited to match an outcome.
