"""LOFO — leave-one-family-out zero-shot detection.

EXPERIMENT_CONTRACT §7 defines the claim this harness measures:

    Zero-shot. Detector frozen. Target family used nowhere in its training —
    not in data, not in tuning, not in threshold selection. One number.

The honest scope of that claim is narrower than it first appears, and this
module encodes the narrowing rather than hiding it:

**Rail scoping applies to hold-outs too.** Detectors are trained per rail
(FINDINGS F-004), so a detector can only be held out from families it could
ever see on its own rail. Card rail holds {F8, F11}; UPI holds {F5, F6};
agentic holds {F10}. A "zero-shot" card detector scored against UPI fraud
would mostly be measuring rail mismatch — the exact conflation F-004
retracted. Therefore:

  - F11 <-> F8 are each other's LOFO siblings on card;
  - F5 <-> F6 on UPI;
  - F10 has no sibling on agentic and receives **no zero-shot number**.
    Reporting one anyway would require an across-rail model whose baseline
    is meaningless; absence of a number is the correct output there.

**What varies in the hold-out.** The contract requires entities, seeds and
parameter ranges to vary so the detector cannot recognise the generator's
fingerprint instead of the fraud. This implementation draws fresh entity
worlds under unseen seeds, samples attack parameters uniformly across the
full registered bounds (not the loop's evolved regions), and spreads episode
placement independently. Renderer-version variation — regenerating the SAME
family from different emitter code — is approximated by these independent
draws but is NOT fully achieved: a true cross-renderer test would need two
independent emitters per family, which does not exist. Stated plainly rather
than papered over.

**Threshold discipline.** The operating cut is frozen on a calibration
stream built ONLY from sibling-family attacks, then applied unchanged to the
target family's stream. Deriving the cut from target labels would turn the
headline recall self-referential — the defect class documented in
evaluate/metrics.py.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from chakra.detect.detector import Detector
from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.rng import Rng
from chakra.loop.orchestrator import Loop, LoopConfig
from chakra.schema.events import Rail
from chakra.schema.features import build_matrix

# Within-rail sibling sets. Anything not listed as a pair has no LOFO sibling.
SIBLINGS_BY_RAIL: dict[Rail, list[str]] = {
    Rail.CARD: ["F8", "F11"],
    Rail.UPI: ["F5", "F6"],
    Rail.AGENTIC: [],
}


@dataclass
class LofOResult:
    target: str
    siblings: list[str]
    train_rows: int
    cal_rows: int
    target_rows: int
    target_fraud: int
    threshold: float
    auprc: float
    auc_roc: float
    recall_at_cut: float
    achieved_fpr_at_cut: float
    baseline_recall_at_cut: float
    baseline_auprc: float

    def headline(self) -> str:
        return (
            f"{self.target} (siblings {'+'.join(self.siblings)}): "
            f"AUPRC {self.auprc:.3f} | recall {self.recall_at_cut:.3f} at frozen cut "
            f"(realised FPR {self.achieved_fpr_at_cut:.4%}) | "
            f"logit baseline AUPRC {self.baseline_auprc:.3f}"
        )

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _stream_matrix(family_code: str, seed: int, n_params: int = 6):
    """A freshly-seeded mixed stream for `family_code`, with the loop's own
    prevalence sizing, plus its (X, y, meta) matrices."""
    family = ATTACK_FAMILIES[family_code]
    cfg = LoopConfig(
        seed=seed,
        generations=1,
        pop_params=n_params,
        n_consumers=400,
        n_merchants=40,
        world_span_days=3.0,
    )
    # Loop binds config.rail to the family's rail in __init__, exactly as the
    # registered runs do — no separate code path to drift.
    loop = Loop(family, cfg)
    rng = Rng(seed + 77_000_000, tag=f"lofo/{family_code}")
    params_list = [family.sample_params(rng.spawn(f"p{i}")) for i in range(n_params)]
    log = loop._build_stream(rng.spawn("stream"), params_list)
    return loop._matrix(log)


def run_lofo(target_code: str, seed_base: int = 9000) -> LofOResult | None:
    """Zero-shot protocol for one target family. Returns None when the target
    has no within-rail sibling (the honest 'not defined' answer)."""
    family = ATTACK_FAMILIES[target_code]
    siblings = [c for c in SIBLINGS_BY_RAIL.get(family.rail, []) if c != target_code]
    if not siblings:
        return None

    # --- frozen training set: sibling attacks only -----------------------
    Xs, ys = [], []
    n_train_rows = 0
    for i, sib in enumerate(siblings):
        X, y, _ = _stream_matrix(sib, seed_base + i)
        Xs.append(X)
        ys.append(y)
        n_train_rows += len(X)
    X_train = _align_concat(Xs)
    y_train = _concat_labels(ys)

    # --- threshold calibration: ALSO sibling-only, fresh world ------------
    Xs_cal, ys_cal = [], []
    for j, sib in enumerate(siblings):
        X, y, _ = _stream_matrix(sib, seed_base + 50 + j)
        Xs_cal.append(X)
        ys_cal.append(y)
    X_cal = _align_concat(Xs_cal)
    y_cal = _concat_labels(ys_cal)

    det = Detector()
    det.fit(X_train, y_train)
    scores_cal = det.score(X_cal)
    cut = Loop._cut_at(scores_cal, y_cal.values.astype(int), 0.005)

    # --- target evaluation: never seen, never tuned on --------------------
    X_t, y_t, meta_t = _stream_matrix(target_code, seed_base + 99)
    scores_t = det.score(X_t)

    from sklearn.metrics import average_precision_score, roc_auc_score

    fraud = y_t.values == 1
    legit = y_t.values == 0
    auprc = float(average_precision_score(y_t, scores_t)) if fraud.any() else float("nan")
    auc = float(roc_auc_score(y_t, scores_t)) if len(np.unique(y_t)) == 2 else float("nan")
    recall = float((scores_t[fraud] >= cut).mean()) if fraud.any() else 0.0
    fpr = float((scores_t[legit] >= cut).mean()) if legit.any() else 0.0

    base_scores_t = det.score_baseline(X_t)
    base_auprc = (
        float(average_precision_score(y_t, base_scores_t)) if fraud.any() else float("nan")
    )
    base_recall = float((base_scores_t[fraud] >= cut).mean()) if fraud.any() else 0.0

    return LofOResult(
        target=target_code,
        siblings=siblings,
        train_rows=n_train_rows,
        cal_rows=len(X_cal),
        target_rows=len(X_t),
        target_fraud=int(y_t.sum()),
        threshold=float(cut),
        auprc=auprc,
        auc_roc=auc,
        recall_at_cut=recall,
        achieved_fpr_at_cut=fpr,
        baseline_recall_at_cut=base_recall,
        baseline_auprc=base_auprc,
    )


def _align_concat(frames: list) -> "pd.DataFrame":
    """Outer-join columns so models from differently-keyed streams still align;
    absent columns become zeros, mirroring Detector._align semantics."""
    import pandas as pd

    cols: list[str] = []
    for f in frames:
        for c in f.columns:
            if c not in cols:
                cols.append(c)
    filled = [f.reindex(columns=cols, fill_value=0.0) for f in frames]
    return pd.concat(filled, ignore_index=True)


def _concat_labels(series_list: list) -> "pd.Series":
    import pandas as pd

    return pd.Series(pd.concat(series_list, ignore_index=True).values, name="label", dtype=int)
