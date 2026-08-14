"""Metrics — the exact panel fixed in the experiment contract.

AUPRC is the headline (not AUC-ROC: under fraud-level imbalance true negatives
swamp the false-positive rate and ROC-AUC flatters an unusable model). FPR on
legitimate payments is first-class. Value-weighted recall counts money, not
rows. Worst-family recall refuses to let an average hide the open family.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd


@dataclass
class MetricBundle:
    auprc: float
    auc_roc: float
    recall_at_0_1pct_fpr: float
    recall_at_0_5pct_fpr: float
    false_alerts_per_million: float
    value_weighted_recall: float
    worst_family_recall: float
    per_family_recall: dict[str, float] = field(default_factory=dict)
    n: int = 0
    n_fraud: int = 0
    # AUPRC's baseline is the positive rate, so an AUPRC quoted without the
    # prevalence it was measured at is uninterpretable. Carried alongside every
    # bundle so the two can never be separated in a chart or a slide.
    prevalence: float = 0.0

    def __post_init__(self) -> None:
        if self.n and not self.prevalence:
            self.prevalence = self.n_fraud / self.n

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    def headline(self) -> str:
        return (
            f"AUPRC {self.auprc:.3f} @ prevalence {self.prevalence:.4%} "
            f"(baseline {self.prevalence:.4f}) | "
            f"recall@0.5%FPR {self.recall_at_0_5pct_fpr:.3f} | "
            f"value-weighted {self.value_weighted_recall:.3f}"
        )


def _threshold_at_fpr(y: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    """Smallest threshold whose FPR on legit rows is <= target_fpr."""
    legit = scores[y == 0]
    if len(legit) == 0:
        return 1.0
    # quantile of legit scores at (1 - target_fpr)
    q = np.quantile(legit, 1.0 - target_fpr)
    return float(q)


def recall_at_fpr(y: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    thr = _threshold_at_fpr(y, scores, target_fpr)
    pos = scores[y == 1]
    if len(pos) == 0:
        return 0.0
    return float((pos >= thr).mean())


def value_weighted_recall(
    y: np.ndarray, scores: np.ndarray, amounts: np.ndarray, target_fpr: float
) -> float:
    """Recall weighted by transaction value at a fixed operating FPR."""
    thr = _threshold_at_fpr(y, scores, target_fpr)
    fraud = y == 1
    if fraud.sum() == 0:
        return 0.0
    caught = fraud & (scores >= thr)
    total_value = amounts[fraud].sum()
    if total_value <= 0:
        return 0.0
    return float(amounts[caught].sum() / total_value)


def evaluate(
    y: np.ndarray,
    scores: np.ndarray,
    meta: pd.DataFrame,
    operating_fpr: float = 0.005,
) -> MetricBundle:
    from sklearn.metrics import average_precision_score, roc_auc_score

    y = np.asarray(y).astype(int)
    scores = np.asarray(scores, dtype=float)
    amounts = meta["amount_inr"].values.astype(float) if "amount_inr" in meta else np.ones(len(y))

    has_both = len(np.unique(y)) == 2
    auprc = float(average_precision_score(y, scores)) if has_both else float("nan")
    auc = float(roc_auc_score(y, scores)) if has_both else float("nan")

    r01 = recall_at_fpr(y, scores, 0.001)
    r05 = recall_at_fpr(y, scores, 0.005)

    thr = _threshold_at_fpr(y, scores, operating_fpr)
    legit = y == 0
    false_alerts = int(((scores >= thr) & legit).sum())
    fapm = (false_alerts / max(1, legit.sum())) * 1_000_000

    vwr = value_weighted_recall(y, scores, amounts, operating_fpr)

    per_family: dict[str, float] = {}
    if "family" in meta.columns:
        fam = meta["family"].values
        caught = scores >= thr
        for f in sorted({x for x in fam if x is not None and str(x) != "nan"}):
            mask = (fam == f) & (y == 1)
            if mask.sum() > 0:
                per_family[str(f)] = float(caught[mask].mean())
    worst = min(per_family.values()) if per_family else float("nan")

    return MetricBundle(
        auprc=auprc,
        auc_roc=auc,
        recall_at_0_1pct_fpr=r01,
        recall_at_0_5pct_fpr=r05,
        false_alerts_per_million=fapm,
        value_weighted_recall=vwr,
        worst_family_recall=worst,
        per_family_recall=per_family,
        n=int(len(y)),
        n_fraud=int(y.sum()),
        prevalence=float(y.mean()) if len(y) else 0.0,
    )
