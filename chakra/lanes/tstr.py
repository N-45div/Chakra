"""Train-on-synthetic, test-on-real (TSTR) against a real card dataset.

The protocol, exactly as the experiment contract fixes it:

  1. Split the real dataset CHRONOLOGICALLY into development and locked test.
     Chronological, not random: a random split lets a model see the future of the
     same fraud campaign it is being tested on, and card fraud is bursty enough
     that this alone can carry a result.
  2. Fit the generator ONLY on the development partition.
  3. Train one classifier on generated rows (TSTR) and one on real development
     rows (TRTR).
  4. Score BOTH on the identical locked real test partition.
  5. Report the gap. TSTR alone is uninterpretable - the question is not whether
     synthetic data works, it is how much is lost relative to the real thing.

What this establishes: dataset-native synthetic utility. What it does NOT
establish: anything about F5, F6, F11, UPI, or Indian rails. Those live in
Lane B and are validated by leave-one-family-out, not by this.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd


@dataclass
class LaneAResult:
    dataset: str
    n_dev: int
    n_test: int
    prevalence_dev: float
    prevalence_test: float
    generator: str
    n_synthetic: int
    trtr_auprc: float
    tstr_auprc: float
    trtr_auc: float
    tstr_auc: float
    trtr_recall_at_fpr: float
    tstr_recall_at_fpr: float
    operating_fpr: float
    baseline_auprc: float
    discriminator_auc: float
    trtr_auprc_weighted: float = 0.0
    tstr_auprc_weighted: float = 0.0
    per_feature_ks: dict = field(default_factory=dict)

    @property
    def utility_gap_auprc(self) -> float:
        """How much AUPRC is lost by training on synthetic instead of real."""
        return self.trtr_auprc - self.tstr_auprc

    def headline(self) -> str:
        return (
            f"{self.dataset}: TRTR AUPRC {self.trtr_auprc:.4f} vs TSTR "
            f"{self.tstr_auprc:.4f} (gap {self.utility_gap_auprc:+.4f}) on an "
            f"identical locked real test set at {self.prevalence_test:.4%} "
            f"prevalence (random baseline {self.baseline_auprc:.4f}); "
            f"real-vs-synthetic discriminator AUC {self.discriminator_auc:.3f}"
        )

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["utility_gap_auprc"] = self.utility_gap_auprc
        return d


def _chronological_split(df, time_col, dev_frac):
    """Development / locked-test split by time, never at random."""
    ordered = df.sort_values(time_col, kind="mergesort").reset_index(drop=True)
    cut = int(len(ordered) * dev_frac)
    return ordered.iloc[:cut].copy(), ordered.iloc[cut:].copy()


def _fit_generator(dev, label_col, seed):
    """Class-conditional Gaussian-copula generator, fitted on DEV only.

    A copula rather than a GAN, deliberately: deterministic under seed, trains in
    seconds, legible failure modes. The published caution that off-the-shelf
    tabular synthesizers lose behavioural structure applies - which is exactly
    why this lane is scoped to dataset-native utility and is never used to
    justify anything about the behavioural families in Lane B.
    """
    from scipy import stats

    rng = np.random.default_rng(seed)
    feats = [c for c in dev.columns if c != label_col]
    models = {}
    for cls in (0, 1):
        sub = dev.loc[dev[label_col] == cls, feats]
        if len(sub) < 5:
            continue
        ranks = sub.rank(method="average") / (len(sub) + 1.0)
        z = pd.DataFrame(stats.norm.ppf(ranks.clip(1e-6, 1 - 1e-6)), columns=feats)
        cov = np.cov(z.values, rowvar=False) + np.eye(len(feats)) * 1e-6
        models[cls] = {
            "cov": cov,
            "margins": {c: np.sort(sub[c].values) for c in feats},
        }
    return {"features": feats, "models": models, "rng": rng}


def _sample(gen, n_by_class, label_col):
    from scipy import stats

    feats = gen["features"]
    rng = gen["rng"]
    out = []
    for cls, n in n_by_class.items():
        m = gen["models"].get(cls)
        if m is None or n <= 0:
            continue
        z = rng.multivariate_normal(np.zeros(len(feats)), m["cov"], size=n)
        u = stats.norm.cdf(z)
        cols = {}
        for i, c in enumerate(feats):
            emp = m["margins"][c]
            idx = np.clip((u[:, i] * len(emp)).astype(int), 0, len(emp) - 1)
            cols[c] = emp[idx]
        frame = pd.DataFrame(cols)
        frame[label_col] = cls
        out.append(frame)
    return pd.concat(out, ignore_index=True) if out else pd.DataFrame()


def _train_score(train, test, label_col, seed, class_weighting=False):
    from lightgbm import LGBMClassifier

    feats = [c for c in train.columns if c != label_col]
    y_tr = train[label_col].values.astype(int)
    pos = max(1, int(y_tr.sum()))
    neg = max(1, len(y_tr) - pos)
    kwargs = {}
    if class_weighting:
        kwargs["scale_pos_weight"] = neg / pos
    clf = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        random_state=seed,
        n_jobs=-1,
        verbose=-1,
        **kwargs,
    )
    clf.fit(train[feats], y_tr)
    return clf.predict_proba(test[feats])[:, 1]


def _recall_at_fpr(y, scores, target_fpr):
    """Recall at a cut whose REALISED false-positive rate is within budget.

    Chosen from observed scores rather than a bare quantile: with ties, a
    quantile cut plus a >= rule can blow straight through the budget.
    """
    legit = scores[y == 0]
    if not len(legit):
        return 0.0
    cut = float(np.quantile(legit, 1.0 - target_fpr))
    if len(legit[legit >= cut]) / len(legit) > target_fpr:
        higher = legit[legit > cut]
        if len(higher):
            cut = float(higher.min())
    pos = scores[y == 1]
    return float((pos >= cut).mean()) if len(pos) else 0.0


def run_lane_a(
    csv_path,
    label_col="Class",
    time_col="Time",
    dev_frac=0.7,
    seed=1000,
    operating_fpr=0.005,
    dataset_name="ULB creditcard",
):
    from scipy import stats
    from sklearn.metrics import average_precision_score, roc_auc_score

    df = pd.read_csv(csv_path)
    dev, test = _chronological_split(df, time_col, dev_frac)

    # Drop the split key from the FEATURES.
    #
    # `Time` in this dataset is a monotonic counter, and the split is
    # chronological, so every value in dev lies strictly below every value in
    # test. A tree trained with it splits on time and then routes the entire
    # test set into one leaf, which cripples the model for a reason that has
    # nothing to do with fraud. The symptom was unmistakable and worth recording:
    # TRTR AUPRC 0.0158 against a published ~0.75 for this dataset, and TSTR
    # BEATING TRTR - synthetic data outperforming real data is not a plausible
    # result, it is a signal that the real model was broken. The copula happened
    # to scramble the counter, which is why it looked better.
    #
    # Time is a splitting device here, never a predictor.
    for frame in (dev, test):
        frame.drop(columns=[time_col], inplace=True, errors="ignore")

    # The generator NEVER sees the locked test partition.
    gen = _fit_generator(dev, label_col, seed)
    n_by_class = {
        0: int((dev[label_col] == 0).sum()),
        1: int((dev[label_col] == 1).sum()),
    }
    synth = _sample(gen, n_by_class, label_col)

    y_test = test[label_col].values.astype(int)
    s_trtr = _train_score(dev, test, label_col, seed)
    s_tstr = _train_score(synth, test, label_col, seed)
    # Same models, class-weighted, purely to quantify what the weighting costs.
    s_trtr_w = _train_score(dev, test, label_col, seed, class_weighting=True)
    s_tstr_w = _train_score(synth, test, label_col, seed, class_weighting=True)

    feats = gen["features"]
    disc_real = dev[feats].copy()
    disc_real["__is_synth"] = 0
    disc_syn = synth[feats].copy()
    disc_syn["__is_synth"] = 1
    disc = pd.concat([disc_real, disc_syn], ignore_index=True)
    d_tr = disc.sample(frac=0.7, random_state=seed)
    d_te = disc.drop(d_tr.index)
    d_scores = _train_score(d_tr, d_te, "__is_synth", seed)
    disc_auc = float(roc_auc_score(d_te["__is_synth"].values, d_scores))

    ks = {
        c: float(stats.ks_2samp(dev[c].values, synth[c].values).statistic)
        for c in feats[:12]
    }

    return LaneAResult(
        dataset=dataset_name,
        n_dev=len(dev),
        n_test=len(test),
        prevalence_dev=float(dev[label_col].mean()),
        prevalence_test=float(y_test.mean()),
        generator="class-conditional Gaussian copula (empirical margins)",
        n_synthetic=len(synth),
        trtr_auprc=float(average_precision_score(y_test, s_trtr)),
        tstr_auprc=float(average_precision_score(y_test, s_tstr)),
        trtr_auc=float(roc_auc_score(y_test, s_trtr)),
        tstr_auc=float(roc_auc_score(y_test, s_tstr)),
        trtr_recall_at_fpr=_recall_at_fpr(y_test, s_trtr, operating_fpr),
        tstr_recall_at_fpr=_recall_at_fpr(y_test, s_tstr, operating_fpr),
        operating_fpr=operating_fpr,
        baseline_auprc=float(y_test.mean()),
        discriminator_auc=disc_auc,
        trtr_auprc_weighted=float(average_precision_score(y_test, s_trtr_w)),
        tstr_auprc_weighted=float(average_precision_score(y_test, s_tstr_w)),
        per_feature_ks=ks,
    )
