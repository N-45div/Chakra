"""The detector.

Two heads plus a mandatory baseline:
  - LightGBM  : the primary supervised head. Retrains fast, which matters
                because the loop retrains it every generation.
  - IsolationForest : an unsupervised novelty head trained on legit traffic
                only. Its job is the narrative's second act — flagging a share
                of a family the supervised head has never seen, because the
                behaviour is statistically odd even when unfamiliar.
  - LogisticRegression : the baseline. Not meant to win; there to prove the
                loop's gains are real rather than assumed.

Class imbalance is handled with `scale_pos_weight` and a threshold tuned on a
validation split, per the experiment contract. SMOTE is deliberately not used.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd


@dataclass
class DetectorConfig:
    n_estimators: int = 300
    learning_rate: float = 0.05
    num_leaves: int = 31
    random_state: int = 0
    iso_contamination: float = 0.02
    # combine supervised prob and novelty score: final = prob OR-ed with novelty
    novelty_weight: float = 0.15


class Detector:
    """Wraps the three models behind one score() surface. Feature columns are
    frozen at first fit so that scoring always aligns, and warm state (the fitted
    column order) survives retraining."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self._columns: list[str] | None = None
        self._gbm = None
        self._iso = None
        self._logit = None
        self._logit_scaler = None
        self._fitted = False

    # -- fitting -----------------------------------------------------------
    def fit(self, X: pd.DataFrame, y: pd.Series) -> "Detector":
        import lightgbm as lgb
        from sklearn.ensemble import IsolationForest
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler

        self._columns = list(X.columns)
        Xv = X.values.astype(float)
        yv = y.values.astype(int)

        pos = max(1, int(yv.sum()))
        neg = max(1, int((yv == 0).sum()))
        spw = neg / pos

        self._gbm = lgb.LGBMClassifier(
            n_estimators=self.config.n_estimators,
            learning_rate=self.config.learning_rate,
            num_leaves=self.config.num_leaves,
            scale_pos_weight=spw,
            random_state=self.config.random_state,
            verbose=-1,
        )
        self._gbm.fit(Xv, yv)

        # novelty head trained on legit rows only
        legit = Xv[yv == 0]
        if len(legit) >= 20:
            self._iso = IsolationForest(
                contamination=self.config.iso_contamination,
                random_state=self.config.random_state,
            )
            self._iso.fit(legit)
        else:
            self._iso = None

        # logistic baseline (scaled)
        self._logit_scaler = StandardScaler().fit(Xv)
        self._logit = LogisticRegression(max_iter=1000, class_weight="balanced")
        self._logit.fit(self._logit_scaler.transform(Xv), yv)

        self._fitted = True
        return self

    # -- scoring -----------------------------------------------------------
    def _align(self, X: pd.DataFrame) -> np.ndarray:
        if self._columns is None:
            raise RuntimeError("detector not fitted")
        missing = [c for c in self._columns if c not in X.columns]
        for c in missing:
            X = X.assign(**{c: 0.0})
        return X[self._columns].values.astype(float)

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Combined fraud score in [0,1]: supervised probability lifted by the
        novelty head so that an unseen-but-odd attack still scores above legit."""
        if not self._fitted:
            raise RuntimeError("detector not fitted")
        Xv = self._align(X)
        prob = self._gbm.predict_proba(Xv)[:, 1]
        if self._iso is not None:
            # decision_function: higher = more normal. Map to novelty in [0,1].
            raw = self._iso.decision_function(Xv)
            novelty = 1.0 / (1.0 + np.exp(5.0 * raw))  # squashes; ~1 when very anomalous
            combined = 1.0 - (1.0 - prob) * (1.0 - self.config.novelty_weight * novelty)
            return combined
        return prob

    def score_supervised(self, X: pd.DataFrame) -> np.ndarray:
        Xv = self._align(X)
        return self._gbm.predict_proba(Xv)[:, 1]

    def score_baseline(self, X: pd.DataFrame) -> np.ndarray:
        Xv = self._align(X)
        return self._logit.predict_proba(self._logit_scaler.transform(Xv))[:, 1]

    def novelty(self, X: pd.DataFrame) -> np.ndarray:
        if self._iso is None:
            return np.zeros(len(X))
        Xv = self._align(X)
        raw = self._iso.decision_function(Xv)
        return 1.0 / (1.0 + np.exp(5.0 * raw))
