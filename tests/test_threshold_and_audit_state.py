"""Tie-safe thresholds and the audit scoring state machine.

Both encode failures that produced plausible-looking output rather than errors.
"""

from datetime import datetime

import numpy as np
import pandas as pd
import pytest

from chakra.evaluate.audit import seal_audit
from chakra.evaluate.metrics import _threshold_at_fpr
from chakra.loop.orchestrator import Loop


# -- tie safety ------------------------------------------------------------

def _degenerate():
    """1,000 identical legitimate scores — the case that broke quantile cuts."""
    scores = np.concatenate([np.full(1000, 0.5), np.array([0.9, 0.95])])
    y = np.concatenate([np.zeros(1000, int), np.ones(2, int)])
    return y, scores


@pytest.mark.parametrize("target", [0.001, 0.005, 0.01])
def test_loop_cut_respects_budget_under_ties(target):
    y, scores = _degenerate()
    cut = Loop._cut_at(scores, y, target)
    achieved = float((scores[y == 0] >= cut).mean())
    assert achieved <= target, (
        f"nominal {target:.1%} budget realised {achieved:.1%} FPR on tied scores"
    )


@pytest.mark.parametrize("target", [0.001, 0.005, 0.01])
def test_metrics_cut_respects_budget_under_ties(target):
    y, scores = _degenerate()
    cut = _threshold_at_fpr(y, scores, target)
    achieved = float((scores[y == 0] >= cut).mean())
    assert achieved <= target


def test_tie_safe_cut_still_separates_when_possible():
    """Safety must not come from refusing to flag anything flaggable."""
    y, scores = _degenerate()
    cut = Loop._cut_at(scores, y, 0.005)
    assert float((scores[y == 1] >= cut).mean()) == 1.0


def test_cut_on_well_spread_scores_is_near_target():
    rng = np.random.default_rng(0)
    scores = np.concatenate([rng.uniform(0, 1, 10_000), rng.uniform(0.8, 1, 50)])
    y = np.concatenate([np.zeros(10_000, int), np.ones(50, int)])
    cut = Loop._cut_at(scores, y, 0.005)
    achieved = float((scores[y == 0] >= cut).mean())
    assert achieved <= 0.005
    assert achieved > 0.002, "cut is far more conservative than the budget asks"


# -- audit state machine ---------------------------------------------------

def _audit():
    features = pd.DataFrame({"a": [1.0, 2.0, 3.0]})
    labels = pd.Series([0, 1, 0], name="label")
    meta = pd.DataFrame(
        {
            "event_id": ["e1", "e2", "e3"],
            "amount_inr": [10.0, 20.0, 30.0],
            "family": ["F11"] * 3,
            "rail": ["card"] * 3,
        }
    )
    return seal_audit(features, labels, meta, seed=1, family="F11", created_at=datetime(2026, 2, 1))


def test_reservation_is_not_a_completed_score(tmp_path):
    """A crash after reserving must not look like a finished run."""
    a = _audit()
    a.claim_scoring(tmp_path)
    assert (tmp_path / "scoring.pending").exists()
    assert not (tmp_path / "scored.json").exists()


def test_commit_promotes_reservation(tmp_path):
    a = _audit()
    a.claim_scoring(tmp_path)
    a.commit_scoring(tmp_path)
    assert (tmp_path / "scored.json").exists()
    assert not (tmp_path / "scoring.pending").exists()


def test_second_scoring_after_commit_is_refused(tmp_path):
    a = _audit()
    a.claim_scoring(tmp_path)
    a.commit_scoring(tmp_path)
    fresh = _audit()  # new process would have a fresh in-memory flag
    with pytest.raises(RuntimeError, match="already scored"):
        fresh.claim_scoring(tmp_path)


def test_stale_reservation_is_reported_not_silently_reused(tmp_path):
    a = _audit()
    a.claim_scoring(tmp_path)  # simulate crash: reserved, never committed
    fresh = _audit()
    with pytest.raises(RuntimeError, match="in progress or"):
        fresh.claim_scoring(tmp_path)


def test_mutation_between_seal_and_scoring_is_caught(tmp_path):
    a = _audit()
    a.meta.loc[0, "amount_inr"] = 999_999.0
    with pytest.raises(RuntimeError, match="has changed"):
        a.claim_scoring(tmp_path)
