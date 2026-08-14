"""The locked audit set must actually be locked.

Each of these encodes a property the first implementation claimed in its
docstring but did not have.
"""

from datetime import datetime

import pandas as pd
import pytest

from chakra.evaluate.audit import seal_audit


def _make(tmpish=None):
    features = pd.DataFrame({"a": [1.0, 2.0, 3.0], "b": [0.1, 0.2, 0.3]})
    labels = pd.Series([0, 1, 0], name="label")
    meta = pd.DataFrame(
        {
            "event_id": ["e1", "e2", "e3"],
            "amount_inr": [10.0, 20.0, 30.0],
            "family": ["F11", "F11", "F11"],
            "rail": ["card", "card", "card"],
        }
    )
    return seal_audit(
        features, labels, meta, seed=1, family="F11", created_at=datetime(2026, 2, 1)
    )


def test_amount_mutation_is_detected():
    """amount_inr drives value-weighted recall, so it must be under the seal."""
    audit = _make()
    audit.verify()
    audit.meta.loc[0, "amount_inr"] = 999_999.0
    with pytest.raises(RuntimeError, match="has changed"):
        audit.verify()


def test_family_mutation_is_detected():
    """family drives per-family and worst-family recall."""
    audit = _make()
    audit.meta.loc[1, "family"] = "F5"
    with pytest.raises(RuntimeError, match="has changed"):
        audit.verify()


def test_label_mutation_is_detected():
    audit = _make()
    audit.labels.loc[0] = 1
    with pytest.raises(RuntimeError, match="has changed"):
        audit.verify()


def test_feature_mutation_is_detected():
    audit = _make()
    audit.features.loc[0, "a"] = 42.0
    with pytest.raises(RuntimeError, match="has changed"):
        audit.verify()


def test_scoring_is_single_use():
    """A set that can be scored twice lets a disappointing number be re-rolled."""
    audit = _make()
    audit.claim_scoring()
    with pytest.raises(RuntimeError, match="already been scored"):
        audit.claim_scoring()


def test_refuses_to_overwrite_a_different_seal(tmp_path):
    first = _make()
    first.save(tmp_path)

    second = _make()
    second.features.loc[0, "a"] = 7.0
    second.digest = "0" * 64  # a genuinely different seal
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        second.save(tmp_path)


def test_resaving_the_same_seal_is_allowed(tmp_path):
    audit = _make()
    audit.save(tmp_path)
    audit.save(tmp_path)  # idempotent, no error
