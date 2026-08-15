"""Adversarial leak tests.

The project claims features cannot see ground truth. That claim was false until
now: `VisibilityIndex.prior()` returned raw Events whose `.label` and `.family`
were readable, and a feature that read one would have produced a perfect
detector and an unfalsifiable result. Nothing in the built-in feature set did —
but "no current feature does" is a convention, not a guarantee.

These tests attack the guarantee rather than assuming it. Each writes the leak a
careless or malicious feature author would write, and asserts it fails.
"""

from datetime import datetime, timedelta

import pytest

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import EventType, Surface
from chakra.schema.features import (
    DecisionView,
    HistoricalView,
    VisibilityIndex,
    build_matrix,
)

WORLD = datetime(2026, 2, 1)


@pytest.fixture(scope="module")
def world():
    rng = Rng(1000)
    pop = build_population(rng, n_consumers=120, n_merchants=12, world_start=WORLD)
    log = generate_background(rng, pop, start=WORLD, days=2.0)
    fam = ATTACK_FAMILIES["F11"]
    log.extend(
        fam.emit(rng, pop, fam.default_params(), start=datetime(2026, 2, 2), n_episodes=3)
    )
    return log


def _any_prior(log, field="device_id"):
    idx = VisibilityIndex(log, Surface.NETWORK)
    auths = [
        e for e in log.sorted_by_time() if e.event_type is EventType.TXN_AUTH_REQUESTED
    ]
    for dec in reversed(auths):
        got = idx.prior(DecisionView.of(dec), field, "attempt", dec.ts, None)
        if got:
            return got
    return []


def test_history_carries_no_label_attribute(world):
    """The exact leak an adversarial feature would exploit."""
    prior = _any_prior(world)
    assert prior, "no prior history found; test would pass vacuously"
    for v in prior:
        assert isinstance(v, HistoricalView)
        assert not hasattr(v, "label"), "a feature can read a historical fraud label"
        assert not hasattr(v, "family"), "a feature can read a historical family"


def test_history_payload_excludes_truth(world):
    prior = _any_prior(world)
    assert prior
    for v in prior:
        assert "label" not in v.payload
        assert "family" not in v.payload
        assert "episode_id" not in v.payload


def test_decision_view_carries_no_truth(world):
    auths = [
        e for e in world.sorted_by_time() if e.event_type is EventType.TXN_AUTH_REQUESTED
    ]
    fraud = [e for e in auths if e.label is not None and e.label.value == "fraud"]
    assert fraud, "no fraud decisions to check"
    view = DecisionView.of(fraud[0])
    assert not hasattr(view, "label")
    assert not hasattr(view, "family")
    assert "label" not in view.payload
    assert "family" not in view.payload


def test_a_feature_attempting_to_read_truth_fails(world):
    """Write the malicious feature and confirm it cannot succeed.

    Previously this exact function body returned a perfect fraud signal.
    """
    idx = VisibilityIndex(world, Surface.NETWORK)
    auths = [
        e for e in world.sorted_by_time() if e.event_type is EventType.TXN_AUTH_REQUESTED
    ]
    dec = auths[-1]
    view = DecisionView.of(dec)

    def malicious_feature(ctx_index, decision, as_of):
        # 1) read truth off the decision itself
        leaked = getattr(decision, "label", None) or decision.payload.get("label")
        if leaked is not None:
            return leaked
        # 2) read truth off history
        for v in ctx_index.prior(decision, "device_id", "attempt", as_of, None):
            got = getattr(v, "label", None) or v.payload.get("label")
            if got is not None:
                return got
        return None

    assert malicious_feature(idx, view, dec.ts) is None, (
        "a feature successfully read ground truth"
    )


def test_observable_outcome_is_still_available(world):
    """Sanitising must not remove legitimate signal: whether a past attempt was
    declined IS a network fact and features depend on it."""
    idx = VisibilityIndex(world, Surface.NETWORK)
    auths = [
        e for e in world.sorted_by_time() if e.event_type is EventType.TXN_AUTH_REQUESTED
    ]
    found_outcome = False
    for dec in reversed(auths):
        outs = idx.prior(
            DecisionView.of(dec), "counterparty_id", "outcome", dec.ts, timedelta(hours=1)
        )
        if outs:
            found_outcome = True
            assert all(isinstance(o.was_declined, bool) for o in outs)
            break
    assert found_outcome, "no observable outcomes reachable; decline features would be dead"


def test_matrix_columns_contain_no_truth_named_field(world):
    features, _, _ = build_matrix(world, Surface.NETWORK)
    lowered = {c.lower() for c in features.columns}
    for banned in ("label", "family", "is_fraud", "episode_id"):
        assert banned not in lowered
