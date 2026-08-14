"""Stream separation, threshold discipline and prevalence control.

These assert the properties that make the loop's numbers mean anything. Each
was added because an audit found the corresponding failure in a real run.
"""

from itertools import combinations

import pytest

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.loop.orchestrator import Loop, LoopConfig


@pytest.fixture(scope="module")
def loop_results():
    cfg = LoopConfig(
        seed=1000,
        generations=2,
        pop_params=3,
        n_consumers=150,
        n_merchants=12,
        world_span_days=1.0,
    )
    loop = Loop(ATTACK_FAMILIES["F11"], cfg)
    return loop.run()


def test_streams_are_disjoint(loop_results):
    """Training rows must never appear in the monitor batch."""
    for gen in loop_results:
        streams = {k: v for k, v in gen.stream_ids.items() if k in ("monitor", "training")}
        assert streams, "no stream provenance recorded"
        for a, b in combinations(streams, 2):
            overlap = streams[a] & streams[b]
            assert not overlap, (
                f"generation {gen.generation}: {a} and {b} share {len(overlap)} "
                f"event ids — measurement is contaminated"
            )


def test_pre_and_post_measured_at_same_alert_budget(loop_results):
    """The whole point of recalibrating per model: pre and post recall are only
    comparable if both are read at the same false-positive rate. An earlier
    version reused the stale threshold and reported recall 1.000 at 1.91% FPR,
    nearly 4x the intended budget."""
    for gen in loop_results:
        assert gen.monitor_fpr_pre == pytest.approx(gen.monitor_fpr_post, abs=0.01), (
            f"generation {gen.generation}: pre/post measured at different alert "
            f"budgets ({gen.monitor_fpr_pre:.4f} vs {gen.monitor_fpr_post:.4f})"
        )


def test_operating_fpr_near_target(loop_results):
    for gen in loop_results:
        assert gen.monitor_fpr_post <= 0.02, (
            f"generation {gen.generation}: FPR {gen.monitor_fpr_post:.4f} far above target"
        )


def test_prevalence_is_controlled(loop_results):
    """Blended prevalence must track the calibrated target. An uncontrolled
    stream once ran ~25% fraud, which makes AUPRC and every threshold
    uninterpretable."""
    from chakra.generate import calibration as C

    target = C.TARGET_BLENDED_FRAUD_PREVALENCE
    for gen in loop_results:
        # A band tight enough to catch a systematic error. The previous range
        # (0.05%-5%) spanned two orders of magnitude and passed happily while
        # realised prevalence sat 30% off target from a double-counted card
        # ownership discount.
        assert 0.75 * target < gen.prevalence < 1.35 * target, (
            f"generation {gen.generation}: prevalence {gen.prevalence:.5f} "
            f"is off target {target:.5f} by more than the tolerated band"
        )


def test_episodes_were_produced(loop_results):
    for gen in loop_results:
        assert gen.n_episodes > 0
