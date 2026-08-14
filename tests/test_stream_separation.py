"""The four streams must never overlap.

If a monitor row were also a training row, the loop's improvement number would
be measured on data the detector had just fitted — the most embarrassing failure
available to this project. This test makes the separation an enforced property
rather than a claim in a document.
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
        episodes_per_param=1,
        n_consumers=60,
        n_merchants=10,
        background_days=0.5,
    )
    loop = Loop(ATTACK_FAMILIES["F11"], cfg)
    return loop.run()


def test_streams_are_disjoint(loop_results):
    for gen in loop_results:
        streams = gen.stream_ids
        assert streams, "no stream provenance recorded"
        for a, b in combinations(streams, 2):
            overlap = streams[a] & streams[b]
            assert not overlap, (
                f"generation {gen.generation}: streams {a} and {b} share "
                f"{len(overlap)} event ids — measurement is contaminated"
            )


def test_monitor_streams_differ_between_pre_and_post(loop_results):
    """Pre- and post-retrain measurements must be on *different* fresh batches,
    otherwise the improvement is partly a memorisation artefact."""
    for gen in loop_results:
        pre = gen.stream_ids.get("monitor_pre", set())
        post = gen.stream_ids.get("monitor_post", set())
        assert pre and post
        assert pre != post


def test_every_generation_produced_attacks(loop_results):
    for gen in loop_results:
        assert gen.n_attack_episodes > 0
