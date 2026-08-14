"""Same seed => identical run; different seed => different run.

This underwrites the contract's promise of median/IQR across 20 fixed seeds. If
determinism breaks, every reported number becomes unreproducible.
"""

from datetime import datetime

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import EventLog, Surface
from chakra.schema.features import build_matrix

WORLD = datetime(2026, 2, 1)


def _run_once(seed: int):
    rng = Rng(seed)
    pop = build_population(rng, n_consumers=60, n_merchants=10, world_start=WORLD)
    log = generate_background(rng, pop, start=WORLD, days=1.0)
    fam = ATTACK_FAMILIES["F11"]
    log.extend(
        fam.emit(rng, pop, fam.default_params(), start=datetime(2026, 2, 1, 6), n_episodes=3)
    )
    features, y, meta = build_matrix(log, Surface.NETWORK)
    return {
        "n_events": len(log),
        "n_rows": len(features),
        "n_fraud": int(y.sum()),
        "feature_sum": float(features.sum().sum()),
        "event_ids": tuple(meta["event_id"][:20]),
    }


def test_same_seed_reproduces_exactly():
    a = _run_once(1000)
    b = _run_once(1000)
    assert a == b, "identical seed produced a different run"


def test_different_seed_produces_different_events():
    a = _run_once(1000)
    b = _run_once(1001)
    assert a["event_ids"] != b["event_ids"], "different seeds produced identical event ids"


def test_spawned_streams_are_independent():
    """Children of the same parent must not be identical to each other."""
    parent = Rng(1000)
    c1 = parent.spawn("a")
    c2 = parent.spawn("b")
    draws1 = [c1.uniform(0, 1) for _ in range(20)]
    draws2 = [c2.uniform(0, 1) for _ in range(20)]
    assert draws1 != draws2


def test_spawn_is_reproducible():
    """The same parent seed yields the same children, in order."""
    a = [Rng(1000).spawn("x").uniform(0, 1) for _ in range(1)]
    b = [Rng(1000).spawn("x").uniform(0, 1) for _ in range(1)]
    assert a == b
