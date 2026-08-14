"""F11 must raise velocity and decline features *by acting*, not by writing them.

This is the empirical half of the no-feature-injection guarantee: the tripwire
tests prove attacks cannot touch the feature layer; this proves they do not need
to, because behaving like a card tester produces the signature on its own.
"""

from datetime import datetime

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.attacks.base import AttackParams
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import Surface
from chakra.schema.features import build_matrix

WORLD = datetime(2026, 2, 1)


def _build(seed=2000, with_attack=True):
    rng = Rng(seed)
    pop = build_population(rng, n_consumers=80, n_merchants=12, world_start=WORLD)
    log = generate_background(rng, pop, start=WORLD, days=1.0)
    if with_attack:
        fam = ATTACK_FAMILIES["F11"]
        params = AttackParams(
            {
                "cards_per_burst": 40,
                "inter_txn_seconds": 1.0,   # fast
                "micro_amount_inr": 2.0,    # micro
                "decline_tolerance": 40,
                "spread_seconds": 0.0,
            }
        )
        log.extend(fam.emit(rng, pop, params, start=datetime(2026, 2, 1, 8), n_episodes=2))
    return build_matrix(log, Surface.NETWORK)


def test_attack_raises_velocity_naturally():
    features, y, _ = _build()
    fraud = y.values == 1
    legit = y.values == 0
    assert fraud.sum() > 0, "no fraud rows produced"
    assert (
        features.loc[fraud, "velocity_10m"].mean()
        > features.loc[legit, "velocity_10m"].mean()
    ), "enumeration did not raise 10-minute velocity above genuine traffic"


def test_attack_raises_decline_ratio_naturally():
    features, y, _ = _build()
    fraud = y.values == 1
    legit = y.values == 0
    assert (
        features.loc[fraud, "decline_ratio_1h"].mean()
        > features.loc[legit, "decline_ratio_1h"].mean()
    ), "enumeration did not raise the decline ratio"


def test_attack_raises_distinct_instruments():
    features, y, _ = _build()
    fraud = y.values == 1
    legit = y.values == 0
    assert (
        features.loc[fraud, "distinct_instruments_1h"].mean()
        > features.loc[legit, "distinct_instruments_1h"].mean()
    ), "one actor walking many cards did not show up as distinct-instrument count"


def test_micro_amount_flag_fires_on_probes():
    features, y, _ = _build()
    fraud = y.values == 1
    assert features.loc[fraud, "is_zero_or_micro"].mean() > 0.9


def test_synthetic_instrument_ids_are_obviously_fake():
    """No realistic or potentially routable card numbers, ever."""
    rng = Rng(3000)
    pop = build_population(rng, n_consumers=20, n_merchants=5, world_start=WORLD)
    fam = ATTACK_FAMILIES["F11"]
    events = fam.emit(rng, pop, fam.default_params(), start=WORLD, n_episodes=2)
    ids = [e.payload.get("instrument_id", "") for e in events]
    ids = [i for i in ids if i]
    assert ids, "attack produced no instrument ids"
    for i in ids:
        assert i.startswith("SYNTH-CARD-"), f"instrument id {i!r} is not obviously synthetic"
        digits = "".join(ch for ch in i if ch.isdigit())
        assert len(digits) < 13, f"instrument id {i!r} contains a PAN-length digit run"
