"""F8 — bust-out mechanics and honest self-valuation.

The slow-temporal family lives or dies on two things: the nurture phase must
genuinely precede and differ from the burst, and the family must not credit
itself with its own nurture spend when valuing an episode.
"""

from datetime import datetime

import numpy as np

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import EventType, Family, Label, Rail, Surface
from chakra.schema.features import build_matrix

WORLD = datetime(2026, 2, 1)
FAM = ATTACK_FAMILIES["F8"]


def _emit(seed=1000):
    rng = Rng(seed)
    pop = build_population(rng, n_consumers=200, n_merchants=20, world_start=WORLD)
    return FAM.emit(
        rng, pop, FAM.default_params(), start=datetime(2026, 2, 1, 6), n_episodes=3
    )


def test_all_rows_are_card_rail_fraud():
    ev = _emit()
    assert ev
    assert all(e.rail is Rail.CARD for e in ev)
    assert all(e.label is Label.FRAUD for e in ev)
    assert all(e.family is Family.F8 for e in ev)


def test_nurture_precedes_burst_within_an_episode():
    ev = _emit()
    by_ep: dict[str, list] = {}
    for e in ev:
        if e.event_type is EventType.TXN_AUTH_REQUESTED:
            by_ep.setdefault(e.episode_id, []).append(e.payload["phase"])
    assert by_ep
    for phases in by_ep.values():
        assert "nurture" in phases and "burst" in phases
        first_burst = phases.index("burst")
        assert set(phases[:first_burst]) == {"nurture"}, (
            "a burst row preceded a nurture row inside one episode"
        )


def test_burst_amounts_dominate_nurture():
    ev = _emit()
    auths = [e for e in ev if e.event_type is EventType.TXN_AUTH_REQUESTED]
    nur = [float(e.payload["amount_inr"]) for e in auths if e.payload["phase"] == "nurture"]
    bur = [float(e.payload["amount_inr"]) for e in auths if e.payload["phase"] == "burst"]
    assert min(bur) > max(nur), "burst must extract at scales above every nurture row"


def test_episode_value_counts_only_burst_at_conversion_discount():
    from chakra.generate import calibration as C

    amounts = [1000.0, 200.0, 3000.0]
    payloads = [{"phase": "burst"}, {"phase": "nurture"}, {"phase": "burst"}]
    expected = 4000.0 * C.CASH_CONVERSION_FACTOR
    assert FAM.episode_value_inr(amounts, payloads) == expected


def test_episode_value_without_payloads_refuses_to_guess():
    try:
        FAM.episode_value_inr([100.0], None)
    except ValueError:
        return
    raise AssertionError("F8 valued an episode without payload context")


def test_single_instrument_per_episode():
    """The whole premise is ONE compromised card worked over time — if the
    family minted fresh instruments it would be F11 in disguise."""
    ev = _emit()
    by_ep: dict[str, set] = {}
    for e in ev:
        if e.event_type is EventType.TXN_AUTH_REQUESTED:
            by_ep.setdefault(e.episode_id, set()).add(e.payload["instrument_id"])
    assert by_ep
    for instruments in by_ep.values():
        assert len(instruments) == 1


def test_no_burner_devices():
    """Runs on the victim's own handset. A device the attack registered would
    hand the detector an emulator flag the real threat does not carry."""
    rng = Rng(7)
    pop = build_population(rng, n_consumers=150, n_merchants=15, world_start=WORLD)
    before = len(pop.devices)
    ev = FAM.emit(rng, pop, FAM.default_params(), start=WORLD, n_episodes=4)
    assert ev
    assert len(pop.devices) == before


def test_deterministic_given_seed():
    a = _emit(1234)
    b = _emit(1234)
    ka = [(e.event_id, e.ts) for e in a]
    kb = [(e.event_id, e.ts) for e in b]
    assert ka == kb


def test_scoped_matrix_yields_clean_rows():
    rng = Rng(55)
    pop = build_population(rng, n_consumers=120, n_merchants=12, world_start=WORLD)
    log = generate_background(rng, pop, start=WORLD, days=1.5, only_rail="card")
    log.extend(FAM.emit(rng, pop, FAM.default_params(), start=datetime(2026, 2, 2, 6), n_episodes=4))
    X, y, meta = build_matrix(log, Surface.NETWORK, rail=Rail.CARD)
    assert y.sum() > 0
    assert np.isfinite(X.values).all(), "feature matrix contains NaN/inf"
    assert set(meta["rail"]) == {"card"}
