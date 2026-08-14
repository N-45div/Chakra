"""A family's detector must be trained and evaluated on its own rail only.

An unscoped F11 audit set held 23,628 legitimate UPI rows, 2,873 legitimate card
rows and 111 card-fraud rows — 89% of the negatives from a rail carrying none of
the positives. Aggregate FPR could then hide card-specific false positives
entirely, and part of the apparent separation was card-versus-UPI behaviour
rather than fraud.
"""

from datetime import datetime

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import Rail, Surface
from chakra.schema.features import build_matrix

WORLD = datetime(2026, 2, 1)


def _mixed_log():
    rng = Rng(4242)
    pop = build_population(rng, n_consumers=120, n_merchants=15, world_start=WORLD)
    log = generate_background(rng, pop, start=WORLD, days=1.0)
    fam = ATTACK_FAMILIES["F11"]
    log.extend(
        fam.emit(rng, pop, fam.default_params(), start=datetime(2026, 2, 1, 9), n_episodes=2)
    )
    return log


def test_unscoped_matrix_mixes_rails():
    """Guards the premise: without scoping the population really is mixed."""
    _, _, meta = build_matrix(_mixed_log(), Surface.NETWORK)
    assert set(meta["rail"]) == {"upi", "card"}


def test_card_scoped_matrix_contains_only_card_rows():
    _, _, meta = build_matrix(_mixed_log(), Surface.NETWORK, rail=Rail.CARD)
    assert set(meta["rail"]) == {"card"}


def test_scoped_negatives_share_the_rail_of_the_positives():
    features, y, meta = build_matrix(_mixed_log(), Surface.NETWORK, rail=Rail.CARD)
    assert y.sum() > 0, "no fraud rows in the scoped matrix"
    rails_of_negatives = set(meta.loc[y.values == 0, "rail"])
    rails_of_positives = set(meta.loc[y.values == 1, "rail"])
    assert rails_of_negatives == rails_of_positives == {"card"}
    assert len(features) == len(meta)


def test_upi_scope_has_no_f11_fraud():
    """F11 is a card family; scoping to UPI must yield a fraud-free population."""
    _, y, _ = build_matrix(_mixed_log(), Surface.NETWORK, rail=Rail.UPI)
    assert y.sum() == 0
