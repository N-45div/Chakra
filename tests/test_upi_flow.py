"""UPI flow prerequisites for F5.

F5's deception is direction inversion — the victim believes they are receiving
while their PIN authorises a debit. That story is only representable if the
event stream gets two things right, and neither was true before.
"""

from collections import Counter
from datetime import datetime

from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import EventType, Surface

WORLD = datetime(2026, 2, 1)


def _log(seed=1000, days=2.0):
    rng = Rng(seed)
    pop = build_population(rng, n_consumers=200, n_merchants=20, world_start=WORLD)
    return generate_background(rng, pop, start=WORLD, days=days)


def test_auth_request_never_precedes_the_pin():
    """The network is asked to approve only after the payer authenticates.
    Reversed, the detector would be deciding before the PIN existed."""
    log = _log()
    pin_at = {
        e.payload["linked_txn_id"]: e.ts for e in log if e.event_type is EventType.PIN_ENTERED
    }
    auth_at = {
        e.payload.get("linked_txn_id"): e.ts
        for e in log
        if e.event_type is EventType.TXN_AUTH_REQUESTED
    }
    violations = [t for t, pin in pin_at.items() if t in auth_at and auth_at[t] < pin]
    assert not violations, f"{len(violations)} UPI auth requests precede their own PIN"


def test_outcome_follows_the_auth_request():
    log = _log()
    auth_at = {
        e.payload.get("linked_txn_id"): e.ts
        for e in log
        if e.event_type is EventType.TXN_AUTH_REQUESTED
    }
    for e in log:
        if e.event_type in (EventType.TXN_AUTHORISED, EventType.TXN_DECLINED):
            src = e.payload.get("linked_txn_id")
            if src in auth_at:
                assert e.ts >= auth_at[src]


def test_initiation_is_not_network_visible():
    """Initiation happens in the payer's app or at the merchant. Treating it as
    network-visible credits the model with sight it does not have."""
    log = _log()
    inits = [e for e in log if e.event_type is EventType.TXN_INITIATED]
    assert inits
    assert all(e.surface is not Surface.NETWORK for e in inits)


def test_genuine_upi_has_push_collect_and_p2p_variety():
    log = _log()
    modes = Counter(
        e.payload.get("initiation_mode")
        for e in log
        if e.event_type is EventType.TXN_AUTH_REQUESTED and e.rail.value == "upi"
    )
    assert {"p2m_push", "p2p_push", "p2m_collect"} <= set(modes)


def test_no_genuine_p2p_collect_exists():
    """NPCI discontinued person-to-person collect on 1 Oct 2025, which is why
    merchant-collect impersonation is the surviving deception rather than plain
    P2P collect. Genuine P2P collect traffic must not exist in the simulation."""
    log = _log()
    modes = {
        e.payload.get("initiation_mode")
        for e in log
        if e.event_type is EventType.TXN_AUTH_REQUESTED
    }
    assert not any(m and "p2p" in m and "collect" in m for m in modes)


def test_collect_flag_is_carried_to_the_decision_row():
    """The detector must be able to tell a pull from a push at decision time."""
    log = _log()
    auths = [
        e
        for e in log
        if e.event_type is EventType.TXN_AUTH_REQUESTED and e.rail.value == "upi"
    ]
    assert auths
    assert all("is_collect" in e.payload for e in auths)
    assert any(e.payload["is_collect"] for e in auths)
