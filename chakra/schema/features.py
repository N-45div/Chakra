"""The feature layer.

One pipeline, applied identically to simulated and real event streams. Each
feature is a pure function of (visible_events, as_of) and declares the surface
it belongs to. The registry builds a feature matrix by, for each decision
event, asking the EventLog for exactly the events that are visible to the
model's surface and available before that decision — so leakage is structurally
impossible rather than merely avoided by discipline.

Attacks do not import this module. A test asserts that. If an attack could
write a feature directly, the detector would be learning the attack author's
rules instead of the fraud, and every hold-out number would be meaningless.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from chakra.schema.events import Event, EventType, Surface, DECISION_EVENTS

# A feature is a function of the visible event list and the decision instant.
FeatureFn = Callable[[list[Event], datetime, Event], float]


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    surface: Surface
    fn: FeatureFn
    window: timedelta | None  # None = unbounded lookback


_REGISTRY: dict[str, FeatureSpec] = {}


def feature(name: str, surface: Surface, window: timedelta | None = None):
    """Register a feature. `surface` declares which decision surface may use it;
    `window` bounds the lookback (None = all visible history)."""

    def deco(fn: FeatureFn) -> FeatureFn:
        if name in _REGISTRY:
            raise ValueError(f"duplicate feature {name!r}")
        _REGISTRY[name] = FeatureSpec(name=name, surface=surface, fn=fn, window=window)
        return fn

    return deco


def registered() -> dict[str, FeatureSpec]:
    return dict(_REGISTRY)


def features_for_surface(surface: Surface) -> list[FeatureSpec]:
    """Features a model on `surface` is permitted to use.

    Uses the same visibility rule as the event log: the network may use only
    network features; issuer/app/telco models may additionally use their own.
    """
    from chakra.schema.events import _VISIBILITY

    allowed = _VISIBILITY[surface]
    return [s for s in _REGISTRY.values() if s.surface in allowed]


def _window_slice(events: list[Event], as_of: datetime, window: timedelta | None) -> list[Event]:
    if window is None:
        return events
    lo = as_of - window
    return [e for e in events if e.ts >= lo]


def build_matrix(log, surface: Surface):
    """Build (X, y, meta) for every decision event in `log`, using only
    information visible to `surface` strictly before each decision.

    Returns a pandas DataFrame X (one row per decision event, columns = the
    surface's features), a Series y (1 = fraud), and a meta DataFrame carrying
    ids, family, amount and timestamp for downstream slicing (value-weighted
    and worst-family metrics need these, and they must never be model inputs).
    """
    import pandas as pd

    specs = features_for_surface(surface)
    rows: list[dict[str, float]] = []
    ys: list[int] = []
    meta: list[dict] = []

    for dec in log.sorted_by_time():
        if dec.event_type not in DECISION_EVENTS:
            continue
        # The decision is made at the instant the transaction is initiated.
        # visible_to() applies a strict `available_at < as_of`, so the decision
        # event itself — and its own outcome, which occurs later — are excluded.
        as_of = dec.ts
        visible = log.visible_to(surface, as_of)
        row: dict[str, float] = {}
        for spec in specs:
            scoped = _window_slice(visible, as_of, spec.window)
            row[spec.name] = float(spec.fn(scoped, as_of, dec))
        rows.append(row)
        ys.append(1 if (dec.label is not None and dec.label.value == "fraud") else 0)
        meta.append(
            {
                "event_id": dec.event_id,
                "actor_id": dec.actor_id,
                "ts": dec.ts,
                "family": dec.family.value if dec.family else None,
                "amount_inr": float(dec.payload.get("amount_inr", 0.0)),
                "episode_id": dec.episode_id,
            }
        )

    X = pd.DataFrame(rows).fillna(0.0)
    y = pd.Series(ys, name="label", dtype=int)
    meta_df = pd.DataFrame(meta)
    return X, y, meta_df


# --------------------------------------------------------------------------
# Network-surface features. All derive from events the payment network sees at
# authorisation time. Nothing here reads a psp_app/telco event — the event log
# would refuse to hand those over to a network-surface build in any case.
# --------------------------------------------------------------------------

def _actor_txn_events(events: list[Event], dec: Event) -> list[Event]:
    """Prior transaction-initiation events for the same actor."""
    return [
        e
        for e in events
        if e.actor_id == dec.actor_id and e.event_type is EventType.TXN_INITIATED
    ]


@feature("velocity_10m", Surface.NETWORK, window=timedelta(minutes=10))
def velocity_10m(events, as_of, dec):
    """Count of the actor's transaction initiations in the last 10 minutes.
    Derived — the enumeration family must actually emit rapid events for this
    to rise; it may never set the value directly."""
    return float(len(_actor_txn_events(events, dec)))


@feature("velocity_1h", Surface.NETWORK, window=timedelta(hours=1))
def velocity_1h(events, as_of, dec):
    return float(len(_actor_txn_events(events, dec)))


@feature("decline_ratio_1h", Surface.NETWORK, window=timedelta(hours=1))
def decline_ratio_1h(events, as_of, dec):
    """Share of the actor's recent authorisations that were declined — the
    classic card-testing signature."""
    auths = [
        e
        for e in events
        if e.actor_id == dec.actor_id
        and e.event_type in (EventType.TXN_AUTHORISED, EventType.TXN_DECLINED)
    ]
    if not auths:
        return 0.0
    declines = sum(1 for e in auths if e.event_type is EventType.TXN_DECLINED)
    return declines / len(auths)


@feature("distinct_instruments_1h", Surface.NETWORK, window=timedelta(hours=1))
def distinct_instruments_1h(events, as_of, dec):
    """How many distinct instruments the actor has touched — one device walking
    many cards is the enumeration tell."""
    instruments = {
        e.payload.get("instrument_id")
        for e in _actor_txn_events(events, dec)
        if e.payload.get("instrument_id")
    }
    instruments.add(dec.payload.get("instrument_id"))
    instruments.discard(None)
    return float(len(instruments))


@feature("amount_vs_actor_mean", Surface.NETWORK)
def amount_vs_actor_mean(events, as_of, dec):
    """This amount relative to the actor's historical mean. 1.0 when in line,
    higher when out of pattern; 0 when no history."""
    amounts = [
        float(e.payload["amount_inr"])
        for e in _actor_txn_events(events, dec)
        if "amount_inr" in e.payload
    ]
    if not amounts:
        return 0.0
    mean = sum(amounts) / len(amounts)
    if mean <= 0:
        return 0.0
    return float(dec.payload.get("amount_inr", 0.0)) / mean


@feature("amount_inr_log", Surface.NETWORK)
def amount_inr_log(events, as_of, dec):
    import math

    return math.log1p(max(0.0, float(dec.payload.get("amount_inr", 0.0))))


@feature("is_zero_or_micro", Surface.NETWORK)
def is_zero_or_micro(events, as_of, dec):
    """Zero-value or sub-₹5 authorisation — the card-tester's validation probe."""
    amt = float(dec.payload.get("amount_inr", 0.0))
    return 1.0 if amt <= 5.0 else 0.0


@feature("payee_newness", Surface.NETWORK)
def payee_newness(events, as_of, dec):
    """1.0 if the actor has never paid this counterparty before, else 0.0.
    Central to authorised-push fraud, where the amount looks normal but the
    beneficiary is brand new."""
    cp = dec.payload.get("counterparty_id")
    if cp is None:
        return 0.0
    seen = {
        e.payload.get("counterparty_id")
        for e in _actor_txn_events(events, dec)
    }
    return 0.0 if cp in seen else 1.0
