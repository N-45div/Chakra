"""The feature layer.

One pipeline, applied identically to simulated and real event streams. Each
feature is a pure function of (visible_events, as_of, decision_event) and
declares the surface it belongs to. The registry builds a feature matrix by
asking the EventLog for exactly the events visible to the model's surface and
available before each decision, so leakage is structurally impossible rather
than avoided by discipline.

Two rules that the first audit forced, and that matter more than the feature
list itself:

1. Features group by OBSERVABLE NETWORK IDENTITIES — device, merchant endpoint,
   instrument, BIN — never by an internal actor id. An earlier version grouped
   velocity by `actor_id`, which for an attack was a freshly-minted internal
   handle unique to that burst. That handed the detector a perfect grouping key
   no real payment network possesses, and it is why F11 looked trivially
   detectable. A real network sees the terminal, the card, the device; it does
   not see "this is fraudster #7".

2. Features are RAIL-SCOPED. Card history must not inherit UPI history through a
   shared actor: they are different rails with different behavioural baselines,
   and mixing them invents signal that no card processor would have.

Attacks do not import this module. A test enforces that.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from chakra.schema.events import DECISION_EVENTS, Event, EventType, Surface

FeatureFn = Callable[[list[Event], datetime, Event], float]


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    surface: Surface
    fn: FeatureFn
    window: timedelta | None  # None = unbounded lookback


_REGISTRY: dict[str, FeatureSpec] = {}


def feature(name: str, surface: Surface, window: timedelta | None = None):
    def deco(fn: FeatureFn) -> FeatureFn:
        if name in _REGISTRY:
            raise ValueError(f"duplicate feature {name!r}")
        _REGISTRY[name] = FeatureSpec(name=name, surface=surface, fn=fn, window=window)
        return fn

    return deco


def registered() -> dict[str, FeatureSpec]:
    return dict(_REGISTRY)


def features_for_surface(surface: Surface) -> list[FeatureSpec]:
    from chakra.schema.events import _VISIBILITY

    allowed = _VISIBILITY[surface]
    return [s for s in _REGISTRY.values() if s.surface in allowed]


def _window_slice(events: list[Event], as_of: datetime, window: timedelta | None) -> list[Event]:
    if window is None:
        return events
    lo = as_of - window
    return [e for e in events if e.ts >= lo]


# ---------------------------------------------------------------------------
# Visibility index.
#
# The naive implementation re-scanned the whole log for every decision, which is
# quadratic and made realistic fraud prevalence unrunnable: hitting 0.4% needs
# thousands of legitimate rows per attack episode, and the scan cost grew faster
# than the volume. The index groups events once per matrix build by the keys the
# network can observe, sorted by time, so each feature does a bisect over a short
# window instead of a full pass.
#
# It changes performance only. Both visibility rules still apply exactly as
# before: surface filtering happens on construction, and `available_at < as_of`
# is enforced on every lookup.
# ---------------------------------------------------------------------------

_KEY_FIELDS = ("device_id", "counterparty_id", "instrument_id")


class VisibilityIndex:
    def __init__(self, log, surface: Surface):
        from bisect import bisect_left

        self._bisect_left = bisect_left
        # surface filtering, once
        from chakra.schema.events import _VISIBILITY

        allowed = _VISIBILITY[surface]
        events = [e for e in log.sorted_by_time() if e.surface in allowed]

        # (rail, field, value, kind) -> (sorted ts list, events list)
        self._groups: dict[tuple, tuple[list, list]] = {}
        for e in events:
            # "attempt" is the authorisation REQUEST, not the initiation: the
            # request is what a network actually observes. Initiation happens in
            # the payer's app before anything reaches the network, so counting
            # initiations would credit the model with visibility it lacks.
            if e.event_type is EventType.TXN_AUTH_REQUESTED:
                kind = "attempt"
            elif e.event_type in (EventType.TXN_AUTHORISED, EventType.TXN_DECLINED):
                kind = "outcome"
            else:
                continue
            for field_name in _KEY_FIELDS:
                val = e.payload.get(field_name)
                if val is None:
                    continue
                key = (e.rail, field_name, val, kind)
                ts_list, ev_list = self._groups.setdefault(key, ([], []))
                ts_list.append(e.ts)
                ev_list.append(e)

    def prior(
        self, dec: Event, field_name: str, kind: str, as_of: datetime, window: timedelta | None
    ) -> list[Event]:
        """Events sharing an observable key with `dec`, on the same rail, within
        `window`, and available strictly before `as_of`."""
        val = dec.payload.get(field_name)
        if val is None:
            return []
        entry = self._groups.get((dec.rail, field_name, val, kind))
        if entry is None:
            return []
        ts_list, ev_list = entry
        lo_ix = 0
        if window is not None:
            lo_ix = self._bisect_left(ts_list, as_of - window)
        hi_ix = self._bisect_left(ts_list, as_of)
        # available_at is usually ts but may be later; enforce it explicitly.
        return [e for e in ev_list[lo_ix:hi_ix] if e.available_at < as_of]


# ---------------------------------------------------------------------------
# Observable grouping keys. Each returns the events the network could associate
# with the decision through a key it can actually see.
# ---------------------------------------------------------------------------

def _same_rail(events: list[Event], dec: Event) -> list[Event]:
    return [e for e in events if e.rail is dec.rail]


def _txn_inits(events: list[Event]) -> list[Event]:
    return [e for e in events if e.event_type is EventType.TXN_INITIATED]


def _by_key(ctx, dec: Event, key: str) -> list[Event]:
    """Prior authorisation attempts sharing an observable key with `dec`, on the
    same rail. Returns [] when the key is absent, so a missing device id degrades
    to 'no evidence' rather than a spurious match on None."""
    return ctx.index.prior(dec, key, "attempt", ctx.as_of, ctx.window)


def _outcomes_by_key(ctx, dec: Event, key: str) -> list[Event]:
    return ctx.index.prior(dec, key, "outcome", ctx.as_of, ctx.window)


@dataclass(frozen=True, slots=True)
class Ctx:
    """What a feature is given: the index, the decision instant, and the window
    declared by that feature's spec."""

    index: "VisibilityIndex"
    as_of: datetime
    window: timedelta | None


def build_matrix(log, surface: Surface, rail=None, only_episodes: set | None = None):
    """Build (X, y, meta) for every decision event on `rail`, using only
    information visible to `surface` strictly before each decision.

    `rail` scopes which decisions become ROWS. History from other rails is
    already excluded from every feature, so this controls the population being
    modelled rather than the lookback.

    Scoping matters more than it looks. An F11 audit set built without it held
    23,628 legitimate UPI rows, 2,873 legitimate card rows and 111 card-fraud
    rows — so 89% of the negatives came from a rail carrying none of the
    positives. A single detector across that mixture can hide card-specific
    false positives entirely inside an aggregate FPR, and part of what it
    appears to separate is card-versus-UPI behaviour rather than fraud. Real
    deployments score a rail; the evaluation should too.

    meta carries labels, family, amount and ids for slicing. None of it is a
    model input.
    """
    import pandas as pd

    specs = features_for_surface(surface)
    index = VisibilityIndex(log, surface)
    rows: list[dict[str, float]] = []
    ys: list[int] = []
    meta: list[dict] = []

    for dec in log.sorted_by_time():
        if dec.event_type not in DECISION_EVENTS:
            continue
        if rail is not None and dec.rail is not rail:
            continue
        # `only_episodes` restricts which decisions become ROWS; the index still
        # covers the whole log, so every feature sees the same history it would
        # otherwise. Used when scoring attacker fitness, where only the attack's
        # own rows are needed and building tens of thousands of genuine rows per
        # candidate per replicate dominates the runtime.
        if only_episodes is not None and dec.episode_id not in only_episodes:
            continue
        # The decision is made when the transaction is initiated. Every index
        # lookup enforces available_at < as_of, so the decision event itself and
        # its own later outcome are both excluded.
        as_of = dec.ts
        row: dict[str, float] = {}
        for spec in specs:
            ctx = Ctx(index=index, as_of=as_of, window=spec.window)
            row[spec.name] = float(spec.fn(ctx, as_of, dec))
        rows.append(row)
        ys.append(1 if (dec.label is not None and dec.label.value == "fraud") else 0)
        meta.append(
            {
                "event_id": dec.event_id,
                "actor_id": dec.actor_id,
                "ts": dec.ts,
                "rail": dec.rail.value,
                "family": dec.family.value if dec.family else None,
                "amount_inr": float(dec.payload.get("amount_inr", 0.0)),
                "episode_id": dec.episode_id,
            }
        )

    X = pd.DataFrame(rows).fillna(0.0)
    y = pd.Series(ys, name="label", dtype=int)
    return X, y, pd.DataFrame(meta)


# ---------------------------------------------------------------------------
# Network-surface features, keyed on what a payment network can actually see.
# ---------------------------------------------------------------------------

@feature("velocity_device_10m", Surface.NETWORK, window=timedelta(minutes=10))
def velocity_device_10m(ctx, as_of, dec):
    """Transactions from this device in 10 minutes, same rail."""
    return float(len(_by_key(ctx, dec, "device_id")))


@feature("velocity_merchant_10m", Surface.NETWORK, window=timedelta(minutes=10))
def velocity_merchant_10m(ctx, as_of, dec):
    """Transactions hitting this merchant endpoint in 10 minutes. An enumeration
    burst concentrates on one endpoint, which is observable to the acquirer."""
    return float(len(_by_key(ctx, dec, "counterparty_id")))


@feature("velocity_instrument_1h", Surface.NETWORK, window=timedelta(hours=1))
def velocity_instrument_1h(ctx, as_of, dec):
    return float(len(_by_key(ctx, dec, "instrument_id")))


@feature("distinct_instruments_device_1h", Surface.NETWORK, window=timedelta(hours=1))
def distinct_instruments_device_1h(ctx, as_of, dec):
    """How many distinct instruments this device has presented. One device
    walking many cards is the enumeration signature."""
    prior = _by_key(ctx, dec, "device_id")
    seen = {e.payload.get("instrument_id") for e in prior}
    seen.add(dec.payload.get("instrument_id"))
    seen.discard(None)
    return float(len(seen))


@feature("distinct_instruments_merchant_1h", Surface.NETWORK, window=timedelta(hours=1))
def distinct_instruments_merchant_1h(ctx, as_of, dec):
    """Distinct instruments presented at this endpoint — the acquirer-side view
    of the same burst, and the one that survives when the attacker rotates
    devices."""
    prior = _by_key(ctx, dec, "counterparty_id")
    seen = {e.payload.get("instrument_id") for e in prior}
    seen.add(dec.payload.get("instrument_id"))
    seen.discard(None)
    return float(len(seen))


@feature("decline_ratio_merchant_1h", Surface.NETWORK, window=timedelta(hours=1))
def decline_ratio_merchant_1h(ctx, as_of, dec):
    outs = _outcomes_by_key(ctx, dec, "counterparty_id")
    if not outs:
        return 0.0
    declines = sum(1 for e in outs if e.event_type is EventType.TXN_DECLINED)
    return declines / len(outs)


@feature("decline_ratio_device_1h", Surface.NETWORK, window=timedelta(hours=1))
def decline_ratio_device_1h(ctx, as_of, dec):
    outs = _outcomes_by_key(ctx, dec, "device_id")
    if not outs:
        return 0.0
    declines = sum(1 for e in outs if e.event_type is EventType.TXN_DECLINED)
    return declines / len(outs)


@feature("amount_vs_instrument_mean", Surface.NETWORK)
def amount_vs_instrument_mean(ctx, as_of, dec):
    """Amount relative to this instrument's own history.

    Returns a NEUTRAL 1.0 when there is no history, not 0.0. Encoding "unknown"
    as a distinct out-of-range value hands the model a free flag: every
    enumerated card was unseen, so 0.0 meant fraud with near-perfect precision
    and the ratio was never actually being used as a ratio. Absence of history is
    reported once, honestly, by has_instrument_history below.
    """
    amounts = [
        float(e.payload["amount_inr"])
        for e in _by_key(ctx, dec, "instrument_id")
        if "amount_inr" in e.payload
    ]
    if not amounts:
        return 1.0
    mean = sum(amounts) / len(amounts)
    if mean <= 0:
        return 1.0
    return float(dec.payload.get("amount_inr", 0.0)) / mean


@feature("has_instrument_history", Surface.NETWORK)
def has_instrument_history(ctx, as_of, dec):
    """Whether this instrument has been seen before on this rail. Kept as its
    own explicit feature so 'unknown' is stated once rather than smuggled into
    the value of every other instrument-derived feature."""
    return 1.0 if _by_key(ctx, dec, "instrument_id") else 0.0


@feature("instrument_newness", Surface.NETWORK)
def instrument_newness(ctx, as_of, dec):
    """1.0 when this instrument has never been seen on this rail before."""
    return 0.0 if _by_key(ctx, dec, "instrument_id") else 1.0


@feature("payee_newness_for_instrument", Surface.NETWORK)
def payee_newness_for_instrument(ctx, as_of, dec):
    """1.0 when this instrument has never paid this counterparty. Central to
    authorised-push fraud, where the amount is unremarkable but the beneficiary
    is brand new."""
    cp = dec.payload.get("counterparty_id")
    if cp is None:
        return 0.0
    seen = {e.payload.get("counterparty_id") for e in _by_key(ctx, dec, "instrument_id")}
    return 0.0 if cp in seen else 1.0


@feature("amount_inr_log", Surface.NETWORK)
def amount_inr_log(ctx, as_of, dec):
    import math

    return math.log1p(max(0.0, float(dec.payload.get("amount_inr", 0.0))))


@feature("is_zero_or_micro", Surface.NETWORK)
def is_zero_or_micro(ctx, as_of, dec):
    """Zero-value or sub-₹5 authorisation — a validation probe rather than a
    purchase. Deliberately a low threshold: an attacker who raises the probe
    amount to evade this pays for it in card-testing cost, which is the kind of
    trade the loop should be forced to make."""
    return 1.0 if float(dec.payload.get("amount_inr", 0.0)) <= 5.0 else 0.0
