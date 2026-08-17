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

_KEY_FIELDS = ("device_id", "counterparty_id", "instrument_id", "payee_vpa", "payer_vpa")

# Fields a row may expose at request time. Everything else — above all `label`
# and `family` — is ground truth that exists only because we generated the data,
# and must be unreachable from a feature. Defined here because both the
# historical views and the decision view are built from it.
_REQUEST_TIME_FIELDS = (
    "instrument_id",
    "payer_vpa",
    "payee_vpa",
    "counterparty_id",
    "amount_inr",
    "mcc",
    "initiation_mode",
    "is_collect",
    "geo_state",
    "device_id",
    "bin",
    "cvv_result",
    "avs_result",
)


@dataclass(frozen=True, slots=True)
class HistoricalView:
    """A truth-free view of one past event, as the network would have seen it.

    This is what `prior()` returns instead of a raw Event. It carries the
    observable outcome — that a past attempt was declined is a network fact — but
    it has NO `label` and NO `family` attribute at all, so a feature cannot read
    ground truth from history even by mistake. The earlier index handed back raw
    Events whose `.label` was readable; the guarantee that features see no truth
    was therefore only a convention, and an adversarial test read a prior fraud
    label straight through it. Removing the attribute makes the leak impossible
    to write rather than merely discouraged.
    """

    ts: datetime
    available_at: datetime
    was_declined: bool
    amount_inr: float
    payload: dict

    def get(self, key: str, default=None):
        return self.payload.get(key, default)


class VisibilityIndex:
    def __init__(self, log, surface: Surface):
        from bisect import bisect_left

        self._bisect_left = bisect_left
        # surface filtering, once
        from chakra.schema.events import _VISIBILITY

        allowed = _VISIBILITY[surface]
        events = [e for e in log.sorted_by_time() if e.surface in allowed]

        # (rail, field, value, kind) -> (sorted ts list, HistoricalView list)
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
            # Build the sanitised view ONCE per event, carrying only
            # request-time fields plus the observable outcome — never label or
            # family.
            view = HistoricalView(
                ts=e.ts,
                available_at=e.available_at,
                was_declined=e.event_type is EventType.TXN_DECLINED,
                amount_inr=float(e.payload.get("amount_inr", 0.0)),
                payload={k: e.payload.get(k) for k in _REQUEST_TIME_FIELDS if k in e.payload},
            )
            for field_name in _KEY_FIELDS:
                val = e.payload.get(field_name)
                if val is None:
                    continue
                key = (e.rail, field_name, val, kind)
                ts_list, view_list = self._groups.setdefault(key, ([], []))
                ts_list.append(e.ts)
                view_list.append(view)

    def prior_by_value(
        self, rail, field_name: str, value, kind: str, as_of: datetime, window: timedelta | None
    ) -> list["HistoricalView"]:
        """Views whose `field_name` equals an EXPLICIT value.

        Needed for cross-key questions. "What did this handle receive before it
        sent?" asks for events whose payee_vpa equals the decision's *payer* vpa,
        which the same-field lookup cannot express — it would silently answer a
        different question than the feature's name claims.
        """
        if value is None:
            return []
        entry = self._groups.get((rail, field_name, value, kind))
        if entry is None:
            return []
        ts_list, view_list = entry
        lo_ix = 0
        if window is not None:
            lo_ix = self._bisect_left(ts_list, as_of - window)
        hi_ix = self._bisect_left(ts_list, as_of)
        return [v for v in view_list[lo_ix:hi_ix] if v.available_at < as_of]

    def prior(
        self, dec, field_name: str, kind: str, as_of: datetime, window: timedelta | None
    ) -> list["HistoricalView"]:
        """Truth-free views sharing an observable key with `dec`, on the same
        rail, within `window`, and available strictly before `as_of`."""
        val = dec.payload.get(field_name)
        if val is None:
            return []
        entry = self._groups.get((dec.rail, field_name, val, kind))
        if entry is None:
            return []
        ts_list, view_list = entry
        lo_ix = 0
        if window is not None:
            lo_ix = self._bisect_left(ts_list, as_of - window)
        hi_ix = self._bisect_left(ts_list, as_of)
        # available_at is usually ts but may be later; enforce it explicitly.
        return [v for v in view_list[lo_ix:hi_ix] if v.available_at < as_of]


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


@dataclass(frozen=True, slots=True)
class DecisionView:
    """An immutable, sanitised view of the transaction being decided.

    Feature functions used to receive the whole Event, which carries `label` and
    `family`. Nothing read them, but nothing prevented it either — a single
    `dec.label` in a feature would have produced a perfect detector and a silent,
    unfalsifiable result. Passing a view with no truth fields at all makes that
    class of mistake impossible to write rather than merely discouraged.
    """

    event_id: str
    rail: object
    ts: datetime
    payload: dict

    @classmethod
    def of(cls, event: Event) -> "DecisionView":
        return cls(
            event_id=event.event_id,
            rail=event.rail,
            ts=event.ts,
            payload={k: event.payload.get(k) for k in _REQUEST_TIME_FIELDS if k in event.payload},
        )


def build_matrix(
    log,
    surface: Surface,
    rail=None,
    only_episodes: set | None = None,
    rows_from: datetime | None = None,
):
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

    from chakra.schema.events import _VISIBILITY as _VISIBLE_TO

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
        # `rows_from` makes the warm-up period HISTORY ONLY: its events populate
        # the index but produce no rows.
        #
        # Without it, evaluation begins on a blank history, so early rows see a
        # payee nobody has paid yet and novelty starts near 1.0 and decays. World
        # length is derived from the prevalence target, so the decay curve — and
        # every feature built on it — moved whenever prevalence moved. An audit
        # measured detector AUC climbing 0.899 -> 0.985 with the attacks held
        # identical and only the world lengthened. Starting evaluation on an
        # already-populated history puts novelty at its steady-state rate from
        # the first scored row.
        if rows_from is not None and dec.ts < rows_from:
            continue
        # The decision is made when the transaction is initiated. Every index
        # lookup enforces available_at < as_of, so the decision event itself and
        # its own later outcome are both excluded.
        as_of = dec.ts
        # A decision row must itself be visible to the model's surface and
        # available at the instant it is scored. Without this, a PSP-only
        # request, or one whose availability lies in the future, still became a
        # network row and exposed its own amount.
        if dec.surface not in _VISIBLE_TO[surface] or dec.available_at > as_of:
            continue
        view = DecisionView.of(dec)
        row: dict[str, float] = {}
        for spec in specs:
            ctx = Ctx(index=index, as_of=as_of, window=spec.window)
            row[spec.name] = float(spec.fn(ctx, as_of, view))
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
    declines = sum(1 for v in outs if v.was_declined)
    return declines / len(outs)


@feature("decline_ratio_device_1h", Surface.NETWORK, window=timedelta(hours=1))
def decline_ratio_device_1h(ctx, as_of, dec):
    outs = _outcomes_by_key(ctx, dec, "device_id")
    if not outs:
        return 0.0
    declines = sum(1 for v in outs if v.was_declined)
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


# ---------------------------------------------------------------------------
# UPI / authorised-push features.
#
# These exist because F5 defeats everything above. The payer's own VPA, device
# and PIN are genuine, so instrument novelty, device velocity and decline ratio
# are all silent. What remains observable is the payer's relationship to the
# PAYEE, and the shape of who else pays that payee.
# ---------------------------------------------------------------------------

@feature("payee_vpa_is_new_to_payer", Surface.NETWORK)
def payee_vpa_is_new_to_payer(ctx, as_of, dec):
    """1.0 when this payer has never paid this payee VPA before.

    The single most direct signal for authorised-push fraud: the credentials are
    correct, the amount may be ordinary, but the destination has no history with
    this payer. It is deliberately not decisive on its own — genuine first
    payments to a new merchant or contact happen constantly, which is exactly
    why the background models a circle of known payees rather than routing
    everything to random parties.
    """
    payee = dec.payload.get("payee_vpa")
    if payee is None:
        return 0.0
    seen = {v.payload.get("payee_vpa") for v in _by_key(ctx, dec, "payer_vpa")}
    return 0.0 if payee in seen else 1.0


@feature("payee_vpa_fan_in_24h", Surface.NETWORK, window=timedelta(hours=24))
def payee_vpa_fan_in_24h(ctx, as_of, dec):
    """Distinct payers sending to this payee VPA in a day.

    The mule signature, and the attacker's central trade-off: one handle
    collecting from many unrelated victims is loud, and suppressing it means
    rotating handles, which costs money per handle. A busy genuine merchant also
    has high fan-in, so this is informative rather than decisive — which is what
    makes it worth learning instead of hard-coding.
    """
    priors = _by_key(ctx, dec, "payee_vpa")
    payers = {v.payload.get("payer_vpa") for v in priors}
    payers.add(dec.payload.get("payer_vpa"))
    payers.discard(None)
    return float(len(payers))


@feature("payee_vpa_age_attempts", Surface.NETWORK)
def payee_vpa_age_attempts(ctx, as_of, dec):
    """How many attempts this payee VPA has ever received. A handle standing up
    to receive its first payments looks different from an established one."""
    return float(len(_by_key(ctx, dec, "payee_vpa")))


@feature("is_collect_flag", Surface.NETWORK)
def is_collect_flag(ctx, as_of, dec):
    """Whether this is a pull rather than a push.

    Genuine merchant collect exists, so this cannot condemn a transaction by
    itself. It matters because collect is the mechanism behind the direction
    inversion that defines the family: the victim believes they are receiving.
    """
    return 1.0 if dec.payload.get("is_collect") else 0.0


@feature("amount_vs_payer_median", Surface.NETWORK)
def amount_vs_payer_median(ctx, as_of, dec):
    """Amount relative to this payer's own typical payment.

    Neutral 1.0 when the payer has no history, so a new customer is not
    condemned by absence of evidence. This is the feature the attacker's
    amount_ratio knob trades against: take more per victim and stand out here,
    or blend in and earn less.
    """
    amounts = sorted(
        float(v.payload.get("amount_inr") or 0.0) for v in _by_key(ctx, dec, "payer_vpa")
    )
    if not amounts:
        return 1.0
    median = amounts[len(amounts) // 2]
    if median <= 0:
        return 1.0
    return float(dec.payload.get("amount_inr", 0.0)) / median


@feature("payer_vpa_velocity_24h", Surface.NETWORK, window=timedelta(hours=24))
def payer_vpa_velocity_24h(ctx, as_of, dec):
    return float(len(_by_key(ctx, dec, "payer_vpa")))


@feature("payer_vpa_fan_out_24h", Surface.NETWORK, window=timedelta(hours=24))
def payer_vpa_fan_out_24h(ctx, as_of, dec):
    """Distinct payees this handle has sent to in a day.

    The other half of the mule signature. Fan-in identifies a collector; fan-out
    identifies the same handle redistributing. A busy individual has neither.
    """
    priors = _by_key(ctx, dec, "payer_vpa")
    payees = {v.payload.get("payee_vpa") for v in priors}
    payees.add(dec.payload.get("payee_vpa"))
    payees.discard(None)
    return float(len(payees))


@feature("payer_vpa_received_before_sending", Surface.NETWORK, window=timedelta(hours=24))
def payer_vpa_received_before_sending(ctx, as_of, dec):
    """How much this handle RECEIVED in the last day before sending now.

    Pass-through is the defining mule behaviour: money arrives and leaves. A
    genuine payer spends from a balance built over time; a mule sends what it
    just received. Deliberately a raw count rather than a ratio, so the model
    learns the relationship rather than being handed a hand-tuned rule.

    Note the cross-key lookup: this asks for payments whose PAYEE was the handle
    now paying. The same-field helper would have counted payments to the current
    payee instead — a different question wearing this one's name.
    """
    return float(
        len(
            ctx.index.prior_by_value(
                dec.rail,
                "payee_vpa",
                dec.payload.get("payer_vpa"),
                "attempt",
                ctx.as_of,
                ctx.window,
            )
        )
    )
