"""Legit background — genuine traffic the attacks hide inside.

Every event here is labelled LEGIT. The background emits raw transaction and
authentication events for genuine consumers paying genuine merchants, shaped by
Lane C aggregates. It contains no fraud by construction; attacks are injected
separately at a controlled prevalence.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate import calibration as C
from chakra.generate.rng import Rng
from chakra.schema.entities import InstrumentKind, Population
from chakra.schema.events import (
    Event,
    EventType,
    EventLog,
    Family,
    Label,
    Rail,
    Surface,
)


def generate_background(
    rng: Rng,
    pop: Population,
    start: datetime,
    days: float,
) -> EventLog:
    """Emit genuine transactions for the whole population over `days`."""
    log = EventLog()
    consumers = pop.consumers()
    merchants = pop.merchants()
    if not merchants:
        raise ValueError("population has no merchants to pay")

    horizon = start + timedelta(days=days)

    for cons in consumers:
        vpas = [i for i in pop.instruments_of(cons.party_id) if i.kind is InstrumentKind.VPA]
        cards = [i for i in pop.instruments_of(cons.party_id) if i.kind is InstrumentKind.CARD]
        if not vpas:
            continue

        # number of transactions across the window ~ Poisson(rate * days)
        n_txn = rng.poisson(C.CONSUMER_DAILY_TXN_MEAN * days)
        # a genuine consumer pays a small, stable set of merchants
        favourites = _favourite_merchants(rng, merchants, k=rng.integers(3, 9))

        for _ in range(n_txn):
            when = start + timedelta(seconds=rng.uniform(0, days * 86400))
            if when >= horizon:
                continue
            rail = rng.weighted_key(C.RAIL_MIX)
            if rail == "card" and cards:
                _emit_card_txn(log, rng, cons, cards[0], favourites, when)
            else:
                _emit_upi_txn(log, rng, cons, vpas[0], favourites, when)

    return log


def _favourite_merchants(rng: Rng, merchants: list, k: int) -> list:
    k = min(k, len(merchants))
    idx = set()
    while len(idx) < k:
        idx.add(rng.integers(0, len(merchants)))
    return [merchants[i] for i in idx]


def _approved(rng: Rng) -> bool:
    return rng.uniform(0, 1) < C.BASELINE_APPROVAL_RATE


def _emit_upi_txn(log, rng, consumer, vpa, merchants, when):
    merch = rng.choice(merchants)
    amount = rng.amount_from_bands(C.UPI_AMOUNT_BANDS)
    init = Event(
        event_id=rng.uid("ev"),
        event_type=EventType.TXN_INITIATED,
        rail=Rail.UPI,
        ts=when,
        actor_id=consumer.party_id,
        surface=Surface.NETWORK,
        available_at=when,
        episode_id=None,
        label=Label.LEGIT,
        family=None,
        payload={
            "instrument_id": vpa.instrument_id,
            "counterparty_id": merch.party_id,
            "amount_inr": amount,
            "mcc": rng.weighted_key(C.MERCHANT_CATEGORIES),
            "initiation_mode": "p2m",
            "geo_state": consumer.home_state,
        },
    )
    log.append(init)
    # genuine PIN authorisation (psp_app surface — not visible to network model).
    # Sample the offset ONCE: ts and available_at must be drawn from the same
    # value, or available_at can land before ts and the invariant (rightly) fires.
    pin_ts = when + timedelta(seconds=rng.uniform(2, 15))
    log.append(
        Event(
            event_id=rng.uid("ev"),
            event_type=EventType.PIN_ENTERED,
            rail=Rail.UPI,
            ts=pin_ts,
            actor_id=consumer.party_id,
            surface=Surface.PSP_APP,
            available_at=pin_ts,
            episode_id=None,
            label=Label.LEGIT,
            payload={"factor": "upi_pin", "outcome": "success", "linked_txn_id": init.event_id},
        )
    )
    _emit_outcome(log, rng, init, consumer, Rail.UPI, when)


def _emit_card_txn(log, rng, consumer, card, merchants, when):
    merch = rng.choice(merchants)
    amount = rng.amount_from_bands(C.CARD_AMOUNT_BANDS)
    init = Event(
        event_id=rng.uid("ev"),
        event_type=EventType.TXN_INITIATED,
        rail=Rail.CARD,
        ts=when,
        actor_id=consumer.party_id,
        surface=Surface.NETWORK,
        available_at=when,
        episode_id=None,
        label=Label.LEGIT,
        family=None,
        payload={
            "instrument_id": card.instrument_id,
            "counterparty_id": merch.party_id,
            "amount_inr": amount,
            "mcc": rng.weighted_key(C.MERCHANT_CATEGORIES),
            "initiation_mode": "ecom",
            "geo_state": consumer.home_state,
            "cvv_result": "match",
            "avs_result": "match",
        },
    )
    log.append(init)
    _emit_outcome(log, rng, init, consumer, Rail.CARD, when)


def _emit_outcome(log, rng, init, consumer, rail, when):
    approved = _approved(rng)
    et = EventType.TXN_AUTHORISED if approved else EventType.TXN_DECLINED
    outcome_ts = when + timedelta(seconds=rng.uniform(0.2, 2.0))
    log.append(
        Event(
            event_id=rng.uid("ev"),
            event_type=et,
            rail=rail,
            ts=outcome_ts,
            actor_id=consumer.party_id,
            surface=Surface.NETWORK,
            available_at=outcome_ts,
            episode_id=None,
            label=Label.LEGIT,
            payload={
                "instrument_id": init.payload["instrument_id"],
                "counterparty_id": init.payload["counterparty_id"],
                "amount_inr": init.payload["amount_inr"],
                "decline_reason": None if approved else "issuer_decline",
            },
        )
    )
