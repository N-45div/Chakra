"""Legit background — genuine traffic the attacks hide inside.

Every event here is labelled LEGIT. The background emits raw transaction and
authentication events for genuine consumers paying genuine merchants, shaped by
Lane C aggregates. It contains no fraud by construction; attacks are injected
separately at a controlled prevalence.

Causal order is enforced: a transaction is initiated, THEN authenticated, THEN
authorised or declined. Emitting the outcome before the PIN would be causally
impossible and would poison any family whose story depends on authentication
semantics — F5 above all, where the whole deception is that the victim's PIN
authorises a debit they believe is a credit.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate import calibration as C  # noqa: N812
from chakra.generate.rng import Rng
from chakra.schema.entities import InstrumentKind, Population
from chakra.schema.events import (
    Event,
    EventType,
    EventLog,
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
        device = pop.device_of(cons.party_id)
        if not vpas:
            continue

        n_txn = rng.poisson(C.CONSUMER_DAILY_TXN_MEAN * days)
        favourites = _favourite_merchants(rng, merchants, k=rng.integers(3, 9))

        # Genuine instrument churn. Some consumers arrive partway through the
        # window (new customers), and some acquire a second instrument partway
        # through (reissue, added card). Both produce legitimate transactions on
        # an instrument nobody has seen before — which is exactly what stops
        # "unseen instrument" from being a free fraud flag.
        active_from = start
        if rng.uniform(0, 1) < C.LATE_ARRIVAL_RATE:
            active_from = start + timedelta(seconds=rng.uniform(0, days * 86400 * 0.8))

        second_card = None
        second_card_from = horizon
        if cards and rng.uniform(0, 1) < C.INSTRUMENT_CHURN_RATE:
            second_card = _reissued_card(rng, pop, cons, when=start)
            second_card_from = start + timedelta(seconds=rng.uniform(0, days * 86400 * 0.9))

        second_vpa = None
        second_vpa_from = horizon
        if rng.uniform(0, 1) < C.INSTRUMENT_CHURN_RATE:
            second_vpa = _additional_vpa(rng, pop, cons, when=start)
            second_vpa_from = start + timedelta(seconds=rng.uniform(0, days * 86400 * 0.9))

        for _ in range(n_txn):
            when = start + timedelta(seconds=rng.uniform(0, days * 86400))
            if when >= horizon or when < active_from:
                continue
            rail = _choose_rail(rng, has_card=bool(cards))
            if rail == "card":
                card = second_card if (second_card and when >= second_card_from) else cards[0]
                _emit_card_txn(log, rng, cons, card, favourites, when, device)
            else:
                vpa = second_vpa if (second_vpa and when >= second_vpa_from) else vpas[0]
                _emit_upi_txn(log, rng, cons, vpa, favourites, when, device)

    return log


def _reissued_card(rng: Rng, pop: Population, consumer, when):
    from chakra.schema.entities import Instrument

    return pop.add_instrument(
        Instrument(
            instrument_id=rng.uid("card"),
            kind=InstrumentKind.CARD,
            owner_party_id=consumer.party_id,
            issued_at=when,
            bin=rng.choice(["414720", "512345", "601100", "353011", "436742"]),
        )
    )


def _additional_vpa(rng: Rng, pop: Population, consumer, when):
    from chakra.schema.entities import Instrument

    return pop.add_instrument(
        Instrument(
            instrument_id=rng.uid("vpa"),
            kind=InstrumentKind.VPA,
            owner_party_id=consumer.party_id,
            issued_at=when,
            psp=rng.choice(["okhdfc", "okicici", "oksbi", "okaxis", "paytm", "ybl", "ibl"]),
        )
    )


def _choose_rail(rng: Rng, has_card: bool) -> str:
    """Sample from the *implemented* rail mix, restricted to rails this consumer
    can actually use. Renormalising keeps the emitted mix matching the documented
    constant instead of silently collapsing unimplemented rails into UPI."""
    mix = dict(C.RAIL_MIX_IMPLEMENTED)
    if not has_card:
        mix.pop("card", None)
    return rng.weighted_key(mix)


def _favourite_merchants(rng: Rng, merchants: list, k: int) -> list:
    k = min(k, len(merchants))
    idx = set()
    while len(idx) < k:
        idx.add(rng.integers(0, len(merchants)))
    return [merchants[i] for i in idx]


def _approved(rng: Rng) -> bool:
    return rng.uniform(0, 1) < C.BASELINE_APPROVAL_RATE


def _emit_upi_txn(log, rng, consumer, vpa, merchants, when, device):
    merch = rng.choice(merchants)
    amount = rng.amount_from_bands(C.UPI_AMOUNT_BANDS)
    device_id = device.device_id if device else None

    init = Event(
        event_id=rng.uid("ev"),
        event_type=EventType.TXN_INITIATED,
        rail=Rail.UPI,
        ts=when,
        actor_id=consumer.party_id,
        surface=Surface.NETWORK,
        available_at=when,
        label=Label.LEGIT,
        payload={
            "instrument_id": vpa.instrument_id,
            "counterparty_id": merch.party_id,
            "amount_inr": amount,
            "mcc": rng.weighted_key(C.MERCHANT_CATEGORIES),
            "initiation_mode": "p2m",
            "geo_state": consumer.home_state,
            "device_id": device_id,
        },
    )
    log.append(init)

    # Authentication happens AFTER initiation and BEFORE the outcome.
    # psp_app surface: the network cannot see the PIN entry itself.
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
            label=Label.LEGIT,
            payload={
                "factor": "upi_pin",
                "outcome": "success",
                "linked_txn_id": init.event_id,
                "device_id": device_id,
            },
        )
    )

    _emit_outcome(log, rng, init, consumer, Rail.UPI, after=pin_ts, device_id=device_id)


def _emit_card_txn(log, rng, consumer, card, merchants, when, device):
    merch = rng.choice(merchants)
    amount = rng.amount_from_bands(C.CARD_AMOUNT_BANDS)
    device_id = device.device_id if device else None

    init = Event(
        event_id=rng.uid("ev"),
        event_type=EventType.TXN_INITIATED,
        rail=Rail.CARD,
        ts=when,
        actor_id=consumer.party_id,
        surface=Surface.NETWORK,
        available_at=when,
        label=Label.LEGIT,
        payload={
            "instrument_id": card.instrument_id,
            "counterparty_id": merch.party_id,
            "amount_inr": amount,
            "mcc": rng.weighted_key(C.MERCHANT_CATEGORIES),
            "initiation_mode": "ecom",
            "geo_state": consumer.home_state,
            "device_id": device_id,
            "bin": card.bin,
            "cvv_result": "match",
            "avs_result": "match",
        },
    )
    log.append(init)
    # card ecom: 3DS/OTP step where present, then the outcome
    otp_ts = when + timedelta(seconds=rng.uniform(3, 20))
    log.append(
        Event(
            event_id=rng.uid("ev"),
            event_type=EventType.OTP_ENTERED,
            rail=Rail.CARD,
            ts=otp_ts,
            actor_id=consumer.party_id,
            surface=Surface.ISSUER,
            available_at=otp_ts,
            label=Label.LEGIT,
            payload={
                "factor": "sms_otp",
                "outcome": "success",
                "linked_txn_id": init.event_id,
                "device_id": device_id,
            },
        )
    )
    _emit_outcome(log, rng, init, consumer, Rail.CARD, after=otp_ts, device_id=device_id)


def _emit_outcome(log, rng, init, consumer, rail, after, device_id):
    """Authorisation outcome, strictly after authentication."""
    approved = _approved(rng)
    et = EventType.TXN_AUTHORISED if approved else EventType.TXN_DECLINED
    outcome_ts = after + timedelta(seconds=rng.uniform(0.2, 2.0))
    log.append(
        Event(
            event_id=rng.uid("ev"),
            event_type=et,
            rail=rail,
            ts=outcome_ts,
            actor_id=consumer.party_id,
            surface=Surface.NETWORK,
            available_at=outcome_ts,
            label=Label.LEGIT,
            payload={
                "instrument_id": init.payload["instrument_id"],
                "counterparty_id": init.payload["counterparty_id"],
                "amount_inr": init.payload["amount_inr"],
                "device_id": device_id,
                "decline_reason": None if approved else "issuer_decline",
            },
        )
    )
