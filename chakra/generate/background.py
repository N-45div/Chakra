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
    only_rail: str | None = None,
) -> EventLog:
    """Emit genuine transactions for the whole population over `days`.

    `only_rail` restricts emission to a single rail. Features are already
    rail-scoped, so events on other rails can never enter a scoped matrix —
    generating them is pure waste, and the waste is large: hitting card-rail
    prevalence means ~8x more traffic, of which ~88% would be UPI rows nothing
    ever reads. Restricting emission is a speedup, not a semantic change, and
    the per-consumer rate is scaled so the retained rail keeps its own volume.
    """
    log = EventLog()
    consumers = pop.consumers()
    merchants = pop.merchants()
    if not merchants:
        raise ValueError("population has no merchants to pay")

    horizon = start + timedelta(days=days)

    for cons in consumers:
        # A small circle of people this consumer actually pays. Genuine P2P is
        # repeated payments to known contacts, which is exactly the baseline a
        # brand-new payee has to stand out against.
        peer_pool = [
            p for p in _favourite_merchants(rng, consumers, k=rng.integers(2, 6))
            if p.party_id != cons.party_id
        ]
        vpas = [i for i in pop.instruments_of(cons.party_id) if i.kind is InstrumentKind.VPA]
        cards = [i for i in pop.instruments_of(cons.party_id) if i.kind is InstrumentKind.CARD]
        device = pop.device_of(cons.party_id)
        if not vpas:
            continue

        rate = C.CONSUMER_DAILY_TXN_MEAN
        if only_rail is not None:
            rate *= C.rail_share_of_legit(only_rail)
        n_txn = rng.poisson(rate * days)
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
            rail = only_rail or _choose_rail(rng, has_card=bool(cards))
            if rail == "card" and not cards:
                continue  # cannot transact on a rail this consumer has no instrument for
            peers = peer_pool
            if rail == "card":
                card = second_card if (second_card and when >= second_card_from) else cards[0]
                _emit_card_txn(log, rng, cons, card, favourites, when, device)
            else:
                vpa = second_vpa if (second_vpa and when >= second_vpa_from) else vpas[0]
                _emit_upi_txn(log, rng, cons, vpa, favourites, when, device, peers=peers, pop=pop)

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


def _upi_mode(rng: Rng) -> tuple[str, bool]:
    """Pick a genuine UPI initiation mode.

    Note what is absent: person-to-person COLLECT. NPCI discontinued P2P collect
    from 1 October 2025 precisely because it was the vector for the classic
    "approve to receive money" scam. Genuine collect therefore exists only in the
    merchant direction, which is also what makes merchant-collect impersonation
    the surviving deception rather than plain P2P collect.
    """
    mode = rng.weighted_key(
        {
            "p2m_push": 0.62,   # scan a QR / intent link and pay a merchant
            "p2p_push": 0.28,   # send money to a person
            "p2m_collect": 0.10,  # merchant raises a request, payer approves
        }
    )
    return mode, mode.endswith("collect")


def _payee_vpa_of(pop, party_id: str) -> str | None:
    """The VPA money actually lands in. UPI addresses a handle, not a party, and
    F5 turns entirely on the payer's relationship to a specific payee VPA."""
    from chakra.schema.entities import InstrumentKind

    for i in pop.instruments.values():
        if i.owner_party_id == party_id and i.kind is InstrumentKind.VPA:
            return i.instrument_id
    return None


def _emit_upi_txn(log, rng, consumer, vpa, merchants, when, device, peers=None, pop=None):
    amount = rng.amount_from_bands(C.UPI_AMOUNT_BANDS)
    device_id = device.device_id if device else None
    mode, is_collect = _upi_mode(rng)

    # A person-to-person payment must actually pay a PERSON. Routing p2p_push to
    # merchants made the mode a label with no behavioural content, and it would
    # have made F5 incoherent: the family's signal is a payment to a brand-new
    # payee, which only means anything if genuine P2P payees are people the payer
    # already knows.
    if mode == "p2p_push" and peers:
        merch = rng.choice(peers)
    else:
        merch = rng.choice(merchants)
    payee_vpa = _payee_vpa_of(pop, merch.party_id) if pop else None

    payload = {
        "instrument_id": vpa.instrument_id,
        "payer_vpa": vpa.instrument_id,
        "payee_vpa": payee_vpa,
        "counterparty_id": merch.party_id,
        "amount_inr": amount,
        "mcc": rng.weighted_key(C.MERCHANT_CATEGORIES),
        "initiation_mode": mode,
        "is_collect": is_collect,
        "geo_state": consumer.home_state,
        "device_id": device_id,
    }

    # A collect is ORIGINATED BY THE PAYEE. Modelling it as a payer initiation
    # with a flag would erase the one structural fact F5 depends on: someone
    # else asked for this money, and the victim only approved it.
    if is_collect:
        init = Event(
            event_id=rng.uid("ev"),
            event_type=EventType.COLLECT_REQUESTED,
            rail=Rail.UPI,
            ts=when,
            actor_id=merch.party_id,  # the PAYEE raises it
            surface=Surface.PSP_APP,
            available_at=when,
            label=Label.LEGIT,
            payload=payload,
        )
    else:
        init = Event(
            event_id=rng.uid("ev"),
            event_type=EventType.TXN_INITIATED,
            rail=Rail.UPI,
            ts=when,
            actor_id=consumer.party_id,
            surface=Surface.PSP_APP,
            available_at=when,
            label=Label.LEGIT,
            payload=payload,
        )
    log.append(init)

    # PIN entry: after initiation, before the network is asked anything.
    # psp_app surface — the network never sees the PIN event itself.
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

    # Only now does the network see an authorisation request. This is the row
    # the detector scores.
    auth_ts = pin_ts + timedelta(seconds=rng.uniform(0.1, 1.5))
    auth = _emit_auth_request(
        log, rng, init, consumer, Rail.UPI, auth_ts, device_id, extra={"is_collect": is_collect}
    )
    _emit_outcome(log, rng, auth, consumer, Rail.UPI, after=auth_ts, device_id=device_id)


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
        # Initiation happens at the merchant/app, before anything reaches the
        # network. The network's own view begins at the authorisation request.
        surface=Surface.PSP_APP,
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
    auth_ts = otp_ts + timedelta(seconds=rng.uniform(0.1, 1.5))
    auth = _emit_auth_request(log, rng, init, consumer, Rail.CARD, auth_ts, device_id)
    _emit_outcome(log, rng, auth, consumer, Rail.CARD, after=auth_ts, device_id=device_id)


def _emit_auth_request(log, rng, init, consumer, rail, when, device_id, extra=None):
    """The network-visible authorisation request — the scored decision point."""
    # Carry EVERY request-time field forward from the initiation.
    #
    # An earlier version enumerated the fields by hand and silently dropped
    # payer_vpa and payee_vpa, so genuine authorisation rows had no VPA fields
    # while F5's did. Every VPA-based feature then separated the classes
    # perfectly — for a purely structural reason that had nothing to do with
    # fraud. Copying the payload and overriding is the version that cannot rot
    # as fields are added.
    payload = dict(init.payload)
    payload["device_id"] = device_id
    payload["linked_txn_id"] = init.event_id
    if extra:
        payload.update(extra)

    auth = Event(
        event_id=rng.uid("ev"),
        event_type=EventType.TXN_AUTH_REQUESTED,
        rail=rail,
        ts=when,
        actor_id=consumer.party_id,
        surface=Surface.NETWORK,
        available_at=when,
        episode_id=init.episode_id,
        label=init.label,
        family=init.family,
        payload=payload,
    )
    log.append(auth)
    return auth


def _emit_outcome(log, rng, auth, consumer, rail, after, device_id):
    """Authorisation outcome, strictly after the authorisation request.

    `linked_txn_id` points at the AUTH REQUEST that produced this outcome. It was
    missing entirely, which meant the ordering test that checked
    "outcome follows its auth request" matched nothing and passed vacuously on
    every run — a green test asserting nothing at all.
    """
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
            episode_id=auth.episode_id,
            label=auth.label,
            family=auth.family,
            payload={
                "instrument_id": auth.payload["instrument_id"],
                "counterparty_id": auth.payload["counterparty_id"],
                "amount_inr": auth.payload["amount_inr"],
                "device_id": device_id,
                "linked_txn_id": auth.event_id,
                "linked_initiation_id": auth.payload.get("linked_txn_id"),
                "decline_reason": None if approved else "issuer_decline",
            },
        )
    )
