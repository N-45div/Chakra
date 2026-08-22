"""F8 — Credit nurture and bust-out.

The slow-temporal family, and the mirror image of F11.

F11 is many instruments, no history: every probe presents a card nobody has
seen, so the tell is loud on day zero. F8 is ONE instrument, all history: the
attacker holds a victim's genuine card credentials — phished, bought from a
data breach, or collusively rented from the cardholder — and spends weeks
behaving like the customer before extracting everything in a burst.

The nurture phase is what makes this family hard. Each transaction is small,
ordinary, approved by the genuine OTP, on the victim's own device, at
merchants the victim plausibly uses. A limit increase requested after three
months of clean spend is indistinguishable from good customership. The burst
then moves fast and converts to cash-equivalents — jewellery, electronics —
because the attacker's clock started the moment they first feared detection.

The signal shape it tests is ESCALATION RELATIVE TO THE ACCOUNT'S OWN HISTORY:
amount versus the instrument's established mean, amount versus the payer's
median, velocity on an instrument that had none. Nothing about any single
nurture row is wrong; only the trajectory betrays the episode.

Time compression, stated openly: a real nurture cycle spans months. Within one
simulated world the same shape is rendered at hours-to-days scale — the signal
is relative pacing and escalation against per-instrument history, both of which
are preserved under uniform time scaling. The bounds below are simulation
bounds, not claims about how long real bust-outs take.

The attacker's levers, and why every one of them is self-priced:

  nurture_txn_count / interval   more, slower nurture builds deeper history and
                                 a higher baseline to escalate FROM — but each
                                 row also feeds amount_vs_instrument_mean, so
                                 the baseline the attacker builds is the one
                                 their burst is measured against.
  escalation_ratio               how gently the amounts climb. Gentle keeps the
                                 mean lagging behind; greedy closes the gap.
  burst_amount_multiple          extraction size versus the card's typical
                                 spend. This is THE trade: yield against the
                                 loudest remaining feature.
  inter_burst_seconds            dumping in one authorisation is cleaner but
                                 risks a single decline killing the episode;
                                 spreading it out re-triggers instrument
                                 velocity on a card whose history is quiet.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.rng import Rng
from chakra.schema.entities import InstrumentKind, Population
from chakra.schema.events import (
    Event,
    EventType,
    Family,
    Label,
    Rail,
    Surface,
)

# Cash-converting merchant categories. Jewellery and consumer electronics are
# the classic bust-out destinations: high resale liquidity, no service
# entitlement tied to the purchaser's identity.
_BURST_CATEGORIES = ("jewellery", "electronics")
_NURTURE_CATEGORIES = {
    "grocery": 0.30,
    "fuel": 0.20,
    "utilities": 0.18,
    "food": 0.22,
    "transport": 0.10,
}


class F8BustOut(AttackFamily):
    code = Family.F8
    rail = Rail.CARD
    name = "Credit nurture and bust-out"

    @property
    def param_specs(self) -> list[ParamSpec]:
        return [
            ParamSpec("nurture_txn_count", 2, 24, integer=True),
            ParamSpec("nurture_amount_inr", 120.0, 4000.0),
            ParamSpec("nurture_interval_seconds", 900.0, 7200.0),
            # Per-transaction growth factor during nurture, applied as
            # amount_i * ratio**i. At 1.0 the attacker spends flat and builds a
            # stable baseline; at 3.0 the mean cannot keep up with the climb.
            ParamSpec("escalation_ratio", 1.0, 1.35),
            ParamSpec("burst_count", 1, 10, integer=True),
            ParamSpec("burst_amount_multiple", 3.0, 40.0),
            ParamSpec("inter_burst_seconds", 20.0, 1800.0),
        ]

    def infrastructure_cost(self, params, attempts: int) -> float:
        """Zero, deliberately, and that is a modelling claim rather than an
        omission.

        Unlike F11 (burner devices), F5/F6/F10 (mule handles and agent
        identities), nothing is ACQUIRED per attempt here: the compromised card
        is one fixed asset already paid for before the episode begins, and the
        family's knobs trade yield directly against features that read
        escalation — the constraint is built into the detector's view of the
        attack, not into a wallet. Charging an invented per-attempt cost would
        manufacture a gradient the mechanism does not contain, which is the
        exact defect class this project exists to prevent (see FINDINGS F-007).
        """
        return 0.0

    def episode_value_inr(
        self,
        authorised_amounts: list[float],
        authorised_payloads: list[dict] | None = None,
    ) -> float:
        """Extraction value, not turnover.

        The episode's authorised rows split into two kinds with opposite signs
        for the attacker: nurture purchases are money the attacker SPENT to
        build a baseline, burst purchases are money taken out. Summing both
        would credit the attacker with their own investment and bias every
        generation toward more nurturing for free.

        What survives is resale: stolen goods do not retail at face value, so
        the burst's face value is discounted by a conversion factor.
        """
        from chakra.generate import calibration as C

        if not authorised_amounts:
            return 0.0
        if authorised_payloads is None:
            # No payload context: refuse to guess. Valuing everything as gain
            # would overstate the attacker; valuing nothing would erase the
            # family. The loop always supplies payloads, so reaching here means
            # a caller skipped the contract — fail loudly instead.
            raise ValueError(
                "F8 requires payload context to separate nurture spend from "
                "burst extraction; called without payloads"
            )
        burst_total = sum(
            amount
            for amount, payload in zip(authorised_amounts, authorised_payloads)
            if payload.get("phase") == "burst"
        )
        return float(burst_total) * C.CASH_CONVERSION_FACTOR

    def emit(self, rng, pop, params, start, n_episodes):
        params = AttackParams(params).clamped(self.param_specs)
        events: list[Event] = []
        for _ in range(n_episodes):
            events.extend(self._one_episode(rng, pop, params, start))
        return events

    def _victim_card(self, rng: Rng, pop: Population):
        """A genuine consumer's card, taken over.

        Drawn from consumers who actually hold cards, through the SAME entity
        generator as everyone else. No burner device: the fraud runs on the
        victim's own handset, which is precisely why device-based signals are
        useless here and the family has to be caught on escalation.
        """
        consumers = pop.consumers()
        if not consumers:
            return None, None, None
        for _ in range(12):
            victim = rng.choice(consumers)
            cards = [
                i for i in pop.instruments_of(victim.party_id) if i.kind is InstrumentKind.CARD
            ]
            if cards:
                return victim, cards[0], pop.device_of(victim.party_id)
        return None, None, None

    def _one_episode(self, rng: Rng, pop: Population, p: AttackParams, start: datetime):
        events: list[Event] = []
        victim, card, device = self._victim_card(rng, pop)
        if victim is None:
            return events

        episode_id = rng.uid("f8ep")
        device_id = device.device_id if device else None
        n_nurture = int(p["nurture_txn_count"])
        base_amount = float(p["nurture_amount_inr"])
        gap = float(p["nurture_interval_seconds"])
        ratio = float(p["escalation_ratio"])
        n_burst = int(p["burst_count"])
        multiple = float(p["burst_amount_multiple"])
        burst_gap = float(p["inter_burst_seconds"])

        # Anchor the burst to what this card plausibly spends, drawn once, so a
        # greedy multiple stands out against THIS card's band rather than an
        # abstract constant.
        typical = rng.amount_from_bands(
            __import__(
                "chakra.generate.calibration", fromlist=["CARD_AMOUNT_BANDS"]
            ).CARD_AMOUNT_BANDS
        )
        burst_amount = round(max(500.0, typical * multiple), 2)

        def _card_txn(amount: float, category: str, phase: str, when: datetime) -> datetime:
            """One card authorisation on the victim's genuine credentials."""
            payload = {
                "instrument_id": card.instrument_id,
                "counterparty_id": rng.choice(pop.merchants()).party_id,
                "amount_inr": round(max(1.0, amount), 2),
                "mcc": category,
                "initiation_mode": "ecom",
                "geo_state": victim.home_state,
                "device_id": device_id,
                "bin": card.bin,
                "cvv_result": "match",
                "avs_result": "match",
                # Attacker-internal bookkeeping so the family can value its own
                # episode honestly: nurture spend is COST, burst extraction is
                # GAIN. It rides in the payload as protocol-level context; no
                # feature reads it, and the no-feature-injection test holds.
                "phase": phase,
            }
            init = Event(
                event_id=rng.uid("ev"),
                event_type=EventType.TXN_INITIATED,
                rail=Rail.CARD,
                ts=when,
                actor_id=victim.party_id,
                surface=Surface.PSP_APP,
                available_at=when,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F8,
                payload=payload,
            )
            events.append(init)

            # Genuine OTP step at the issuer. The network never sees it — which
            # is the point: on the network surface this row looks like the
            # customer's own spend.
            otp_ts = when + timedelta(seconds=rng.uniform(3, 20))
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.OTP_ENTERED,
                    rail=Rail.CARD,
                    ts=otp_ts,
                    actor_id=victim.party_id,
                    surface=Surface.ISSUER,
                    available_at=otp_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F8,
                    payload={
                        "factor": "sms_otp",
                        "outcome": "success",
                        "linked_txn_id": init.event_id,
                        "device_id": device_id,
                    },
                )
            )

            auth_ts = otp_ts + timedelta(seconds=rng.uniform(0.1, 1.5))
            auth_payload = dict(payload)
            auth_payload["linked_txn_id"] = init.event_id
            auth = Event(
                event_id=rng.uid("ev"),
                event_type=EventType.TXN_AUTH_REQUESTED,
                rail=Rail.CARD,
                ts=auth_ts,
                actor_id=victim.party_id,
                surface=Surface.NETWORK,
                available_at=auth_ts,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F8,
                payload=auth_payload,
            )
            events.append(auth)

            # Approved like genuine spend: correct credentials, correct OTP.
            out_ts = auth_ts + timedelta(seconds=rng.uniform(0.2, 2.0))
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.TXN_AUTHORISED,
                    rail=Rail.CARD,
                    ts=out_ts,
                    actor_id=victim.party_id,
                    surface=Surface.NETWORK,
                    available_at=out_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F8,
                    payload={
                        "instrument_id": card.instrument_id,
                        "counterparty_id": auth.payload["counterparty_id"],
                        "amount_inr": auth.payload["amount_inr"],
                        "device_id": device_id,
                        "linked_txn_id": auth.event_id,
                        "linked_initiation_id": init.event_id,
                        "decline_reason": None,
                    },
                )
            )
            return out_ts

        when = start
        # Nurture: ordinary spend on ordinary categories, climbing gently. The
        # escalation is exponential in the parameter but bounded hard so no
        # bound combination can push a nurture row into burst-scale amounts.
        for ix in range(n_nurture):
            amount = min(
                base_amount * (ratio**ix),
                base_amount * 4.0,
            )
            category = rng.weighted_key(_NURTURE_CATEGORIES)
            when = when + timedelta(seconds=max(60.0, gap))
            when = _card_txn(amount, category, "nurture", when)

        # Burst: fast, large, cash-shaped. This is the extraction the whole
        # nurture phase was buying.
        for _ in range(n_burst):
            when = when + timedelta(seconds=max(5.0, burst_gap))
            category = rng.choice(_BURST_CATEGORIES)
            when = _card_txn(burst_amount, category, "burst", when)

        return events
