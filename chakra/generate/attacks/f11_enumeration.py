"""F11 — Enumeration / card testing.

Mechanism: an attacker walks a batch of card numbers against a weakly-limited
endpoint, validating each with a tiny or zero-value authorisation. Live cards
are confirmed by which probes get approved. The tell is behavioural — many
distinct instruments from one actor, high velocity, high decline ratio,
micro-amounts — and the whole point of Chakra is that the attack produces those
tells by *acting*, never by writing a feature.

Parameters (the fraudster's knobs, mutated within pre-registered bounds):
  cards_per_burst   how many card numbers tested in one burst
  inter_txn_seconds mean gap between probes (lower = faster, more detectable)
  micro_amount_inr  probe amount (small to stay unnoticed)
  decline_tolerance how many declines before abandoning a burst
  spread_seconds    optional jitter to spread a burst over time (evasion knob)
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.rng import Rng
from chakra.schema.entities import Device, Population
from chakra.schema.events import (
    Event,
    EventType,
    Family,
    Label,
    Rail,
    Surface,
)

# Enumerated instruments are OBVIOUSLY SYNTHETIC tokens, never realistic or
# potentially routable card numbers. A fraud simulator has no business minting
# strings that look like live PANs — they can leak into logs, screenshots and
# demo videos. The detector only ever sees derived behaviour, so the id's shape
# is irrelevant to the science and the safe choice costs nothing.
_SYNTH_ISSUER_TAGS = ["SYNTHA", "SYNTHB", "SYNTHC", "SYNTHD", "SYNTHE", "SYNTHF"]


class F11Enumeration(AttackFamily):
    code = Family.F11
    name = "Enumeration / card testing"

    @property
    def param_specs(self) -> list[ParamSpec]:
        return [
            ParamSpec("cards_per_burst", 5, 60, integer=True),
            ParamSpec("inter_txn_seconds", 0.5, 45.0),
            # Probe amount. The upper bound reaches into the genuine UPI/card
            # amount range on purpose: capped at ₹40 the attacker could never
            # make a probe look like a real purchase, so amount alone separated
            # the classes and no amount of evolution could help. Larger probes
            # cost the tester more per validation — the trade should be the
            # attacker's to make, not one the bounds make for them.
            ParamSpec("micro_amount_inr", 1.0, 900.0),
            ParamSpec("decline_tolerance", 3, 40, integer=True),
            ParamSpec("spread_seconds", 0.0, 600.0),
            # device rotation: how many probes before switching device. A real
            # tester can burn devices to break device-keyed velocity, but each
            # rotation costs money — which is exactly the trade the loop should
            # have to make rather than getting evasion for free.
            ParamSpec("probes_per_device", 1, 60, integer=True),
            # endpoint rotation: how many probes before moving to another
            # merchant. Added after the first honest multi-seed run showed zero
            # evasion across every seed: with all probes pinned to one endpoint,
            # the acquirer-side distinct-instrument count was inescapable and the
            # attacker had no move that could work. That is an under-specified
            # adversary, not a strong detector. Real card testers spray across
            # merchants, so the action space must include it.
            ParamSpec("probes_per_endpoint", 1, 60, integer=True),
        ]

    def emit(self, rng, pop, params, start, n_episodes):
        params = AttackParams(params).clamped(self.param_specs)
        events: list[Event] = []
        for _ in range(n_episodes):
            events.extend(self._one_burst(rng, pop, params, start))
        return events

    def _one_burst(self, rng: Rng, pop: Population, p: AttackParams, start: datetime):
        events: list[Event] = []
        # The tester's internal handle. Deliberately NOT used as a detection key
        # anywhere — features group on observable identities (device, endpoint,
        # instrument). A real network has no "this is fraudster #7" column.
        actor_id = rng.uid("f11actor")

        def new_device():
            return pop.add_device(
                Device(
                    device_id=rng.uid("f11dev"),
                    first_seen_at=start,
                    os="android",
                    is_emulator=True,
                    sim_id=rng.uid("f11sim"),
                    imei_hash=rng.uid("f11imei"),
                )
            )

        device = new_device()
        # merchant endpoints that accept card-only input (donation/subscription
        # style). Reuse population merchants so targets look ordinary.
        merchants = pop.merchants()

        def new_endpoint():
            return rng.choice(merchants).party_id if merchants else rng.uid("endpoint")

        target_id = new_endpoint()

        episode_id = rng.uid("f11ep")
        n_cards = int(p["cards_per_burst"])
        gap = float(p["inter_txn_seconds"])
        spread = float(p["spread_seconds"])
        amount = round(float(p["micro_amount_inr"]), 2)
        tolerance = int(p["decline_tolerance"])

        probes_per_device = int(p["probes_per_device"])
        probes_per_endpoint = int(p["probes_per_endpoint"])
        when = start
        declines = 0
        for probe_ix in range(n_cards):
            if probe_ix > 0 and probe_ix % probes_per_device == 0:
                device = new_device()  # burn the device, break device velocity
            if probe_ix > 0 and probe_ix % probes_per_endpoint == 0:
                target_id = new_endpoint()  # spray across merchants
            # deliberately non-routable, self-labelling synthetic identifier
            pan = f"SYNTH-CARD-{rng.choice(_SYNTH_ISSUER_TAGS)}-{rng.integers(100000, 999999):06d}"
            # advance time: base gap plus optional spread jitter (evasion)
            when = when + timedelta(seconds=max(0.05, gap + rng.uniform(0, spread / n_cards)))

            init = Event(
                event_id=rng.uid("ev"),
                event_type=EventType.TXN_INITIATED,
                rail=Rail.CARD,
                ts=when,
                actor_id=actor_id,
                surface=Surface.NETWORK,
                available_at=when,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F11,
                payload={
                    "instrument_id": pan,
                    "counterparty_id": target_id,
                    "amount_inr": amount,
                    "mcc": "shopping",
                    "initiation_mode": "ecom",
                    "geo_state": "OTHER",
                    "device_id": device.device_id,
                    # a tester guesses CVV/expiry, so most probes fail these
                    "cvv_result": "match" if rng.uniform(0, 1) < 0.12 else "mismatch",
                    "avs_result": "mismatch",
                },
            )
            events.append(init)

            # a card is "live" on the ~12% where the guessed CVV matched
            live = init.payload["cvv_result"] == "match"
            outcome_et = EventType.TXN_AUTHORISED if live else EventType.TXN_DECLINED
            outcome_ts = when + timedelta(seconds=rng.uniform(0.1, 1.0))
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=outcome_et,
                    rail=Rail.CARD,
                    ts=outcome_ts,
                    actor_id=actor_id,
                    surface=Surface.NETWORK,
                    available_at=outcome_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F11,
                    payload={
                        "instrument_id": pan,
                        "counterparty_id": target_id,
                        "amount_inr": amount,
                        "device_id": device.device_id,
                        "decline_reason": None if live else "do_not_honor",
                    },
                )
            )
            if not live:
                declines += 1
                if declines >= tolerance:
                    break  # tester abandons this burst

        return events
