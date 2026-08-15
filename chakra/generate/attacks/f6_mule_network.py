"""F6 — Mule networks and layering.

The receiving end of nearly every other family, and the only one whose signal is
purely a property of the GRAPH rather than of any single transaction.

Every individual hop here is unremarkable. A payment arrives, sits briefly, and
leaves. The amounts are ordinary, the credentials are genuine, the devices are
real. Nothing about one transaction is wrong. What is wrong is the shape: many
unrelated payers converging on one account, and the balance leaving almost as
fast as it arrives, fanning out again across further accounts.

That makes F6 the family that tests whether the detector learned *structure* or
merely learned per-row anomalies — which is why the experiment contract nominates
it as the graph-dependent hold-out.

India context: RBI's own Innovation Hub runs MuleHunter.AI against mule-behaviour
patterns across banks, and roughly 1.33 million mule accounts were frozen in
2025. The regulator is operating this exact class of model, which is the
strongest feasibility argument available for building it.

The attacker's levers, and what each costs:

  fan_in_per_mule     unrelated payers converging on one handle. High is
                      efficient and loud; low needs more mules, and each mule is
                      recruited or bought.
  dwell_seconds       how long funds rest before moving on. Instant pass-through
                      is the classic tell; holding longer is quieter but ties up
                      the money and risks a freeze.
  layer_depth         how many hops before cash-out. Deeper obscures the origin
                      and costs a mule per layer.
  fan_out_per_mule    how widely each hop redistributes.
  amount_jitter       whether each hop moves the full balance (obvious) or a
                      varied fraction (quieter, slower).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.rng import Rng
from chakra.schema.entities import Instrument, InstrumentKind, Party, PartyType, Population
from chakra.schema.events import (
    Event,
    EventType,
    Family,
    Label,
    Rail,
    Surface,
)

_PSPS = ["okhdfc", "okicici", "oksbi", "okaxis", "paytm", "ybl", "ibl"]


class F6MuleNetwork(AttackFamily):
    code = Family.F6
    rail = Rail.UPI
    name = "Mule networks and layering"

    @property
    def param_specs(self) -> list[ParamSpec]:
        return [
            ParamSpec("fan_in_per_mule", 2, 40, integer=True),
            ParamSpec("dwell_seconds", 5.0, 86_400.0),
            ParamSpec("layer_depth", 1, 4, integer=True),
            ParamSpec("fan_out_per_mule", 1, 8, integer=True),
            ParamSpec("amount_jitter", 0.0, 0.6),
            ParamSpec("inter_hop_seconds", 2.0, 3600.0),
        ]

    def infrastructure_cost(self, params, attempts: int) -> float:
        """Every mule account in the network is a recruited or purchased asset.

        This is the trade the family turns on: suppressing fan-in and deepening
        layering both mean more mules. Free mules would make an arbitrarily wide,
        arbitrarily deep network costless and the family trivially winnable.
        """
        from chakra.generate import calibration as C

        fan_in = max(1, int(params["fan_in_per_mule"]))
        depth = max(1, int(params["layer_depth"]))
        fan_out = max(1, int(params["fan_out_per_mule"]))
        # first layer absorbs the victims; each subsequent layer multiplies out
        n_mules = max(1, -(-attempts // fan_in))
        for _ in range(depth - 1):
            n_mules += max(1, n_mules * fan_out)
        return C.MULE_VPA_ACQUISITION_COST_INR * n_mules

    def emit(self, rng, pop, params, start, n_episodes):
        params = AttackParams(params).clamped(self.param_specs)
        events: list[Event] = []
        for _ in range(n_episodes):
            events.extend(self._one_network(rng, pop, params, start))
        return events

    # ------------------------------------------------------------------
    def _new_mule(self, rng: Rng, pop: Population, when: datetime) -> Instrument:
        """A mule account, built by the SAME generator as any genuine one.

        Nothing about the identity marks it — same psp pool, same id scheme, a
        plausible creation date. If mule entities were constructed differently
        from genuine ones the detector would learn the construction, not the
        laundering, which is the artifact class this project keeps finding.
        """
        party = pop.add_party(
            Party(
                party_id=rng.uid("cons"),
                party_type=PartyType.CONSUMER,
                created_at=when - timedelta(days=rng.integers(1, 400)),
                kyc_level=1,
                home_state=rng.weighted_key(
                    __import__(
                        "chakra.generate.calibration", fromlist=["STATES"]
                    ).STATES
                ),
            )
        )
        return pop.add_instrument(
            Instrument(
                instrument_id=rng.uid("vpa"),
                kind=InstrumentKind.VPA,
                owner_party_id=party.party_id,
                issued_at=party.created_at,
                psp=rng.choice(_PSPS),
            )
        )

    def _hop(
        self,
        events: list[Event],
        rng: Rng,
        payer_vpa: str,
        payer_party: str,
        payee_vpa: str,
        payee_party: str,
        amount: float,
        when: datetime,
        episode_id: str,
        device_id: str | None,
    ):
        """One transfer. Deliberately ordinary — the fraud is the pattern of
        hops, never any single one of them."""
        payload = {
            "instrument_id": payer_vpa,
            "payer_vpa": payer_vpa,
            "payee_vpa": payee_vpa,
            "counterparty_id": payee_party,
            "amount_inr": round(amount, 2),
            "mcc": "other",
            "initiation_mode": "p2p_push",
            "is_collect": False,
            "geo_state": "OTHER",
            "device_id": device_id,
        }
        init = Event(
            event_id=rng.uid("ev"),
            event_type=EventType.TXN_INITIATED,
            rail=Rail.UPI,
            ts=when,
            actor_id=payer_party,
            surface=Surface.PSP_APP,
            available_at=when,
            episode_id=episode_id,
            label=Label.FRAUD,
            family=Family.F6,
            payload=payload,
        )
        events.append(init)

        pin_ts = when + timedelta(seconds=rng.uniform(2, 12))
        events.append(
            Event(
                event_id=rng.uid("ev"),
                event_type=EventType.PIN_ENTERED,
                rail=Rail.UPI,
                ts=pin_ts,
                actor_id=payer_party,
                surface=Surface.PSP_APP,
                available_at=pin_ts,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F6,
                payload={
                    "factor": "upi_pin",
                    "outcome": "success",
                    "linked_txn_id": init.event_id,
                    "device_id": device_id,
                },
            )
        )

        auth_ts = pin_ts + timedelta(seconds=rng.uniform(0.1, 1.5))
        auth_payload = dict(payload)
        auth_payload["linked_txn_id"] = init.event_id
        auth = Event(
            event_id=rng.uid("ev"),
            event_type=EventType.TXN_AUTH_REQUESTED,
            rail=Rail.UPI,
            ts=auth_ts,
            actor_id=payer_party,
            surface=Surface.NETWORK,
            available_at=auth_ts,
            episode_id=episode_id,
            label=Label.FRAUD,
            family=Family.F6,
            payload=auth_payload,
        )
        events.append(auth)

        out_ts = auth_ts + timedelta(seconds=rng.uniform(0.2, 2.0))
        events.append(
            Event(
                event_id=rng.uid("ev"),
                event_type=EventType.TXN_AUTHORISED,
                rail=Rail.UPI,
                ts=out_ts,
                actor_id=payer_party,
                surface=Surface.NETWORK,
                available_at=out_ts,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F6,
                payload={
                    "instrument_id": payer_vpa,
                    "payer_vpa": payer_vpa,
                    "payee_vpa": payee_vpa,
                    "counterparty_id": payee_party,
                    "amount_inr": round(amount, 2),
                    "device_id": device_id,
                    "linked_txn_id": auth.event_id,
                    "linked_initiation_id": init.event_id,
                    "decline_reason": None,
                },
            )
        )
        return out_ts

    def _one_network(self, rng: Rng, pop: Population, p: AttackParams, start: datetime):
        events: list[Event] = []
        episode_id = rng.uid("f6ep")

        consumers = pop.consumers()
        if not consumers:
            return events

        fan_in = int(p["fan_in_per_mule"])
        dwell = float(p["dwell_seconds"])
        depth = int(p["layer_depth"])
        fan_out = int(p["fan_out_per_mule"])
        jitter = float(p["amount_jitter"])
        hop_gap = float(p["inter_hop_seconds"])

        collector = self._new_mule(rng, pop, start)
        when = start
        collected = 0.0

        # Layer 1: unrelated payers converge on one handle. Each payment is
        # individually unremarkable; the convergence is the signal.
        for _ in range(fan_in):
            payer = rng.choice(consumers)
            vpas = [
                i for i in pop.instruments_of(payer.party_id) if i.kind is InstrumentKind.VPA
            ]
            if not vpas:
                continue
            device = pop.device_of(payer.party_id)
            amount = rng.amount_from_bands(
                __import__(
                    "chakra.generate.calibration", fromlist=["UPI_AMOUNT_BANDS"]
                ).UPI_AMOUNT_BANDS
            )
            when = when + timedelta(seconds=max(1.0, hop_gap))
            self._hop(
                events,
                rng,
                payer_vpa=vpas[0].instrument_id,
                payer_party=payer.party_id,
                payee_vpa=collector.instrument_id,
                payee_party=collector.owner_party_id,
                amount=amount,
                when=when,
                episode_id=episode_id,
                device_id=device.device_id if device else None,
            )
            collected += amount

        # Subsequent layers: the balance moves on after dwelling. Pass-through
        # speed and fan-out width are the attacker's remaining levers.
        frontier = [(collector, collected)]
        for _ in range(depth - 1):
            next_frontier: list[tuple[Instrument, float]] = []
            for holder, balance in frontier:
                if balance <= 1.0:
                    continue
                splits = max(1, fan_out)
                when = when + timedelta(seconds=max(1.0, dwell))
                for _ in range(splits):
                    share = balance / splits
                    share *= 1.0 + rng.uniform(-jitter, jitter)
                    if share <= 1.0:
                        continue
                    onward = self._new_mule(rng, pop, when)
                    when = when + timedelta(seconds=max(1.0, hop_gap))
                    self._hop(
                        events,
                        rng,
                        payer_vpa=holder.instrument_id,
                        payer_party=holder.owner_party_id,
                        payee_vpa=onward.instrument_id,
                        payee_party=onward.owner_party_id,
                        amount=share,
                        when=when,
                        episode_id=episode_id,
                        device_id=None,
                    )
                    next_frontier.append((onward, share))
            frontier = next_frontier

        return events
