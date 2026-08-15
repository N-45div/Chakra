"""F5 — Authorised push payment on UPI.

The family the adaptive loop actually needs.

F11 gave the loop no gradient: enumeration is defined by behaviour it cannot
hide, so evasion sat at zero on every seed and selection had nothing to act on.
F5 is the opposite case. The victim's own device, VPA and PIN are used, the
authentication succeeds because it is genuine, and the payment is real. Nothing
about the credential is wrong. The only thing that is wrong is who the money
goes to and why the victim believed they should send it.

Three mechanisms, sharing one signal shape — the payer consents while the
attacker controls the destination:

  collect_impersonation  a merchant-collect request dressed as a refund or
                         cashback. RBI and NPCI both warn that a UPI PIN is
                         never needed to RECEIVE money; the deception is that
                         approving a pull feels like accepting a credit.
                         Note this is merchant collect: NPCI discontinued P2P
                         collect on 1 Oct 2025 precisely to kill the P2P
                         version, so the surviving vector is impersonating a
                         merchant.
  qr_substitution        a fake sticker over a merchant's QR, or an
                         AI-regenerated QR identical but for the VPA. The payer
                         pushes willingly, to the wrong handle.
  screen_share           a KYC-urgency call walks the victim into AnyDesk or
                         TeamViewer; the attacker watches and directs. RBI has
                         warned about this by name.

What makes it a real adversarial problem: the attacker's evasion levers trade
directly against yield.

  victims_per_payee_vpa  fan-in. One mule VPA collecting from many unrelated
                         payers is the loudest signal available. Rotating VPAs
                         suppresses it — and costs money per handle.
  amount_ratio           how much to take relative to the victim's own typical
                         payment. Greedy extracts more per victim and stands out
                         against their history; modest blends in and yields less.
  mode                   collect is easier to run at scale but carries the
                         is_collect flag; a pushed QR substitution has no such
                         marker but needs physical or contextual access.
  dwell_seconds          how long after contact the payment lands.

None of these is free, which is the point: the loop has to discover a trade
rather than a dominant strategy.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.rng import Rng
from chakra.schema.entities import Instrument, InstrumentKind, Population
from chakra.schema.events import (
    Event,
    EventType,
    Family,
    Label,
    Rail,
    Surface,
)

_MECHANISMS = ("collect_impersonation", "qr_substitution", "screen_share")


class F5UpiDeception(AttackFamily):
    code = Family.F5
    rail = Rail.UPI
    name = "Authorised push payment on UPI"

    @property
    def param_specs(self) -> list[ParamSpec]:
        return [
            # How many victims each attacker-controlled payee VPA collects from
            # before it is retired. Low = quiet but needs more handles.
            ParamSpec("victims_per_payee_vpa", 1, 40, integer=True),
            # Take as a multiple of the victim's own typical payment. Near 1.0
            # is indistinguishable by amount alone; high extracts more per hit.
            ParamSpec("amount_ratio", 0.4, 12.0),
            # Victims worked in one campaign.
            ParamSpec("victims_per_campaign", 2, 30, integer=True),
            # Seconds between successive victims — pace of the operation.
            ParamSpec("inter_victim_seconds", 30.0, 7200.0),
            # Delay between contacting a victim and the payment landing.
            ParamSpec("dwell_seconds", 20.0, 1800.0),
            # Share of victims worked by collect rather than a pushed payment.
            ParamSpec("collect_share", 0.0, 1.0),
        ]

    def infrastructure_cost(self, params, attempts: int) -> float:
        """Mule VPAs acquired to absorb `attempts` victims.

        This is the trade at the heart of the family. Fan-in is the loudest
        signal a mule handle produces, and the only way to suppress it is to
        spread victims across more handles — each of which must be recruited or
        bought. Making the handle free would make low fan-in a costless evasion
        and the family trivially winnable.
        """
        from chakra.generate import calibration as C

        per_vpa = max(1, int(params["victims_per_payee_vpa"]))
        n_vpa = max(1, -(-attempts // per_vpa))
        return C.MULE_VPA_ACQUISITION_COST_INR * n_vpa

    def emit(self, rng, pop, params, start, n_episodes):
        params = AttackParams(params).clamped(self.param_specs)
        events: list[Event] = []
        for _ in range(n_episodes):
            events.extend(self._one_campaign(rng, pop, params, start))
        return events

    # ------------------------------------------------------------------
    def _mule_vpa(self, rng: Rng, pop: Population, when: datetime) -> Instrument:
        """A fresh attacker-controlled handle.

        Created through the same generator as any other VPA: nothing about the
        identity betrays it, which is the whole premise. Only the pattern of who
        pays it, and how those payers behaved, can give it away.
        """
        return pop.add_instrument(
            Instrument(
                instrument_id=rng.uid("vpa"),
                kind=InstrumentKind.VPA,
                owner_party_id=rng.uid("f5mule"),
                issued_at=when,
                psp=rng.choice(["okhdfc", "okicici", "oksbi", "okaxis", "paytm", "ybl", "ibl"]),
            )
        )

    def _one_campaign(self, rng: Rng, pop: Population, p: AttackParams, start: datetime):
        events: list[Event] = []
        episode_id = rng.uid("f5ep")

        consumers = pop.consumers()
        if not consumers:
            return events

        n_victims = int(p["victims_per_campaign"])
        per_vpa = int(p["victims_per_payee_vpa"])
        ratio = float(p["amount_ratio"])
        pace = float(p["inter_victim_seconds"])
        dwell = float(p["dwell_seconds"])
        collect_share = float(p["collect_share"])

        payee = self._mule_vpa(rng, pop, start)
        on_this_vpa = 0
        when = start

        for _ in range(n_victims):
            if on_this_vpa >= per_vpa:
                payee = self._mule_vpa(rng, pop, when)  # retire and rotate
                on_this_vpa = 0
            on_this_vpa += 1

            victim = rng.choice(consumers)
            vpas = [
                i for i in pop.instruments_of(victim.party_id) if i.kind is InstrumentKind.VPA
            ]
            if not vpas:
                continue
            payer_vpa = vpas[0]
            device = pop.device_of(victim.party_id)

            # The victim's OWN device. No burner, no emulator — that is what
            # makes this family hard and what makes device-based signals useless
            # against it.
            device_id = device.device_id if device else None

            use_collect = rng.uniform(0, 1) < collect_share
            mechanism = (
                "collect_impersonation"
                if use_collect
                else rng.choice(["qr_substitution", "screen_share"])
            )

            # Amount is anchored to what this victim plausibly pays, so a greedy
            # ratio is what makes it stand out — not an arbitrary fraud amount.
            typical = rng.amount_from_bands(
                __import__(
                    "chakra.generate.calibration", fromlist=["UPI_AMOUNT_BANDS"]
                ).UPI_AMOUNT_BANDS
            )
            amount = round(max(1.0, typical * ratio), 2)

            when = when + timedelta(seconds=max(1.0, pace))
            contact_ts = when
            pay_ts = contact_ts + timedelta(seconds=max(1.0, dwell))

            payload = {
                "instrument_id": payer_vpa.instrument_id,
                "payer_vpa": payer_vpa.instrument_id,
                "payee_vpa": payee.instrument_id,
                "counterparty_id": payee.owner_party_id,
                "amount_inr": amount,
                "mcc": "other",
                "initiation_mode": "p2m_collect" if use_collect else "p2m_push",
                "is_collect": use_collect,
                "geo_state": victim.home_state,
                "device_id": device_id,
                "mechanism": mechanism,
            }

            if use_collect:
                # The ATTACKER raises the request. The victim never initiates.
                origin = Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.COLLECT_REQUESTED,
                    rail=Rail.UPI,
                    ts=contact_ts,
                    actor_id=payee.owner_party_id,
                    surface=Surface.PSP_APP,
                    available_at=contact_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F5,
                    payload=payload,
                )
            else:
                origin = Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.TXN_INITIATED,
                    rail=Rail.UPI,
                    ts=contact_ts,
                    actor_id=victim.party_id,
                    surface=Surface.PSP_APP,
                    available_at=contact_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F5,
                    payload=payload,
                )
            events.append(origin)

            # The victim's genuine PIN, entered willingly. This is the crux:
            # authentication SUCCEEDS. Nothing at the auth layer is anomalous.
            pin_ts = pay_ts
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.PIN_ENTERED,
                    rail=Rail.UPI,
                    ts=pin_ts,
                    actor_id=victim.party_id,
                    surface=Surface.PSP_APP,
                    available_at=pin_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F5,
                    payload={
                        "factor": "upi_pin",
                        "outcome": "success",
                        "linked_txn_id": origin.event_id,
                        "device_id": device_id,
                    },
                )
            )

            auth_ts = pin_ts + timedelta(seconds=rng.uniform(0.1, 1.5))
            auth_payload = dict(payload)
            auth_payload["linked_txn_id"] = origin.event_id
            auth = Event(
                event_id=rng.uid("ev"),
                event_type=EventType.TXN_AUTH_REQUESTED,
                rail=Rail.UPI,
                ts=auth_ts,
                actor_id=victim.party_id,
                surface=Surface.NETWORK,
                available_at=auth_ts,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F5,
                payload=auth_payload,
            )
            events.append(auth)

            # Authorised. A genuine payer with a genuine PIN and sufficient
            # balance is approved — the money is gone before anyone disputes.
            out_ts = auth_ts + timedelta(seconds=rng.uniform(0.2, 2.0))
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.TXN_AUTHORISED,
                    rail=Rail.UPI,
                    ts=out_ts,
                    actor_id=victim.party_id,
                    surface=Surface.NETWORK,
                    available_at=out_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F5,
                    payload={
                        "instrument_id": payer_vpa.instrument_id,
                        "payer_vpa": payer_vpa.instrument_id,
                        "payee_vpa": payee.instrument_id,
                        "counterparty_id": payee.owner_party_id,
                        "amount_inr": amount,
                        "device_id": device_id,
                        "linked_txn_id": auth.event_id,
                        "linked_initiation_id": origin.event_id,
                        "decline_reason": None,
                    },
                )
            )

        return events
