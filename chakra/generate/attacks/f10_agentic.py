"""F10 — Agentic checkout manipulation.

The newest rail, and the one whose threat model the mandate layer was supposed
to close.

An agentic checkout runs inside a signed protocol: the assistant declares an
intent, finalises a cart with the merchant, presents a payment whose signature
covers exactly what is presented. Intent↔Cart consistency and signature
validation are deterministic policy checks (EXPERIMENT_CONTRACT §4) — so F10
does not attack them. It cannot win there, and neither should any detector
pretending the checks are its job.

The manipulation happens UPSTREAM of everything the policy layer sees. A prompt
injection in a product page the agent reads, or a malicious shopping plugin,
rewrites what the agent *declares*: by the time intent is signed, the cart
already points at the attacker's merchant at the attacker's amount. Every
downstream artifact is then internally consistent — valid signature, matching
cart, matching payment, matching authorisation. The victim delegated an agent;
the agent did exactly what it had been tricked into wanting.

That premise has a consequence this family is built to honour: on this rail,
consistency carries no information, and every row — genuine or fraudulent —
passes the mandate checks. What can still betray the operation is its SHAPE:

  victims_per_agent     how many unrelated principals one fake agent serves
                        before being rotated out. Fan-out across principals is
                        the agentic analogue of mule fan-in; suppressing it
                        means registering more agents, each of which costs real
                        money through a compromised developer account.
  delegate_age_seconds  how long after delegation the abuse begins. An
                        assistant provisioned for one household that starts
                        transacting for strangers minutes later is behaving
                        like an onboarding funnel, not software.
  amount_ratio          extraction size versus the principal's own typical
                        basket. Greedy stands out against payer history;
                        modest blends in and yields less.
  inter_victim_seconds  pace of the operation.
  victims_per_campaign  campaign width.

India context: agentic checkout is arriving on live rails precisely as UPI's
delegated-payment mandates are being standardised, which makes "who is really
behind this assistant" an open supervisory question rather than a solved one.
The simulation prices that question honestly: fake agents are registered
through the same directory door as honest ones, carry registry entries and key
ids indistinguishable from genuine, and differ only in behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.rng import Rng
from chakra.schema.entities import (
    AgentIdentity,
    InstrumentKind,
    Party,
    PartyType,
    Population,
)
from chakra.schema.events import (
    Event,
    EventType,
    Family,
    Label,
    Rail,
    Surface,
)

_PSPS = ["okhdfc", "okicici", "oksbi", "okaxis", "paytm", "ybl", "ibl"]


class F10AgenticCheckout(AttackFamily):
    code = Family.F10
    rail = Rail.AGENTIC
    name = "Agentic checkout manipulation"

    @property
    def param_specs(self) -> list[ParamSpec]:
        return [
            ParamSpec("victims_per_agent", 1, 25, integer=True),
            ParamSpec("amount_ratio", 0.4, 12.0),
            ParamSpec("victims_per_campaign", 2, 20, integer=True),
            ParamSpec("inter_victim_seconds", 60.0, 7200.0),
            ParamSpec("delegate_age_seconds", 60.0, 172_800.0),
        ]

    def infrastructure_cost(self, params, attempts: int) -> float:
        """Agent identities acquired to work `attempts` principals.

        The family's evasion lever against fan-out features is rotation, and a
        directory-listed identity costs money to obtain — a compromised
        developer account, KYC-grade paperwork, or both. Free agents would make
        `victims_per_agent -> 1` a costless dominant strategy and the family
        trivially winnable, which is the same failure shape as free mule VPAs
        in F5/F6.
        """
        from chakra.generate import calibration as C

        per_agent = max(1, int(params["victims_per_agent"]))
        n_agents = max(1, -(-attempts // per_agent))
        return C.AGENT_ACQUISITION_COST_INR * n_agents

    def episode_value_inr(
        self,
        authorised_amounts: list[float],
        authorised_payloads: list[dict] | None = None,
    ) -> float:
        """Goods bought with manipulated carts are resold, not retailed."""
        from chakra.generate import calibration as C

        return float(sum(authorised_amounts)) * C.CASH_CONVERSION_FACTOR

    def emit(self, rng, pop, params, start, n_episodes):
        params = AttackParams(params).clamped(self.param_specs)
        events: list[Event] = []
        for _ in range(n_episodes):
            events.extend(self._one_campaign(rng, pop, params, start))
        return events

    # ------------------------------------------------------------------
    def _fake_agent(self, rng: Rng, pop: Population, when: datetime) -> AgentIdentity:
        """A registered attacker-operated assistant.

        Registered through the SAME door as genuine ones — directory entry,
        key id, the works — because a registration barrier the attacker cannot
        pass would make the family impossible rather than hard. Nothing about
        the ENTITY may betray it; only behaviour can.
        """
        return pop.add_agent(
            AgentIdentity(
                agent_id=rng.uid("agent"),
                registry_entry=True,
                pubkey_id=rng.uid("pk"),
                scope_merchants=frozenset(),
                scope_max_amount=float("inf"),
            )
        )

    def _mule_merchant(self, rng: Rng, pop: Population, when: datetime) -> Party:
        """The merchant the injected instruction routes payments to.

        Constructed by the same generator as any genuine merchant — plausible
        age, ordinary category footprint. If fake merchants were built
        differently the detector would learn construction, not manipulation,
        which is the artifact class this project keeps catching (see FINDINGS).
        """
        return pop.add_party(
            Party(
                party_id=rng.uid("merch"),
                party_type=PartyType.MERCHANT,
                created_at=when - timedelta(days=rng.integers(1, 300)),
                kyc_level=1,
                home_state=rng.weighted_key(
                    __import__(
                        "chakra.generate.calibration", fromlist=["STATES"]
                    ).STATES
                ),
            )
        )

    def _one_campaign(self, rng: Rng, pop: Population, p: AttackParams, start: datetime):
        events: list[Event] = []
        episode_id = rng.uid("f10ep")

        consumers = pop.consumers()
        if not consumers:
            return events

        per_agent = int(p["victims_per_agent"])
        ratio = float(p["amount_ratio"])
        n_victims = int(p["victims_per_campaign"])
        pace = float(p["inter_victim_seconds"])
        delegate_age = float(p["delegate_age_seconds"])

        agent = self._fake_agent(rng, pop, start)
        merchant = self._mule_merchant(rng, pop, start)
        served_on_this_agent = 0
        when = start

        for _ in range(n_victims):
            if served_on_this_agent >= per_agent:
                # Rotate the burned identity for a fresh one. Costs money via
                # infrastructure_cost; buys silence against fan-out features.
                agent = self._fake_agent(rng, pop, when)
                served_on_this_agent = 0
            served_on_this_agent += 1

            victim = rng.choice(consumers)
            vpas = [
                i for i in pop.instruments_of(victim.party_id) if i.kind is InstrumentKind.VPA
            ]
            if not vpas:
                continue
            funding = vpas[0]

            typical = rng.amount_from_bands(
                __import__(
                    "chakra.generate.calibration", fromlist=["AGENTIC_AMOUNT_BANDS"]
                ).AGENTIC_AMOUNT_BANDS
            )
            # The declared cart ALREADY carries the inflated amount: the
            # injection rewrote what the agent wants before anything was
            # signed. Cart == payment == auth throughout — the mandate layer
            # passes because there is nothing left for it to catch.
            amount = round(max(1.0, typical * ratio), 2)

            when = when + timedelta(seconds=max(1.0, pace))
            contact_ts = when
            delegate_ts = contact_ts
            first_txn_ts = contact_ts + timedelta(seconds=max(1.0, delegate_age))

            # Delegation happens in the victim's app ("install this AI
            # shopping assistant"), invisible to the network surface.
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.DELEGATE_ADDED,
                    rail=Rail.AGENTIC,
                    ts=delegate_ts,
                    actor_id=victim.party_id,
                    surface=Surface.PSP_APP,
                    available_at=delegate_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F10,
                    payload={
                        "agent_id": agent.agent_id,
                        "principal_id": victim.party_id,
                        "device_id": None,
                    },
                )
            )

            # Provisioning time carried inside the signed protocol payload: an
            # agent attests its own registration instant, so it is request-time
            # observable even though the delegation itself never reached the
            # network.
            provisioned_at = first_txn_ts - timedelta(seconds=max(1.0, delegate_age))
            protocol = {
                "agent_id": agent.agent_id,
                "principal_id": victim.party_id,
                "cart_total_inr": amount,
                "counterparty_id": merchant.party_id,
                "item_count": rng.integers(1, 12),
                "agent_provisioned_at": provisioned_at,
            }

            intent_ts = first_txn_ts
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.AGENT_INTENT_DECLARED,
                    rail=Rail.AGENTIC,
                    ts=intent_ts,
                    actor_id=victim.party_id,
                    surface=Surface.NETWORK,
                    available_at=intent_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F10,
                    payload=dict(protocol),
                )
            )

            cart_ts = intent_ts + timedelta(seconds=rng.uniform(1, 30))
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.AGENT_CART_BUILT,
                    rail=Rail.AGENTIC,
                    ts=cart_ts,
                    actor_id=victim.party_id,
                    surface=Surface.NETWORK,
                    available_at=cart_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F10,
                    payload=dict(protocol),
                )
            )

            pay_ts = cart_ts + timedelta(seconds=rng.uniform(0.3, 8))
            payload = dict(protocol)
            payload.update({
                "instrument_id": funding.instrument_id,
                "payer_vpa": funding.instrument_id,
                "amount_inr": amount,
                "mcc": "shopping",
                "initiation_mode": "agentic",
                "is_collect": False,
                "geo_state": victim.home_state,
            })
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.AGENT_PAYMENT_PRESENTED,
                    rail=Rail.AGENTIC,
                    ts=pay_ts,
                    actor_id=victim.party_id,
                    surface=Surface.NETWORK,
                    available_at=pay_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F10,
                    payload=dict(payload),
                )
            )

            auth_ts = pay_ts + timedelta(seconds=rng.uniform(0.05, 0.6))
            # No linked_txn_id: on this rail the mandate protocol, not a
            # payer-side initiation, precedes the authorisation request.
            auth = Event(
                event_id=rng.uid("ev"),
                event_type=EventType.TXN_AUTH_REQUESTED,
                rail=Rail.AGENTIC,
                ts=auth_ts,
                actor_id=victim.party_id,
                surface=Surface.NETWORK,
                available_at=auth_ts,
                episode_id=episode_id,
                label=Label.FRAUD,
                family=Family.F10,
                payload=payload,
            )
            events.append(auth)

            # Approved: the mandate is valid, the balance sufficient, the
            # signature genuine. The victim learns of it from a delivery
            # notification for something they never ordered.
            out_ts = auth_ts + timedelta(seconds=rng.uniform(0.2, 2.0))
            events.append(
                Event(
                    event_id=rng.uid("ev"),
                    event_type=EventType.TXN_AUTHORISED,
                    rail=Rail.AGENTIC,
                    ts=out_ts,
                    actor_id=victim.party_id,
                    surface=Surface.NETWORK,
                    available_at=out_ts,
                    episode_id=episode_id,
                    label=Label.FRAUD,
                    family=Family.F10,
                    payload={
                        "instrument_id": funding.instrument_id,
                        "counterparty_id": merchant.party_id,
                        "agent_id": agent.agent_id,
                        "principal_id": victim.party_id,
                        "amount_inr": amount,
                        "device_id": None,
                        "linked_txn_id": auth.event_id,
                        "linked_initiation_id": None,
                        "decline_reason": None,
                    },
                )
            )

        return events
