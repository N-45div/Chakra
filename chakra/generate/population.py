"""Population model — creates the entities the world is made of.

Calibrated to Lane C aggregates. Fraud and genuine entities are drawn from the
same generators so that nothing about an entity's *identity* betrays it; the
detector must work from behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chakra.generate import calibration as C
from chakra.generate import calibration as C  # noqa: N812
from chakra.generate.rng import Rng
from chakra.schema.entities import (
    AgentIdentity,
    Device,
    Instrument,
    InstrumentKind,
    Party,
    PartyType,
    Population,
)

_PSPS = ["okhdfc", "okicici", "oksbi", "okaxis", "paytm", "ybl", "ibl"]
_BINS = ["414720", "512345", "601100", "353011", "436742"]


def build_population(
    rng: Rng,
    n_consumers: int,
    n_merchants: int,
    n_agents: int = 0,
    world_start: datetime | None = None,
) -> Population:
    """Create a population of consumers, merchants and (optionally) agents,
    each with plausible instruments and devices."""
    if world_start is None:
        world_start = datetime(2026, 1, 1)
    pop = Population()

    for _ in range(n_consumers):
        created = world_start - timedelta(days=rng.integers(30, 2000))
        p = pop.add_party(
            Party(
                party_id=rng.uid("cons"),
                party_type=PartyType.CONSUMER,
                created_at=created,
                kyc_level=1 if rng.uniform(0, 1) < 0.75 else 0,
                home_state=rng.weighted_key(C.STATES),
            )
        )
        # one device, one VPA, and a card for most consumers. Card ownership is
        # set high enough that the emitted rail mix can actually reach the
        # calibrated card share — a consumer with no card can never contribute
        # a card transaction, so low ownership silently caps the mix.
        pop.add_device(
            Device(
                device_id=rng.uid("dev"),
                first_seen_at=created,
                os=rng.choice(["android", "ios"], [0.8, 0.2]),
                is_emulator=False,
                sim_id=rng.uid("sim"),
                imei_hash=rng.uid("imei"),
                owner_party_id=p.party_id,
            )
        )
        pop.add_instrument(
            Instrument(
                instrument_id=rng.uid("vpa"),
                kind=InstrumentKind.VPA,
                owner_party_id=p.party_id,
                issued_at=created,
                psp=rng.choice(_PSPS),
            )
        )
        if rng.uniform(0, 1) < C.CARD_OWNERSHIP_RATE:
            pop.add_instrument(
                Instrument(
                    instrument_id=rng.uid("card"),
                    kind=InstrumentKind.CARD,
                    owner_party_id=p.party_id,
                    issued_at=created,
                    bin=rng.choice(_BINS),
                )
            )

    for _ in range(n_merchants):
        created = world_start - timedelta(days=rng.integers(60, 2500))
        m = pop.add_party(
            Party(
                party_id=rng.uid("merch"),
                party_type=PartyType.MERCHANT,
                created_at=created,
                kyc_level=1,
                home_state=rng.weighted_key(C.STATES),
            )
        )
        pop.add_instrument(
            Instrument(
                instrument_id=rng.uid("mvpa"),
                kind=InstrumentKind.VPA,
                owner_party_id=m.party_id,
                issued_at=created,
                psp=rng.choice(_PSPS),
            )
        )

    for _ in range(n_agents):
        merchants = pop.merchants()
        scope = frozenset(
            m.party_id for m in _sample(rng, merchants, k=min(5, len(merchants)))
        )
        pop.add_agent(
            AgentIdentity(
                agent_id=rng.uid("agent"),
                registry_entry=True,
                pubkey_id=rng.uid("pk"),
                scope_merchants=scope,
                scope_max_amount=float(rng.choice([2000, 5000, 10000, 25000])),
            )
        )

    return pop


def _sample(rng: Rng, items: list, k: int) -> list:
    if k >= len(items):
        return list(items)
    idx = set()
    while len(idx) < k:
        idx.add(rng.integers(0, len(items)))
    return [items[i] for i in idx]
