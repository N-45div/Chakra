"""Entities that populate the simulation.

The population model creates these, calibrated to NPCI/RBI aggregates (Lane C).
Attacks may create entities; they may not create features. Entity ids are
deterministic given a seeded RNG so that whole runs reproduce.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class PartyType(str, Enum):
    CONSUMER = "consumer"
    MERCHANT = "merchant"
    AGENT = "agent"
    BC_OPERATOR = "bc_operator"  # AePS business correspondent


class InstrumentKind(str, Enum):
    CARD = "card"
    VPA = "vpa"
    ACCOUNT = "account"
    TOKEN = "token"
    WALLET = "wallet"


@dataclass(slots=True)
class Party:
    party_id: str
    party_type: PartyType
    created_at: datetime
    kyc_level: int          # 0 = min-KYC, 1 = full-KYC
    home_state: str


@dataclass(slots=True)
class Instrument:
    instrument_id: str
    kind: InstrumentKind
    owner_party_id: str
    issued_at: datetime
    psp: str | None = None
    bin: str | None = None  # card only


@dataclass(slots=True)
class Device:
    device_id: str
    first_seen_at: datetime
    os: str
    is_emulator: bool = False
    sim_id: str | None = None
    imei_hash: str | None = None


@dataclass(slots=True)
class AgentIdentity:
    """F10 only. An agent that transacts on a consumer's behalf."""

    agent_id: str
    registry_entry: bool          # present in the trusted-agent directory?
    pubkey_id: str | None
    scope_merchants: frozenset[str]
    scope_max_amount: float


@dataclass(slots=True)
class Population:
    """A snapshot of everyone and everything in a simulated world.

    Held as plain dicts keyed by id for O(1) lookup during generation. This is
    the shared substrate the legit background and every attack draw on, so that
    fraud entities are indistinguishable *as entities* from genuine ones and the
    detector must work from behaviour, not from a giveaway id scheme.
    """

    parties: dict[str, Party] = field(default_factory=dict)
    instruments: dict[str, Instrument] = field(default_factory=dict)
    devices: dict[str, Device] = field(default_factory=dict)
    agents: dict[str, AgentIdentity] = field(default_factory=dict)

    def add_party(self, p: Party) -> Party:
        self.parties[p.party_id] = p
        return p

    def add_instrument(self, i: Instrument) -> Instrument:
        self.instruments[i.instrument_id] = i
        return i

    def add_device(self, d: Device) -> Device:
        self.devices[d.device_id] = d
        return d

    def add_agent(self, a: AgentIdentity) -> AgentIdentity:
        self.agents[a.agent_id] = a
        return a

    def consumers(self) -> list[Party]:
        return [p for p in self.parties.values() if p.party_type is PartyType.CONSUMER]

    def merchants(self) -> list[Party]:
        return [p for p in self.parties.values() if p.party_type is PartyType.MERCHANT]

    def instruments_of(self, party_id: str) -> list[Instrument]:
        return [i for i in self.instruments.values() if i.owner_party_id == party_id]
