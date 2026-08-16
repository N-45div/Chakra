"""Attack-family base classes.

An attack is a *parameterised raw-event emitter*. The loop's proposer mutates
the parameter vector within pre-registered bounds (a realism constraint — real
attackers face budgets — not a knob turned until the demo looks good). The
family renders those parameters into events.

Hard rule, enforced by test: this module and its subclasses must not import
chakra.schema.features. Attacks describe *what happens*; the feature pipeline,
shared with real data, decides what the model sees.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from chakra.generate.rng import Rng
from chakra.schema.entities import Population
from chakra.schema.events import Event, Family, Rail


@dataclass(frozen=True, slots=True)
class ParamSpec:
    """One tunable parameter and the pre-registered bounds it may be mutated in."""

    name: str
    low: float
    high: float
    integer: bool = False

    def clamp(self, value: float) -> float:
        v = max(self.low, min(self.high, value))
        return float(round(v)) if self.integer else float(v)


class AttackParams(dict):
    """A parameter vector. Plain dict with clamping against a spec."""

    def clamped(self, specs: list[ParamSpec]) -> "AttackParams":
        out = AttackParams(self)
        for s in specs:
            if s.name in out:
                out[s.name] = s.clamp(out[s.name])
        return out


class AttackFamily(ABC):
    code: Family
    name: str
    # The rail this family operates on, declared by the family itself rather
    # than configured on the loop. Registering a UPI family and having it
    # silently scored by a card-scoped detector would produce a plausible
    # number and no error anywhere.
    rail: Rail

    @property
    @abstractmethod
    def param_specs(self) -> list[ParamSpec]:
        """The mutable parameter space (the fraudster's knobs)."""

    def default_params(self) -> AttackParams:
        return AttackParams({s.name: (s.low + s.high) / 2 for s in self.param_specs})

    def infrastructure_cost(self, params: "AttackParams", attempts: int) -> float:
        """Rupees the attacker spends on ASSETS to make `attempts`, excluding the
        value of the payments themselves.

        Declared per family because evasion is bought with different things on
        each: F11 burns devices and merchant endpoints, F5 burns mule VPAs. The
        loop previously hard-coded F11's knobs here, which crashed the moment a
        second family was registered — a useful failure, since silently charging
        one family's cost model to another would have been worse.

        Default is zero, so a family that has not thought about cost gets no
        free evasion by omission — it gets a visibly missing cost model.
        """
        return 0.0

    def episode_value_inr(self, authorised_amounts: list[float]) -> float:
        """Rupees the attacker GAINED from the authorised transactions that
        landed before the first alert.

        Declared per family because the same authorised row means different
        things. For an authorised-push scam the gain is the money taken from the
        victim; for a mule network it is the value moved through; for a card
        tester it is emphatically NOT the one-rupee probe that happened to be
        approved — it is the resale value of the live card that probe just
        confirmed.

        This exists because utility previously mixed units: yield was a COUNT of
        validated cards and cost was RUPEES, bridged by an invented constant.
        With F6 that broke outright — a four-layer network implies hundreds of
        mule accounts, so cost dominated any plausible count and the loop would
        have collapsed to minimum depth rather than finding a trade. Both sides
        are now rupees and the bridge constant is gone.
        """
        return float(sum(authorised_amounts))

    def sample_params(self, rng: Rng) -> AttackParams:
        return AttackParams(
            {s.name: rng.uniform(s.low, s.high) for s in self.param_specs}
        ).clamped(self.param_specs)

    @abstractmethod
    def emit(
        self,
        rng: Rng,
        pop: Population,
        params: AttackParams,
        start: datetime,
        n_episodes: int,
    ) -> list[Event]:
        """Render `n_episodes` attack episodes into raw events.

        MUST emit only events. MUST NOT compute or set any feature. Each episode
        shares one episode_id so the loop can trace an attack end to end.
        """
