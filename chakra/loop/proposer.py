"""The evolutionary proposer.

Reads which attacks slipped past the detector (the feedback batch), keeps the
parameter vectors of the survivors as fitness, and produces the next
generation's parameters by mutation and crossover within pre-registered bounds.

Bounded mutation is a realism constraint (real attackers have budgets), fixed
before the run — never a knob turned until the curve looks good. All randomness
flows through the seeded Rng so a whole run reproduces.
"""

from __future__ import annotations

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.rng import Rng


class EvolutionaryProposer:
    def __init__(self, family: AttackFamily, step_frac: float = 0.15) -> None:
        self.family = family
        self.specs: list[ParamSpec] = family.param_specs
        # per-parameter mutation sigma = step_frac of the parameter's range.
        # Pre-registered: fixed here, not tuned mid-run.
        self.step_frac = step_frac

    def initial(self, rng: Rng, pop_size: int) -> list[AttackParams]:
        return [self.family.sample_params(rng) for _ in range(pop_size)]

    def _mutate(self, rng: Rng, params: AttackParams) -> AttackParams:
        out = AttackParams(params)
        for s in self.specs:
            span = s.high - s.low
            out[s.name] = params[s.name] + rng.normal(0.0, self.step_frac * span)
        return out.clamped(self.specs)

    def _crossover(self, rng: Rng, a: AttackParams, b: AttackParams) -> AttackParams:
        out = AttackParams()
        for s in self.specs:
            out[s.name] = a[s.name] if rng.uniform(0, 1) < 0.5 else b[s.name]
        return out.clamped(self.specs)

    def next_generation(
        self,
        rng: Rng,
        scored: list[tuple[AttackParams, float]],
        pop_size: int,
    ) -> list[AttackParams]:
        """Given (params, evasion_rate) pairs, breed the next generation.

        Higher evasion = higher fitness. Elite survivors are kept, the rest are
        children of tournament-selected parents with mutation. If nothing evaded
        (all fitness 0) we still mutate the least-caught to keep exploring.
        """
        if not scored:
            return [self.family.sample_params(rng) for _ in range(pop_size)]

        ranked = sorted(scored, key=lambda t: t[1], reverse=True)
        elite_n = max(1, pop_size // 5)
        elites = [p for p, _ in ranked[:elite_n]]

        next_gen: list[AttackParams] = list(elites)
        while len(next_gen) < pop_size:
            a = self._tournament(rng, ranked)
            b = self._tournament(rng, ranked)
            child = self._crossover(rng, a, b)
            child = self._mutate(rng, child)
            next_gen.append(child)
        return next_gen[:pop_size]

    def _tournament(self, rng: Rng, ranked: list[tuple[AttackParams, float]], k: int = 3) -> AttackParams:
        best = None
        best_fit = -1.0
        for _ in range(k):
            idx = rng.integers(0, len(ranked))
            params, fit = ranked[idx]
            if fit > best_fit:
                best_fit = fit
                best = params
        return best
