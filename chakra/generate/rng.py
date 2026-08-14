"""Deterministic sampling and id minting.

Everything stochastic in Chakra flows through a numpy Generator built from a
SeedSequence. Child streams are produced with SeedSequence.spawn(), which is the
supported way to get *statistically independent* substreams — deriving a child
seed by drawing an integer from the parent (the obvious shortcut) couples the
streams and makes independence an assumption rather than a guarantee.

No wall-clock, no global random state. That is what lets a whole run reproduce
and lets the loop's four streams be simultaneously independent and repeatable.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np


class Rng:
    """Seeded sampling primitives plus deterministic, stream-tagged id minting."""

    def __init__(self, seed: int | np.random.SeedSequence, tag: str = "root") -> None:
        if isinstance(seed, np.random.SeedSequence):
            self._seq = seed
        else:
            self._seq = np.random.SeedSequence(seed)
        self.tag = tag
        self._g = np.random.default_rng(self._seq)
        self._counter = 0
        # A short, stable fingerprint of this stream, used to tag ids so rows
        # from different streams can never collide.
        #
        # It must include spawn_key, not just entropy: SeedSequence.spawn()
        # keeps the parent's entropy and distinguishes children *only* by their
        # spawn key. Fingerprinting on entropy alone gave every child the same
        # tag, so independent streams minted identical event ids and the
        # four-stream separation became unverifiable.
        ent = self._seq.entropy
        ent_tuple = tuple(ent) if isinstance(ent, (tuple, list)) else (ent,)
        fingerprint = hash((ent_tuple, tuple(self._seq.spawn_key)))
        self.stream_id = f"{abs(fingerprint) % 10**8:08d}"

    @property
    def seed(self) -> int:
        ent = self._seq.entropy
        return int(ent if not isinstance(ent, tuple) else ent[0])

    def spawn(self, tag: str) -> "Rng":
        """An independent child stream, derived via SeedSequence.spawn()."""
        (child_seq,) = self._seq.spawn(1)
        return Rng(child_seq, tag=f"{self.tag}/{tag}")

    def uid(self, prefix: str) -> str:
        """Ids carry the stream tag, so a row's provenance is visible and
        cross-stream contamination is detectable rather than invisible."""
        self._counter += 1
        return f"{prefix}-{self.stream_id}-{self._counter}"

    # -- sampling ----------------------------------------------------------
    def choice(self, options, weights=None):
        if weights is not None:
            weights = np.asarray(weights, dtype=float)
            weights = weights / weights.sum()
        idx = self._g.choice(len(options), p=weights)
        return options[idx]

    def weighted_key(self, mapping: dict[str, float]) -> str:
        keys = list(mapping.keys())
        return self.choice(keys, [mapping[k] for k in keys])

    def poisson(self, mean: float) -> int:
        return int(self._g.poisson(mean))

    def uniform(self, lo: float, hi: float) -> float:
        return float(self._g.uniform(lo, hi))

    def integers(self, lo: int, hi: int) -> int:
        return int(self._g.integers(lo, hi))

    def normal(self, mu: float, sigma: float) -> float:
        return float(self._g.normal(mu, sigma))

    def exponential(self, scale: float) -> float:
        return float(self._g.exponential(scale))

    def amount_from_bands(self, bands: list[tuple]) -> float:
        weights = [b[2] for b in bands]
        band = self.choice(bands, weights)
        return round(self.uniform(band[0], band[1]), 2)

    def jittered_time(self, base: datetime, max_seconds: float) -> datetime:
        return base + timedelta(seconds=self.uniform(0, max_seconds))
