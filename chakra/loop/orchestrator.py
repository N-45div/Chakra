"""The four-stream adaptive loop.

Each generation uses four independent event streams, per the experiment
contract, so that no number is measured on data the detector trained on:

  feedback  — scored; caught/missed outcomes drive the attacker's mutation.
  training  — independent rows the detector retrains on.
  monitor   — fresh rows, never trained on; source of the pre/post recall claim.
  audit     — untouched until the very end (handled by the caller, scored once).

Streams are built from independent RNG children so they are disjoint yet
reproducible. The improvement plotted by the UI is monitor-batch recall before
vs after retraining, with legit FPR beside it — never evasion-vs-recall, which
are complements at a fixed threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from chakra.detect.detector import Detector, DetectorConfig
from chakra.generate.attacks.base import AttackFamily, AttackParams
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.loop.proposer import EvolutionaryProposer
from chakra.schema.events import EventLog, Surface
from chakra.schema.features import build_matrix


@dataclass
class LoopConfig:
    seed: int
    generations: int = 10
    pop_params: int = 12          # attacker parameter-vectors per generation
    episodes_per_param: int = 4   # attack episodes rendered per vector
    n_consumers: int = 400
    n_merchants: int = 40
    background_days: float = 3.0
    surface: Surface = Surface.NETWORK
    operating_fpr: float = 0.005
    decision_threshold_fpr: float = 0.005


@dataclass
class GenerationResult:
    generation: int
    evasion_rate: float          # share of attack episodes the detector missed (feedback)
    monitor_recall_pre: float    # recall on fresh monitor batch, before retraining
    monitor_recall_post: float   # recall on fresh monitor batch, after retraining
    monitor_fpr: float           # legit FPR on the monitor batch (post)
    novelty_recall: float        # share caught by the novelty head alone (pre)
    n_attack_episodes: int
    best_params: dict = field(default_factory=dict)
    # provenance: the event-id sets each stream produced this generation.
    # Recorded so a test can assert the four streams never overlap, rather than
    # the separation being a claim in a document.
    stream_ids: dict[str, set] = field(default_factory=dict)


class Loop:
    """Runs one seeded adaptive loop for a single family."""

    def __init__(self, family: AttackFamily, config: LoopConfig) -> None:
        self.family = family
        self.config = config
        self.root = Rng(config.seed, tag=f"loop/{family.code.value}")
        self.proposer = EvolutionaryProposer(family)
        self.detector = Detector(DetectorConfig(random_state=config.seed))
        self.results: list[GenerationResult] = []
        self._world_start = datetime(2026, 2, 1)
        self._last_stream_ids: set = set()
        self._last_feedback_ids: set = set()

    # -- stream construction ----------------------------------------------
    def _fresh_population(self, rng: Rng):
        return build_population(
            rng,
            n_consumers=self.config.n_consumers,
            n_merchants=self.config.n_merchants,
            world_start=self._world_start,
        )

    def _build_stream(self, rng: Rng, params_list: list[AttackParams]) -> EventLog:
        """A stream = fresh legit background + attacks from the given params."""
        pop = self._fresh_population(rng)
        log = generate_background(rng, pop, start=self._world_start, days=self.config.background_days)
        for params in params_list:
            events = self.family.emit(
                rng, pop, params,
                start=self._world_start + timedelta(hours=rng.uniform(1, self.config.background_days * 20)),
                n_episodes=self.config.episodes_per_param,
            )
            log.extend(events)
        return log

    def _matrix(self, log: EventLog):
        return build_matrix(log, self.config.surface)

    # -- one generation ----------------------------------------------------
    def _seed_detector(self, rng: Rng, params_list: list[AttackParams]) -> None:
        """Initial fit so generation 0 has a real (if weak) detector."""
        log = self._build_stream(rng.spawn("seedfit"), params_list)
        X, y, _ = self._matrix(log)
        self.detector.fit(X, y)

    def _evasion_per_param(
        self, rng: Rng, params_list: list[AttackParams], threshold: float
    ) -> list[tuple[AttackParams, float]]:
        """Score each param vector's attacks on the feedback stream; return
        (params, evasion_rate) where evasion = fraction of that vector's fraud
        decision-events scoring below threshold."""
        out: list[tuple[AttackParams, float]] = []
        seen: set = set()
        for i, params in enumerate(params_list):
            log = self._build_stream(rng.spawn(f"fb{i}"), [params])
            features, y, meta = self._matrix(log)
            seen |= set(meta["event_id"]) if len(meta) else set()
            if y.sum() == 0:
                out.append((params, 0.0))
                continue
            scores = self.detector.score(features)
            fraud = y.values == 1
            missed = (scores[fraud] < threshold).mean()
            out.append((params, float(missed)))
        self._last_feedback_ids = seen
        return out

    def _monitor_recall(self, rng: Rng, params_list: list[AttackParams], threshold: float, tag: str = "mon"):
        """Recall + legit FPR + novelty-head recall on a fresh monitor stream.

        Monitor data is measurement only: it never touches the detector's fit,
        the proposer's fitness, the operating threshold, or the fusion weights.
        """
        log = self._build_stream(rng.spawn(tag), params_list)
        X, y, meta = self._matrix(log)
        self._last_stream_ids = set(meta["event_id"]) if len(meta) else set()
        if y.sum() == 0:
            return 0.0, 0.0, 0.0
        scores = self.detector.score(X)
        nov = self.detector.novelty(X)
        fraud = y.values == 1
        legit = y.values == 0
        recall = float((scores[fraud] >= threshold).mean())
        fpr = float((scores[legit] >= threshold).mean()) if legit.sum() else 0.0
        nov_thr = np.quantile(nov[legit], 0.99) if legit.sum() else 1.0
        novelty_recall = float((nov[fraud] >= nov_thr).mean())
        return recall, fpr, novelty_recall

    def _threshold(self, rng: Rng, params_list: list[AttackParams]) -> float:
        """Operating threshold = quantile of legit scores at the target FPR,
        computed on a calibration stream separate from training and monitor."""
        log = self._build_stream(rng.spawn("cal"), params_list)
        features, y, _ = self._matrix(log)
        scores = self.detector.score(features)
        legit = scores[y.values == 0]
        if len(legit) == 0:
            return 0.5
        return float(np.quantile(legit, 1.0 - self.config.decision_threshold_fpr))

    def run(self) -> list[GenerationResult]:
        rng = self.root
        params_list = self.proposer.initial(rng.spawn("init"), self.config.pop_params)
        self._seed_detector(rng, params_list)

        for gen in range(self.config.generations):
            provenance: dict[str, set] = {}

            # threshold calibrated on its own stream — never on monitor data
            threshold = self._threshold(rng, params_list)

            # measure BEFORE retraining, on a fresh monitor batch
            pre_recall, _, novelty_recall = self._monitor_recall(
                rng, params_list, threshold, tag=f"mon_pre{gen}"
            )
            provenance["monitor_pre"] = self._last_stream_ids

            # feedback: which params evaded -> fitness for the proposer
            scored = self._evasion_per_param(rng, params_list, threshold)
            provenance["feedback"] = self._last_feedback_ids
            evasion = float(np.mean([s for _, s in scored]))

            # train the detector on an INDEPENDENT training stream
            train_log = self._build_stream(rng.spawn(f"train{gen}"), params_list)
            x_train, y_train, train_meta = self._matrix(train_log)
            provenance["training"] = set(train_meta["event_id"]) if len(train_meta) else set()
            self.detector.fit(x_train, y_train)

            # measure AFTER retraining, on ANOTHER fresh monitor batch
            post_recall, post_fpr, _ = self._monitor_recall(
                rng, params_list, threshold, tag=f"mon_post{gen}"
            )
            provenance["monitor_post"] = self._last_stream_ids

            best = max(scored, key=lambda t: t[1])[0] if scored else {}
            self.results.append(
                GenerationResult(
                    generation=gen,
                    evasion_rate=evasion,
                    monitor_recall_pre=pre_recall,
                    monitor_recall_post=post_recall,
                    monitor_fpr=post_fpr,
                    novelty_recall=novelty_recall,
                    n_attack_episodes=self.config.pop_params * self.config.episodes_per_param,
                    best_params=dict(best),
                    stream_ids=provenance,
                )
            )

            # attacker adapts for the next generation
            params_list = self.proposer.next_generation(
                rng.spawn(f"evolve{gen}"), scored, self.config.pop_params
            )

        return self.results
