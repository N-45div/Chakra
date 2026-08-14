"""The four-stream adaptive loop.

Each generation uses four independent event streams so that no number is
measured on data the detector trained on:

  calibration — sets the operating threshold at the target FPR.
  feedback    — scored; caught/missed outcomes drive the attacker's mutation.
  training    — independent rows the detector retrains on.
  monitor     — a FROZEN batch scored before and after retraining.
  audit       — built once, never touched by the loop, scored at the very end.

Three corrections the first audit forced, each of which invalidated a number
the earlier version reported:

1. The monitor batch is now the SAME batch before and after retraining. Scoring
   two different batches confounds the improvement with batch variance; a paired
   comparison on frozen data is the only way the delta means anything. Neither
   batch is ever trained on, so reusing it costs nothing.

2. The threshold is RECALIBRATED for the retrained model. Previously the post
   measurement reused the pre model's threshold, so "recall 1.000" was being
   read at whatever FPR that stale cut happened to land on — 1.91% in one
   generation, nearly 4x the intended alert budget. Both models are now cut at
   the same target FPR on their own calibration data, which is the only way the
   two recalls are comparable.

3. Fitness is EPISODE-LEVEL and yield-aware. Row-level evasion rewarded
   abandoning a burst after three probes: fewer rows, less accumulated history,
   higher apparent evasion — while achieving almost nothing. An attacker is
   scored on cards successfully validated without the episode being caught.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np

from chakra.detect.detector import Detector, DetectorConfig
from chakra.generate import calibration as C  # noqa: N812
from chakra.generate.attacks.base import AttackFamily, AttackParams
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.loop.proposer import EvolutionaryProposer
from chakra.schema.events import EventLog, EventType, Surface
from chakra.schema.features import build_matrix


@dataclass
class LoopConfig:
    seed: int
    generations: int = 10
    pop_params: int = 12
    episodes_per_param: int = 1
    n_consumers: int = 400
    n_merchants: int = 40
    # Attacks are spread across this span; the background's actual duration is
    # derived from the prevalence target, not set directly.
    world_span_days: float = 3.0
    surface: Surface = Surface.NETWORK
    target_fpr: float = 0.005
    # blended fraud prevalence in every stream. Attack volume is scaled to hit
    # this rather than left to whatever the parameters happen to emit — an
    # uncontrolled prevalence made an earlier smoke stream ~25% fraud, which
    # makes AUPRC and every threshold meaningless.
    target_prevalence: float = C.TARGET_BLENDED_FRAUD_PREVALENCE


@dataclass
class EpisodeOutcome:
    episode_id: str
    caught: bool
    cards_validated: int   # live cards confirmed = attacker yield
    probes: int            # attempts made = attacker cost


@dataclass
class GenerationResult:
    generation: int
    episode_evasion: float       # share of attack EPISODES not caught
    attacker_yield: float        # mean validated cards per uncaught episode
    monitor_recall_pre: float    # frozen monitor batch, pre-retrain, @target FPR
    monitor_recall_post: float   # same frozen batch, post-retrain, @target FPR
    monitor_fpr_pre: float
    monitor_fpr_post: float
    prevalence: float
    n_episodes: int
    best_params: dict = field(default_factory=dict)
    stream_ids: dict[str, set] = field(default_factory=dict)


class Loop:
    def __init__(self, family: AttackFamily, config: LoopConfig) -> None:
        self.family = family
        self.config = config
        self.root = Rng(config.seed, tag=f"loop/{family.code.value}")
        self.proposer = EvolutionaryProposer(family)
        self.detector = Detector(DetectorConfig(random_state=config.seed))
        self.results: list[GenerationResult] = []
        self._world_start = datetime(2026, 2, 1)
        self._audit = None

    # -- stream construction ----------------------------------------------
    def _build_stream(self, rng: Rng, params_list: list[AttackParams]) -> EventLog:
        """Attacks first, then legitimate background sized to hit the target
        blended prevalence.

        The order matters. Generating a fixed background and then topping up with
        whole attack episodes cannot hit a low prevalence: one episode is 3-60
        rows, so in a small world the smallest possible injection already
        overshoots — an early smoke stream ran ~25% fraud against a 0.4% target,
        which makes AUPRC and every threshold uninterpretable. Emitting the
        attacks first and then scaling the world to them makes the prevalence
        exact by construction.
        """
        pop = build_population(
            rng,
            n_consumers=self.config.n_consumers,
            n_merchants=self.config.n_merchants,
            world_start=self._world_start,
        )

        attack_events = []
        for params in params_list:
            attack_events.extend(
                self.family.emit(
                    rng,
                    pop,
                    params,
                    start=self._world_start
                    + timedelta(hours=rng.uniform(1, self.config.world_span_days * 20)),
                    n_episodes=self.config.episodes_per_param,
                )
            )
        n_fraud = sum(1 for e in attack_events if e.event_type is EventType.TXN_INITIATED)

        p = self.config.target_prevalence
        need_legit = int(round(n_fraud * (1.0 - p) / max(1e-9, p)))
        per_consumer_day = max(0.1, C.CONSUMER_DAILY_TXN_MEAN)
        days = max(0.5, need_legit / (self.config.n_consumers * per_consumer_day))

        log = generate_background(rng, pop, start=self._world_start, days=days)
        log.extend(attack_events)
        return log

    def _matrix(self, log: EventLog):
        return build_matrix(log, self.config.surface)

    def _calibrate(self, rng: Rng, params_list: list[AttackParams]) -> float:
        """Operating threshold at the target FPR, on its own calibration stream.
        Recomputed for whichever model is currently fitted."""
        log = self._build_stream(rng.spawn("cal"), params_list)
        features, y, _ = self._matrix(log)
        scores = self.detector.score(features)
        legit = scores[y.values == 0]
        if len(legit) == 0:
            return 0.5
        return float(np.quantile(legit, 1.0 - self.config.target_fpr))

    # -- measurement -------------------------------------------------------
    @staticmethod
    def _score_frozen(detector, frozen, threshold):
        features, y, _ = frozen
        scores = detector.score(features)
        fraud = y.values == 1
        legit = y.values == 0
        recall = float((scores[fraud] >= threshold).mean()) if fraud.sum() else 0.0
        fpr = float((scores[legit] >= threshold).mean()) if legit.sum() else 0.0
        return recall, fpr

    def _episode_outcomes(
        self, rng: Rng, params: AttackParams, threshold: float
    ) -> list[EpisodeOutcome]:
        """Run one parameter vector and score it at the episode level.

        An episode counts as caught if ANY of its transactions is flagged — a
        real fraud team that catches one probe investigates the burst. Yield is
        the number of live cards confirmed, which is what the attacker is
        actually trying to obtain.
        """
        log = self._build_stream(rng, [params])
        features, y, meta = self._matrix(log)
        if y.sum() == 0:
            return []
        scores = self.detector.score(features)
        flagged = scores >= threshold

        # authorised fraud probes = validated cards (attacker yield)
        validated: dict[str, int] = {}
        for e in log:
            if (
                e.event_type is EventType.TXN_AUTHORISED
                and e.episode_id
                and e.label is not None
                and e.label.value == "fraud"
            ):
                validated[e.episode_id] = validated.get(e.episode_id, 0) + 1

        out: list[EpisodeOutcome] = []
        fraud_meta = meta[y.values == 1]
        for ep, grp in fraud_meta.groupby("episode_id"):
            idx = grp.index.to_numpy()
            out.append(
                EpisodeOutcome(
                    episode_id=str(ep),
                    caught=bool(flagged[idx].any()),
                    cards_validated=validated.get(ep, 0),
                    probes=len(idx),
                )
            )
        return out

    @staticmethod
    def _fitness(outcomes: list[EpisodeOutcome]) -> float:
        """Yield-aware fitness: cards validated while staying uncaught, per
        episode. Abandoning after three probes no longer wins — it evades, but
        it validates almost nothing, which is the real attacker's trade-off."""
        if not outcomes:
            return 0.0
        return float(
            np.mean([0.0 if o.caught else float(o.cards_validated) for o in outcomes])
        )

    # -- main --------------------------------------------------------------
    def build_locked_audit(self, params_list: list[AttackParams]):
        """Seal an audit stream from its own dedicated seed branch.

        Built before the loop starts and never read by it. Scored exactly once,
        by score_locked_audit(), after all generations are complete.
        """
        from chakra.evaluate.audit import seal_audit

        audit_rng = Rng(self.config.seed + 10_000_000, tag="audit")
        log = self._build_stream(audit_rng, params_list)
        features, y, meta = self._matrix(log)
        self._audit = seal_audit(
            features,
            y,
            meta,
            seed=self.config.seed,
            family=self.family.code.value,
            created_at=self._world_start,
        )
        return self._audit

    def score_locked_audit(self, rng: Rng, params_list: list[AttackParams]):
        """The single, final look at the audit stream."""
        from chakra.evaluate.metrics import evaluate

        if self._audit is None:
            raise RuntimeError("no locked audit stream was built")
        self._audit.verify()
        threshold = self._calibrate(rng, params_list)
        scores = self.detector.score(self._audit.features)
        bundle = evaluate(
            self._audit.labels.values,
            scores,
            self._audit.meta,
            operating_fpr=self.config.target_fpr,
        )
        return bundle, threshold

    def run(self) -> list[GenerationResult]:
        rng = self.root
        params_list = self.proposer.initial(rng.spawn("init"), self.config.pop_params)

        # initial fit so generation 0 has a real (if weak) detector
        seed_log = self._build_stream(rng.spawn("seedfit"), params_list)
        x0, y0, _ = self._matrix(seed_log)
        self.detector.fit(x0, y0)

        for gen in range(self.config.generations):
            provenance: dict[str, set] = {}

            # ONE frozen monitor batch, scored twice
            monitor_log = self._build_stream(rng.spawn(f"mon{gen}"), params_list)
            frozen = self._matrix(monitor_log)
            provenance["monitor"] = set(frozen[2]["event_id"])
            prevalence = float(frozen[1].mean())

            thr_pre = self._calibrate(rng, params_list)
            recall_pre, fpr_pre = self._score_frozen(self.detector, frozen, thr_pre)

            # feedback -> episode-level, yield-aware fitness
            scored: list[tuple[AttackParams, float]] = []
            fb_ids: set = set()
            all_outcomes: list[EpisodeOutcome] = []
            for i, params in enumerate(params_list):
                fb_rng = rng.spawn(f"fb{gen}_{i}")
                outcomes = self._episode_outcomes(fb_rng, params, thr_pre)
                all_outcomes.extend(outcomes)
                fb_ids |= {o.episode_id for o in outcomes}
                scored.append((params, self._fitness(outcomes)))
            provenance["feedback_episodes"] = fb_ids

            ep_evasion = (
                float(np.mean([0.0 if o.caught else 1.0 for o in all_outcomes]))
                if all_outcomes
                else 0.0
            )
            yield_uncaught = [float(o.cards_validated) for o in all_outcomes if not o.caught]
            attacker_yield = float(np.mean(yield_uncaught)) if yield_uncaught else 0.0

            # retrain on an INDEPENDENT training stream
            train_log = self._build_stream(rng.spawn(f"train{gen}"), params_list)
            x_train, y_train, train_meta = self._matrix(train_log)
            provenance["training"] = set(train_meta["event_id"])
            self.detector.fit(x_train, y_train)

            # SAME frozen batch, threshold recalibrated for the NEW model
            thr_post = self._calibrate(rng, params_list)
            recall_post, fpr_post = self._score_frozen(self.detector, frozen, thr_post)

            best = max(scored, key=lambda t: t[1])[0] if scored else {}
            self.results.append(
                GenerationResult(
                    generation=gen,
                    episode_evasion=ep_evasion,
                    attacker_yield=attacker_yield,
                    monitor_recall_pre=recall_pre,
                    monitor_recall_post=recall_post,
                    monitor_fpr_pre=fpr_pre,
                    monitor_fpr_post=fpr_post,
                    prevalence=prevalence,
                    n_episodes=len(all_outcomes),
                    best_params=dict(best),
                    stream_ids=provenance,
                )
            )

            params_list = self.proposer.next_generation(
                rng.spawn(f"evolve{gen}"), scored, self.config.pop_params
            )

        return self.results
