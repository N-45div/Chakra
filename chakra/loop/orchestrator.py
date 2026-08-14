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
from chakra.schema.events import EventLog, EventType, Rail, Surface
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
    # The rail this family's detector operates on. Rows, training, calibration
    # and audit are all scoped to it.
    rail: Rail = Rail.CARD
    # Independent worlds each candidate is evaluated over before selection.
    # One episode in one random world makes fitness mostly sampling error.
    fitness_replicates: int = 3
    target_fpr: float = 0.005
    # blended fraud prevalence in every stream. Attack volume is scaled to hit
    # this rather than left to whatever the parameters happen to emit — an
    # uncontrolled prevalence made an earlier smoke stream ~25% fraud, which
    # makes AUPRC and every threshold meaningless.
    target_prevalence: float = C.TARGET_BLENDED_FRAUD_PREVALENCE


@dataclass
class EpisodeOutcome:
    """Sequence-aware outcome for one attack episode.

    An earlier version recorded only `caught` and total validated cards, and
    zeroed the whole episode on any alert. That scored a tester flagged on its
    forty-first probe identically to one flagged on its first, which badly
    overstates containment: forty validated cards is a successful attack that
    happened to end. Yield is now counted strictly BEFORE the first alert, and
    the probes spent are carried so cost can enter utility.
    """

    episode_id: str
    caught: bool
    validated_before_alert: int   # yield the attacker actually keeps
    validated_total: int          # for diagnostics only
    probes_to_alert: int          # how long it survived
    probes: int                   # attempts made = attacker cost
    probe_value_spent: float      # rupees put at risk across probes


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
        n_fraud = sum(
            1
            for e in attack_events
            if e.event_type is EventType.TXN_INITIATED and e.rail is self.config.rail
        )

        # Prevalence is targeted WITHIN the scoped rail, so the world must be
        # sized by how much genuine traffic that rail actually carries.
        p = self.config.target_prevalence
        need_legit_on_rail = int(round(n_fraud * (1.0 - p) / max(1e-9, p)))
        rail_share = max(1e-6, C.rail_share_of_legit(self.config.rail.value))
        per_consumer_day_on_rail = max(0.01, C.CONSUMER_DAILY_TXN_MEAN * rail_share)
        days = max(
            0.5, need_legit_on_rail / (self.config.n_consumers * per_consumer_day_on_rail)
        )

        log = generate_background(rng, pop, start=self._world_start, days=days)
        log.extend(attack_events)
        return log

    def _matrix(self, log: EventLog):
        """Rows are scoped to the family's own rail. A card-fraud detector must
        not be trained, calibrated or audited against UPI negatives it will
        never be asked to score."""
        return build_matrix(log, self.config.surface, rail=self.config.rail)

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
        """Run one parameter vector and score it at the episode level, in order.

        An episode is 'caught' at the first flagged probe — a real fraud team
        that catches one probe investigates the burst and the tester loses the
        endpoint. Everything validated before that moment is kept; everything
        after it is not.
        """
        log = self._build_stream(rng, [params])
        features, y, meta = self._matrix(log)
        if y.sum() == 0:
            return []
        scores = self.detector.score(features)
        flagged = scores >= threshold

        # authorisation outcome per fraud probe, in time order, by episode
        authorised: dict[str, bool] = {}
        for e in log:
            if e.episode_id and e.label is not None and e.label.value == "fraud":
                if e.event_type is EventType.TXN_AUTHORISED:
                    authorised[f"{e.episode_id}|{e.payload.get('instrument_id')}"] = True

        out: list[EpisodeOutcome] = []
        fraud_meta = meta[y.values == 1].sort_values("ts")
        for ep, grp in fraud_meta.groupby("episode_id"):
            idx = grp.index.to_numpy()
            ep_flags = flagged[idx]
            alert_positions = np.flatnonzero(ep_flags)
            first_alert = int(alert_positions[0]) if alert_positions.size else len(idx)

            # Walk the episode's own events in time order, counting authorised
            # probes and tracking how many initiations have gone by, so yield
            # can be split at the first alert.
            ordered = sorted(
                (e for e in log if e.episode_id == ep), key=lambda e: e.ts
            )
            validated_before = 0
            validated_total = 0
            probe_pos = 0
            for e in ordered:
                if e.label is None or e.label.value != "fraud":
                    continue
                if e.event_type is EventType.TXN_AUTHORISED:
                    validated_total += 1
                    if probe_pos <= first_alert:
                        validated_before += 1
                elif e.event_type is EventType.TXN_INITIATED:
                    probe_pos += 1

            out.append(
                EpisodeOutcome(
                    episode_id=str(ep),
                    caught=bool(alert_positions.size),
                    validated_before_alert=validated_before,
                    validated_total=validated_total,
                    probes_to_alert=first_alert,
                    probes=len(idx),
                    probe_value_spent=float(grp["amount_inr"].sum()),
                )
            )
        return out

    @staticmethod
    def _fitness(outcomes: list[EpisodeOutcome]) -> float:
        """Net attacker utility per episode.

        Value kept = cards validated before the first alert. Cost = the probe
        value put at risk, discounted so it shapes the trade rather than
        dominating it. Both terms are needed: yield alone rewards reckless
        spraying, cost alone rewards doing nothing.
        """
        if not outcomes:
            return 0.0
        cost_weight = 1.0 / 5000.0  # rupees per unit of validated-card value
        return float(
            np.mean(
                [
                    o.validated_before_alert - cost_weight * o.probe_value_spent
                    for o in outcomes
                ]
            )
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
            rail=self.config.rail.value,
        )
        return self._audit

    def score_locked_audit(self, rng: Rng, params_list: list[AttackParams]):
        """The single, final look at the audit stream.

        The threshold is frozen on separate calibration data and passed INTO the
        metrics, so every threshold-dependent figure is read at the cut a
        deployment would actually use. Letting evaluate() derive its own cut from
        the audit labels would make the reported recall self-referential — and
        would leave the threshold recorded in the artifact unrelated to the
        numbers printed beside it, which is what an earlier version did.
        """
        from chakra.evaluate.metrics import evaluate

        if self._audit is None:
            raise RuntimeError("no locked audit stream was built")
        self._audit.claim_scoring()  # verifies the seal and consumes the one look
        threshold = self._calibrate(rng, params_list)
        scores = self.detector.score(self._audit.features)
        bundle = evaluate(
            self._audit.labels.values,
            scores,
            self._audit.meta,
            operating_fpr=self.config.target_fpr,
            threshold=threshold,
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
                # Replicate each candidate over several independent worlds.
                # A single episode in one random world makes fitness so noisy
                # that selection is mostly sampling error.
                rep_outcomes: list[EpisodeOutcome] = []
                for rep in range(self.config.fitness_replicates):
                    fb_rng = rng.spawn(f"fb{gen}_{i}_{rep}")
                    rep_outcomes.extend(self._episode_outcomes(fb_rng, params, thr_pre))
                all_outcomes.extend(rep_outcomes)
                fb_ids |= {o.episode_id for o in rep_outcomes}
                scored.append((params, self._fitness(rep_outcomes)))
            provenance["feedback_episodes"] = fb_ids

            ep_evasion = (
                float(np.mean([0.0 if o.caught else 1.0 for o in all_outcomes]))
                if all_outcomes
                else 0.0
            )
            # yield the attacker keeps, across ALL episodes — not only uncaught
            # ones, since a burst flagged late still banked what came before.
            attacker_yield = (
                float(np.mean([float(o.validated_before_alert) for o in all_outcomes]))
                if all_outcomes
                else 0.0
            )

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
