# Findings

Running log of results and, more importantly, of results that did not hold.
Every entry states what was measured, on how many seeds, and what it does not
license anyone to claim.

---

## F-001 · No uncaught F11 episode observed in a development pilot

> **Status: DOWNGRADED.** This entry originally read "F11 enumeration is not
> evadable within its action space". That is a stronger claim than a five-seed,
> six-generation search can support, and part of its supporting evidence was
> false (see F-003). It is now recorded as a development pilot, not a result.

**Setup:** family F11, seeds 1000–1004, 6 generations, blended prevalence
controlled to 0.4%, network surface only, audit stream sealed before the loop.

**This run does not satisfy the registered contract**, which specifies 20 seeds
and 10 generations. It is a development pilot and nothing in it is submission-safe.

The only defensible statement of the outcome:

> No fully uncaught F11 episode was observed during this five-seed,
> six-generation development search.

Not "F11 is not evadable." Absence of an observed evasion in a small search is
not a property of the family.

### Result

| Measure | Median across 5 seeds | IQR |
|---|---|---|
| Final episode evasion | **0.000** | 0.000 – 0.000 |
| Final attacker yield (cards validated while uncaught) | **0.000** | 0.000 – 0.000 |
| Monitor recall, pre-retrain | 0.966 | 0.960 – 0.971 |
| Monitor recall, post-retrain | 1.000 | 1.000 – 1.000 |
| Audit AUPRC @ 0.4% prevalence | 0.943 | 0.943 – 0.950 |
| Audit recall @ 0.5% FPR | 0.946 | 0.939 – 0.948 |

**The attacker never once got away with a burst, on any seed.**

This held after the attacker's action space was widened specifically to give it
the moves a real card tester has: device rotation, endpoint rotation, and a
probe-amount range reaching into the genuine amount distribution. Widening the
action space changed the evolved parameters. It did not change the outcome.

### Why no conclusion about evadability follows

Enumeration *is* plausibly hard to hide — many instruments unknown to the
network, concentrated on endpoints, mostly declining. But this run cannot
establish that, for three reasons beyond its size:

- Fitness was identically zero everywhere, so the search never moved (F-003).
  A search that never explored cannot report that nothing was found.
- Positives and negatives came from different rails (F-004), so the separation
  measured is partly between card and UPI behaviour rather than between fraud
  and genuine card traffic.
- The attacker's utility zeroes an entire episode on a single late alert
  (F-005), so partially-successful bursts are scored as total failures.

### What this does NOT license

- It does not show the detector is good in general. It shows one family is loud.
- It does not show the adaptive loop works. **A loop with zero evasion has a flat
  fitness landscape and therefore no gradient** — the parameter drift seen on any
  single seed is noise, not learning.
- It does not transfer to any other family, rail, or dataset.

### Consequence for the build

**F11 is a good machinery test and a poor loop showcase.** The loop can only
demonstrate co-evolution on families where the attacker holds *genuine*
credentials and therefore leaves no "unknown instrument" trace: F5 (UPI
authorised push), F6 (mule networks), F8 (bust-out). Those are next, and the
tiered hold-out in the experiment contract already anticipates it — F11 was
designated the *easy* tier precisely on this expectation.

---

## F-002 · A single seed's evolved parameters were misread as a finding (retracted)

An earlier write-up stated that the attacker "discovered the real-world card
testing evasion playbook" — slow down, spread out, abandon early — from one
seed's final parameter vector.

**Retracted.** A second seed did not reproduce half of it, and the corrected
experiment showed why: episode evasion is zero, so fitness is flat, so selection
had nothing to select on and the parameters were drifting at random. The
apparent playbook was noise dressed in a plausible story.

The failure mode is worth naming because it is the one this whole project exists
to prevent: a result that *sounded* like the literature, reported from n=1,
without checking whether the mechanism that would produce it was even active.

Standing rule: no directional claim about attacker behaviour is reportable
unless it reproduces across seeds **and** the fitness signal driving it is
non-zero.

---

## F-003 · The "probe amount evolved upward" claim was false (retracted)

I reported that probe amounts evolved upward on every seed — 197, 345, 363, 491,
579 INR — and called it "a genuine, reproducible direction".

**False.** The saved per-generation artifacts show the value is identical from
generation 0 to generation 5 on all five seeds:

```
seed 1000: 491.38 → 491.38 → 491.38 → 491.38 → 491.38 → 491.38
seed 1001: 363.13 → ... unchanged
seed 1002: 344.64 → ... unchanged
seed 1003: 197.00 → ... unchanged
seed 1004: 579.12 → ... unchanged
```

Nothing evolved. Those are the initial random draws from a uniform range whose
midpoint is ~450, which is exactly the spread observed. Because every candidate
scored zero fitness, the elite selection is a stable tie and simply carries the
first initial candidate through every generation untouched.

I compared the final values against the *bound's* lower end (1 INR) instead of
against their own generation-0 values, and read a spread of random draws as a
trend. The artifacts needed to catch this were sitting in `runs/` the whole time.

This is the second retraction of a claim about attacker learning in this project
(see F-002), and the mechanism is the same both times: a story that sounded like
the literature, asserted without checking whether the process that would produce
it was running at all.

**Standing rule, strengthened:** no claim that a parameter evolved is reportable
without a generation-0 versus generation-N comparison from the saved artifacts,
on every seed, with non-zero fitness demonstrated over the same interval.

---

## F-004 · Mixed-rail training and evaluation (open defect)

The audit set for seed 1000 contains 23,628 legitimate UPI rows, 2,873
legitimate card rows, 111 card-fraud rows, and no UPI fraud at all. So **89% of
the negatives come from a rail that carries none of the positives.**

One detector is trained across both. Aggregate FPR can therefore hide
card-specific false positives entirely, and part of the measured separation is
between card and UPI behaviour rather than between fraud and genuine card
traffic. Every metric computed this way — AUPRC included — describes a mixed
population that no real deployment would score as one.

Fix: rail-scoped matrices, detectors, thresholds and audits.

---

## F-005 · Attacker utility overstates containment (open defect)

An alert on the final probe of a burst zeroes every card validated earlier in
that episode. A tester who validates forty cards and is flagged on the
forty-first is scored identically to one caught on its first attempt. Probe
count and probe value are described as attacker costs but never enter fitness at
all, and each candidate is evaluated on a single episode in its own random world,
so any future non-zero fitness will be extremely noisy.

Fix: cards validated *before the first alert*, probes and time to first alert,
probe-value cost, net utility, and replicated episodes over common background
worlds.

---

## Defects found by guardrails rather than by inspection

Recorded because each was invisible in output and would have quietly
invalidated results:

1. `available_at` sampled independently of `ts`, letting events claim to be
   observable before they happened. Caught by the Event invariant.
2. Stream fingerprints derived from `SeedSequence.entropy` alone; `spawn()`
   varies only `spawn_key`, so every independent stream minted identical event
   ids and four-stream separation was unverifiable. Caught by the separation test.
3. Authorisation outcomes emitted before their own PIN/OTP events — causally
   impossible, and fatal to F5 specifically.
4. Pre/post recall compared at different alert budgets: 1.91% FPR against a 0.5%
   target in one generation.
5. Row-level fitness rewarding early abandonment, which evades by achieving
   nothing.
6. Blended prevalence ~25% against a 0.4% target.
7. Features grouped on an internal `actor_id` that no payment network can observe.
8. `amount_vs_instrument_mean` returning a 0.0 sentinel for unseen instruments,
   which was itself a near-perfect fraud flag.
9. No instrument churn in the genuine population, making "unseen instrument" a
   ~98%-precise fraud signal for reasons unrelated to fraud.
