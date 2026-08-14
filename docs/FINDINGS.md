# Findings

Running log of results and, more importantly, of results that did not hold.
Every entry states what was measured, on how many seeds, and what it does not
license anyone to claim.

---

## F-001 · F11 enumeration is not evadable within its action space

**Date sealed:** first full multi-seed run after the spine corrections.
**Setup:** family F11, seeds 1000–1004, 6 generations, blended prevalence
controlled to 0.4%, network surface only, locked audit stream sealed before the
loop and scored once.

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

### The one direction that did reproduce

Probe amount evolved upward on **every** seed — final values 197, 345, 363,
491, 579 INR, against an initial range starting at 1 INR. That is a genuine,
reproducible direction: the loop consistently discovers that micro-value probes
are conspicuous and pushes them toward the legitimate amount distribution.

It bought no evasion. A reproducible search direction is not the same as a
successful evasion, and the two must not be reported as one thing.

### Why it is not evadable

Enumeration is defined by behaviour that cannot be hidden without the attack
ceasing to be enumeration: many distinct instruments unknown to the network,
concentrated on endpoints, with most attempts declining. Rotating devices splits
the device-keyed signal but leaves the acquirer-side view intact; rotating
endpoints does the reverse; raising amounts costs money per validation and
leaves both. The remaining separators are structural, not incidental.

This is consistent with the real world, where card networks report high
efficacy against enumeration and have shipped dedicated detectors for it.

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
