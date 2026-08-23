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

## F-006 · F5 produces a fitness gradient where F11 did not (preliminary)

> **Status: RETRACTED.** The evasion figures below were an artifact of the broken
> fitness function described in F-007, not a property of F5.
>
> A controlled repeat settled it — identical configuration, identical seeds, the
> corrected monetary utility as the only change:
>
> | Seed | Evasion, broken utility | Evasion, monetary utility |
> |---|---|---|
> | 1000 | 0.500 | 0.083 |
> | 1001 | 0.167 | 0.000 |
> | 1002 | 0.000 | 0.000 |
>
> **Why the broken model manufactured a gradient.** Cost was divided by 5,000
> before being subtracted from a count, so the attacker's infrastructure spend
> was effectively free and it optimised almost purely for victims defrauded.
> Rotating mule VPAs is the evasion lever in this family, and rotation was
> costing it nothing. Once a handle costs what a handle costs, spreading victims
> thinly stops paying for itself, fan-in rises, and the detector catches the
> campaigns.
>
> The honest reading is the opposite of the original claim: **when evasion is
> priced correctly, F5's apparent gradient largely disappears.** What looked like
> the loop discovering an evasion strategy was the loop exploiting a modelling
> error that handed it free evasion.
>
> This is the third retraction of a claim about attacker learning in this
> project. It is the first one caught by its own controlled experiment rather
> than by an external reviewer.

**Status: PRELIMINARY.** Three seeds, four generations. The registered contract
requires 20 seeds and 10 generations, so nothing here is reportable. It is
recorded because it is the first evidence that the adaptive loop can move at all.

**Setup:** family F5 (UPI authorised push), UPI rail, prevalence 0.42–0.43%,
frozen thresholds, four-stream loop, two fitness replicates over shared worlds.

### What was observed

| Seed | Episode evasion by generation | Monitor recall, pre-retrain | Monitor recall, post-retrain |
|---|---|---|---|
| 1000 | 0.000 → 0.000 → **0.500** → 0.417 | 0.823 → 0.705 → 0.282 → 0.419 | 0.835 → 0.853 → 0.462 → 0.645 |
| 1001 | 0.000 → 0.000 → **0.167** → 0.167 | 0.853 → 0.700 → 0.381 → 0.556 | 0.853 → 0.800 → 0.881 → 0.500 |
| 1002 | 0.000 → 0.000 → 0.000 → 0.000 | 0.882 → 0.975 → 0.775 → 0.929 | 0.804 → 0.966 → 0.955 → 0.912 |

- **Non-zero evasion on 2 of 3 seeds.** F11 produced exactly zero on every seed
  under every configuration tried, including after its action space was widened.
- **Retraining improved monitor recall on 3 of 3 seeds** (mean post-minus-pre
  +0.141, +0.136, +0.019), measured on a frozen batch neither model trained on.

### What may and may not be said

Sayable: *in a three-seed, four-generation development pilot, F5 produced
non-zero episode evasion on two of three seeds, and retraining improved recall
on the frozen monitor batch on all three.*

Not sayable: that F5 "demonstrates co-evolution", that the loop converges, or
that any particular evolved parameter is a strategy. Seed 1002 never evaded at
all, which alone rules out a general claim, and four generations on three seeds
cannot distinguish a trend from noise.

### Why F5 behaves differently from F11

F11's signature is inseparable from the attack: many unknown instruments,
concentrated, mostly declining. F5's is not. The payer's VPA, device and PIN are
genuine and the authentication legitimately succeeds, so instrument novelty,
device velocity and decline ratio are all silent. What remains is the payer's
relationship to the payee handle — and in the emitted data, **genuine merchants
show higher fan-in (9.3) than the mule handle (8.5)**, so the mule signature does
not separate on its own. That is what leaves the attacker somewhere to hide, and
it is the precondition for the loop having anything to learn.

### Caveat carried forward

The attacker's levers all trade against yield by construction — fewer victims per
handle means buying more handles, a smaller take blends in but earns less. Whether
the loop is finding a genuine trade-off or exploiting a modelling artefact is
**not established** by this pilot and is the first thing the contract run must
examine.

---

## F-007 · Attacker utility mixed units (fixed before it produced a result)

Fitness was:

```
validated_before_alert  -  (1/5000) * probe_value_spent
```

The first term is a **count** of validated items. The second is **rupees**. The
`1/5000` was an invented bridge, so the whole expression had no consistent unit
and its behaviour depended entirely on a constant chosen by feel.

F6 is what exposed it. Mule-network cost compounds per layer: four layers with
fan-out eight implies over seven hundred mule accounts, roughly ₹1.09M, which
against a count of perhaps twenty hops produces a penalty two orders of magnitude
larger than any achievable yield. The loop would have driven straight to minimum
depth and minimum fan-out, sat in that corner, and the corner would have looked
exactly like a discovered laundering strategy.

**Fixed:** each family declares what an episode was worth in rupees, because the
same authorised row means different things. A card tester gains the live card,
not the one-rupee probe that proved it. An authorised-push scam gains the money
taken from the victim. A mule network gains the value moved through, not the hop
count — counting hops would reward long chains of tiny transfers, the opposite of
a launderer's objective. Utility is now value minus cost, both rupees, and the
bridge constant is deleted rather than retuned.

**Found by reading, not by running**, while tooling was unavailable — so no
result was ever produced under the broken model and nothing had to be retracted.
That is the first time in this project a defect of this class was caught before
rather than after it generated a number.

**Consequence:** F-006 is retracted. The controlled repeat under the corrected
utility reproduced almost none of its evasion, confirming the figures were an
artifact of the unit error rather than a property of the family.

**What survives the correction.** Two observations, both weaker and both more
trustworthy than the retracted claim:

- **Episodes bank real money before being caught.** Yield before the first alert
  ran ₹1,383–6,502 per generation on seed 1000 even with episode evasion at
  essentially zero. Binary "caught" was hiding this completely: a campaign that
  is eventually flagged has usually already extracted value, and the difference
  between catching it on victim two and victim twenty is the entire point.
- **Retraining improved monitor recall in 7 of 12 generations**, on a frozen
  batch neither model trained on. Not the 9 of 12 an earlier configuration
  suggested, and not consistent enough to call a result.

Neither is reportable. Both are the right size of claim for three seeds and four
generations.

---

## F-008 · F8 valued its own attack at zero (fixed)

Found by an adversarial review workflow, independently reproduced, and fixed.

`F8.episode_value_inr` separates nurture spend from burst extraction by reading
`payload["phase"]`. The loop collects payloads from **TXN_AUTHORISED** events —
and F8's authorised payload was hand-enumerated and dropped `phase`. The burst
filter therefore matched nothing on every parameter vector.

Measured on the family's own emitted events, through the exact call the
orchestrator makes:

```
authorised events   : 38   (0 of 38 carried `phase`)
rupees moved        : ₹17,51,450.52
episode_value_inr() : ₹0.00
```

With value identically zero and `infrastructure_cost` also zero, F8's fitness
reduced to *minus its own spend* — maximised by attacking as small and as
seldom as possible, the exact opposite of a bust-out. **Every F8 loop
generation run before this fix optimised backwards.**

The test that certified the valuation built its payloads by hand:

```python
payloads = [{"phase": "burst"}, {"phase": "nurture"}, {"phase": "burst"}]
```

so it passed green on a code path the loop can never reach — the vacuous-test
class again, this time *enabling* an accounting error rather than merely
failing to catch one.

**Fixed:** `phase` is carried onto the authorised event, and a new test
exercises the real path — emit, collect authorised payloads exactly as
`_episode_outcomes` does, and require a positive valuation. Post-fix the same
episode values at ₹13,67,280.68.

**Consequence:** F8's ten completed seeds have meaningless loop dynamics and
must be re-run. Its zero-shot LOFO number is unaffected — that path never calls
`episode_value_inr`.

---

## F-009 · F10's genuine agent population has no churn (open)

Confirmed by review, severity reduced from critical to high on verification.

Every genuine consumer is bound 1:1 to one agent for the whole world: the agent
is cached on the consumer and never rotated or shared. So
`agent_distinct_principals_24h` is a **point mass at 1.0** on every genuine row
— zero variance — and the rule `> 1` is a fraud detector with *exactly* zero
false positives, for reasons that have nothing to do with fraud.

This is the same shape as the instrument-churn defect: the genuine population
lacks a behaviour the attack necessarily exhibits. F-006 records that F5 was
only a real trade because genuine merchants had **higher** fan-in than the mule
handle. Here there is no genuine cover at all — no household, family or
comparison-shopping agent traffic.

The verifier established two limits on the claim. The declared trade *does*
exist and moves the metric in the declared direction, but it is a **cliff
rather than a gradient**: any value above 1 is instantly fatal, so the only
playable setting is exactly 1 and there is nothing for the loop to search.
And it is **not load-bearing** — ablating all three agent-identity features
still leaves recall 1.000 and AUPRC 0.897–0.924, because separation is carried
by payee and instrument novelty.

**Status: open.** F10's headline numbers stand; the claim that agent fan-out
represents a learnable rotation-economics trade does not. Fix is to give the
genuine population agent sharing and rotation.

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
