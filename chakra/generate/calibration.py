"""Lane C — India calibration constants.

These are aggregate figures from public NPCI/RBI reporting used only to shape
the *distributions* of the simulated legit background (amount bands, rail mix,
merchant categories, approval rates, geography). They are aggregates, never
labelled rows, and are never used as detection ground truth.

Every constant here is a public aggregate or a defensible modelling choice, not
a claimed transaction-level fact. Where a value is a modelling assumption rather
than a sourced figure it is marked ASSUMPTION so it is never mistaken for data.
"""

from __future__ import annotations

# Rail mix for retail digital payments. UPI dominates Indian retail volume;
# the split below is a modelling simplification across the rails Chakra
# simulates, not an exact published breakdown. ASSUMPTION (order-of-magnitude
# consistent with UPI being the large majority of retail digital volume).
RAIL_MIX = {
    "upi": 0.82,
    "card": 0.13,
    "aeps": 0.03,
    "agentic": 0.02,
}

# The rails the background generator can actually emit today. AePS and agentic
# traffic arrive with families F12 and F10; until then, sampling RAIL_MIX
# directly would silently fold their share into UPI and the emitted mix would
# not match the documented one. Renormalising over implemented rails keeps the
# constant and the behaviour honest, and a test asserts the emitted mix matches
# this — not the aspirational one.
IMPLEMENTED_RAILS = ("upi", "card")
RAIL_MIX_IMPLEMENTED = {
    r: RAIL_MIX[r] / sum(RAIL_MIX[x] for x in IMPLEMENTED_RAILS) for r in IMPLEMENTED_RAILS
}

# Share of consumers holding a card. Set above the card rail share so the mix is
# not capped by instrument availability: a consumer with no card can never
# contribute a card transaction. ASSUMPTION.
CARD_OWNERSHIP_RATE = 0.80

# Instrument churn in the genuine population.
#
# Without churn, every consumer uses one instrument for the whole window, so
# after warm-up essentially no legitimate transaction presents an unseen
# instrument — while every enumerated card is unseen by construction. That made
# "never seen this instrument" a ~98%-precise fraud flag and rendered F11
# trivially detectable for reasons that have nothing to do with fraud.
#
# Real card populations churn constantly: new customers arrive, cards are
# reissued after expiry or compromise, people add a second card, and guest
# checkouts present instruments no merchant has seen. A detector that treated
# instrument novelty as near-certain fraud would decline every new customer.
#
# ASSUMPTION: share of consumers who acquire an additional instrument partway
# through the window, and share who begin transacting only partway through
# (i.e. arrive as new customers).
INSTRUMENT_CHURN_RATE = 0.25
LATE_ARRIVAL_RATE = 0.15

# Fraction of the simulated interval reserved as warm-up before any attack may
# begin.
#
# Without it, attacks landed in the first day while genuine traffic ran on for
# months, so only ~20 genuine card decisions existed before the first fraud and
# 0% of fraud rows had instrument history against 99% of genuine ones. A model
# can score that perfectly by learning "early, unfamiliar world" — a property of
# the schedule, not of fraud. Attacks are now confined to the post-warm-up
# interval and spread across it.
WARMUP_FRACTION = 0.35

# What evasion costs the attacker, in rupees.
#
# Rotation used to be free: an attacker could burn a device every probe and pay
# nothing for it, which is not the trade a real card tester faces. Burner
# handsets and freshly-stood-up merchant endpoints are acquired assets, and
# charging for them is what turns "rotate constantly" from a dominant strategy
# into a decision. ASSUMPTION — order-of-magnitude only.
DEVICE_ACQUISITION_COST_INR = 400.0
ENDPOINT_ACQUISITION_COST_INR = 250.0


def rail_share_of_legit(rail: str) -> float:
    """Expected share of genuine transactions landing on `rail`.

    Needed because prevalence is controlled within the rail the detector is
    scoped to, not across the blended stream. Sizing a world for 0.4% blended
    prevalence and then evaluating card-only rows yields ~3.9% on that rail,
    since card carries roughly an eighth of the traffic — an eightfold error in
    the quantity every threshold and AUPRC is read against.

    Card share is discounted by ownership: a consumer with no card can never
    contribute a card transaction, so those consumers push their whole volume
    onto UPI.
    """
    # Pure rail mix. Who can actually transact on the rail is a separate factor,
    # applied exactly once by rail_participation_rate() — folding it in here as
    # well discounted card twice and left prevalence ~30% BELOW target, while
    # omitting it entirely left prevalence ~30% ABOVE. Two distinct quantities
    # that had been conflated in both directions.
    if rail == "card":
        return RAIL_MIX_IMPLEMENTED["card"]
    return RAIL_MIX_IMPLEMENTED["upi"]


def rail_participation_rate(rail: str) -> float:
    """Share of consumers who can transact on `rail` at all.

    The generator skips a consumer with no card, so only ~80% of the population
    ever contributes card volume. Sizing a world as if all of them did produced
    ~20% fewer genuine rows than assumed, and prevalence correspondingly higher.
    Everyone holds a VPA, so UPI participation is total.
    """
    return CARD_OWNERSHIP_RATE if rail == "card" else 1.0

# UPI transaction-type split. P2M has grown to roughly half of UPI volume.
# ASSUMPTION, order-of-magnitude.
UPI_TYPE_MIX = {
    "p2p": 0.45,
    "p2m": 0.50,
    "bill": 0.03,
    "recharge": 0.02,
}

# Amount bands in INR, (lower, upper, weight). UPI is overwhelmingly low-value;
# the long tail is thin but heavy in value. ASSUMPTION shaped to a low-value-
# dominant retail distribution.
UPI_AMOUNT_BANDS = [
    (1, 100, 0.34),
    (100, 500, 0.31),
    (500, 2000, 0.22),
    (2000, 10000, 0.10),
    (10000, 100000, 0.03),
]

CARD_AMOUNT_BANDS = [
    (50, 500, 0.20),
    (500, 2000, 0.34),
    (2000, 10000, 0.30),
    (10000, 50000, 0.13),
    (50000, 300000, 0.03),
]

# Baseline authorisation approval rate for genuine traffic. ASSUMPTION.
BASELINE_APPROVAL_RATE = 0.94

# Merchant category weights (a compact set standing in for the MCC space).
MERCHANT_CATEGORIES = {
    "grocery": 0.22,
    "food": 0.18,
    "fuel": 0.10,
    "utilities": 0.12,
    "shopping": 0.16,
    "entertainment": 0.08,
    "healthcare": 0.06,
    "transport": 0.05,
    "education": 0.03,
}

# A compact set of states/UTs with population-weighted-ish sampling weights.
# ASSUMPTION; only the relative spread matters for geo-anomaly features.
STATES = {
    "MH": 0.13, "UP": 0.16, "BR": 0.09, "WB": 0.08, "MP": 0.06,
    "TN": 0.07, "RJ": 0.06, "KA": 0.06, "GJ": 0.05, "AP": 0.04,
    "OR": 0.03, "TG": 0.03, "KL": 0.03, "JH": 0.03, "AS": 0.03,
    "PB": 0.02, "CG": 0.02, "HR": 0.02, "DL": 0.02, "OTHER": 0.03,
}

# Genuine consumers make on the order of a few UPI transactions a day.
# ASSUMPTION: per-consumer daily transaction rate (Poisson mean).
CONSUMER_DAILY_TXN_MEAN = 2.4

# Fraud prevalence in the *legit background* is zero by construction: the
# background is genuine traffic, and fraud is injected by the attack families
# at a controlled prevalence set per experiment. This constant documents the
# target blended prevalence the loop aims for when mixing attacks in.
TARGET_BLENDED_FRAUD_PREVALENCE = 0.004  # 0.4%

# A mule VPA is an acquired asset: a recruited or purchased account plus the
# identity behind it. Fan-in is the loudest signal such a handle produces, and
# spreading victims across more handles is the only way to suppress it — so a
# free handle would make low fan-in a costless evasion. ASSUMPTION.
MULE_VPA_ACQUISITION_COST_INR = 1500.0

# What a confirmed-live card is worth to a card tester. The probe that validates
# it moves a rupee or two; the asset created is the card itself, which is what
# gets sold on. Valuing a burst at the probe amounts would make every cost
# dominate it and misrepresent the economics entirely. ASSUMPTION.
VALIDATED_CARD_VALUE_INR = 800.0

# Rate at which genuine consumers pay someone they have never paid before.
#
# This exists because the genuine payee population used to be CLOSED: each
# consumer's circle of merchants and peers was drawn once at world build and
# never grew, so genuine novelty was a fixed per-lifetime budget of a few
# events. World LENGTH, meanwhile, is derived from the prevalence target — the
# lower the prevalence, the longer the world must run to dilute the attacks.
#
# The two together produce a pure artifact. Driving prevalence to 0.4% stretches
# the world past a year, so the genuine novelty RATE decays toward zero while
# every fraud row is novel by construction. An adversarial audit measured the
# consequence directly: holding the attacks identical and varying only
# prevalence, detector AUC climbed from 0.941 to 0.977 — the model looking better
# purely because the world got longer.
#
# INSTRUMENT_CHURN_RATE did not help: it is a per-lifetime coin flip, so it too
# evaporates as the world lengthens. Novelty has to be a RATE.
#
# ASSUMPTION: share of genuine transactions that go to a first-time payee. Real
# consumers keep discovering shops, services and people indefinitely.
NEW_PAYEE_DISCOVERY_RATE = 0.06

# Share of merchants that open DURING the simulated window rather than existing
# before it. A closed merchant pool cannot supply first-time payees forever.
# ASSUMPTION.
MERCHANT_ARRIVAL_SHARE = 0.35
