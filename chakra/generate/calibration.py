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
