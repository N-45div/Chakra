"""F10 — the mandate layer passes; behaviour is all that remains.

The family's premise is that manipulation happens upstream of the signed
protocol, so every consistency check the mandate layer runs passes for fraud
rows exactly as it does for genuine ones. These tests pin that premise: if a
future edit breaks cart/payment/auth consistency, or lets fake agents differ
from genuine ones AS ENTITIES, the family stops testing what it claims.
"""

from datetime import datetime

import numpy as np

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.background import generate_background
from chakra.generate.population import build_population
from chakra.generate.rng import Rng
from chakra.schema.events import EventType, Family, Label, Rail, Surface
from chakra.schema.features import build_matrix

WORLD = datetime(2026, 2, 1)
FAM = ATTACK_FAMILIES["F10"]


def _world(seed=1000, n_ep=3):
    rng = Rng(seed)
    pop = build_population(rng, n_consumers=200, n_merchants=20, world_start=WORLD)
    ev = FAM.emit(rng, pop, FAM.default_params(), start=datetime(2026, 2, 1, 6), n_episodes=n_ep)
    return rng, pop, ev


def test_all_rows_are_agentic_rail_fraud():
    _, _, ev = _world()
    assert ev
    assert all(e.rail is Rail.AGENTIC for e in ev)
    assert all(e.family is Family.F10 for e in ev)


def test_mandate_layer_passes_for_every_fraud_row():
    """Intent, cart, payment and authorisation must agree — the policy checks
    of contract §4 cannot be the thing that catches this family."""
    _, _, ev = _world(n_ep=5)
    by_ep: dict[str, dict[str, list]] = {}
    for e in ev:
        if e.event_type in (
            EventType.AGENT_INTENT_DECLARED,
            EventType.AGENT_CART_BUILT,
            EventType.AGENT_PAYMENT_PRESENTED,
            EventType.TXN_AUTH_REQUESTED,
        ):
            step = {
                EventType.AGENT_INTENT_DECLARED: "intent",
                EventType.AGENT_CART_BUILT: "cart",
                EventType.AGENT_PAYMENT_PRESENTED: "payment",
                EventType.TXN_AUTH_REQUESTED: "auth",
            }[e.event_type]
            by_ep.setdefault(e.episode_id, {}).setdefault(step, []).append(e)
    inconsistencies = []
    for steps in by_ep.values():
        for e in steps.get("payment", []) + steps.get("auth", []):
            if float(e.payload["amount_inr"]) != float(e.payload["cart_total_inr"]):
                inconsistencies.append((e.episode_id, "presented", "amount != cart_total"))
        declared = float(steps["intent"][0].payload["cart_total_inr"])
        if abs(declared - float(steps["auth"][0].payload["amount_inr"])) > 1e-9:
            inconsistencies.append((e.episode_id, "intent", "declared != authorised"))
        for name in ("cart", "payment", "auth"):
            for e in steps.get(name, []):
                if e.payload["counterparty_id"] != steps["intent"][0].payload["counterparty_id"]:
                    inconsistencies.append((e.episode_id, name, "merchant swapped after intent"))
    assert not inconsistencies, f"mandate layer would catch its own family: {inconsistencies[:5]}"


def test_agent_identity_is_entity_indistinguishable_from_genuine():
    """Fake agents are registered through the same door as real ones. If only
    honest agents were directory-listed, registry_entry would be a free flag."""
    rng = Rng(31)
    pop = build_population(rng, n_consumers=150, n_merchants=15, world_start=WORLD)
    bg = generate_background(rng, pop, start=WORLD, days=0.5, only_rail="agentic")
    genuine = {e.payload.get("agent_id") for e in bg if e.payload.get("agent_id")}
    _, pop2, ev = _world(seed=31, n_ep=4)
    fake_ids = {e.payload["agent_id"] for e in ev if e.payload.get("agent_id")}
    fake_agents = [pop2.agents[a] for a in fake_ids]
    genuine_agents = [pop.agents[a] for a in genuine]
    assert fake_agents and genuine_agents
    assert all(a.registry_entry for a in fake_agents)
    assert all(a.registry_entry for a in genuine_agents)


def test_protocol_precedes_the_authorisation_request():
    _, _, ev = _world()
    auth_ts = {}
    proto_ts = []
    for e in ev:
        if e.event_type is EventType.TXN_AUTH_REQUESTED:
            auth_ts[e.episode_id] = e.ts
        elif e.event_type in (EventType.AGENT_INTENT_DECLARED, EventType.AGENT_CART_BUILT):
            proto_ts.append((e.episode_id, e.ts))
    assert auth_ts
    late = [t for ep, t in proto_ts if t >= auth_ts[ep]]
    assert not late, "protocol events fired at/after their own authorisation request"


def test_infrastructure_cost_reacts_to_rotation():
    p_rotating = FAM.default_params()
    p_rotating["victims_per_agent"] = 1
    p_loyal = FAM.default_params()
    p_loyal["victims_per_agent"] = 25
    c_rot = FAM.infrastructure_cost(p_rotating, attempts=50)
    c_loo = FAM.infrastructure_cost(p_loyal, attempts=50)
    assert c_rot > c_loo > 0


def test_scoped_matrix_yields_clean_rows_and_reads_agent_keys():
    rng = Rng(55)
    pop = build_population(rng, n_consumers=120, n_merchants=12, world_start=WORLD)
    log = generate_background(rng, pop, start=WORLD, days=1.5, only_rail="agentic")
    log.extend(FAM.emit(rng, pop, FAM.default_params(), start=datetime(2026, 2, 2, 6), n_episodes=6))
    X, y, meta = build_matrix(log, Surface.NETWORK, rail=Rail.AGENTIC)
    assert y.sum() > 0
    assert np.isfinite(X.values).all(), "feature matrix contains NaN/inf"
    assert set(meta["rail"]) == {"agentic"}
    # fan-out feature must actually fire on the injected agents
    from chakra.generate.attacks import ATTACK_FAMILIES as AF

    fam_rows = meta[meta["family"] == "F10"]
    assert len(fam_rows) > 0
    col = X.loc[fam_rows.index, "agent_distinct_principals_24h"]
    assert (col > 1).any(), "fan-out signal never fires despite multi-victim campaigns"


def test_deterministic_given_seed():
    _, _, a = _world(seed=99, n_ep=2)
    _, _, b = _world(seed=99, n_ep=2)
    ka = [(e.event_id, e.ts) for e in a]
    kb = [(e.event_id, e.ts) for e in b]
    assert ka == kb


def test_delegate_added_never_network_visible():
    """Delegation happens in the victim's app. The network may learn agent
    provenance only through what the protocol carries forward."""
    _, _, ev = _world()
    delegates = [e for e in ev if e.event_type is EventType.DELEGATE_ADDED]
    assert delegates
    assert all(e.surface is Surface.PSP_APP for e in delegates)
