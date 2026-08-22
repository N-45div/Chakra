# Chakra — Event Ontology

Separate schemas per rail, linked by one common event ontology. There is deliberately **no merged "UPI + card" table**: a merged table would assert a cross-rail equivalence that does not exist, and would let a model borrow card-rail signal to "explain" UPI fraud.

The simulator emits **events**. Features are derived from events by the feature layer. Attacks never touch the feature layer.

---

## 1. Base event

Every event, on every rail, carries these fields.

| Field | Type | Notes |
|---|---|---|
| `event_id` | uuid | |
| `event_type` | enum | see §3 |
| `rail` | enum | `upi` \| `card` \| `aeps` \| `agentic` \| `account` |
| `ts` | datetime (UTC) | when the event occurred |
| `actor_id` | uuid | party that caused it |
| `decision_surface` | enum | `network` \| `issuer` \| `psp_app` \| `telco` — who could observe this |
| `available_at` | datetime | when this becomes observable **to that surface**; ≥ `ts` |
| `episode_id` | uuid \| null | groups events belonging to one attack or one genuine journey |
| `label` | enum \| null | `legit` \| `fraud`; family code when fraud |
| `family` | enum \| null | `F5` \| `F6` \| `F8` \| `F10` \| `F11` |

`available_at` is the load-bearing field. A screen-share flag has `decision_surface = psp_app` and an `available_at` that a network-surface model may never read. The feature layer enforces `available_at < decision_timestamp` and raises on violation.

## 2. Entities

| Entity | Key fields |
|---|---|
| `Party` | `party_id`, `party_type` (`consumer`\|`merchant`\|`agent`\|`bc_operator`), `created_at`, `kyc_level`, `home_state` |
| `Instrument` | `instrument_id`, `kind` (`card`\|`vpa`\|`account`\|`token`\|`wallet`), `owner_party_id`, `issued_at`, `psp`, `bin` (card only) |
| `Device` | `device_id`, `first_seen_at`, `os`, `is_emulator`, `sim_id`, `imei_hash` |
| `AgentIdentity` | `agent_id`, `registry_entry` (bool), `pubkey_id`, `scope_merchants`, `scope_max_amount` — F10 only |

Entities are created by the simulator's population model, calibrated to NPCI/RBI aggregates (Lane C). Attacks may create entities; they may not create features.

## 3. Event types

### 3.1 Transaction events
`txn_initiated`, `collect_requested`, `txn_auth_requested`, `txn_authorised`, `txn_declined`, `txn_settled`, `txn_reversed`

Payload: `instrument_id`, `counterparty_id`, `amount_inr`, `mcc`, `channel`, `initiation_mode` (`push`\|`collect`\|`qr_intent`\|`pos`\|`ecom`\|`agentic`), `device_id`, `geo_state`, `decline_reason`.

`txn_auth_requested` is the single scored decision point: on UPI it can only follow the payer's PIN, on card the issuer's OTP step, on agentic the signed payment presentation. Securing the decision to that instant is what stops a model from deciding before the customer has authenticated.

`txn_initiated` and `collect_requested` stay distinct — the direction-inversion deception at the heart of F5 is only visible if a payer-initiated push and a payee-raised collect are distinguishable at the event level.

### 3.2 Authentication events
`pin_entered`, `otp_issued`, `otp_entered`, `biometric_presented`, `mandate_signed`, `device_bound`

Payload: `factor`, `outcome`, `linked_txn_id`, `surface`, `latency_ms`.

`otp_issued` → `otp_entered` latency is where relay attacks live. Do not collapse these into one event.

### 3.3 Relationship events
`beneficiary_added`, `delegate_added`, `mandate_created`, `mandate_modified`, `token_provisioned`, `account_opened`

Payload: `from_party`, `to_party`, `limit_amount`, `scope`, `consent_ref`.

These build the graph F6 depends on. Graph features must be computed **as of** `decision_timestamp` — degree over the whole dataset includes edges from the future and is a leak.

### 3.4 Dispute events
`dispute_raised`, `dispute_evidence_filed`, `dispute_resolved`

Payload: `linked_txn_id`, `reason_code`, `days_since_txn`, `outcome`.

### 3.5 Context events (non-network surfaces)
`session_started`, `session_ended`, `screen_share_started`, `remote_access_detected`, `call_started`, `call_ended`, `app_installed`

**All carry `decision_surface` of `psp_app` or `telco`.** They exist so the simulation is faithful to how the fraud actually works, and they are excluded from the default network-surface model. They enter only the labelled ablation.

### 3.6 Agent events (F10)
`agent_intent_declared`, `agent_cart_built`, `agent_payment_presented`, `agent_signature_presented`

Protocol payload (network surface, carried forward into the authorisation request):
`agent_id`, `principal_id`, `cart_total_inr`, `counterparty_id`, `item_count`, `agent_provisioned_at`.

Delegation itself (`delegate_added`) stays on `psp_app` — the network learns agent provenance only through what the signed protocol carries forward. Signature validity and Intent↔Cart consistency are **deterministic policy checks**, not model features: F10's manipulation happens upstream of the declared intent, so every check passes by construction and the model's job is the behavioural residue (agent fan-out across principals, delegate age, pacing).

## 4. Feature layer

One pipeline, applied identically to simulated and real event streams. Each feature declares:

```python
@feature(surface="network", window="10m")
def velocity_10m(events, as_of): ...
```

Rules:
1. Derived from events only. Never written by an attack.
2. Declares `surface`; excluded automatically when the model's surface budget does not include it.
3. Computed `as_of` a timestamp; may read only events with `available_at < as_of`.
4. Deterministic given (events, as_of) — no wall-clock, no RNG.

## 5. Rail schemas

Each rail projects the common ontology into its own table. Shared columns keep the ontology's names; rail-specific columns do not leak across.

- `upi_events` — adds `payer_vpa`, `payee_vpa`, `psp_handle`, `collect_flag`
- `card_events` — adds `bin`, `token_id`, `cvv_result`, `avs_result`, `three_ds_outcome`
- `aeps_events` — adds `bc_terminal_id`, `aadhaar_ref_hash`, `biometric_modality`, `liveness_score`
- `agentic_events` — adds `agent_id`, `mandate_refs`, `signature_status`
- `account_events` — adds `balance_before`, `balance_after`, `dwell_seconds`

## 6. Storage

Parquet under `data/interim/<lane>/<rail>/`, partitioned by date. The locked audit stream lives in `data/locked/` and is write-once; a test asserts its hash is unchanged between runs.

---

*Changes to this schema after the first locked-audit scoring must be recorded as dated amendments in the experiment contract.*
