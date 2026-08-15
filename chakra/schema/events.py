"""The common event ontology.

The simulator emits *events*. Features are derived from events by the feature
layer (chakra.schema.features). Attacks emit events only — they never write
features. See docs/EVENT_SCHEMA.md and docs/EXPERIMENT_CONTRACT.md.

The load-bearing field is `available_at`: when an event first becomes
observable *to its decision_surface*. A feature computed for a network-surface
model may only read events whose surface it is allowed to see AND whose
`available_at` precedes the decision timestamp. This is what stops signals the
network cannot observe at authorisation time (a screen-share flag on the
handset, a call's full duration, a future graph edge) from silently leaking in.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Iterator


class Rail(str, Enum):
    UPI = "upi"
    CARD = "card"
    AEPS = "aeps"
    AGENTIC = "agentic"
    ACCOUNT = "account"


class Surface(str, Enum):
    """Which system could observe an event at decision time."""

    NETWORK = "network"
    ISSUER = "issuer"
    PSP_APP = "psp_app"
    TELCO = "telco"


class Label(str, Enum):
    LEGIT = "legit"
    FRAUD = "fraud"


class Family(str, Enum):
    """Only the five executable families carry a code. The other eight are
    mapped in the taxonomy but never simulated, per the experiment contract."""

    F5 = "F5"   # UPI authorised-push deception
    F6 = "F6"   # mule networks
    F8 = "F8"   # credit nurture and bust-out
    F10 = "F10"  # agentic checkout manipulation
    F11 = "F11"  # enumeration / card testing


class EventType(str, Enum):
    # transaction
    TXN_INITIATED = "txn_initiated"
    # A payee-originated request for money (UPI collect). Distinct from
    # TXN_INITIATED because the direction of origination is the whole subject of
    # F5: in a push the payer starts it, in a collect the payee does, and the
    # deception is that a victim reads the second as the first.
    COLLECT_REQUESTED = "collect_requested"
    # The moment the network is asked to approve. Distinct from initiation
    # because on UPI they are not the same instant: the payer opens a request,
    # authenticates with their PIN, and only then does an authorisation request
    # reach the network. Scoring at initiation would place the network's
    # decision before the customer had authenticated — impossible in the real
    # flow, and fatal to F5 in particular, whose deception is that the victim's
    # PIN authorises a debit they believe is a credit.
    TXN_AUTH_REQUESTED = "txn_auth_requested"
    TXN_AUTHORISED = "txn_authorised"
    TXN_DECLINED = "txn_declined"
    TXN_SETTLED = "txn_settled"
    TXN_REVERSED = "txn_reversed"
    # authentication
    PIN_ENTERED = "pin_entered"
    OTP_ISSUED = "otp_issued"
    OTP_ENTERED = "otp_entered"
    BIOMETRIC_PRESENTED = "biometric_presented"
    MANDATE_SIGNED = "mandate_signed"
    DEVICE_BOUND = "device_bound"
    # relationship
    BENEFICIARY_ADDED = "beneficiary_added"
    DELEGATE_ADDED = "delegate_added"
    MANDATE_CREATED = "mandate_created"
    MANDATE_MODIFIED = "mandate_modified"
    TOKEN_PROVISIONED = "token_provisioned"
    ACCOUNT_OPENED = "account_opened"
    # dispute
    DISPUTE_RAISED = "dispute_raised"
    DISPUTE_EVIDENCE_FILED = "dispute_evidence_filed"
    DISPUTE_RESOLVED = "dispute_resolved"
    # context (non-network surfaces only)
    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    SCREEN_SHARE_STARTED = "screen_share_started"
    REMOTE_ACCESS_DETECTED = "remote_access_detected"
    CALL_STARTED = "call_started"
    CALL_ENDED = "call_ended"
    APP_INSTALLED = "app_installed"
    # agent (F10)
    AGENT_INTENT_DECLARED = "agent_intent_declared"
    AGENT_CART_BUILT = "agent_cart_built"
    AGENT_PAYMENT_PRESENTED = "agent_payment_presented"
    AGENT_SIGNATURE_PRESENTED = "agent_signature_presented"


# The single point at which the detector is asked to decide.
#
# TXN_AUTH_REQUESTED, not TXN_INITIATED: the network decides when an
# authorisation request reaches it, which on UPI is only after the payer has
# entered their PIN. Anchoring to initiation would have the network deciding
# before the customer authenticated, and would make the PIN — the whole subject
# of the F5 deception — unavailable at decision time for reasons of ordering
# rather than of surface.
#
# Not TXN_AUTHORISED either: that row would exist only because the outcome is
# already known, which is the outcome leak in its purest form, and it would
# double-count every transaction. Prior *historical* outcomes stay visible and
# are legitimate signal; it is this transaction's own outcome that must not be.
DECISION_EVENTS: frozenset[EventType] = frozenset({EventType.TXN_AUTH_REQUESTED})


@dataclass(slots=True)
class Event:
    """One event on one rail.

    ts:            when the event actually occurred.
    available_at:  when it first becomes observable to `surface`. Must be >= ts.
                   For same-surface real-time signals this equals ts; for signals
                   that surface only after the fact (final call duration, a
                   settled dispute) it is later.
    payload:       rail/type-specific fields (see EVENT_SCHEMA.md §3).
    """

    event_id: str
    event_type: EventType
    rail: Rail
    ts: datetime
    actor_id: str
    surface: Surface
    available_at: datetime
    episode_id: str | None = None
    label: Label | None = None
    family: Family | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.available_at < self.ts:
            raise ValueError(
                f"available_at ({self.available_at}) precedes ts ({self.ts}) "
                f"for event {self.event_id}: an event cannot be observable "
                f"before it happens."
            )

    def to_row(self) -> dict[str, Any]:
        """Flatten to a storage row. Enum members become their string values;
        payload keys are promoted to top-level columns (prefixed to avoid
        collision with ontology fields)."""
        row: dict[str, Any] = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "rail": self.rail.value,
            "ts": self.ts,
            "actor_id": self.actor_id,
            "surface": self.surface.value,
            "available_at": self.available_at,
            "episode_id": self.episode_id,
            "label": self.label.value if self.label else None,
            "family": self.family.value if self.family else None,
        }
        for k, v in self.payload.items():
            row[f"p_{k}"] = v
        return row


class EventLog:
    """An ordered, append-only collection of events.

    Kept deliberately dumb: it holds events and can materialise a DataFrame.
    It knows nothing about features — that separation is what the
    no-feature-injection guarantee rests on.
    """

    def __init__(self, events: Iterable[Event] | None = None) -> None:
        self._events: list[Event] = list(events) if events else []

    def append(self, event: Event) -> None:
        self._events.append(event)

    def extend(self, events: Iterable[Event]) -> None:
        self._events.extend(events)

    def copy(self) -> "EventLog":
        """A shallow copy sharing the same immutable Event objects.

        Used to inject different candidates' attacks into one shared background
        world without each candidate mutating the world the next one will see.
        """
        return EventLog(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[Event]:
        return iter(self._events)

    def sorted_by_time(self) -> list[Event]:
        """Events in causal order. Ties broken by event_id for determinism."""
        return sorted(self._events, key=lambda e: (e.ts, e.event_id))

    def to_frame(self):
        import pandas as pd

        if not self._events:
            return pd.DataFrame()
        return pd.DataFrame([e.to_row() for e in self.sorted_by_time()])

    def visible_to(self, surface: Surface, as_of: datetime) -> list[Event]:
        """Events a model on `surface` may legitimately read when making a
        decision at `as_of`.

        Two independent constraints, both enforced here so no downstream code
        can forget one:
          1. surface visibility — a network model cannot see psp_app/telco events.
          2. temporal availability — available_at must strictly precede as_of.
        """
        allowed = _VISIBILITY[surface]
        return [
            e
            for e in self._events
            if e.surface in allowed and e.available_at < as_of
        ]


# Which surfaces each decision surface is permitted to observe. The network
# sees only network events. The issuer sees network + issuer. App/telco models
# (used only in the labelled ablation) see their own surface plus network.
_VISIBILITY: dict[Surface, frozenset[Surface]] = {
    Surface.NETWORK: frozenset({Surface.NETWORK}),
    Surface.ISSUER: frozenset({Surface.NETWORK, Surface.ISSUER}),
    Surface.PSP_APP: frozenset({Surface.NETWORK, Surface.PSP_APP}),
    Surface.TELCO: frozenset({Surface.NETWORK, Surface.TELCO}),
}
