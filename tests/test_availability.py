"""Signal-availability enforcement: a network-surface model can never read a
psp_app/telco event, and no feature can read an event from the future.
"""

from datetime import datetime, timedelta

import pytest

from chakra.schema.events import Event, EventType, EventLog, Rail, Surface


def _ev(surface, ts, available_at, actor="a"):
    return Event(
        event_id=f"e_{ts.timestamp()}_{surface.value}",
        event_type=EventType.TXN_INITIATED,
        rail=Rail.UPI,
        ts=ts,
        actor_id=actor,
        surface=surface,
        available_at=available_at,
    )


def test_available_at_before_ts_rejected():
    now = datetime(2026, 2, 1, 12, 0, 0)
    with pytest.raises(ValueError):
        _ev(Surface.NETWORK, now, now - timedelta(seconds=1))


def test_network_cannot_see_psp_app_events():
    now = datetime(2026, 2, 1, 12, 0, 0)
    log = EventLog(
        [
            _ev(Surface.NETWORK, now, now),
            _ev(Surface.PSP_APP, now, now),
            _ev(Surface.TELCO, now, now),
        ]
    )
    visible = log.visible_to(Surface.NETWORK, as_of=now + timedelta(minutes=1))
    surfaces = {e.surface for e in visible}
    assert surfaces == {Surface.NETWORK}


def test_future_events_not_visible():
    now = datetime(2026, 2, 1, 12, 0, 0)
    future = now + timedelta(minutes=5)
    log = EventLog(
        [
            _ev(Surface.NETWORK, now, now),
            _ev(Surface.NETWORK, future, future),
        ]
    )
    visible = log.visible_to(Surface.NETWORK, as_of=now + timedelta(minutes=1))
    assert len(visible) == 1
    assert all(e.available_at < now + timedelta(minutes=1) for e in visible)


def test_issuer_sees_network_plus_issuer_only():
    now = datetime(2026, 2, 1, 12, 0, 0)
    log = EventLog(
        [
            _ev(Surface.NETWORK, now, now),
            _ev(Surface.ISSUER, now, now),
            _ev(Surface.TELCO, now, now),
        ]
    )
    visible = log.visible_to(Surface.ISSUER, as_of=now + timedelta(minutes=1))
    surfaces = {e.surface for e in visible}
    assert surfaces == {Surface.NETWORK, Surface.ISSUER}
