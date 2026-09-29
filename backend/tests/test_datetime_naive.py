"""Timestamps are naive UTC so they insert cleanly on tz-naive columns (SQLite + Postgres).

Regression guard for the Postgres seed crash: asyncpg rejects an aware datetime for a
TIMESTAMP WITHOUT TIME ZONE column ("can't subtract offset-naive and offset-aware").
"""

from datetime import UTC, datetime

from shadowportx.db.base import utcnow


def test_utcnow_is_naive():
    now = utcnow()
    assert now.tzinfo is None, "utcnow() must be naive so it matches tz-naive DB columns"


def test_utcnow_tracks_real_utc():
    delta = abs((datetime.now(UTC).replace(tzinfo=None) - utcnow()).total_seconds())
    assert delta < 5
