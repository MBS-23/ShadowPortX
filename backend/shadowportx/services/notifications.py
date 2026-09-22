"""Outbound notifications — alert on new findings via webhook channels.

Slack/Teams/Discord all accept an incoming-webhook URL with a JSON body, so a single
generic sender covers them. Vendor connectors (Jira, ServiceNow, SIEM) plug in as
additional ``kind`` handlers behind the same interface.
"""

from __future__ import annotations

import logging

import httpx
from sqlalchemy import select

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import session_scope

logger = logging.getLogger("shadowportx.notifications")


def _slack_payload(alert: dict) -> dict:
    sev = alert["severity"].upper()
    return {
        "text": (
            f":rotating_light: *ShadowPortX {sev}* — {alert['title']}\n"
            f"Asset: `{alert['asset']}` · SPX-ES: *{alert['risk']}* · {alert['spx_id']}"
        )
    }


async def _send(channel: models.NotificationChannel, alert: dict) -> bool:
    payload = _slack_payload(alert) if channel.kind == "slack" else {"finding": alert}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(channel.url, json=payload)
        return resp.status_code < 400
    except httpx.HTTPError as exc:
        logger.warning("notification to channel %s failed: %s", channel.id, exc)
        return False


async def dispatch(org_id: int, alerts: list[dict]) -> int:
    """Send each alert to every enabled channel meeting its severity threshold."""
    if not alerts:
        return 0
    async with session_scope() as session:
        channels = (await session.execute(
            select(models.NotificationChannel).where(
                models.NotificationChannel.organization_id == org_id,
                models.NotificationChannel.enabled.is_(True),
            )
        )).scalars().all()
    if not channels:
        return 0

    sent = 0
    for alert in alerts:
        a_rank = enums.Severity(alert["severity"]).rank
        for ch in channels:
            if a_rank >= ch.min_severity.rank and await _send(ch, alert):
                sent += 1
    if sent:
        logger.info("dispatched %d notification(s) for org %s", sent, org_id)
    return sent


async def send_test(channel: models.NotificationChannel) -> bool:
    return await _send(channel, {
        "title": "Test alert from ShadowPortX", "asset": "example.com",
        "risk": 0, "spx_id": "SPX-TEST", "severity": "high",
    })
