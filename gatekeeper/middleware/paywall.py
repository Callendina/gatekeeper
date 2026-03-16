"""Soft paywall: track anonymous usage per cookie (session apps) or IP (API apps).

Session-based apps: tracked by the anonymous session cookie, so a user changing
IPs still counts against the same quota. Falls back to IP if no cookie.

API-only apps: tracked by IP (no cookies in API calls).
"""
import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from gatekeeper.models import AnonymousUsage
from gatekeeper.config import AppConfig


async def check_paywall(
    db: AsyncSession, ip: str, app: AppConfig, session_token: str | None = None
) -> bool:
    """Returns True if the anonymous user is within their free quota."""
    if not app.paywall.enabled:
        return True

    is_api_mode = app.paywall.max_api_calls_per_hour > 0

    # Determine tracking key: cookie for session apps, IP for API apps
    if is_api_mode or not session_token:
        tracking_key = ip
        tracking_type = "ip"
    else:
        tracking_key = session_token
        tracking_type = "cookie"

    usage = await _get_or_create_usage(db, tracking_key, tracking_type, app.slug, ip)

    now = datetime.datetime.utcnow()

    if is_api_mode:
        window_duration = datetime.timedelta(hours=1)
        if now - usage.window_start > window_duration:
            usage.api_call_count = 0
            usage.window_start = now

        usage.api_call_count += 1
        # Update IP in case it changed (cookie-tracked entries)
        usage.ip_address = ip
        await db.commit()
        return usage.api_call_count <= app.paywall.max_api_calls_per_hour

    if app.paywall.max_sessions_per_week > 0:
        window_duration = datetime.timedelta(weeks=1)
        if now - usage.window_start > window_duration:
            usage.session_count = 0
            usage.window_start = now

        usage.session_count += 1
        usage.ip_address = ip
        await db.commit()
        return usage.session_count <= app.paywall.max_sessions_per_week

    return True


async def _get_or_create_usage(
    db: AsyncSession, tracking_key: str, tracking_type: str, app_slug: str, ip: str
) -> AnonymousUsage:
    stmt = select(AnonymousUsage).where(
        AnonymousUsage.tracking_key == tracking_key,
        AnonymousUsage.app_slug == app_slug,
    )
    result = await db.execute(stmt)
    usage = result.scalar_one_or_none()

    if usage is None:
        usage = AnonymousUsage(
            tracking_key=tracking_key,
            tracking_type=tracking_type,
            app_slug=app_slug,
            ip_address=ip,
            session_count=0,
            api_call_count=0,
            window_start=datetime.datetime.utcnow(),
        )
        db.add(usage)
        await db.flush()

    return usage
