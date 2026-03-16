"""Soft paywall: track anonymous usage per IP per app."""
import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from gatekeeper.models import AnonymousUsage
from gatekeeper.config import AppConfig


async def check_paywall(db: AsyncSession, ip: str, app: AppConfig) -> bool:
    """Returns True if the anonymous user is within their free quota."""
    if not app.paywall.enabled:
        return True

    stmt = select(AnonymousUsage).where(
        AnonymousUsage.ip_address == ip,
        AnonymousUsage.app_slug == app.slug,
    )
    result = await db.execute(stmt)
    usage = result.scalar_one_or_none()

    now = datetime.datetime.utcnow()

    if usage is None:
        usage = AnonymousUsage(
            ip_address=ip,
            app_slug=app.slug,
            session_count=1,
            api_call_count=1,
            window_start=now,
        )
        db.add(usage)
        await db.commit()
        return True

    # Check if we need to reset the window
    if app.paywall.max_api_calls_per_hour > 0:
        # API call tracking: 1-hour window
        window_duration = datetime.timedelta(hours=1)
        if now - usage.window_start > window_duration:
            usage.api_call_count = 0
            usage.window_start = now

        usage.api_call_count += 1
        await db.commit()
        return usage.api_call_count <= app.paywall.max_api_calls_per_hour

    if app.paywall.max_sessions_per_week > 0:
        # Session tracking: 1-week window
        window_duration = datetime.timedelta(weeks=1)
        if now - usage.window_start > window_duration:
            usage.session_count = 0
            usage.window_start = now

        usage.session_count += 1
        await db.commit()
        return usage.session_count <= app.paywall.max_sessions_per_week

    return True
