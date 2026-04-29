"""Soft paywall: track anonymous usage per cookie (session apps) or IP (API apps).

Returns one of three states:
- "allowed": within free quota, pass through
- "nag": exceeded nag threshold but within hard limit, show dismissable prompt
- "blocked": exceeded hard limit, must register

Session-based apps: tracked by the anonymous session cookie.
API-only apps: tracked by IP.
"""
import datetime
from enum import Enum
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.models import AnonymousUsage
from gatekeeper.config import AppConfig


class PaywallResult(str, Enum):
    ALLOWED = "allowed"
    NAG = "nag"
    BLOCKED = "blocked"


async def check_paywall(
    db: AsyncSession, ip: str, app: AppConfig, session_token: str | None = None
) -> PaywallResult:
    """Check whether an anonymous user is within their free quota."""
    if not app.paywall.enabled:
        return PaywallResult.ALLOWED

    is_api_mode = app.paywall.max_api_calls_per_hour > 0

    if is_api_mode:
        # API mode: increment on every call, track by IP
        usage = await _get_or_create_usage(db, ip, "ip", app.slug, ip)
        now = utcnow()
        window_duration = datetime.timedelta(hours=1)
        if now - usage.window_start > window_duration:
            usage.api_call_count = 0
            usage.window_start = now
        usage.api_call_count += 1
        usage.ip_address = ip
        await db.commit()
        if usage.api_call_count <= app.paywall.max_api_calls_per_hour:
            return PaywallResult.ALLOWED
        return PaywallResult.BLOCKED

    if app.paywall.max_sessions_per_week > 0:
        # Session mode: just CHECK the count, don't increment.
        tracking_key = session_token if session_token else ip
        tracking_type = "cookie" if session_token else "ip"
        usage = await _get_or_create_usage(db, tracking_key, tracking_type, app.slug, ip)
        now = utcnow()
        window_duration = datetime.timedelta(weeks=1)
        if now - usage.window_start > window_duration:
            usage.session_count = 0
            usage.window_start = now
            await db.commit()

        count = usage.session_count
        if count <= app.paywall.nag_after_sessions or not app.paywall.nag_enabled:
            if count <= app.paywall.max_sessions_per_week:
                return PaywallResult.ALLOWED
            return PaywallResult.BLOCKED
        else:
            if count <= app.paywall.max_sessions_per_week:
                return PaywallResult.NAG
            return PaywallResult.BLOCKED

    return PaywallResult.ALLOWED


async def record_new_session(
    db: AsyncSession, ip: str, app: AppConfig
) -> PaywallResult:
    """Record that a new anonymous session was created. Returns paywall state."""
    if not app.paywall.enabled or app.paywall.max_sessions_per_week <= 0:
        return PaywallResult.ALLOWED

    usage = await _get_or_create_usage(db, ip, "ip", app.slug, ip)
    now = utcnow()
    window_duration = datetime.timedelta(weeks=1)
    if now - usage.window_start > window_duration:
        usage.session_count = 0
        usage.window_start = now
    usage.session_count += 1
    await db.commit()

    count = usage.session_count
    if app.paywall.nag_enabled and count > app.paywall.nag_after_sessions:
        if count <= app.paywall.max_sessions_per_week:
            return PaywallResult.NAG
        return PaywallResult.BLOCKED
    if count <= app.paywall.max_sessions_per_week:
        return PaywallResult.ALLOWED
    return PaywallResult.BLOCKED


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
            window_start=utcnow(),
        )
        try:
            db.add(usage)
            await db.flush()
        except IntegrityError:
            await db.rollback()
            result = await db.execute(stmt)
            usage = result.scalar_one()

    return usage
