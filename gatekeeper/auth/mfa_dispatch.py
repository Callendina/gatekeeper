"""Shared MFA dispatcher used by forward_auth (per-app + system-admin)
and the admin UI. Returns a redirect Response, or None if the user has
cleared the MFA gate for this request.

All MFA gate decisions go through this one function. Adding a new method
means: extend `_VALID_MFA_METHODS` in config.py, add a branch here, add
a route module that mirrors `auth/totp.py` or `auth/sms_otp.py`.
"""
from urllib.parse import quote

from fastapi import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.auth.totp import get_totp
from gatekeeper.models import Session, User, UserAppRole, UserPhone


async def dispatch_mfa(
    *,
    db: AsyncSession,
    session: Session | None,
    user: User,
    app_slug: str,
    methods: list[str],
    step_up_seconds: int,
    path: str,
) -> Response | None:
    """Resolve the user's bound MFA method for `app_slug` and return the
    redirect that gets them to the right enrol/verify page — or None if
    they're cleared.

    `app_slug` may be a real app slug or the pseudo-slug "_system" for
    the system-admin gate.
    """
    if not methods:
        return None

    next_q = quote(path or "/")
    role_row = await db.scalar(
        select(UserAppRole).where(
            UserAppRole.user_id == user.id,
            UserAppRole.app_slug == app_slug,
        )
    )
    bound = role_row.mfa_method if role_row else None

    if bound is None:
        if len(methods) == 1:
            bound = methods[0]
        elif "totp" in methods:
            existing_totp = await get_totp(db, user.id)
            if existing_totp is not None and existing_totp.confirmed_at is not None:
                bound = "totp"
                if role_row is not None:
                    role_row.mfa_method = "totp"
                    await db.commit()

    if bound is None:
        return Response(
            status_code=302,
            headers={"Location": f"/_auth/mfa/choose?app={app_slug}&next={next_q}"},
        )

    if bound == "totp":
        rec = await get_totp(db, user.id)
        if rec is None or rec.confirmed_at is None:
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/totp/enroll?next={next_q}"},
            )
        if _needs_step_up(session, step_up_seconds):
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/totp/verify?next={next_q}"},
            )
        return None

    if bound == "sms_otp":
        phone = await db.scalar(select(UserPhone).where(UserPhone.user_id == user.id))
        if phone is None or phone.confirmed_at is None:
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/phone/enroll?next={next_q}&app={app_slug}"},
            )
        if _needs_step_up(session, step_up_seconds):
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/sms-otp/verify?app={app_slug}&next={next_q}"},
            )
        return None

    # Unknown bound method (config drift) — fall through to the picker.
    return Response(
        status_code=302,
        headers={"Location": f"/_auth/mfa/choose?app={app_slug}&next={next_q}"},
    )


def _needs_step_up(session: Session | None, step_up_seconds: int) -> bool:
    if session is None or session.totp_verified_at is None:
        return True
    if step_up_seconds <= 0:
        return False
    age = (utcnow() - session.totp_verified_at).total_seconds()
    return age > step_up_seconds
