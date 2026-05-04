"""Admin routes for managing users, IP blocklist, and viewing access logs."""
import datetime
from urllib.parse import quote

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, delete
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import (
    User, UserAppRole, OAuthAccount, IPBlocklist, AccessLog, Session,
    APIKey, InviteCode, InviteUse, InviteWaitlist, InviteUserLimit,
    UserTOTP, UserPhone, SmsOtpChallenge,
)
from gatekeeper.sms.validation import normalize, PhoneValidationError
from gatekeeper.middleware.ip_block import block_ip, unblock_ip
from gatekeeper.auth.sessions import validate_session

from pathlib import Path

router = APIRouter(prefix="/_auth/admin")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def init_admin_routes(config: GatekeeperConfig):
    global _config
    _config = config


async def _totp_redirect_if_required(
    db: AsyncSession, user: User, session: Session | None, request: Request
):
    """When system_admin_requires_mfa is set, dispatch the user to the
    enrol/verify URL for whichever method they've bound for the `_system`
    pseudo-app. Returns None if OK."""
    if not _config.system_admin_requires_mfa:
        return None
    from gatekeeper.auth.mfa_dispatch import dispatch_mfa
    return await dispatch_mfa(
        db=db, session=session, user=user, app_slug="_system",
        methods=_config.system_admin_mfa_methods,
        step_up_seconds=0, path=request.url.path or "/_auth/admin",
    )


async def _require_admin(request: Request, db: AsyncSession):
    """Check that the request is from a system admin by validating the session cookie.
    Returns the admin email, or an appropriate response (redirect to login or access denied)."""
    session_token = request.cookies.get("gk_session")
    authenticated_user = None

    if session_token:
        # Try all configured app slugs
        for app_slug in _config.apps:
            session, user, role, _grp = await validate_session(db, session_token, app_slug)
            if user:
                if user.is_system_admin:
                    redir = await _totp_redirect_if_required(db, user, session, request)
                    return redir if redir else user.email
                authenticated_user = user.email

        # Also check sessions not scoped to any app (e.g. from the admin domain)
        if not authenticated_user:
            stmt = select(Session).where(
                Session.token == session_token,
                Session.expires_at > utcnow(),
            )
            result = await db.execute(stmt)
            session = result.scalar_one_or_none()
            if session and session.user_id:
                user_stmt = select(User).where(User.id == session.user_id)
                user_result = await db.execute(user_stmt)
                user = user_result.scalar_one_or_none()
                if user:
                    if user.is_system_admin:
                        redir = await _totp_redirect_if_required(db, user, session, request)
                        return redir if redir else user.email
                    authenticated_user = user.email

    if authenticated_user:
        # Signed in but not a system admin
        return HTMLResponse(
            f"<h2>Access denied</h2>"
            f"<p>You are signed in as <strong>{authenticated_user}</strong> "
            f"but this account is not a system administrator.</p>"
            f"<p><a href='/_auth/logout?app='>Sign out</a> and try a different account.</p>",
            status_code=403,
        )

    # Not authenticated — redirect to login
    app_slug = next(iter(_config.apps), "")
    host = request.headers.get("host", "")
    app_for_host = _config.app_for_domain(host)
    if app_for_host:
        app_slug = app_for_host.slug
    return RedirectResponse(
        url=f"/_auth/login?app={app_slug}&next=/_auth/admin", status_code=302
    )


def _check_admin(result):
    """Returns (email, None) if admin, or (None, response) if redirect."""
    if isinstance(result, str):
        return result, None
    return None, result


async def _pending_waitlist_count(db: AsyncSession) -> int:
    return await db.scalar(
        select(func.count(InviteWaitlist.id)).where(InviteWaitlist.status == "pending")
    ) or 0


async def _pending_invite_count(db: AsyncSession) -> int:
    return await db.scalar(
        select(func.count(UserAppRole.id)).where(UserAppRole.pending_invite == True)
    ) or 0


@router.get("")
async def admin_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    user_count = await db.scalar(select(func.count(User.id)))
    blocked_count = await db.scalar(select(func.count(IPBlocklist.id)))

    # Get active API key counts per app
    from gatekeeper.auth.api_keys import count_active_keys
    api_key_counts = {}
    for slug in _config.apps:
        if _config.apps[slug].api_access.enabled:
            api_key_counts[slug] = await count_active_keys(db, slug)

    pending_waitlist = await _pending_waitlist_count(db)

    pending_invite = await _pending_invite_count(db)

    return templates.TemplateResponse(request, "admin/dashboard.html", {
        "request": request,
        "user_count": user_count,
        "blocked_count": blocked_count,
        "apps": _config.apps,
        "api_key_counts": api_key_counts,
        "pending_waitlist": pending_waitlist,
        "pending_invite": pending_invite,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
    })


@router.get("/users")
async def list_users(request: Request, db: AsyncSession = Depends(get_db)):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    stmt = select(User).order_by(User.created_at.desc())
    result = await db.execute(stmt)
    users = result.scalars().all()

    # Get roles for each user
    user_roles = {}
    for user in users:
        role_stmt = select(UserAppRole).where(UserAppRole.user_id == user.id)
        role_result = await db.execute(role_stmt)
        user_roles[user.id] = role_result.scalars().all()

    # MFA enrollment status per user (None / unconfirmed / datetime)
    totp_rows = (await db.execute(select(UserTOTP))).scalars().all()
    user_totp = {t.user_id: t for t in totp_rows}
    phone_rows = (await db.execute(select(UserPhone))).scalars().all()
    user_phone = {p.user_id: p for p in phone_rows}

    return templates.TemplateResponse(request, "admin/users.html", {
        "request": request,
        "users": users,
        "user_roles": user_roles,
        "user_totp": user_totp,
        "user_phone": user_phone,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
        "pending_invite": await _pending_invite_count(db),
    })


@router.post("/users/{user_id}/totp/reset")
async def admin_reset_totp(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Resets all MFA state for the user — TOTP, phone, and any
    per-(user, app) method bindings — forcing fresh enrolment on next
    protected access. The route name is historical; it now resets every
    factor the user has, not just TOTP.

    Specifically:
    - Bumps `user_totp.key_num`, clears `confirmed_at` and `last_counter`
      (existing TOTP behaviour).
    - Bumps `user_phone.key_num`, clears `confirmed_at` (so any in-flight
      SMS challenges become unverifiable and the user must re-confirm
      the number).
    - Clears `mfa_method` on every UserAppRole row for the user, so the
      method picker fires again on next MFA encounter.
    - Clears `totp_verified_at` on every active session so already-stepped-up
      sessions can't keep bypassing the gate.
    """
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from sqlalchemy import update
    from gatekeeper.auth.totp import reset_totp

    await reset_totp(db, user_id)

    # Bump phone key_num + clear confirmed_at if the user had a phone
    # enrolled. The bump invalidates any in-flight SMS challenges by
    # making the secret pepper they were derived under no longer match
    # — though challenge HMACs don't include key_num today, the
    # forced-re-enrolment of confirmed_at means new challenges have to
    # be issued post-confirmation anyway.
    phone = await db.scalar(
        select(UserPhone).where(UserPhone.user_id == user_id)
    )
    if phone is not None:
        phone.key_num += 1
        phone.confirmed_at = None
        phone.last_change_at = utcnow()

    # Clear method bindings for every app this user has a role for, so
    # the picker (or single-method auto-bind) runs fresh on next MFA hit.
    await db.execute(
        update(UserAppRole)
        .where(UserAppRole.user_id == user_id)
        .values(mfa_method=None)
    )

    # Revoke any existing totp_verified_at on this user's sessions.
    sessions = (await db.execute(
        select(Session).where(Session.user_id == user_id, Session.totp_verified_at.isnot(None))
    )).scalars().all()
    for s in sessions:
        s.totp_verified_at = None
    await db.commit()

    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.post("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    request: Request,
    app_slug: str = Form(...),
    role: str = Form(...),
    group: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    app_config = _config.apps.get(app_slug)
    if not app_config:
        return HTMLResponse(f"<h2>Unknown app: {app_slug}</h2>", status_code=400)
    if role not in app_config.roles:
        return HTMLResponse(
            f"<h2>Invalid role '{role}' for {app_slug}.</h2>"
            f"<p>Valid roles: {', '.join(app_config.roles)}</p>",
            status_code=400,
        )

    stmt = select(UserAppRole).where(
        UserAppRole.user_id == user_id,
        UserAppRole.app_slug == app_slug,
    )
    result = await db.execute(stmt)
    app_role = result.scalar_one_or_none()

    # The form on the admin users page pre-fills both role and group with the
    # current values, so a blank group on submit is an explicit clear (rather
    # than "keep existing"). Always use the submitted value verbatim.
    group_value = group.strip() or None
    if app_role:
        app_role.role = role
        app_role.group = group_value
    else:
        app_role = UserAppRole(user_id=user_id, app_slug=app_slug, role=role, group=group_value)
        db.add(app_role)

    await db.commit()
    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.post("/users/{user_id}/approve")
async def approve_pending_user(
    user_id: int,
    request: Request,
    app_slug: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    stmt = select(UserAppRole).where(
        UserAppRole.user_id == user_id,
        UserAppRole.app_slug == app_slug,
        UserAppRole.pending_invite == True,
    )
    result = await db.execute(stmt)
    app_role = result.scalar_one_or_none()
    if app_role:
        app_role.pending_invite = False
        await db.commit()

    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.post("/users/{user_id}/deny")
async def deny_pending_user(
    user_id: int,
    request: Request,
    app_slug: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    # Delete the UserAppRole (removes their access for this app)
    await db.execute(
        delete(UserAppRole).where(
            UserAppRole.user_id == user_id,
            UserAppRole.app_slug == app_slug,
        )
    )
    await db.commit()

    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.post("/users/{user_id}/delete")
async def delete_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Hard-delete a user and all their FK-tied data: OAuth accounts, app
    roles across all apps, sessions, API keys, invite-user limits. The
    AccessLog and InviteUse audit tables are left intact (they reference
    by email string, not user_id, so they survive deletion as audit trail)."""
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    # Look up the user first — surface a clear error if not found, and guard
    # against an admin deleting their own account (which would lock them out).
    target = await db.scalar(select(User).where(User.id == user_id))
    if target is None:
        return HTMLResponse(f"<h2>User #{user_id} not found</h2>", status_code=404)
    if target.email == admin:
        return HTMLResponse(
            "<h2>Cannot delete your own admin account.</h2>"
            "<p>Sign in as a different admin first, or use the database directly.</p>",
            status_code=400,
        )

    # Delete dependent rows in order of FK dependency. Sessions and API keys
    # have nullable FKs but it's cleaner to remove them than orphan.
    await db.execute(delete(OAuthAccount).where(OAuthAccount.user_id == user_id))
    await db.execute(delete(UserAppRole).where(UserAppRole.user_id == user_id))
    await db.execute(delete(Session).where(Session.user_id == user_id))
    await db.execute(delete(APIKey).where(APIKey.user_id == user_id))
    await db.execute(delete(InviteUserLimit).where(InviteUserLimit.user_id == user_id))
    await db.execute(delete(UserPhone).where(UserPhone.user_id == user_id))
    await db.execute(delete(User).where(User.id == user_id))
    await db.commit()

    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.post("/users/{user_id}/phone")
async def admin_set_phone(
    user_id: int,
    request: Request,
    phone_number: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Bind a phone number to a user. Admin-confirmed immediately (no OTP).

    Used for WhatsApp linking: operator onboards a coach by entering their
    phone here, which sets confirmed_at = now so the WhatsApp handler can
    resolve them.

    Replaces any existing unconfirmed number. If a confirmed number already
    exists, the form must be submitted again to override it (the template
    shows a warning).
    """
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    try:
        e164, _ = normalize(phone_number, _config.sms.country_allowlist)
    except PhoneValidationError as exc:
        return HTMLResponse(
            f"<h2>Invalid phone number</h2><p>{exc.code}: {phone_number!r}</p>"
            f"<p><a href='/_auth/admin/users'>← back</a></p>",
            status_code=400,
        )

    phone = await db.scalar(select(UserPhone).where(UserPhone.user_id == user_id))
    if phone is None:
        phone = UserPhone(
            user_id=user_id, e164=e164,
            confirmed_at=utcnow(), key_num=0,
        )
        db.add(phone)
    else:
        if phone.e164 != e164:
            phone.key_num += 1
        phone.e164 = e164
        phone.confirmed_at = utcnow()
        phone.last_change_at = utcnow()
    await db.commit()
    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.post("/users/{user_id}/phone/remove")
async def admin_remove_phone(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Remove a user's phone binding (deletes the user_phone row)."""
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    await db.execute(delete(UserPhone).where(UserPhone.user_id == user_id))
    await db.commit()
    return RedirectResponse(url="/_auth/admin/users", status_code=302)


@router.get("/ip-blocklist")
async def ip_blocklist_page(request: Request, db: AsyncSession = Depends(get_db)):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    stmt = select(IPBlocklist).order_by(IPBlocklist.blocked_at.desc())
    result = await db.execute(stmt)
    blocked = result.scalars().all()

    return templates.TemplateResponse(request, "admin/ip_blocklist.html", {
        "request": request,
        "blocked_ips": blocked,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


@router.post("/ip-blocklist/add")
async def add_ip_block(
    request: Request,
    ip_address: str = Form(...),
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    await block_ip(db, ip_address, reason=reason, blocked_by=admin)
    return RedirectResponse(url="/_auth/admin/ip-blocklist", status_code=302)


@router.post("/ip-blocklist/remove")
async def remove_ip_block(
    request: Request,
    ip_address: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    await unblock_ip(db, ip_address)
    return RedirectResponse(url="/_auth/admin/ip-blocklist", status_code=302)


@router.get("/access-log")
async def access_log_page(
    request: Request,
    ip: str = "",
    app_slug: str = "",
    status: str = "",
    page: int = 1,
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    per_page = 100
    stmt = select(AccessLog).order_by(AccessLog.timestamp.desc())

    if ip:
        stmt = stmt.where(AccessLog.ip_address == ip)
    if app_slug:
        stmt = stmt.where(AccessLog.app_slug == app_slug)
    if status:
        stmt = stmt.where(AccessLog.status == status)

    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return templates.TemplateResponse(request, "admin/access_log.html", {
        "request": request,
        "logs": logs,
        "filter_ip": ip,
        "filter_app": app_slug,
        "filter_status": status,
        "page": page,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


@router.get("/sms")
async def sms_page(
    request: Request,
    drop_app: str = "",
    drop_method: str = "",
    db: AsyncSession = Depends(get_db),
):
    """SMS-OTP operations dashboard. Pulls data from two sources:
      - sms_otp_challenges (recent activity, last 50)
      - access_log filtered by `sms_otp_*` status strings (spend / errors)
    """
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    now = utcnow()
    last_24h = now - datetime.timedelta(hours=24)
    last_7d = now - datetime.timedelta(days=7)

    # --- Recent challenges (no plaintext code, no full number)
    recent_stmt = (
        select(SmsOtpChallenge)
        .order_by(SmsOtpChallenge.issued_at.desc())
        .limit(50)
    )
    recent = (await db.execute(recent_stmt)).scalars().all()

    # --- Spend (24h + 7d) parsed from sms_otp_sent_to_provider events
    spend_stmt = (
        select(AccessLog.app_slug, AccessLog.status, AccessLog.timestamp)
        .where(
            AccessLog.status.like("sms_otp_sent_to_provider:%"),
            AccessLog.timestamp >= last_7d,
        )
    )
    spend_rows = (await db.execute(spend_stmt)).all()
    spend_24h: dict[str, int] = {}
    spend_7d: dict[str, int] = {}
    sent_24h_count = 0
    for app_slug, status, ts in spend_rows:
        # status format: "sms_otp_sent_to_provider:<provider>:cost=<cents>"
        cost = _parse_cost_from_status(status)
        if cost is None or cost < 0:
            continue
        spend_7d[app_slug] = spend_7d.get(app_slug, 0) + cost
        if ts >= last_24h:
            spend_24h[app_slug] = spend_24h.get(app_slug, 0) + cost
            sent_24h_count += 1

    # --- Failure breakdown over the last 24h
    failure_stmt = (
        select(AccessLog.status, func.count(AccessLog.id))
        .where(
            AccessLog.status.like("sms_otp_send_failed:%"),
            AccessLog.timestamp >= last_24h,
        )
        .group_by(AccessLog.status)
    )
    failures = [
        {"category": status.split(":", 1)[1] if ":" in status else status, "count": n}
        for status, n in (await db.execute(failure_stmt)).all()
    ]

    # --- Drop-method preview: count users currently bound to a method on an app
    preview = None
    if drop_app and drop_method:
        bound_count = await db.scalar(
            select(func.count(UserAppRole.id)).where(
                UserAppRole.app_slug == drop_app,
                UserAppRole.mfa_method == drop_method,
            )
        )
        preview = {
            "app": drop_app, "method": drop_method,
            "count": int(bound_count or 0),
        }

    # --- App→methods mapping for the drop-method form
    app_methods = {
        slug: list(app_cfg.mfa.methods) for slug, app_cfg in _config.apps.items()
    }
    app_methods["_system"] = list(_config.system_admin_mfa_methods)

    return templates.TemplateResponse(request, "admin/sms.html", {
        "request": request,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
        "pending_invite": await _pending_invite_count(db),
        "recent": recent,
        "spend_24h": spend_24h,
        "spend_7d": spend_7d,
        "sent_24h_count": sent_24h_count,
        "failures": failures,
        "app_methods": app_methods,
        "preview": preview,
        "sms_provider": _config.sms.provider,
        "sms_test_mode": _config.sms.test_mode,
    })


def _parse_cost_from_status(status: str) -> int | None:
    """Pull cost cents out of `sms_otp_sent_to_provider:<provider>:cost=<n>`.
    Returns None on parse failure (treated as "no cost data" — won't sum)."""
    marker = "cost="
    idx = status.rfind(marker)
    if idx < 0:
        return None
    try:
        return int(status[idx + len(marker):])
    except ValueError:
        return None


async def _render_api_keys_page(
    request: Request,
    db: AsyncSession,
    admin: str,
    app_slug: str,
    extra: dict | None = None,
):
    from gatekeeper.middleware.rate_limit import _api_key_log
    import time

    now = utcnow()
    stmt = select(APIKey).where(APIKey.expires_at > now).order_by(APIKey.created_at.desc())
    if app_slug:
        stmt = stmt.where(APIKey.app_slug == app_slug)
    result = await db.execute(stmt)
    keys = result.scalars().all()

    key_info = []
    current_time = time.time()
    window = 60.0
    for k in keys:
        if k.key_type == "registered":
            tier = "registered"
        elif k.user_id is not None:
            tier = "temp_authenticated"
        else:
            tier = "temp_anonymous"

        app_config = _config.apps.get(k.app_slug)
        if app_config and app_config.api_access.enabled:
            limits = app_config.api_access.api_rate_limits
            default_limit = {
                "temp_anonymous": limits.temp_anonymous_per_minute,
                "temp_authenticated": limits.temp_authenticated_per_minute,
                "registered": limits.registered_per_minute,
            }[tier]
        else:
            default_limit = 0

        effective_limit = k.rate_limit_override if k.rate_limit_override > 0 else default_limit

        entries = _api_key_log.get(k.key, [])
        cutoff = current_time - window
        usage = sum(w for t, w in entries if t > cutoff)

        user_email = None
        if k.user_id:
            user_result = await db.execute(select(User).where(User.id == k.user_id))
            user_obj = user_result.scalar_one_or_none()
            if user_obj:
                user_email = user_obj.email

        key_info.append({
            "id": k.id,
            "key_short": k.key[:12] + "...",
            "app_slug": k.app_slug,
            "tier": tier,
            "user_email": user_email,
            "ip_address": k.ip_address,
            "created_at": k.created_at,
            "expires_at": k.expires_at,
            "default_limit": default_limit,
            "override_limit": k.rate_limit_override,
            "effective_limit": effective_limit,
            "usage": usage,
        })

    ctx = {
        "request": request,
        "keys": key_info,
        "filter_app": app_slug,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
    }
    if extra:
        ctx.update(extra)
    return templates.TemplateResponse(request, "admin/api_keys.html", ctx)


@router.get("/api-keys")
async def api_keys_page(
    request: Request,
    app_slug: str = "",
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect
    return await _render_api_keys_page(request, db, admin, app_slug)


@router.post("/api-keys/issue")
async def issue_admin_api_key(
    request: Request,
    app_slug: str = Form(...),
    user_email: str = Form(...),
    expiry_override_days: int = Form(0),
    rate_limit_override: int = Form(0),
    force: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from gatekeeper.auth.api_keys import issue_registered_key_for_user

    app = _config.apps.get(app_slug)
    if app is None:
        return await _render_api_keys_page(
            request, db, admin, "",
            extra={"issue_error": f"Unknown app: {app_slug}"},
        )
    if not app.api_access.enabled:
        return await _render_api_keys_page(
            request, db, admin, app_slug,
            extra={"issue_error": f"API access not enabled for app '{app_slug}'."},
        )

    email_norm = user_email.strip().lower()
    if not email_norm:
        return await _render_api_keys_page(
            request, db, admin, app_slug,
            extra={"issue_error": "Email is required."},
        )
    user_result = await db.execute(select(User).where(User.email == email_norm))
    user = user_result.scalar_one_or_none()
    if user is None:
        return await _render_api_keys_page(
            request, db, admin, app_slug,
            extra={"issue_error": f"No user found with email '{email_norm}'."},
        )

    override_expiry = expiry_override_days * 86400 if expiry_override_days > 0 else None
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")

    key, expires_at, error = await issue_registered_key_for_user(
        db, app, user, ip,
        override_expiry_seconds=override_expiry,
        force=force,
    )
    if error:
        return await _render_api_keys_page(
            request, db, admin, app_slug,
            extra={
                "issue_error": (
                    f"{error['error']} (current: {error['current']}, "
                    f"limit: {error['limit']}). Tick 'Force' to override."
                ),
            },
        )

    if rate_limit_override > 0:
        result = await db.execute(select(APIKey).where(APIKey.key == key))
        api_key_obj = result.scalar_one_or_none()
        if api_key_obj:
            api_key_obj.rate_limit_override = rate_limit_override
            await db.commit()

    import cyclops
    cyclops.event(
        "gatekeeper.api_key.issued",
        outcome="success",
        actor=f"admin:{admin}",
        app_slug=app_slug,
        key_type="registered",
        masked_email=cyclops.redact_email(user.email),
        masked_key=cyclops.redact_token(key),
        expires_at=expires_at.isoformat() + "Z",
        forced=force,
    )

    return await _render_api_keys_page(
        request, db, admin, app_slug,
        extra={
            "issued_key": key,
            "issued_for": user.email,
            "issued_app": app_slug,
            "issued_expires": expires_at,
        },
    )


@router.post("/api-keys/{key_id}/boost")
async def boost_api_key(
    key_id: int,
    request: Request,
    rate_limit: int = Form(...),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    if api_key:
        api_key.rate_limit_override = rate_limit
        await db.commit()

    return RedirectResponse(url="/_auth/admin/api-keys", status_code=302)


@router.post("/api-keys/{key_id}/delete")
async def delete_api_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(APIKey).where(APIKey.id == key_id))
    await db.commit()

    return RedirectResponse(url="/_auth/admin/api-keys", status_code=302)


# --- Invite management ---


@router.get("/invites")
async def invites_page(
    request: Request,
    app_slug: str = "",
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    code_stmt = select(InviteCode).order_by(InviteCode.created_at.desc())
    if app_slug:
        code_stmt = code_stmt.where(InviteCode.app_slug == app_slug)
    codes = (await db.execute(code_stmt)).scalars().all()

    wl_stmt = select(InviteWaitlist).order_by(InviteWaitlist.created_at.desc())
    if app_slug:
        wl_stmt = wl_stmt.where(InviteWaitlist.app_slug == app_slug)
    waitlist = (await db.execute(wl_stmt)).scalars().all()

    # Load use details for each code
    code_uses = {}
    for c in codes:
        uses_result = await db.execute(
            select(InviteUse).where(InviteUse.invite_code_id == c.id)
            .order_by(InviteUse.granted_at.desc())
        )
        code_uses[c.id] = uses_result.scalars().all()

    # Load users for the grant form
    users_result = await db.execute(select(User).order_by(User.email))
    all_users = users_result.scalars().all()

    return templates.TemplateResponse(request, "admin/invites.html", {
        "request": request,
        "codes": codes,
        "code_uses": code_uses,
        "waitlist": waitlist,
        "filter_app": app_slug,
        "apps": _config.apps,
        "all_users": all_users,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


@router.post("/invites/create")
async def admin_create_code(
    request: Request,
    app_slug: str = Form(...),
    max_uses: int = Form(100),
    expiry_days: int = Form(0),
    custom_code: str = Form(""),
    role: str = Form(""),
    group: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from gatekeeper.auth.invites import generate_invite_code

    code = custom_code.strip() or generate_invite_code()
    expires_at = (
        utcnow() + datetime.timedelta(days=expiry_days)
        if expiry_days > 0 else None
    )

    invite = InviteCode(
        app_slug=app_slug, code=code, code_type="bulk",
        max_uses=max_uses, expires_at=expires_at,
        role=role.strip() or None,
        group=group.strip() or None,
    )
    db.add(invite)
    await db.commit()

    return RedirectResponse(
        url=f"/_auth/admin/invites?app_slug={app_slug}", status_code=302
    )


@router.post("/invites/codes/{code_id}/revoke")
async def revoke_code(
    code_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    code = await db.get(InviteCode, code_id)
    if code and code.active:
        code.active = False
        await db.commit()

    return RedirectResponse(
        url=f"/_auth/admin/invites?app_slug={code.app_slug if code else ''}",
        status_code=302,
    )


@router.post("/invites/waitlist/{wl_id}/approve")
async def approve_waitlist(
    wl_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from gatekeeper.auth.invites import generate_invite_code

    wl = await db.get(InviteWaitlist, wl_id)
    if not wl or wl.status != "pending":
        return RedirectResponse(url="/_auth/admin/invites", status_code=302)

    app_config = _config.apps.get(wl.app_slug)
    expiry_days = (app_config.invite.personal_invites.expiry_days
                   if app_config else 7)
    expires_at = utcnow() + datetime.timedelta(days=expiry_days)

    code = generate_invite_code()
    invite = InviteCode(
        app_slug=wl.app_slug, code=code, code_type="bulk",
        created_by_email=admin, max_uses=1, expires_at=expires_at,
    )
    db.add(invite)
    await db.flush()

    wl.status = "approved"
    wl.invite_code_id = invite.id
    wl.reviewed_at = utcnow()
    wl.reviewed_by = admin
    await db.commit()

    return RedirectResponse(
        url=f"/_auth/admin/invites?app_slug={wl.app_slug}", status_code=302
    )


@router.post("/invites/waitlist/{wl_id}/deny")
async def deny_waitlist(
    wl_id: int,
    request: Request,
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    wl = await db.get(InviteWaitlist, wl_id)
    if not wl or wl.status != "pending":
        return RedirectResponse(url="/_auth/admin/invites", status_code=302)

    wl.status = "denied"
    wl.reason = reason or None
    wl.reviewed_at = utcnow()
    wl.reviewed_by = admin

    # Add IP to blocklist
    await block_ip(db, wl.ip_address, reason=f"Waitlist denied: {wl.email}", blocked_by=admin)

    await db.commit()

    return RedirectResponse(
        url=f"/_auth/admin/invites?app_slug={wl.app_slug}", status_code=302
    )


@router.post("/invites/grant")
async def grant_invite_slots(
    request: Request,
    app_slug: str = Form(...),
    user_ids: str = Form(""),
    additional_invites: int = Form(5),
    db: AsyncSession = Depends(get_db),
):
    """Grant additional personal invite capacity to selected users."""
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from gatekeeper.auth.invites import get_user_invite_limit

    app_config = _config.apps.get(app_slug)
    if not app_config:
        return HTMLResponse(f"<h2>Unknown app: {app_slug}</h2>", status_code=400)
    default_limit = (app_config.invite.personal_invites.max_per_user
                     if app_config else 5)

    ids = [int(uid.strip()) for uid in user_ids.split(",") if uid.strip().isdigit()]

    for uid in ids:
        current_limit = await get_user_invite_limit(db, uid, app_slug, default_limit)
        new_limit = current_limit + additional_invites

        existing = await db.scalar(
            select(InviteUserLimit).where(
                InviteUserLimit.user_id == uid,
                InviteUserLimit.app_slug == app_slug,
            )
        )
        if existing:
            existing.max_invites = new_limit
        else:
            db.add(InviteUserLimit(
                user_id=uid, app_slug=app_slug, max_invites=new_limit,
            ))

    await db.commit()

    return RedirectResponse(
        url=f"/_auth/admin/invites?app_slug={app_slug}", status_code=302
    )


# --- Analytics ---


@router.get("/analytics")
async def analytics_page(
    request: Request,
    app_slug: str = "",
    days: int = 7,
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    days = min(max(days, 1), 90)
    cutoff = utcnow() - datetime.timedelta(days=days)

    # Build base filter
    filters = [AccessLog.timestamp >= cutoff]
    if app_slug:
        filters.append(AccessLog.app_slug == app_slug)

    # -- Daily summary: unique sessions per day --
    date_expr = func.date(AccessLog.timestamp).label("day")
    daily_stmt = (
        select(
            date_expr,
            func.count(func.distinct(AccessLog.session_token)).label("unique_sessions"),
            func.count(func.distinct(AccessLog.ip_address)).label("unique_ips"),
            func.count(AccessLog.id).label("total_requests"),
            func.count(func.distinct(AccessLog.user_email)).label("unique_users"),
        )
        .where(*filters)
        .group_by(date_expr)
        .order_by(desc(date_expr))
    )
    daily_rows = (await db.execute(daily_stmt)).all()

    # -- Per-session detail for the selected period --
    session_stmt = (
        select(
            AccessLog.session_token,
            AccessLog.ip_address,
            AccessLog.user_email,
            func.min(AccessLog.timestamp).label("first_seen"),
            func.max(AccessLog.timestamp).label("last_seen"),
            func.count(AccessLog.id).label("request_count"),
            func.min(AccessLog.referrer).label("referrer"),
            func.min(AccessLog.user_agent).label("user_agent"),
            AccessLog.app_slug,
        )
        .where(*filters, AccessLog.session_token.isnot(None))
        .group_by(AccessLog.session_token)
        .order_by(desc(func.max(AccessLog.timestamp)))
        .limit(500)
    )
    session_rows = (await db.execute(session_stmt)).all()

    sessions = []
    for row in session_rows:
        first = row.first_seen
        last = row.last_seen
        if first and last:
            duration_secs = (last - first).total_seconds()
            if duration_secs < 60:
                duration = f"{int(duration_secs)}s"
            elif duration_secs < 3600:
                duration = f"{int(duration_secs // 60)}m"
            else:
                hours = int(duration_secs // 3600)
                mins = int((duration_secs % 3600) // 60)
                duration = f"{hours}h{mins}m"
        else:
            duration = "-"

        sessions.append({
            "token_short": (row.session_token or "")[:12] + "...",
            "ip": row.ip_address,
            "user_email": row.user_email,
            "signed_in": bool(row.user_email),
            "first_seen": first,
            "last_seen": last,
            "duration": duration,
            "requests": row.request_count,
            "referrer": row.referrer,
            "user_agent": row.user_agent,
            "app_slug": row.app_slug,
        })

    return templates.TemplateResponse(request, "admin/analytics.html", {
        "request": request,
        "daily_rows": daily_rows,
        "sessions": sessions,
        "filter_app": app_slug,
        "filter_days": days,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "terminal_enabled": _config.terminal_enabled,
        "pending_waitlist": await _pending_waitlist_count(db),
    })
