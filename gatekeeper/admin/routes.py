"""Admin routes for managing users, IP blocklist, and viewing access logs."""
import datetime
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, delete
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import User, UserAppRole, IPBlocklist, AccessLog, Session, APIKey, InviteCode, InviteUse, InviteWaitlist, InviteUserLimit
from gatekeeper.middleware.ip_block import block_ip, unblock_ip
from gatekeeper.auth.sessions import validate_session

from pathlib import Path

router = APIRouter(prefix="/_auth/admin")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def init_admin_routes(config: GatekeeperConfig):
    global _config
    _config = config


async def _require_admin(request: Request, db: AsyncSession):
    """Check that the request is from a system admin by validating the session cookie.
    Returns the admin email, or an appropriate response (redirect to login or access denied)."""
    session_token = request.cookies.get("gk_session")
    authenticated_user = None

    if session_token:
        # Try all configured app slugs
        for app_slug in _config.apps:
            session, user, role = await validate_session(db, session_token, app_slug)
            if user:
                if user.is_system_admin:
                    return user.email
                authenticated_user = user.email

        # Also check sessions not scoped to any app (e.g. from the admin domain)
        if not authenticated_user:
            stmt = select(Session).where(
                Session.token == session_token,
                Session.expires_at > datetime.datetime.utcnow(),
            )
            result = await db.execute(stmt)
            session = result.scalar_one_or_none()
            if session and session.user_id:
                user_stmt = select(User).where(User.id == session.user_id)
                user_result = await db.execute(user_stmt)
                user = user_result.scalar_one_or_none()
                if user:
                    if user.is_system_admin:
                        return user.email
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

    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "user_count": user_count,
        "blocked_count": blocked_count,
        "apps": _config.apps,
        "api_key_counts": api_key_counts,
        "pending_waitlist": pending_waitlist,
        "admin_email": admin,
        "environment": _config.environment,
        "pending_waitlist": await _pending_waitlist_count(db),
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

    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "users": users,
        "user_roles": user_roles,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


@router.post("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    request: Request,
    app_slug: str = Form(...),
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    stmt = select(UserAppRole).where(
        UserAppRole.user_id == user_id,
        UserAppRole.app_slug == app_slug,
    )
    result = await db.execute(stmt)
    app_role = result.scalar_one_or_none()

    if app_role:
        app_role.role = role
    else:
        app_role = UserAppRole(user_id=user_id, app_slug=app_slug, role=role)
        db.add(app_role)

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

    return templates.TemplateResponse("admin/ip_blocklist.html", {
        "request": request,
        "blocked_ips": blocked,
        "admin_email": admin,
        "environment": _config.environment,
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

    return templates.TemplateResponse("admin/access_log.html", {
        "request": request,
        "logs": logs,
        "filter_ip": ip,
        "filter_app": app_slug,
        "filter_status": status,
        "page": page,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


@router.get("/api-keys")
async def api_keys_page(
    request: Request,
    app_slug: str = "",
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from gatekeeper.middleware.rate_limit import _api_key_log
    import time

    now = datetime.datetime.utcnow()
    stmt = select(APIKey).where(APIKey.expires_at > now).order_by(APIKey.created_at.desc())
    if app_slug:
        stmt = stmt.where(APIKey.app_slug == app_slug)
    result = await db.execute(stmt)
    keys = result.scalars().all()

    # Build key info with usage stats and default limits
    key_info = []
    current_time = time.time()
    window = 60.0
    for k in keys:
        # Determine tier and default limit
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

        # Get current weighted usage from in-memory tracker
        entries = _api_key_log.get(k.key, [])
        cutoff = current_time - window
        usage = sum(w for t, w in entries if t > cutoff)

        # Look up user email
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

    return templates.TemplateResponse("admin/api_keys.html", {
        "request": request,
        "keys": key_info,
        "filter_app": app_slug,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


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

    return templates.TemplateResponse("admin/invites.html", {
        "request": request,
        "codes": codes,
        "code_uses": code_uses,
        "waitlist": waitlist,
        "filter_app": app_slug,
        "apps": _config.apps,
        "all_users": all_users,
        "admin_email": admin,
        "environment": _config.environment,
        "pending_waitlist": await _pending_waitlist_count(db),
    })


@router.post("/invites/create")
async def admin_create_code(
    request: Request,
    app_slug: str = Form(...),
    max_uses: int = Form(100),
    expiry_days: int = Form(0),
    custom_code: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    admin, redirect = _check_admin(await _require_admin(request, db))
    if redirect:
        return redirect

    from gatekeeper.auth.invites import generate_invite_code

    code = custom_code.strip() or generate_invite_code()
    expires_at = (
        datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)
        if expiry_days > 0 else None
    )

    invite = InviteCode(
        app_slug=app_slug, code=code, code_type="bulk",
        max_uses=max_uses, expires_at=expires_at,
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
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)

    code = generate_invite_code()
    invite = InviteCode(
        app_slug=wl.app_slug, code=code, code_type="bulk",
        created_by_email=admin, max_uses=1, expires_at=expires_at,
    )
    db.add(invite)
    await db.flush()

    wl.status = "approved"
    wl.invite_code_id = invite.id
    wl.reviewed_at = datetime.datetime.utcnow()
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
    wl.reviewed_at = datetime.datetime.utcnow()
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
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)

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

    return templates.TemplateResponse("admin/analytics.html", {
        "request": request,
        "daily_rows": daily_rows,
        "sessions": sessions,
        "filter_app": app_slug,
        "filter_days": days,
        "apps": _config.apps,
        "admin_email": admin,
        "environment": _config.environment,
        "pending_waitlist": await _pending_waitlist_count(db),
    })
