"""Admin routes for managing users, IP blocklist, and viewing access logs."""
import datetime
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, delete
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import User, UserAppRole, IPBlocklist, AccessLog, Session, APIKey
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

    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "user_count": user_count,
        "blocked_count": blocked_count,
        "apps": _config.apps,
        "api_key_counts": api_key_counts,
        "admin_email": admin,
        "environment": _config.environment,
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

        # Get current usage from in-memory tracker
        timestamps = _api_key_log.get(k.key, [])
        cutoff = current_time - window
        usage = len([t for t in timestamps if t > cutoff])

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
