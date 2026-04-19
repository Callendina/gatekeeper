"""Invite code management — public entry, personal invites, admin API."""
import secrets
import datetime
import hashlib
import hmac
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig, AppConfig
from gatekeeper.models import InviteCode, InviteUse, InviteWaitlist, InviteUserLimit, User
from gatekeeper.auth.sessions import validate_session
from gatekeeper.middleware.ip_block import block_ip

from pathlib import Path

router = APIRouter(prefix="/_auth")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


INVITE_FAIL_LIMIT = 50

# In-memory tracker: {ip: fail_count}
_invite_failures: dict[str, int] = {}


def init_invite_routes(config: GatekeeperConfig):
    global _config
    _config = config


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def _resolve_app(request: Request, app: str) -> tuple[str, AppConfig | None]:
    app_config = _config.apps.get(app) if app else None
    if not app_config:
        host = request.headers.get("host", "")
        app_config = _config.app_for_domain(host)
        if app_config:
            app = app_config.slug
    return app, app_config


# ---------------------------------------------------------------------------
# Cookie signing helpers (used by both routes and forward_auth)
# ---------------------------------------------------------------------------

def generate_invite_code() -> str:
    """Generate a human-friendly invite code in XXXX-XXXX format."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1 to avoid ambiguity
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"{part1}-{part2}"


def sign_invite_cookie(invite_use_id: int, code_id: int, timestamp: int,
                       secret_key: str, app_slug: str) -> str:
    msg = f"{invite_use_id}:{code_id}:{timestamp}:{app_slug}".encode()
    return hmac.new(secret_key.encode(), msg, hashlib.sha256).hexdigest()


def make_invite_cookie(invite_use_id: int, code_id: int,
                       secret_key: str, app_slug: str) -> str:
    ts = int(datetime.datetime.utcnow().timestamp())
    sig = sign_invite_cookie(invite_use_id, code_id, ts, secret_key, app_slug)
    return f"{invite_use_id}:{code_id}:{ts}:{sig}"


def verify_invite_cookie(cookie_value: str, secret_key: str,
                         app_slug: str, max_age_days: int) -> int | None:
    """Verify invite cookie. Returns invite_use_id or None."""
    try:
        parts = cookie_value.split(":")
        if len(parts) != 4:
            return None
        invite_use_id, code_id, ts, sig = (
            int(parts[0]), int(parts[1]), int(parts[2]), parts[3]
        )
        expected = sign_invite_cookie(invite_use_id, code_id, ts,
                                      secret_key, app_slug)
        if not hmac.compare_digest(sig, expected):
            return None
        age = datetime.datetime.utcnow().timestamp() - ts
        if age > max_age_days * 86400:
            return None
        return invite_use_id
    except (ValueError, IndexError):
        return None


async def validate_invite_code_db(db: AsyncSession, app_slug: str,
                                  code_str: str) -> InviteCode | None:
    """Look up a valid, active, non-expired, non-exhausted invite code (case-insensitive)."""
    now = datetime.datetime.utcnow()
    from sqlalchemy import func as sa_func
    stmt = select(InviteCode).where(
        InviteCode.app_slug == app_slug,
        sa_func.upper(InviteCode.code) == code_str.upper(),
        InviteCode.active == True,
    )
    result = await db.execute(stmt)
    code_obj = result.scalar_one_or_none()
    if code_obj is None:
        return None
    if code_obj.expires_at and code_obj.expires_at < now:
        return None
    if code_obj.max_uses > 0 and code_obj.use_count >= code_obj.max_uses:
        return None
    return code_obj


async def record_invite_use(db: AsyncSession, code_obj: InviteCode,
                            email: str | None, ip: str) -> InviteUse:
    use = InviteUse(
        invite_code_id=code_obj.id,
        used_by_email=email,
        ip_address=ip,
    )
    db.add(use)
    code_obj.use_count += 1
    await db.commit()
    return use


async def get_user_invite_limit(db: AsyncSession, user_id: int,
                                app_slug: str, default: int) -> int:
    """Get the effective invite limit for a user (per-user override or app default)."""
    override = await db.scalar(
        select(InviteUserLimit.max_invites).where(
            InviteUserLimit.user_id == user_id,
            InviteUserLimit.app_slug == app_slug,
        )
    )
    return override if override is not None else default


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

def _render_invite_page(request: Request, app: str, app_config, next: str,
                        error: str = "") -> HTMLResponse:
    """Render the invite page — custom HTML or default template."""
    app_name = app_config.name if app_config else "Application"

    if app_config and app_config.invite.invite_html_file:
        try:
            with open(app_config.invite.invite_html_file) as f:
                html = f.read()
            html = html.replace("{{APP_NAME}}", app_name)
            html = html.replace("{{INVITE_SUBMIT_URL}}",
                                f"/_auth/invite/validate?app={app}&next={next}")
            waitlist_url = (f"/_auth/invite/waitlist?app={app}"
                           if app_config.invite.waitlist else "")
            html = html.replace("{{WAITLIST_SUBMIT_URL}}", waitlist_url)
            html = html.replace("{{LOGIN_URL}}",
                                f"/_auth/login?app={app}&next={next}")
            html = html.replace("{{ERROR}}", error)
            html = html.replace("{{WAITLIST_CONFIRMED}}", "")
            html = html.replace("{{WAITLIST_EMAIL}}", "")
            return HTMLResponse(html)
        except FileNotFoundError:
            pass

    return templates.TemplateResponse("auth/invite.html", {
        "request": request,
        "app": app,
        "app_name": app_name,
        "next": next,
        "show_waitlist": app_config.invite.waitlist if app_config else False,
        "error": error,
    })


@router.get("/invite")
async def invite_page(request: Request, app: str = "", next: str = "/"):
    app, app_config = _resolve_app(request, app)
    return _render_invite_page(request, app, app_config, next)


@router.post("/invite/validate")
async def validate_invite(
    request: Request,
    app: str = "",
    next: str = "/",
    code: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    app_slug, app_config = _resolve_app(request, app)
    if not app_config:
        return HTMLResponse("<h2>Unknown app</h2>", status_code=400)

    ip = _get_client_ip(request)
    code_obj = await validate_invite_code_db(db, app_slug, code.strip())
    if code_obj is None:
        _invite_failures[ip] = _invite_failures.get(ip, 0) + 1
        if _invite_failures[ip] >= INVITE_FAIL_LIMIT:
            await block_ip(db, ip, reason="Exceeded invite code attempt limit",
                           blocked_by="gatekeeper-auto")
            _invite_failures.pop(ip, None)
            return HTMLResponse("<h2>Blocked</h2><p>Too many invalid invite code attempts.</p>",
                                status_code=403)
        return _render_invite_page(request, app_slug, app_config, next,
                                   error="Invalid or expired invite code.")

    _invite_failures.pop(ip, None)  # Clear failures on success
    use = await record_invite_use(db, code_obj, None, ip)

    response = RedirectResponse(url=next, status_code=302)
    cookie_val = make_invite_cookie(use.id, code_obj.id,
                                    _config.secret_key, app_slug)
    response.set_cookie(
        "gk_invite_granted", cookie_val,
        httponly=True, secure=True, samesite="lax",
        max_age=app_config.invite.cookie_max_age_days * 86400,
    )
    return response


@router.post("/invite/waitlist")
async def join_waitlist(
    request: Request,
    app: str = "",
    email: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    app_slug, app_config = _resolve_app(request, app)
    if not app_config or not app_config.invite.waitlist:
        return HTMLResponse("<h2>Waitlist not enabled</h2>", status_code=400)

    ip = _get_client_ip(request)
    email = email.strip().lower()
    if not email or "@" not in email or "." not in email.split("@")[-1] or len(email) > 254:
        return _render_invite_page(request, app_slug, app_config, "/",
                                   error="Please enter a valid email address.")

    existing = await db.scalar(
        select(InviteWaitlist).where(
            InviteWaitlist.app_slug == app_slug,
            InviteWaitlist.email == email,
        )
    )
    if not existing:
        entry = InviteWaitlist(
            app_slug=app_slug,
            email=email,
            ip_address=ip,
        )
        db.add(entry)
        await db.commit()

    # Render the invite page with waitlist confirmation message
    if app_config and app_config.invite.invite_html_file:
        try:
            with open(app_config.invite.invite_html_file) as f:
                html = f.read()
            app_name = app_config.name
            html = html.replace("{{APP_NAME}}", app_name)
            html = html.replace("{{INVITE_SUBMIT_URL}}", "")
            html = html.replace("{{WAITLIST_SUBMIT_URL}}", "")
            html = html.replace("{{LOGIN_URL}}", "")
            html = html.replace("{{ERROR}}", "")
            html = html.replace("{{WAITLIST_CONFIRMED}}", "true")
            html = html.replace("{{WAITLIST_EMAIL}}", email)
            return HTMLResponse(html)
        except FileNotFoundError:
            pass

    return templates.TemplateResponse("auth/invite_waitlist_confirm.html", {
        "request": request,
        "app_name": app_config.name,
        "email": email,
    })


# ---------------------------------------------------------------------------
# Authenticated user routes (personal invites)
# ---------------------------------------------------------------------------

@router.post("/invite/create")
async def create_personal_invite(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    host = request.headers.get("host", "")
    app_config = _config.app_for_domain(host)
    if not app_config:
        return JSONResponse({"error": "Unknown app"}, status_code=400)
    if not app_config.invite.enabled:
        return JSONResponse({"error": "Invites not enabled"}, status_code=400)
    if not app_config.invite.personal_invites.enabled:
        return JSONResponse({"error": "Personal invites not enabled"}, status_code=400)

    session_token = request.cookies.get("gk_session")
    if not session_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    session, user, role = await validate_session(db, session_token, app_config.slug)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    pi = app_config.invite.personal_invites
    max_allowed = await get_user_invite_limit(
        db, user.id, app_config.slug, pi.max_per_user
    )
    count = await db.scalar(
        select(func.count(InviteCode.id)).where(
            InviteCode.app_slug == app_config.slug,
            InviteCode.code_type == "personal",
            InviteCode.created_by_email == user.email,
        )
    ) or 0
    if count >= max_allowed:
        return JSONResponse({
            "error": f"Maximum personal invites ({max_allowed}) reached",
        }, status_code=429)

    code = generate_invite_code()
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=pi.expiry_days)
                  if pi.expiry_days > 0 else None)
    invite = InviteCode(
        app_slug=app_config.slug,
        code=code,
        code_type="personal",
        created_by_email=user.email,
        max_uses=1,
        expires_at=expires_at,
    )
    db.add(invite)
    await db.commit()

    return JSONResponse({
        "code": code,
        "expires_at": expires_at.isoformat() + "Z" if expires_at else None,
    })


@router.get("/invite/status")
async def invite_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Return the current user's invite status: counts, unused codes, and remaining capacity."""
    host = request.headers.get("host", "")
    app_config = _config.app_for_domain(host)
    if not app_config:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    session_token = request.cookies.get("gk_session")
    if not session_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    session, user, role = await validate_session(db, session_token, app_config.slug)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    pi = app_config.invite.personal_invites
    max_allowed = await get_user_invite_limit(
        db, user.id, app_config.slug, pi.max_per_user
    )

    # Get all personal codes by this user
    stmt = (
        select(InviteCode)
        .where(
            InviteCode.app_slug == app_config.slug,
            InviteCode.code_type == "personal",
            InviteCode.created_by_email == user.email,
        )
        .order_by(InviteCode.created_at.desc())
    )
    result = await db.execute(stmt)
    codes = result.scalars().all()

    now = datetime.datetime.utcnow()
    total_created = len(codes)
    used_codes = []
    unused_codes = []

    for c in codes:
        code_info = {
            "code": c.code,
            "active": c.active,
            "expires_at": c.expires_at.isoformat() + "Z" if c.expires_at else None,
            "created_at": c.created_at.isoformat() + "Z",
        }
        expired = c.expires_at and c.expires_at < now
        if c.use_count > 0:
            # Fetch who used it
            uses_result = await db.execute(
                select(InviteUse).where(InviteUse.invite_code_id == c.id)
            )
            uses = uses_result.scalars().all()
            code_info["used_by"] = [
                {"email": u.used_by_email, "at": u.granted_at.isoformat() + "Z"}
                for u in uses
            ]
            used_codes.append(code_info)
        elif not c.active or expired:
            # Expired or revoked but never used — still counts towards total
            code_info["status"] = "expired" if expired else "revoked"
            used_codes.append(code_info)
        else:
            unused_codes.append(code_info)

    remaining = max(0, max_allowed - total_created)

    return JSONResponse({
        "total_created": total_created,
        "total_used": len(used_codes),
        "total_unused": len(unused_codes),
        "remaining": remaining,
        "max_allowed": max_allowed,
        "unused_codes": unused_codes,
        "used_codes": used_codes,
        "personal_invites_enabled": pi.enabled,
    })


# ---------------------------------------------------------------------------
# Admin API routes (require admin_api_key via X-Admin-Key header)
# ---------------------------------------------------------------------------

@router.post("/invite/codes")
async def create_bulk_code(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    app_slug = body.get("app_slug", "")
    app_config = _config.apps.get(app_slug)
    if not app_config:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    provided_key = request.headers.get("x-admin-key", "")
    if not app_config.admin_api_key or provided_key != app_config.admin_api_key:
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=401)

    max_uses = body.get("max_uses", 100)
    expiry_days = body.get("expiry_days", 0)
    custom_code = body.get("code", "")
    role = body.get("role", None)
    group = body.get("group", None)

    # Validate role against app config if provided
    if role and role not in app_config.roles:
        return JSONResponse({"error": f"Invalid role '{role}'. Valid: {app_config.roles}"}, status_code=400)

    code = custom_code or generate_invite_code()
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)
                  if expiry_days > 0 else None)

    invite = InviteCode(
        app_slug=app_slug,
        code=code,
        code_type="bulk",
        max_uses=max_uses,
        expires_at=expires_at,
        role=role or None,
        group=group or None,
    )
    db.add(invite)
    await db.commit()

    return JSONResponse({
        "code": code,
        "role": role,
        "group": group,
        "max_uses": max_uses,
        "expires_at": expires_at.isoformat() + "Z" if expires_at else None,
    })


@router.get("/invite/codes")
async def list_codes(
    request: Request,
    app: str = "",
    db: AsyncSession = Depends(get_db),
):
    app_config = _config.apps.get(app)
    if not app_config:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    provided_key = request.headers.get("x-admin-key", "")
    if not app_config.admin_api_key or provided_key != app_config.admin_api_key:
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=401)

    stmt = (
        select(InviteCode)
        .where(InviteCode.app_slug == app)
        .order_by(InviteCode.created_at.desc())
    )
    result = await db.execute(stmt)
    codes = result.scalars().all()

    return JSONResponse({"codes": [
        {
            "id": c.id, "code": c.code, "code_type": c.code_type,
            "created_by_email": c.created_by_email,
            "max_uses": c.max_uses, "use_count": c.use_count,
            "active": c.active, "role": c.role,
            "expires_at": c.expires_at.isoformat() + "Z" if c.expires_at else None,
            "created_at": c.created_at.isoformat() + "Z",
        }
        for c in codes
    ]})


@router.patch("/invite/codes/{code}")
async def update_code(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    app_slug = body.get("app_slug", "")
    app_config = _config.apps.get(app_slug)
    if not app_config:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    provided_key = request.headers.get("x-admin-key", "")
    if not app_config.admin_api_key or provided_key != app_config.admin_api_key:
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=401)

    code_obj = await db.scalar(
        select(InviteCode).where(
            InviteCode.app_slug == app_slug,
            InviteCode.code == code,
        )
    )
    if not code_obj:
        return JSONResponse({"error": "Code not found"}, status_code=404)

    if "active" in body:
        code_obj.active = body["active"]
    if "max_uses" in body:
        code_obj.max_uses = body["max_uses"]

    await db.commit()
    return JSONResponse({"status": "updated"})
