"""Magic link (passwordless email) login."""
import secrets
import datetime
import time
import logging
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import User, UserAppRole, MagicLink, InviteUse
from gatekeeper.auth.sessions import create_session
from gatekeeper.auth.email import send_magic_link_email

from pathlib import Path

router = APIRouter(prefix="/_auth")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

logger = logging.getLogger("gatekeeper.magic_link")

# In-memory rate limit: {ip: [timestamp, ...]}
_ip_requests: dict[str, list[float]] = {}


def init_magic_link_routes(config: GatekeeperConfig):
    global _config
    _config = config


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def _resolve_app(request: Request, app: str):
    app_config = _config.apps.get(app) if app else None
    if not app_config:
        host = request.headers.get("host", "")
        app_config = _config.app_for_domain(host)
        if app_config:
            app = app_config.slug
    return app, app_config


def _check_ip_rate_limit(ip: str, max_per_10min: int) -> bool:
    """Returns True if allowed, False if rate limited."""
    now = time.time()
    cutoff = now - 600  # 10 minute window
    entries = _ip_requests.get(ip, [])
    entries = [t for t in entries if t > cutoff]
    _ip_requests[ip] = entries
    return len(entries) < max_per_10min


def _record_ip_request(ip: str):
    _ip_requests.setdefault(ip, []).append(time.time())


async def _check_email_rate_limit(
    db: AsyncSession, email: str, app_slug: str, min_interval_minutes: int
) -> bool:
    """Returns True if allowed (no recent send to this email for this app)."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=min_interval_minutes)
    stmt = select(MagicLink).where(
        MagicLink.email == email,
        MagicLink.app_slug == app_slug,
        MagicLink.created_at > cutoff,
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is None


async def _user_has_app_role(db: AsyncSession, email: str, app_slug: str) -> bool:
    """Check if a user with this email has an existing UserAppRole for the app."""
    stmt = (
        select(UserAppRole)
        .join(User, User.id == UserAppRole.user_id)
        .where(User.email == email, UserAppRole.app_slug == app_slug)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is not None


@router.post("/magic-link")
async def send_magic_link(
    request: Request,
    email: str = Form(...),
    app: str = Form(""),
    next: str = Form("/"),
    db: AsyncSession = Depends(get_db),
):
    app_slug, app_config = _resolve_app(request, app)
    ip = _get_client_ip(request)

    # Always show the same response regardless of outcome
    success_msg = "If that address is eligible, check your inbox for a sign-in link."

    if not app_config or not app_config.magic_link.enabled:
        return _sent_page(request, app_slug, app_config, success_msg)

    if not _config.email.enabled:
        logger.error("Magic link requested but email not configured")
        return _sent_page(request, app_slug, app_config, success_msg)

    # Per-IP rate limit
    if not _check_ip_rate_limit(ip, app_config.magic_link.rate_limit_per_ip_per_10min):
        return _sent_page(request, app_slug, app_config, success_msg)

    # Per-email rate limit
    if not await _check_email_rate_limit(
        db, email, app_slug, app_config.magic_link.rate_limit_per_email_minutes
    ):
        return _sent_page(request, app_slug, app_config, success_msg)

    # Invite-only gate: existing users always allowed, new users need invite
    has_invite = False
    if app_config.invite.enabled:
        is_returning = await _user_has_app_role(db, email, app_slug)
        if not is_returning:
            from gatekeeper.auth.invites import verify_invite_cookie
            cookie = request.cookies.get("gk_invite_granted")
            if cookie:
                invite_use_id = verify_invite_cookie(
                    cookie, _config.secret_key, app_slug,
                    app_config.invite.cookie_max_age_days,
                )
                has_invite = invite_use_id is not None
            if not has_invite:
                # New user without invite — silently don't send
                return _sent_page(request, app_slug, app_config, success_msg)
        else:
            has_invite = True  # Returning user, treat as having invite

    _record_ip_request(ip)

    # Generate magic link
    token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=app_config.magic_link.link_expiry_minutes
    )

    ml = MagicLink(
        token=token,
        email=email.strip().lower(),
        app_slug=app_slug,
        ip_address=ip,
        has_invite=has_invite,
        expires_at=expires_at,
    )
    db.add(ml)
    await db.commit()

    # Build the verification link
    host = request.headers.get("host", "")
    scheme = request.url.scheme
    link = f"{scheme}://{host}/_auth/magic-link/verify?token={token}&next={next}"

    await send_magic_link_email(email, link, app_config.name, _config.email)

    return _sent_page(request, app_slug, app_config, success_msg)


def _sent_page(request, app_slug, app_config, message):
    """Render the 'check your email' page."""
    app_name = app_config.name if app_config else "Application"

    # Custom sent page
    if app_config and app_config.magic_link.sent_html_file:
        try:
            with open(app_config.magic_link.sent_html_file) as f:
                html = f.read()
            html = html.replace("{{APP_NAME}}", app_name)
            html = html.replace("{{MESSAGE}}", message)
            html = html.replace("{{LOGIN_URL}}", f"/_auth/login?app={app_slug}")
            return HTMLResponse(html)
        except FileNotFoundError:
            pass

    return templates.TemplateResponse("auth/magic_link_sent.html", {
        "request": request,
        "app": app_slug,
        "app_name": app_name,
        "message": message,
    })


@router.get("/magic-link/verify")
async def verify_magic_link(
    request: Request,
    token: str = "",
    next: str = "/",
    db: AsyncSession = Depends(get_db),
):
    if not token:
        return HTMLResponse("<h2>Invalid link</h2>", status_code=400)

    # Look up the magic link
    stmt = select(MagicLink).where(MagicLink.token == token)
    result = await db.execute(stmt)
    ml = result.scalar_one_or_none()

    if ml is None:
        return HTMLResponse("<h2>Invalid or expired link</h2>", status_code=400)

    now = datetime.datetime.utcnow()
    if ml.expires_at < now:
        return HTMLResponse("<h2>This link has expired</h2><p>Please request a new one.</p>", status_code=400)

    if ml.used_at is not None:
        return HTMLResponse("<h2>This link has already been used</h2><p>Please request a new one.</p>", status_code=400)

    # Mark as used
    ml.used_at = now
    await db.flush()

    app_config = _config.apps.get(ml.app_slug)
    email = ml.email

    # Find or create user
    user_stmt = select(User).where(User.email == email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    is_new_user = user is None
    if is_new_user:
        display_name = email.split("@")[0]
        user = User(email=email, display_name=display_name)
        db.add(user)
        await db.flush()

    # Check/create app role
    role_stmt = select(UserAppRole).where(
        UserAppRole.user_id == user.id,
        UserAppRole.app_slug == ml.app_slug,
    )
    role_result = await db.execute(role_stmt)
    app_role = role_result.scalar_one_or_none()

    if app_role is None and app_config:
        # Determine pending status
        pending = False
        if app_config.invite.enabled and not ml.has_invite:
            pending = True

        app_role = UserAppRole(
            user_id=user.id,
            app_slug=ml.app_slug,
            role=app_config.default_role,
            pending_invite=pending,
        )
        db.add(app_role)

        # Link invite use to email if applicable
        if ml.has_invite and app_config.invite.enabled:
            invite_cookie = request.cookies.get("gk_invite_granted")
            if invite_cookie:
                from gatekeeper.auth.invites import verify_invite_cookie
                invite_use_id = verify_invite_cookie(
                    invite_cookie, _config.secret_key, ml.app_slug,
                    app_config.invite.cookie_max_age_days,
                )
                if invite_use_id:
                    invite_use = await db.scalar(
                        select(InviteUse).where(InviteUse.id == invite_use_id)
                    )
                    if invite_use and not invite_use.used_by_email:
                        invite_use.used_by_email = email

    await db.commit()

    # Create session
    ip = _get_client_ip(request)
    session_token = await create_session(db, user.id, ml.app_slug, ip)

    # Redirect
    if app_role and app_role.pending_invite:
        redirect_url = f"/_auth/pending?app={ml.app_slug}"
    else:
        redirect_url = next

    host = request.headers.get("host", "")
    target_host = (app_config.domains[0] if app_config and app_config.domains else "")

    if target_host and target_host != host:
        # Cross-domain: use set-session endpoint
        from gatekeeper.auth.login import _sign_session_token
        ts = int(time.time())
        sig = _sign_session_token(session_token, ts)
        from urllib.parse import quote
        redirect_url = (
            f"https://{target_host}/_auth/set-session"
            f"?token={session_token}&sig={sig}&ts={ts}&next={quote(redirect_url)}"
        )
        return RedirectResponse(url=redirect_url, status_code=302)

    full_url = f"https://{target_host}{redirect_url}" if target_host else redirect_url
    response = RedirectResponse(url=full_url, status_code=302)
    response.set_cookie(
        "gk_session", session_token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 180,
    )
    return response


# --- Pending page ---


@router.get("/pending")
async def pending_page(
    request: Request,
    app: str = "",
    db: AsyncSession = Depends(get_db),
):
    app_slug, app_config = _resolve_app(request, app)
    app_name = app_config.name if app_config else "Application"

    # Check if user is logged in
    session_token = request.cookies.get("gk_session")
    user_email = None
    if session_token and app_slug:
        from gatekeeper.auth.sessions import validate_session
        _sess, user, _role = await validate_session(db, session_token, app_slug)
        if user:
            user_email = user.email

    # Custom pending page
    if app_config and app_config.magic_link.pending_html_file:
        try:
            with open(app_config.magic_link.pending_html_file) as f:
                html = f.read()
            html = html.replace("{{APP_NAME}}", app_name)
            html = html.replace("{{CODE_SUBMIT_URL}}", f"/_auth/pending/submit-code?app={app_slug}")
            html = html.replace("{{WAITLIST_SUBMIT_URL}}", f"/_auth/invite/waitlist?app={app_slug}")
            html = html.replace("{{LOGOUT_URL}}", f"/_auth/logout?app={app_slug}")
            html = html.replace("{{USER_EMAIL}}", user_email or "")
            return HTMLResponse(html)
        except FileNotFoundError:
            pass

    has_waitlist = app_config.invite.waitlist if app_config else False

    return templates.TemplateResponse("auth/pending.html", {
        "request": request,
        "app": app_slug,
        "app_name": app_name,
        "user_email": user_email,
        "has_waitlist": has_waitlist,
    })


@router.post("/pending/submit-code")
async def pending_submit_code(
    request: Request,
    code: str = Form(...),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    app_slug, app_config = _resolve_app(request, app)

    if not app_config:
        return HTMLResponse("<h2>Unknown app</h2>", status_code=400)

    # Must be logged in
    session_token = request.cookies.get("gk_session")
    if not session_token:
        return RedirectResponse(url=f"/_auth/login?app={app_slug}", status_code=302)

    from gatekeeper.auth.sessions import validate_session
    _sess, user, _role = await validate_session(db, session_token, app_slug)
    if not user:
        return RedirectResponse(url=f"/_auth/login?app={app_slug}", status_code=302)

    # Validate the invite code
    from gatekeeper.auth.invites import validate_invite_code_db, record_invite_use
    code_obj = await validate_invite_code_db(db, app_slug, code.strip())
    if not code_obj:
        return RedirectResponse(
            url=f"/_auth/pending?app={app_slug}&error=invalid_code", status_code=302
        )

    # Record invite use
    ip = _get_client_ip(request)
    await record_invite_use(db, code_obj, user.email, ip)

    # Clear pending status
    role_stmt = select(UserAppRole).where(
        UserAppRole.user_id == user.id,
        UserAppRole.app_slug == app_slug,
    )
    role_result = await db.execute(role_stmt)
    app_role = role_result.scalar_one_or_none()
    if app_role and app_role.pending_invite:
        app_role.pending_invite = False
        await db.commit()

    # Redirect to app
    if app_config.domains:
        return RedirectResponse(url=f"https://{app_config.domains[0]}/", status_code=302)
    return RedirectResponse(url="/", status_code=302)


def cleanup_expired_magic_links_sync():
    """Called from periodic cleanup to remove old magic links."""
    pass  # Handled in async version below


async def cleanup_expired_magic_links(db: AsyncSession):
    """Remove magic links that have expired or been used (older than 1 day)."""
    from sqlalchemy import delete
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    await db.execute(
        delete(MagicLink).where(MagicLink.expires_at < cutoff)
    )
    await db.commit()
