"""API key issuance and validation.

Two types of keys:
- "registered": long-lived, issued to authenticated users via /_auth/api-key
- "temp": short-lived (e.g. 30 min), issued to anonymous frontend users who
  have a valid gk_session cookie, via /_auth/api-key/temp
"""
import secrets
import datetime
from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import APIKey, User, UserAppRole
from gatekeeper.auth.sessions import validate_session

router = APIRouter(prefix="/_auth")
_config: GatekeeperConfig = None


async def count_active_keys(db: AsyncSession, app_slug: str) -> dict:
    """Count active (non-expired) API keys by tier for an app."""
    now = datetime.datetime.utcnow()
    base = select(func.count(APIKey.id)).where(
        APIKey.app_slug == app_slug,
        APIKey.expires_at > now,
    )
    temp_anon = await db.scalar(
        base.where(APIKey.key_type == "temp", APIKey.user_id.is_(None))
    )
    temp_auth = await db.scalar(
        base.where(APIKey.key_type == "temp", APIKey.user_id.isnot(None))
    )
    registered = await db.scalar(
        base.where(APIKey.key_type == "registered")
    )
    return {
        "temp_anonymous": temp_anon or 0,
        "temp_authenticated": temp_auth or 0,
        "registered": registered or 0,
    }


def init_api_key_routes(config: GatekeeperConfig):
    global _config
    _config = config


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


@router.post("/api-key")
async def issue_registered_key(
    request: Request, db: AsyncSession = Depends(get_db)
):
    """Issue a long-lived API key to an authenticated user.

    Requires a valid session cookie for an authenticated (non-anonymous) user.
    Returns the key in JSON. If the user already has a key for this app,
    the old one is replaced.
    """
    session_token = request.cookies.get("gk_session")
    if not session_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    # Determine the app from the host
    host = request.headers.get("host", "")
    app = _config.app_for_domain(host)
    if app is None:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    if not app.api_access.enabled:
        return JSONResponse({"error": "API keys not enabled for this app"}, status_code=400)

    session, user, role = await validate_session(db, session_token, app.slug)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    ip = _get_client_ip(request)

    # Check active key limit (count before revoking old key)
    counts = await count_active_keys(db, app.slug)
    # Subtract 1 if user already has a registered key (it will be revoked)
    existing = await db.scalar(
        select(func.count(APIKey.id)).where(
            APIKey.user_id == user.id, APIKey.app_slug == app.slug,
            APIKey.key_type == "registered",
            APIKey.expires_at > datetime.datetime.utcnow(),
        )
    )
    effective_count = counts["registered"] - (existing or 0)
    if effective_count >= app.api_access.api_rate_limits.max_registered:
        return JSONResponse({"error": "Maximum registered API keys reached"}, status_code=429)

    # Revoke any existing registered key for this user+app
    await db.execute(
        delete(APIKey).where(
            APIKey.user_id == user.id,
            APIKey.app_slug == app.slug,
            APIKey.key_type == "registered",
        )
    )

    key = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(
        days=app.api_access.registered_key_duration_days
    )

    api_key = APIKey(
        key=key,
        app_slug=app.slug,
        user_id=user.id,
        key_type="registered",
        ip_address=ip,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()

    return JSONResponse({
        "api_key": key,
        "expires_at": expires_at.isoformat() + "Z",
        "type": "registered",
    })


@router.post("/api-key/temp")
async def issue_temp_key(
    request: Request, db: AsyncSession = Depends(get_db)
):
    """Issue a short-lived API key for anonymous frontend use.

    Requires a valid gk_session cookie (even an anonymous one — this proves
    the caller is coming from the frontend, not calling the API directly).
    """
    host = request.headers.get("host", "")
    app = _config.app_for_domain(host)
    if app is None:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    if not app.api_access.enabled:
        return JSONResponse({"error": "API keys not enabled for this app"}, status_code=400)

    # Check for existing session, or create anonymous one if none exists.
    # This handles the case where forward_auth can't pass Set-Cookie back
    # (Caddy < 2.7 doesn't support copy_response_headers).
    session_token = request.cookies.get("gk_session")
    set_cookie_token = None  # if set, we need to set the cookie in the response
    session, user, role = None, None, None

    if session_token:
        session, user, role = await validate_session(db, session_token, app.slug)

    if session is None:
        # Create anonymous session and set cookie in response
        ip = _get_client_ip(request)
        from .sessions import create_session
        set_cookie_token = await create_session(db, None, app.slug, ip)
        session_token = set_cookie_token
        # Re-validate to get the session object
        session, user, role = await validate_session(db, session_token, app.slug)

    if session is None:
        return JSONResponse({"error": "Could not create session"}, status_code=500)

    ip = _get_client_ip(request)

    # Check active key limit
    counts = await count_active_keys(db, app.slug)
    limits = app.api_access.api_rate_limits
    if user is not None:
        if counts["temp_authenticated"] >= limits.max_temp_authenticated:
            return JSONResponse({"error": "Maximum temp API keys (authenticated) reached"}, status_code=429)
    else:
        if counts["temp_anonymous"] >= limits.max_temp_anonymous:
            return JSONResponse({"error": "Maximum temp API keys (anonymous) reached"}, status_code=429)

    def _maybe_set_cookie(response):
        """Set gk_session cookie if we created a new anonymous session."""
        if set_cookie_token:
            response.set_cookie(
                "gk_session", set_cookie_token,
                httponly=True, secure=True, samesite="lax",
                max_age=86400 * 7,
            )
        return response

    # Always issue a temp key (attach user_id if authenticated)
    key = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=app.api_access.temp_key_duration_minutes
    )

    api_key = APIKey(
        key=key, app_slug=app.slug,
        user_id=user.id if user else None,
        key_type="temp", ip_address=ip, expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()

    return _maybe_set_cookie(JSONResponse({
        "api_key": key,
        "expires_at": expires_at.isoformat() + "Z",
        "type": "temp",
        "duration_minutes": app.api_access.temp_key_duration_minutes,
    }))


async def validate_api_key(
    db: AsyncSession, key: str, app_slug: str
) -> tuple[APIKey | None, User | None, str | None]:
    """Validate an API key. Returns (api_key, user, role) or (None, None, None)."""
    stmt = select(APIKey).where(
        APIKey.key == key,
        APIKey.app_slug == app_slug,
        APIKey.expires_at > datetime.datetime.utcnow(),
    )
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()

    if api_key is None:
        return None, None, None

    if api_key.user_id is None:
        # Temp key — no user attached
        return api_key, None, None

    # Look up the user and their role
    user_stmt = select(User).where(User.id == api_key.user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if user is None:
        return None, None, None

    role_stmt = select(UserAppRole).where(
        UserAppRole.user_id == user.id,
        UserAppRole.app_slug == app_slug,
    )
    role_result = await db.execute(role_stmt)
    app_role = role_result.scalar_one_or_none()
    role = app_role.role if app_role else None

    return api_key, user, role


async def cleanup_expired_keys(db: AsyncSession):
    await db.execute(
        delete(APIKey).where(APIKey.expires_at < datetime.datetime.utcnow())
    )
    await db.commit()
