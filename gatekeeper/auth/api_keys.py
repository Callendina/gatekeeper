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

from gatekeeper._time import utcnow
from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import APIKey, User, UserAppRole
from gatekeeper.auth.sessions import validate_session

router = APIRouter(prefix="/_auth")
_config: GatekeeperConfig = None


async def count_active_keys(db: AsyncSession, app_slug: str) -> dict:
    """Count active (non-expired) API keys by tier for an app."""
    now = utcnow()
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


async def issue_registered_key_for_user(
    db: AsyncSession,
    app,
    user: User,
    ip: str,
    *,
    override_expiry_seconds: int | None = None,
    force: bool = False,
) -> tuple[str | None, datetime.datetime | None, dict | None]:
    """Mint a registered API key for (user, app), replacing any existing one.

    Returns (key, expires_at, None) on success, or (None, None, error_dict) when
    the per-app `max_registered` cap would be exceeded. `force=True` bypasses the
    cap (admin override). `override_expiry_seconds`, when set, replaces the
    configured `registered_key_duration_seconds`.
    """
    if not force:
        counts = await count_active_keys(db, app.slug)
        existing = await db.scalar(
            select(func.count(APIKey.id)).where(
                APIKey.user_id == user.id, APIKey.app_slug == app.slug,
                APIKey.key_type == "registered",
                APIKey.expires_at > utcnow(),
            )
        )
        effective_count = counts["registered"] - (existing or 0)
        max_reg = app.api_access.api_rate_limits.max_registered
        if effective_count >= max_reg:
            return None, None, {
                "error": "Maximum registered API keys reached",
                "type": "max_active_keys",
                "tier": "registered",
                "current": effective_count,
                "limit": max_reg,
            }

    await db.execute(
        delete(APIKey).where(
            APIKey.user_id == user.id,
            APIKey.app_slug == app.slug,
            APIKey.key_type == "registered",
        )
    )

    key = secrets.token_urlsafe(32)
    duration = override_expiry_seconds or app.api_access.registered_key_duration_seconds
    expires_at = utcnow() + datetime.timedelta(seconds=duration)

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

    return key, expires_at, None


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

    host = request.headers.get("host", "")
    app = _config.app_for_domain(host)
    if app is None:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    if not app.api_access.enabled:
        return JSONResponse({"error": "API keys not enabled for this app"}, status_code=400)

    session, user, role, _grp = await validate_session(db, session_token, app.slug)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    ip = _get_client_ip(request)

    key, expires_at, error = await issue_registered_key_for_user(db, app, user, ip)
    if error:
        return JSONResponse(error, status_code=429)

    import cyclops
    cyclops.event(
        "gatekeeper.api_key.issued",
        outcome="success",
        app_slug=app.slug,
        key_type="registered",
        masked_email=cyclops.redact_email(user.email),
        masked_key=cyclops.redact_token(key),
        expires_at=expires_at.isoformat() + "Z",
    )

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
        session, user, role, _grp = await validate_session(db, session_token, app.slug)

    if session is None:
        # Create anonymous session and set cookie in response
        ip = _get_client_ip(request)
        from .sessions import create_session
        set_cookie_token = await create_session(db, None, app.slug, ip)
        session_token = set_cookie_token
        # Re-validate to get the session object
        session, user, role, _grp = await validate_session(db, session_token, app.slug)

    if session is None:
        return JSONResponse({"error": "Could not create session"}, status_code=500)

    ip = _get_client_ip(request)

    # Check active key limit
    counts = await count_active_keys(db, app.slug)
    limits = app.api_access.api_rate_limits
    if user is not None:
        if counts["temp_authenticated"] >= limits.max_temp_authenticated:
            return JSONResponse({
                "error": "Maximum temp API keys (authenticated) reached",
                "type": "max_active_keys",
                "tier": "temp_authenticated",
                "current": counts["temp_authenticated"],
                "limit": limits.max_temp_authenticated,
            }, status_code=429)
    else:
        if counts["temp_anonymous"] >= limits.max_temp_anonymous:
            return JSONResponse({
                "error": "Maximum temp API keys (anonymous) reached",
                "type": "max_active_keys",
                "tier": "temp_anonymous",
                "current": counts["temp_anonymous"],
                "limit": limits.max_temp_anonymous,
            }, status_code=429)

    def _maybe_set_cookie(response):
        """Set gk_session cookie if we created a new anonymous session."""
        if set_cookie_token:
            response.set_cookie(
                "gk_session", set_cookie_token,
                httponly=True, secure=True, samesite="lax",
                max_age=86400 * 7,
            )
        return response

    # Reuse an existing active temp key if one exists for this user/session
    is_authenticated = user is not None
    duration = app.api_access.temp_key_duration_for(is_authenticated)
    now = utcnow()

    if is_authenticated:
        existing_stmt = select(APIKey).where(
            APIKey.user_id == user.id,
            APIKey.app_slug == app.slug,
            APIKey.key_type == "temp",
            APIKey.expires_at > now,
        )
    else:
        # For anonymous users, match by IP
        existing_stmt = select(APIKey).where(
            APIKey.user_id.is_(None),
            APIKey.app_slug == app.slug,
            APIKey.key_type == "temp",
            APIKey.ip_address == ip,
            APIKey.expires_at > now,
        )

    existing_result = await db.execute(existing_stmt)
    existing_key = existing_result.scalar_one_or_none()

    if existing_key:
        # Extend expiry as if it were just used
        existing_key.expires_at = now + datetime.timedelta(minutes=duration)
        await db.commit()
        return _maybe_set_cookie(JSONResponse({
            "api_key": existing_key.key,
            "expires_at": existing_key.expires_at.isoformat() + "Z",
            "type": "temp",
            "duration_minutes": duration,
            "reused": True,
        }))

    # No existing key — issue a new temp key
    key = secrets.token_urlsafe(32)
    expires_at = now + datetime.timedelta(minutes=duration)

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
        "duration_minutes": duration,
    }))


async def validate_api_key(
    db: AsyncSession, key: str, app_slug: str
) -> tuple[APIKey | None, User | None, str | None, str | None]:
    """Validate an API key. Returns (api_key, user, role, group) or (None, None, None, None)."""
    stmt = select(APIKey).where(
        APIKey.key == key,
        APIKey.app_slug == app_slug,
        APIKey.expires_at > utcnow(),
    )
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()

    if api_key is None:
        return None, None, None, None

    if api_key.user_id is None:
        # Temp key — no user attached
        return api_key, None, None, None

    # Look up the user and their role
    user_stmt = select(User).where(User.id == api_key.user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if user is None:
        return None, None, None, None

    role_stmt = select(UserAppRole).where(
        UserAppRole.user_id == user.id,
        UserAppRole.app_slug == app_slug,
    )
    role_result = await db.execute(role_stmt)
    app_role = role_result.scalar_one_or_none()
    role = app_role.role if app_role else None
    group = app_role.group if app_role else None

    return api_key, user, role, group


async def cleanup_expired_keys(db: AsyncSession):
    await db.execute(
        delete(APIKey).where(APIKey.expires_at < utcnow())
    )
    await db.commit()
