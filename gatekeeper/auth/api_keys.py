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
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import APIKey, User, UserAppRole
from gatekeeper.auth.sessions import validate_session

router = APIRouter(prefix="/_auth")
_config: GatekeeperConfig = None


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
        "expires_at": expires_at.isoformat(),
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
    session_token = request.cookies.get("gk_session")
    if not session_token:
        return JSONResponse({"error": "No session — are you accessing this from the frontend?"}, status_code=401)

    host = request.headers.get("host", "")
    app = _config.app_for_domain(host)
    if app is None:
        return JSONResponse({"error": "Unknown app"}, status_code=400)

    if not app.api_access.enabled:
        return JSONResponse({"error": "API keys not enabled for this app"}, status_code=400)

    # Validate the session exists (even if anonymous)
    session, user, role = await validate_session(db, session_token, app.slug)
    if session is None:
        return JSONResponse({"error": "Invalid session"}, status_code=401)

    ip = _get_client_ip(request)

    # If the user is authenticated, just issue a registered key instead
    if user is not None:
        # Reuse the registered key endpoint logic
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
            key=key, app_slug=app.slug, user_id=user.id,
            key_type="registered", ip_address=ip, expires_at=expires_at,
        )
        db.add(api_key)
        await db.commit()
        return JSONResponse({
            "api_key": key,
            "expires_at": expires_at.isoformat(),
            "type": "registered",
        })

    # Anonymous user: issue a short-lived temp key
    key = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=app.api_access.temp_key_duration_minutes
    )

    api_key = APIKey(
        key=key, app_slug=app.slug, user_id=None,
        key_type="temp", ip_address=ip, expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()

    return JSONResponse({
        "api_key": key,
        "expires_at": expires_at.isoformat(),
        "type": "temp",
        "duration_minutes": app.api_access.temp_key_duration_minutes,
    })


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
