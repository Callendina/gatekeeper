"""
The core forward_auth endpoint that Caddy calls for every request.

Caddy sends the original request details via headers:
  X-Forwarded-Method, X-Forwarded-Uri, X-Forwarded-Host, X-Forwarded-For

Gatekeeper responds:
  200 + X-Gatekeeper-User, X-Gatekeeper-Role headers -> request is allowed
  401 -> redirect to login
  403 -> blocked (IP ban or paywall)
  429 -> rate limited
"""
import datetime
from fastapi import APIRouter, Request, Response, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig, AppConfig
from gatekeeper.auth.sessions import validate_session, create_session
from gatekeeper.middleware.ip_block import is_ip_blocked
from gatekeeper.middleware.rate_limit import check_rate_limit
from gatekeeper.middleware.paywall import check_paywall, record_new_session
from gatekeeper.auth.api_keys import validate_api_key
from gatekeeper.models import AccessLog

import fnmatch

router = APIRouter()
_config: GatekeeperConfig = None


def init_forward_auth(config: GatekeeperConfig):
    global _config
    _config = config


def _path_matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


@router.get("/_auth/verify")
@router.head("/_auth/verify")
async def verify(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
    host = request.headers.get("x-forwarded-host", "")
    path = request.headers.get("x-forwarded-uri", "/")
    method = request.headers.get("x-forwarded-method", "GET")

    # Resolve which app this request is for
    app = _config.app_for_domain(host)
    if app is None:
        return Response(status_code=403, content="Unknown app")

    # 1. Check IP blocklist
    if await is_ip_blocked(db, ip):
        await _log(db, ip, app.slug, path, method, None, "blocked")
        return Response(status_code=403, content="Blocked")

    # 2. Check rate limit
    if not check_rate_limit(ip, _config.rate_limit):
        await _log(db, ip, app.slug, path, method, None, "rate_limited")
        return Response(status_code=429, content="Rate limited")

    # 3. Check if this is an API path requiring a key
    is_api_path = app.api_access.enabled and _path_matches_any(path, app.api_access.paths)

    if is_api_path:
        # API paths in key_required mode: must have a valid X-API-Key
        api_key_header = request.headers.get("x-forwarded-api-key", "")
        if not api_key_header:
            await _log(db, ip, app.slug, path, method, None, "api_key_missing")
            return Response(
                status_code=401,
                content="API key required. See /_auth/api-key for details.",
            )

        api_key_obj, api_user, api_role = await validate_api_key(db, api_key_header, app.slug)
        if api_key_obj is None:
            await _log(db, ip, app.slug, path, method, None, "api_key_invalid")
            return Response(status_code=401, content="Invalid or expired API key")

        # Valid API key — check paywall for temp keys (anonymous usage)
        if api_key_obj.key_type == "temp" and app.paywall.enabled:
            paywall_ok = await check_paywall(db, ip, app, session_token=None)
            if not paywall_ok:
                await _log(db, ip, app.slug, path, method, None, "paywall")
                return Response(status_code=403, content="Usage limit exceeded. Please register.")

        # Allowed via API key
        response = Response(status_code=200)
        if api_user:
            response.headers["X-Gatekeeper-User"] = api_user.email
            response.headers["X-Gatekeeper-Role"] = api_role or ""
            if api_user.is_system_admin:
                response.headers["X-Gatekeeper-System-Admin"] = "true"
            await _log(db, ip, app.slug, path, method, api_user.email, "allowed")
        else:
            response.headers["X-Gatekeeper-User"] = ""
            response.headers["X-Gatekeeper-Role"] = ""
            await _log(db, ip, app.slug, path, method, None, "allowed")
        return response

    # 4. Non-API paths: check session
    session_token = request.cookies.get("gk_session")
    session, user, role = None, None, None

    if session_token:
        session, user, role = await validate_session(db, session_token, app.slug)

    # 5. If path requires auth and user is not authenticated
    is_protected = _path_matches_any(path, app.protected_paths)

    if is_protected and user is None:
        await _log(db, ip, app.slug, path, method, None, "auth_required")
        login_url = f"/_auth/login?app={app.slug}&next={path}"
        return Response(
            status_code=401,
            headers={"X-Gatekeeper-Login-URL": login_url},
            content="Authentication required",
        )

    # 6. Check paywall for anonymous users
    if user is None and app.paywall.enabled:
        paywall_ok = await check_paywall(db, ip, app, session_token=session_token)
        if not paywall_ok:
            await _log(db, ip, app.slug, path, method, None, "paywall")
            register_url = f"/_auth/register?app={app.slug}"
            return Response(
                status_code=403,
                headers={"X-Gatekeeper-Register-URL": register_url},
                content="Registration required",
            )

    # 7. Create anonymous session if none exists (for tracking)
    if session is None and app.paywall.enabled:
        # Record the new session for paywall counting
        within_quota = await record_new_session(db, ip, app)
        if not within_quota:
            await _log(db, ip, app.slug, path, method, None, "paywall")
            login_url = f"/_auth/login?app={app.slug}"
            return Response(
                status_code=403,
                headers={"X-Gatekeeper-Register-URL": login_url},
                content="Registration required",
            )

        token = await create_session(db, None, app.slug, ip)
        response = Response(status_code=200)
        response.set_cookie(
            "gk_session", token,
            httponly=True, secure=True, samesite="lax",
            max_age=86400 * 7,
        )
        response.headers["X-Gatekeeper-User"] = ""
        response.headers["X-Gatekeeper-Role"] = ""
        await _log(db, ip, app.slug, path, method, None, "allowed")
        return response

    # 8. Allowed — return user info headers
    response = Response(status_code=200)
    if user:
        response.headers["X-Gatekeeper-User"] = user.email
        response.headers["X-Gatekeeper-Role"] = role or ""
        if user.is_system_admin:
            response.headers["X-Gatekeeper-System-Admin"] = "true"
    else:
        response.headers["X-Gatekeeper-User"] = ""
        response.headers["X-Gatekeeper-Role"] = ""

    await _log(db, ip, app.slug, path, method, user.email if user else None, "allowed")
    return response


async def _log(
    db: AsyncSession, ip: str, app_slug: str, path: str,
    method: str, user_email: str | None, status: str
):
    log = AccessLog(
        ip_address=ip, app_slug=app_slug, path=path,
        method=method, user_email=user_email, status=status,
    )
    db.add(log)
    await db.commit()
