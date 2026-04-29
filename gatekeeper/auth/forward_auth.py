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
import json
from fastapi import APIRouter, Request, Response, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig, AppConfig
from gatekeeper.auth.sessions import validate_session, create_session
from gatekeeper.middleware.ip_block import is_ip_blocked
from gatekeeper.middleware.rate_limit import check_rate_limit, check_api_key_rate_limit
from gatekeeper.middleware.paywall import check_paywall, record_new_session, PaywallResult
from gatekeeper.auth.api_keys import validate_api_key
from gatekeeper.auth.invites import (
    verify_invite_cookie, validate_invite_code_db, record_invite_use,
    make_invite_cookie, _invite_failures, INVITE_FAIL_LIMIT,
)
from gatekeeper.models import AccessLog, Session, User

import fnmatch
from urllib.parse import urlparse, parse_qs, urlencode, quote

from gatekeeper.auth.totp import get_totp

router = APIRouter()
_config: GatekeeperConfig = None


def init_forward_auth(config: GatekeeperConfig):
    global _config
    _config = config


def _path_matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


async def _check_totp_gate(
    db, session, user, role, mfa, path: str
):
    """If MFA is required for this user/path, return a redirect Response;
    otherwise None. Caller has already filtered to authenticated users.

    Decision logic:
    - role-triggered: user's role for this app is in mfa.required_for_roles
    - path-triggered: requested path matches one of mfa.required_for_paths
    Either trigger requires:
      - an enrolled (confirmed) UserTOTP — else redirect to /enroll
      - a fresh enough session.totp_verified_at — else redirect to /verify
    "fresh enough" = totp_verified_at is set AND (step_up_seconds == 0
    OR verified within the last step_up_seconds).
    """
    if not mfa.enabled:
        return None
    role_triggered = bool(role) and role in mfa.required_for_roles
    path_triggered = bool(mfa.required_for_paths) and _path_matches_any(path, mfa.required_for_paths)
    if not (role_triggered or path_triggered):
        return None

    rec = await get_totp(db, user.id)
    next_q = quote(path or "/")
    if rec is None or rec.confirmed_at is None:
        return Response(
            status_code=302,
            headers={"Location": f"/_auth/totp/enroll?next={next_q}"},
        )

    needs_step_up = session.totp_verified_at is None
    if not needs_step_up and mfa.step_up_seconds > 0:
        age = (utcnow() - session.totp_verified_at).total_seconds()
        if age > mfa.step_up_seconds:
            needs_step_up = True

    if needs_step_up:
        return Response(
            status_code=302,
            headers={"Location": f"/_auth/totp/verify?next={next_q}"},
        )
    return None


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def _has_invite_grant(request: Request, app) -> bool:
    """Check if request has a valid gk_invite_granted cookie."""
    cookie = request.cookies.get("gk_invite_granted")
    if not cookie:
        return False
    return verify_invite_cookie(
        cookie, _config.secret_key, app.slug, app.invite.cookie_max_age_days
    ) is not None


async def _check_invite_gate(request: Request, db, app, ip: str,
                             path: str, method: str,
                             session_token: str | None = None,
                             referrer: str | None = None,
                             user_agent: str | None = None):
    """Check invite gate. Returns a Response to send, or None to continue."""
    # Public paths bypass the invite gate entirely
    if app.invite.public_paths and _path_matches_any(path, app.invite.public_paths):
        return None

    # Authenticated users with valid sessions always pass
    if session_token:
        _sess, _usr, _role, _grp = await validate_session(db, session_token, app.slug)
        if _usr is not None:
            return None  # authenticated user

    # API key in header — let through (key validated later)
    if request.headers.get("x-forwarded-api-key", ""):
        return None

    # Exempt paths pass through
    if app.api_access.exempt_paths and _path_matches_any(path, app.api_access.exempt_paths):
        return None

    # Valid invite cookie
    if _has_invite_grant(request, app):
        return None

    # Check for invite code in URL query params
    parsed = urlparse(path)
    qs = parse_qs(parsed.query)
    code_str = qs.get(app.invite.url_param, [None])[0]
    if code_str:
        code_obj = await validate_invite_code_db(db, app.slug, code_str)
        if code_obj:
            _invite_failures.pop(ip, None)
            use = await record_invite_use(db, code_obj, None, ip)
            # Redirect to clean URL (strip invite param) with cookie set
            remaining_qs = {k: v for k, v in qs.items() if k != app.invite.url_param}
            clean_path = parsed.path
            if remaining_qs:
                clean_path += "?" + urlencode(remaining_qs, doseq=True)
            response = Response(status_code=302, headers={"Location": clean_path})
            cookie_val = make_invite_cookie(
                use.id, code_obj.id, _config.secret_key, app.slug
            )
            response.set_cookie(
                "gk_invite_granted", cookie_val,
                httponly=True, secure=True, samesite="lax",
                max_age=app.invite.cookie_max_age_days * 86400,
            )
            await _log(db, ip, app.slug, path, method, None, "invite_granted",
                       session_token=session_token, referrer=referrer, user_agent=user_agent)
            return response
        else:
            # Invalid code in URL param
            _invite_failures[ip] = _invite_failures.get(ip, 0) + 1
            if _invite_failures[ip] >= INVITE_FAIL_LIMIT:
                from gatekeeper.middleware.ip_block import block_ip
                await block_ip(db, ip, reason="Exceeded invite code attempt limit",
                               blocked_by="gatekeeper-auto")
                _invite_failures.pop(ip, None)
                await _log(db, ip, app.slug, path, method, None, "blocked",
                           session_token=session_token, referrer=referrer, user_agent=user_agent)
                return Response(status_code=403, content="Blocked")

    # No valid invite — redirect to invite page
    await _log(db, ip, app.slug, path, method, None, "invite_required",
               session_token=session_token, referrer=referrer, user_agent=user_agent)
    invite_url = f"/_auth/invite?app={app.slug}&next={path}"
    return Response(status_code=302, headers={"Location": invite_url})


@router.get("/_auth/verify")
@router.head("/_auth/verify")
async def verify(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
    host = request.headers.get("x-forwarded-host", "")
    path = request.headers.get("x-forwarded-uri", "/")
    method = request.headers.get("x-forwarded-method", "GET")
    referrer = request.headers.get("x-forwarded-referer", "") or request.headers.get("referer", "") or None
    user_agent = request.headers.get("x-forwarded-user-agent", "") or request.headers.get("user-agent", "") or None
    session_token = request.cookies.get("gk_session")

    # Resolve which app this request is for
    app = _config.app_for_domain(host)
    if app is None:
        return Response(status_code=403, content="Unknown app")

    # Common extra fields for logging
    _extra = dict(session_token=session_token, referrer=referrer, user_agent=user_agent)

    # 1. Check IP blocklist
    if await is_ip_blocked(db, ip):
        await _log(db, ip, app.slug, path, method, None, "blocked", **_extra)
        return Response(status_code=403, content="Blocked")

    # 2. Invite gate (only for invite_only apps)
    if app.invite.enabled:
        invite_response = await _check_invite_gate(request, db, app, ip, path, method, **_extra)
        if invite_response is not None:
            return invite_response

    # 3. Validate session early
    session, user, role, group = None, None, None, None
    if session_token:
        session, user, role, group = await validate_session(db, session_token, app.slug)

    # 3a. Check if user is pending invite — redirect to waiting room
    if user:
        from gatekeeper.models import UserAppRole
        pending_role = await db.scalar(
            select(UserAppRole).where(
                UserAppRole.user_id == user.id,
                UserAppRole.app_slug == app.slug,
                UserAppRole.pending_invite == True,
            )
        )
        if pending_role:
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/pending?app={app.slug}"},
            )

    # 3b. TOTP / MFA gate (only for authenticated users; anon and API-key
    # requests are handled by other gates).
    if user is not None:
        totp_response = await _check_totp_gate(db, session, user, role, app.mfa, path)
        if totp_response is not None:
            await _log(db, ip, app.slug, path, method, user.email, "totp_required", **_extra)
            return totp_response

    # 4. Check rate limit (per-app, authenticated users may get a higher limit)
    rl_ok, rl_count, rl_limit = check_rate_limit(ip, app.rate_limit, authenticated=user is not None)
    if not rl_ok:
        await _log(db, ip, app.slug, path, method, None, "rate_limited", **_extra)
        return Response(
            status_code=429,
            content=json.dumps({
                "error": "Rate limited",
                "type": "ip_rate_limit",
                "current": rl_count,
                "limit": rl_limit,
                "ip": ip,
            }),
            media_type="application/json",
        )

    # 4. Check if this is an API path requiring a key
    is_exempt = app.api_access.exempt_paths and _path_matches_any(path, app.api_access.exempt_paths)
    is_api_path = app.api_access.enabled and _path_matches_any(path, app.api_access.paths) and not is_exempt

    if is_api_path:
        # API paths in key_required mode: must have a valid X-API-Key
        api_key_header = request.headers.get("x-forwarded-api-key", "")
        if not api_key_header:
            await _log(db, ip, app.slug, path, method, None, "api_key_missing", **_extra)
            return Response(
                status_code=401,
                content="API key required. See /_auth/api-key for details.",
            )

        api_key_obj, api_user, api_role, api_group = await validate_api_key(db, api_key_header, app.slug)
        if api_key_obj is None:
            await _log(db, ip, app.slug, path, method, None, "api_key_invalid", **_extra)
            return Response(status_code=401, content="Invalid or expired API key")

        # Per-key rate limit (override takes precedence if set)
        limits = app.api_access.api_rate_limits
        if api_key_obj.rate_limit_override > 0:
            key_limit = api_key_obj.rate_limit_override
        elif api_key_obj.key_type == "registered":
            key_limit = limits.registered_per_minute
        elif api_key_obj.user_id is not None:
            key_limit = limits.temp_authenticated_per_minute
        else:
            key_limit = limits.temp_anonymous_per_minute

        # Look up path weight (default 1)
        path_weight = 1
        for pattern, weight in app.api_access.path_weights.items():
            if fnmatch.fnmatch(path, pattern):
                path_weight = weight
                break

        krl_ok, krl_count, krl_limit = check_api_key_rate_limit(api_key_obj.key, key_limit, weight=path_weight)
        if not krl_ok:
            await _log(db, ip, app.slug, path, method, None, "api_key_rate_limited", **_extra)
            tier = "registered" if api_key_obj.key_type == "registered" else (
                "temp_authenticated" if api_key_obj.user_id else "temp_anonymous"
            )
            return Response(
                status_code=429,
                content=json.dumps({
                    "error": "API key rate limit exceeded",
                    "type": "api_key_rate_limit",
                    "tier": tier,
                    "current": krl_count,
                    "limit": krl_limit,
                }),
                media_type="application/json",
            )

        # Check paywall for temp keys (anonymous usage)
        if api_key_obj.key_type == "temp" and api_key_obj.user_id is None and app.paywall.enabled:
            paywall_ok = await check_paywall(db, ip, app, session_token=None)
            if not paywall_ok:
                await _log(db, ip, app.slug, path, method, None, "paywall", **_extra)
                return Response(status_code=403, content="Usage limit exceeded. Please register.")

        # Auto-extend temp keys on use (up to max lifetime)
        if api_key_obj.key_type == "temp":
            max_hours = app.api_access.temp_key_max_lifetime_hours
            if max_hours and api_key_obj.created_at:
                hard_limit = api_key_obj.created_at + datetime.timedelta(hours=max_hours)
                if utcnow() >= hard_limit:
                    await _log(db, ip, app.slug, path, method, api_user.email if api_user else None, "temp_key_expired", **_extra)
                    return Response(status_code=401, content="Temp key max lifetime exceeded. Please request a new key.")
            is_auth = api_key_obj.user_id is not None
            duration = app.api_access.temp_key_duration_for(is_auth)
            new_expiry = utcnow() + datetime.timedelta(
                minutes=duration
            )
            if max_hours and api_key_obj.created_at:
                new_expiry = min(new_expiry, hard_limit)
            api_key_obj.expires_at = new_expiry
            await db.commit()

        # Allowed via API key
        response = Response(status_code=200)
        if api_user:
            response.headers["X-Gatekeeper-User"] = api_user.email
            response.headers["X-Gatekeeper-Role"] = api_role or ""
            response.headers["X-Gatekeeper-Group"] = api_group or ""
            if api_user.is_system_admin:
                response.headers["X-Gatekeeper-System-Admin"] = "true"
            await _log(db, ip, app.slug, path, method, api_user.email, "allowed", **_extra)
        else:
            response.headers["X-Gatekeeper-User"] = ""
            response.headers["X-Gatekeeper-Role"] = ""
            await _log(db, ip, app.slug, path, method, None, "allowed", **_extra)
        return response

    # 5. If path requires auth and user is not authenticated
    is_protected = _path_matches_any(path, app.protected_paths)

    if is_protected and user is None:
        # Try API key auth as fallback (only for apps with key_required mode)
        api_key_header = request.headers.get("x-forwarded-api-key", "")
        if app.api_access.enabled and api_key_header:
            api_key_obj, api_user, api_role, api_group = await validate_api_key(db, api_key_header, app.slug)
            if api_key_obj is None:
                await _log(db, ip, app.slug, path, method, None, "api_key_invalid", **_extra)
                return Response(status_code=401, content="Invalid or expired API key")
            if api_user is None:
                # Anonymous temp key — protected paths need a real user
                await _log(db, ip, app.slug, path, method, None, "auth_required", **_extra)
                login_url = f"/_auth/login?app={app.slug}&next={path}"
                return Response(status_code=302, headers={"Location": login_url})
            # Valid key with a user — allow through
            response = Response(status_code=200)
            response.headers["X-Gatekeeper-User"] = api_user.email
            response.headers["X-Gatekeeper-Role"] = api_role or ""
            response.headers["X-Gatekeeper-Group"] = api_group or ""
            if api_user.is_system_admin:
                response.headers["X-Gatekeeper-System-Admin"] = "true"
            await _log(db, ip, app.slug, path, method, api_user.email, "allowed", **_extra)
            return response

        await _log(db, ip, app.slug, path, method, None, "auth_required", **_extra)
        login_url = f"/_auth/login?app={app.slug}&next={path}"
        return Response(
            status_code=302,
            headers={"Location": login_url},
        )

    # 6. Check paywall for anonymous users for anonymous users
    nag_dismissed = request.cookies.get("gk_nag_dismissed") == "1"

    if user is None and app.paywall.enabled and not is_exempt:
        pw_result = await check_paywall(db, ip, app, session_token=session_token)
        if pw_result == PaywallResult.BLOCKED:
            await _log(db, ip, app.slug, path, method, None, "paywall", **_extra)
            login_url = f"/_auth/login?app={app.slug}&next={path}"
            return Response(status_code=302, headers={"Location": login_url})
        if pw_result == PaywallResult.NAG and not nag_dismissed:
            await _log(db, ip, app.slug, path, method, None, "paywall_nag", **_extra)
            nag_url = f"/_auth/nag?app={app.slug}&next={path}"
            return Response(status_code=302, headers={"Location": nag_url})

    # 7. Create anonymous session if none exists (for tracking)
    if session is None and app.paywall.enabled and not is_exempt:
        # Record the new session for paywall counting
        pw_result = await record_new_session(db, ip, app)
        if pw_result == PaywallResult.BLOCKED:
            await _log(db, ip, app.slug, path, method, None, "paywall", **_extra)
            login_url = f"/_auth/login?app={app.slug}&next={path}"
            return Response(status_code=302, headers={"Location": login_url})
        if pw_result == PaywallResult.NAG and not nag_dismissed:
            await _log(db, ip, app.slug, path, method, None, "paywall_nag", **_extra)
            nag_url = f"/_auth/nag?app={app.slug}&next={path}"
            return Response(status_code=302, headers={"Location": nag_url})

        token = await create_session(db, None, app.slug, ip)
        response = Response(status_code=200)
        response.set_cookie(
            "gk_session", token,
            httponly=True, secure=True, samesite="lax",
            max_age=86400 * 180,
        )
        response.headers["X-Gatekeeper-User"] = ""
        response.headers["X-Gatekeeper-Role"] = ""
        response.headers["X-Gatekeeper-Group"] = ""
        await _log(db, ip, app.slug, path, method, None, "allowed",
                   session_token=token, referrer=referrer, user_agent=user_agent)
        return response

    # 8. Allowed — return user info headers
    response = Response(status_code=200)
    if user:
        response.headers["X-Gatekeeper-User"] = user.email
        response.headers["X-Gatekeeper-Role"] = role or ""
        response.headers["X-Gatekeeper-Group"] = group or ""
        if user.is_system_admin:
            response.headers["X-Gatekeeper-System-Admin"] = "true"
    else:
        response.headers["X-Gatekeeper-User"] = ""
        response.headers["X-Gatekeeper-Role"] = ""
        response.headers["X-Gatekeeper-Group"] = ""

    await _log(db, ip, app.slug, path, method, user.email if user else None, "allowed", **_extra)
    return response


@router.get("/_auth/verify-system-admin")
@router.head("/_auth/verify-system-admin")
async def verify_system_admin(request: Request, db: AsyncSession = Depends(get_db)):
    """Forward-auth endpoint that allows requests only from system admins.

    Used to gate gatekeeper-internal admin tools (e.g. /_term/* on the
    gatekeeper domain). Distinct from /_auth/verify because the gatekeeper
    domain itself is not registered as an "app" in the per-app config.
    """
    ip = _get_client_ip(request)
    host = request.headers.get("x-forwarded-host", "")
    path = request.headers.get("x-forwarded-uri", "/")
    method = request.headers.get("x-forwarded-method", "GET")
    referrer = request.headers.get("x-forwarded-referer", "") or request.headers.get("referer", "") or None
    user_agent = request.headers.get("x-forwarded-user-agent", "") or request.headers.get("user-agent", "") or None
    session_token = request.cookies.get("gk_session")
    _extra = dict(session_token=session_token, referrer=referrer, user_agent=user_agent)

    # Must be explicitly enabled in config (defense-in-depth: don't expose
    # this on environments where the protected feature isn't installed).
    if not _config.terminal_enabled:
        await _log(db, ip, "_system", path, method, None, "blocked", **_extra)
        return Response(status_code=404, content="Not found")

    if await is_ip_blocked(db, ip):
        await _log(db, ip, "_system", path, method, None, "blocked", **_extra)
        return Response(status_code=403, content="Blocked")

    # Find the user behind this session, regardless of which app's session it is.
    user = None
    session = None
    if session_token:
        for app_slug in _config.apps:
            sess, candidate, _role, _grp = await validate_session(db, session_token, app_slug)
            if candidate:
                user = candidate
                session = sess
                break
        if user is None:
            # Session may not be scoped to a configured app
            session = await db.scalar(
                select(Session).where(
                    Session.token == session_token,
                    Session.expires_at > utcnow(),
                )
            )
            if session and session.user_id:
                user = await db.scalar(select(User).where(User.id == session.user_id))

    if user is None:
        # Not signed in — bounce to login. Use any configured app slug for
        # the post-login redirect; admins generally have a session for one.
        app_slug = next(iter(_config.apps), "")
        login_url = f"/_auth/login?app={app_slug}&next={path}"
        await _log(db, ip, "_system", path, method, None, "auth_required", **_extra)
        return Response(status_code=302, headers={"Location": login_url})

    if not user.is_system_admin:
        await _log(db, ip, "_system", path, method, user.email, "blocked", **_extra)
        return Response(status_code=403, content="System admin access required")

    # System-admin TOTP gate. We piggy-back on the same /_auth/totp/{enroll,verify}
    # routes used by app-scoped MFA — they look up the session/user themselves.
    if _config.system_admin_requires_totp:
        rec = await get_totp(db, user.id)
        next_q = quote(path or "/")
        if rec is None or rec.confirmed_at is None:
            await _log(db, ip, "_system", path, method, user.email, "totp_required", **_extra)
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/totp/enroll?next={next_q}"},
            )
        if session is None or session.totp_verified_at is None:
            await _log(db, ip, "_system", path, method, user.email, "totp_required", **_extra)
            return Response(
                status_code=302,
                headers={"Location": f"/_auth/totp/verify?next={next_q}"},
            )

    response = Response(status_code=200)
    response.headers["X-Gatekeeper-User"] = user.email
    response.headers["X-Gatekeeper-System-Admin"] = "true"
    await _log(db, ip, "_system", path, method, user.email, "allowed", **_extra)
    return response


async def _log(
    db: AsyncSession, ip: str, app_slug: str, path: str,
    method: str, user_email: str | None, status: str,
    session_token: str | None = None, referrer: str | None = None,
    user_agent: str | None = None,
):
    log = AccessLog(
        ip_address=ip, app_slug=app_slug, path=path,
        method=method, user_email=user_email, status=status,
        session_token=session_token, referrer=referrer,
        user_agent=user_agent,
    )
    db.add(log)
    await db.commit()
