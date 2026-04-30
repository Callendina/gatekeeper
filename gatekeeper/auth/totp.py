"""TOTP (RFC 6238) enrollment and verification.

The per-user secret is *not* stored; it is derived deterministically from
(server.secret_key, user_id, key_num) via HMAC-SHA256 each time it is
needed. Admin reset bumps key_num, which invalidates the old secret and
forces re-enrollment with a new derivation.

Enrollment is a two-step flow:
    GET  /_auth/totp/enroll          -> renders QR + secret string
    POST /_auth/totp/enroll/confirm  -> verifies first code, sets confirmed_at

Verification (step-up) is similar:
    GET  /_auth/totp/verify          -> form
    POST /_auth/totp/verify          -> sets session.totp_verified_at on success

The forward_auth gate is what redirects users here; this module never
checks whether the user *should* be doing TOTP — it just lets them.
"""
import base64
import datetime
import hmac
import hashlib
import logging
import time
from pathlib import Path
from urllib.parse import quote, urlencode

import io

import pyotp
import segno
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.config import GatekeeperConfig
from gatekeeper.database import get_db
from gatekeeper.auth.mfa_lockout import (
    FAIL_BLOCK_THRESHOLD as TOTP_FAIL_BLOCK_THRESHOLD,
    record_failure as _record_failure_shared,
    clear as _clear_failures_shared,
)
from gatekeeper.middleware.ip_block import block_ip, is_ip_blocked
from gatekeeper.models import Session, User, UserTOTP

router = APIRouter(prefix="/_auth/totp")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
logger = logging.getLogger("gatekeeper.totp")


def init_totp_routes(config: GatekeeperConfig):
    global _config
    _config = config


# ---- pure derivation helpers ----

def derive_secret(master_key: str, user_id: int, key_num: int) -> str:
    """Derive a base32-encoded TOTP secret (160 bits) from the master key.

    The domain-separation tag ('totp-v1|') keeps this HMAC namespace
    distinct from any other use of master_key (session signing, etc).
    """
    raw = hmac.new(
        master_key.encode("utf-8"),
        f"totp-v1|{user_id}|{key_num}".encode("utf-8"),
        hashlib.sha256,
    ).digest()[:20]  # 160 bits — RFC 4226 / 6238 standard length
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def issuer_for(config: GatekeeperConfig) -> str:
    """Issuer string shown in users' authenticator apps."""
    base = config.totp_issuer or "Gatekeeper"
    if config.environment:
        return f"{base} - {config.environment}"
    return base


def qr_svg(uri: str) -> str:
    """Render the otpauth URI as an inline SVG QR code. omitsize=True so
    segno emits a viewBox instead of fixed width/height — without it,
    browsers clip the QR when CSS overrides the dimensions, producing an
    unreadable image."""
    qr = segno.make_qr(uri)
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=6, border=2, xmldecl=False, omitsize=True)
    return buf.getvalue().decode("utf-8")


def otpauth_uri(secret: str, email: str, issuer: str) -> str:
    """Build an otpauth://totp URI per the de-facto Google Authenticator spec."""
    label = quote(f"{issuer}:{email}", safe="")
    params = urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return f"otpauth://totp/{label}?{params}"


# ---- DB helpers ----

async def get_totp(db: AsyncSession, user_id: int) -> UserTOTP | None:
    return await db.scalar(select(UserTOTP).where(UserTOTP.user_id == user_id))


async def get_or_create_totp(db: AsyncSession, user_id: int) -> UserTOTP:
    rec = await get_totp(db, user_id)
    if rec is None:
        rec = UserTOTP(user_id=user_id, key_num=0, confirmed_at=None, last_counter=0)
        db.add(rec)
        await db.commit()
        await db.refresh(rec)
    return rec


async def reset_totp(db: AsyncSession, user_id: int) -> None:
    """Bump key_num and clear confirmed_at — forces re-enrollment with a new secret."""
    rec = await get_totp(db, user_id)
    if rec is None:
        # Nothing to reset.
        return
    rec.key_num += 1
    rec.confirmed_at = None
    rec.last_counter = 0
    await db.commit()


def _verify_code(secret: str, code: str, last_counter: int) -> tuple[bool, int]:
    """Validate a 6-digit code against the secret with ±1 window skew tolerance.

    Returns (ok, new_last_counter). On success new_last_counter is the
    accepted counter and must be persisted by the caller. On failure it
    equals last_counter (caller should not write).
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False, last_counter

    totp = pyotp.TOTP(secret)
    now = int(time.time())
    current_counter = now // 30
    # Accept previous, current, next 30s window.
    for offset in (-1, 0, 1):
        candidate = current_counter + offset
        if candidate <= last_counter:
            continue  # already used (anti-replay)
        expected = totp.at(candidate * 30)
        if hmac.compare_digest(expected, code):
            return True, candidate
    return False, last_counter


# ---- IP failure tracking ----

# These are shared across MFA methods (TOTP + SMS OTP) so a mixed-method
# attacker can't get 2x the budget against a single IP.
_record_failure = _record_failure_shared
_clear_failures = _clear_failures_shared


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ---- session helper ----

async def _resolve_session_user(
    db: AsyncSession, session_token: str | None
) -> tuple[Session | None, User | None]:
    """Look up a session and its user *without* binding to a specific app slug.

    Used because TOTP routes are reachable from any app's domain — we just
    need to know who is signed in, not which app they came from.
    """
    if not session_token:
        return None, None
    stmt = select(Session).where(
        Session.token == session_token,
        Session.expires_at > utcnow(),
    )
    session = await db.scalar(stmt)
    if session is None or session.user_id is None:
        return session, None
    user = await db.scalar(select(User).where(User.id == session.user_id))
    return session, user


def _first_app_slug() -> str:
    for slug in _config.apps:
        return slug
    return ""


def _safe_next(next_url: str | None) -> str:
    """Only allow same-host relative paths as the post-TOTP redirect target."""
    if not next_url:
        return "/"
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


# ---- routes ----

@router.get("/enroll")
async def enroll_get(
    request: Request,
    next: str = "/",
    db: AsyncSession = Depends(get_db),
):
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None:
        # Not signed in — bounce to login.
        host = request.headers.get("host", "")
        app_for_host = _config.app_for_domain(host)
        app_slug = app_for_host.slug if app_for_host else _first_app_slug()
        return RedirectResponse(
            url=f"/_auth/login?app={app_slug}&next={quote(next)}", status_code=302
        )

    rec = await get_or_create_totp(db, user.id)
    if rec.confirmed_at is not None:
        # Already enrolled — go straight to verify.
        return RedirectResponse(
            url=f"/_auth/totp/verify?next={quote(_safe_next(next))}", status_code=302
        )

    secret = derive_secret(_config.secret_key, user.id, rec.key_num)
    issuer = issuer_for(_config)
    uri = otpauth_uri(secret, user.email, issuer)

    return templates.TemplateResponse("auth/totp_enroll.html", {
        "request": request,
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg": qr_svg(uri),
        "issuer": issuer,
        "user_email": user.email,
        "next": _safe_next(next),
    })


@router.post("/enroll/confirm")
async def enroll_confirm(
    request: Request,
    code: str = Form(...),
    next: str = Form("/"),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)

    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return RedirectResponse(url="/_auth/login", status_code=302)

    rec = await get_or_create_totp(db, user.id)
    if rec.confirmed_at is not None:
        # Already enrolled — fall through to step-up verify rather than
        # trying to "re-confirm" (which would silently fail-and-retry).
        return RedirectResponse(
            url=f"/_auth/totp/verify?next={quote(_safe_next(next))}", status_code=302
        )

    secret = derive_secret(_config.secret_key, user.id, rec.key_num)
    ok, new_counter = _verify_code(secret, code, rec.last_counter)

    import cyclops
    if not ok:
        fails = _record_failure(ip)
        cyclops.event(
            "gatekeeper.totp.enrolled",
            outcome="failure",
            masked_email=cyclops.redact_email(user.email),
            reason="bad_code",
            failures_in_window=fails,
        )
        if fails >= TOTP_FAIL_BLOCK_THRESHOLD:
            await block_ip(
                db, ip, reason="Exceeded TOTP attempt limit",
                blocked_by="gatekeeper-auto",
            )
            _clear_failures(ip)
            return HTMLResponse("Blocked", status_code=403)
        # Re-render the form with the same QR (key_num unchanged).
        issuer = issuer_for(_config)
        uri = otpauth_uri(secret, user.email, issuer)
        return templates.TemplateResponse("auth/totp_enroll.html", {
            "request": request,
            "secret": secret,
            "otpauth_uri": uri,
            "qr_svg": qr_svg(uri),
            "issuer": issuer,
            "user_email": user.email,
            "next": _safe_next(next),
            "error": "That code didn't match. Try again.",
        }, status_code=400)

    _clear_failures(ip)
    rec.confirmed_at = utcnow()
    rec.last_counter = new_counter
    session.totp_verified_at = utcnow()
    await db.commit()

    cyclops.event(
        "gatekeeper.totp.enrolled",
        outcome="success",
        masked_email=cyclops.redact_email(user.email),
    )
    return RedirectResponse(url=_safe_next(next), status_code=302)


@router.get("/verify")
async def verify_get(
    request: Request,
    next: str = "/",
    db: AsyncSession = Depends(get_db),
):
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None:
        host = request.headers.get("host", "")
        app_for_host = _config.app_for_domain(host)
        app_slug = app_for_host.slug if app_for_host else _first_app_slug()
        return RedirectResponse(
            url=f"/_auth/login?app={app_slug}&next={quote(next)}", status_code=302
        )

    rec = await get_totp(db, user.id)
    if rec is None or rec.confirmed_at is None:
        # Not enrolled yet — send to enroll instead.
        return RedirectResponse(
            url=f"/_auth/totp/enroll?next={quote(_safe_next(next))}", status_code=302
        )

    return templates.TemplateResponse("auth/totp_verify.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
    })


@router.post("/verify")
async def verify_post(
    request: Request,
    code: str = Form(...),
    next: str = Form("/"),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)

    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return RedirectResponse(url="/_auth/login", status_code=302)

    rec = await get_totp(db, user.id)
    if rec is None or rec.confirmed_at is None:
        return RedirectResponse(
            url=f"/_auth/totp/enroll?next={quote(_safe_next(next))}", status_code=302
        )

    secret = derive_secret(_config.secret_key, user.id, rec.key_num)
    ok, new_counter = _verify_code(secret, code, rec.last_counter)

    import cyclops
    if not ok:
        fails = _record_failure(ip)
        cyclops.event(
            "gatekeeper.totp.verified",
            outcome="failure",
            masked_email=cyclops.redact_email(user.email),
            reason="bad_code",
            failures_in_window=fails,
        )
        if fails >= TOTP_FAIL_BLOCK_THRESHOLD:
            await block_ip(
                db, ip, reason="Exceeded TOTP attempt limit",
                blocked_by="gatekeeper-auto",
            )
            _clear_failures(ip)
            return HTMLResponse("Blocked", status_code=403)
        return templates.TemplateResponse("auth/totp_verify.html", {
            "request": request,
            "user_email": user.email,
            "next": _safe_next(next),
            "error": "That code didn't match. Try again.",
        }, status_code=400)

    _clear_failures(ip)
    rec.last_counter = new_counter
    session.totp_verified_at = utcnow()
    await db.commit()

    cyclops.event(
        "gatekeeper.totp.verified",
        outcome="success",
        masked_email=cyclops.redact_email(user.email),
    )
    return RedirectResponse(url=_safe_next(next), status_code=302)
