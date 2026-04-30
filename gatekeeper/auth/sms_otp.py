"""SMS-OTP routes.

Three flows live here:

  Phone enrolment (one-time, per user):
    GET  /_auth/phone/enroll              — number entry form
    POST /_auth/phone/enroll              — send confirmation OTP
    POST /_auth/phone/enroll/confirm      — verify confirmation OTP, bind UserPhone

  Step-up verification (every gated request, subject to step_up_seconds):
    GET  /_auth/sms-otp/verify            — issue + render OTP form
    POST /_auth/sms-otp/verify            — verify code, set session.totp_verified_at
    POST /_auth/sms-otp/resend            — invalidate in-flight, issue fresh

  Provider delivery webhook:
    POST /_auth/sms/webhook/{secret}      — ClickSend delivery receipt

The forward_auth gate redirects users here based on `UserAppRole.mfa_method`.
This module never decides whether the user *should* be doing SMS OTP — it
just lets them. Same posture as `auth/totp.py`.
"""
import datetime
import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.auth.mfa_lockout import (
    FAIL_BLOCK_THRESHOLD, record_failure, clear as clear_failures,
)
from gatekeeper.config import GatekeeperConfig
from gatekeeper.database import get_db
from gatekeeper.middleware.ip_block import block_ip, is_ip_blocked
from gatekeeper.models import (
    AccessLog, Session, SmsOtpChallenge, User, UserPhone,
)
from gatekeeper.sms import challenges as ch
from gatekeeper.sms.providers import get_provider
from gatekeeper.sms.rate_limit import (
    Allowed, Tripped, check_and_record,
)
from gatekeeper.sms.validation import (
    CountryNotAllowed, InvalidPhoneFormat, NotMobileLine,
    PhoneValidationError, VoIPRejected, normalize,
)


router = APIRouter()
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
logger = logging.getLogger("gatekeeper.sms_otp")

PHONE_ENROLL_PSEUDO_APP = "_phone_enroll"


def init_sms_otp_routes(config: GatekeeperConfig):
    global _config
    _config = config


# ---- helpers ----------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _safe_next(next_url: str | None) -> str:
    if not next_url:
        return "/"
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


async def _resolve_session_user(
    db: AsyncSession, session_token: str | None
) -> tuple[Session | None, User | None]:
    if not session_token:
        return None, None
    session = await db.scalar(
        select(Session).where(
            Session.token == session_token,
            Session.expires_at > utcnow(),
        )
    )
    if session is None or session.user_id is None:
        return session, None
    user = await db.scalar(select(User).where(User.id == session.user_id))
    return session, user


def _login_redirect(request: Request, next_url: str) -> RedirectResponse:
    host = request.headers.get("host", "")
    app_for_host = _config.app_for_domain(host)
    app_slug = app_for_host.slug if app_for_host else next(iter(_config.apps), "")
    return RedirectResponse(
        url=f"/_auth/login?app={app_slug}&next={quote(next_url)}", status_code=302
    )


async def _record_event(
    db: AsyncSession, *, ip: str, app_slug: str, user_email: str | None,
    status: str, session_token: str | None, request: Request,
) -> None:
    """Drop a row into access_log so the dashboards downstream can see it.
    Status values are SMS-specific (sms_otp_issued, _verified, etc) and are
    distinct from the 'allowed/blocked/...' set used by forward_auth."""
    log = AccessLog(
        ip_address=ip,
        app_slug=app_slug,
        path=request.url.path,
        method=request.method,
        user_email=user_email,
        status=status,
        session_token=session_token,
        referrer=request.headers.get("referer"),
        user_agent=request.headers.get("user-agent"),
    )
    db.add(log)
    await db.commit()


async def _get_phone(db: AsyncSession, user_id: int) -> UserPhone | None:
    return await db.scalar(select(UserPhone).where(UserPhone.user_id == user_id))


async def _send_sms(
    db: AsyncSession, *, request: Request, ip: str, user: User, session: Session,
    e164: str, app_slug: str, ttl_seconds: int = 300,
) -> tuple[str, str] | RedirectResponse | HTMLResponse:
    """Issue a fresh challenge and call the provider. Returns
    (challenge_id, target_last4) on success; an error Response on failure.

    Caller has already invalidated any pre-existing pending challenge for
    this (user, app, session). Caller is also responsible for redirecting
    to the OTP entry form on success."""
    rl_result = check_and_record(
        e164=e164, user_id=user.id, ip=ip, app_slug=app_slug,
        cfg=_config.sms.rate_limits,
    )
    if isinstance(rl_result, Tripped):
        await _record_event(
            db, ip=ip, app_slug=app_slug, user_email=user.email,
            status=f"sms_otp_rate_limited:{rl_result.tier}:{rl_result.window}",
            session_token=session.token, request=request,
        )
        return HTMLResponse(
            f"Too many code requests ({rl_result.tier} {rl_result.window} "
            f"limit reached). Please try again later.",
            status_code=429,
        )

    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug=app_slug, e164=e164,
        session_token=session.token, secret_key=_config.secret_key,
        ttl_seconds=ttl_seconds,
    )
    await _record_event(
        db, ip=ip, app_slug=app_slug, user_email=user.email,
        status="sms_otp_issued", session_token=session.token, request=request,
    )

    body = (
        f"Your {(_config.totp_issuer or 'Gatekeeper')} verification code is "
        f"{issued.plaintext_code}. Expires in {ttl_seconds // 60} minutes."
    )
    provider = get_provider(_config.sms)
    send_result = await provider.send(
        to_e164=e164, body=body, idempotency_key=issued.challenge.id, db=db,
    )
    if not send_result.accepted:
        await ch.mark_invalidated(db, issued.challenge.id)
        await _record_event(
            db, ip=ip, app_slug=app_slug, user_email=user.email,
            status=f"sms_otp_send_failed:{send_result.error_category or 'unknown'}",
            session_token=session.token, request=request,
        )
        # InsufficientCredit is the operator-actionable failure — surface
        # it as a 5xx and let the future dashboard alert from the event.
        if send_result.error_category == "insufficient_credit":
            return HTMLResponse(
                "Verification temporarily unavailable. Please try again shortly.",
                status_code=503,
            )
        return HTMLResponse(
            "We couldn't send the code right now. Please try again in a moment.",
            status_code=503,
        )

    if send_result.provider_message_id:
        await ch.attach_provider_message_id(
            db, issued.challenge.id, send_result.provider_message_id,
        )

    # sms_otp_sent_to_provider conveys the post-provider acceptance state
    # so the future dashboard can compute spend / latency / error-rate.
    # Cost suffix is "cost=N" cents (-1 means provider didn't return one).
    cost = send_result.cost_cents if send_result.cost_cents is not None else -1
    provider_name = provider.name
    await _record_event(
        db, ip=ip, app_slug=app_slug, user_email=user.email,
        status=f"sms_otp_sent_to_provider:{provider_name}:cost={cost}",
        session_token=session.token, request=request,
    )
    return issued.challenge.id, issued.challenge.target_last4


# ---- enrolment routes -------------------------------------------------------

@router.get("/_auth/phone/enroll")
async def enroll_get(
    request: Request,
    next: str = "/",
    app: str = "",
    db: AsyncSession = Depends(get_db),
):
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None:
        return _login_redirect(request, request.url.path + f"?next={quote(next)}&app={app}")

    phone = await _get_phone(db, user.id)
    if phone is not None and phone.confirmed_at is not None:
        # Already enrolled — go straight to step-up verify for this app.
        return RedirectResponse(
            url=f"/_auth/sms-otp/verify?app={app}&next={quote(_safe_next(next))}",
            status_code=302,
        )

    return templates.TemplateResponse(request, "auth/phone_enroll.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
        "app_slug": app,
        "submitted_number": "",
    })


@router.post("/_auth/phone/enroll")
async def enroll_post(
    request: Request,
    number: str = Form(...),
    next: str = Form("/"),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)

    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return _login_redirect(request, "/_auth/phone/enroll")

    try:
        e164, last4 = normalize(number, _config.sms.country_allowlist)
    except PhoneValidationError as exc:
        message = {
            InvalidPhoneFormat.code: "That doesn't look like a valid mobile number.",
            CountryNotAllowed.code: "Sorry, we can only verify Australian mobile numbers right now.",
            NotMobileLine.code: "We can only text mobile numbers — landlines aren't supported.",
            VoIPRejected.code: "Internet phone (VoIP) numbers aren't accepted.",
        }.get(exc.code, "We couldn't verify that number.")
        await _record_event(
            db, ip=ip, app_slug=PHONE_ENROLL_PSEUDO_APP, user_email=user.email,
            status=f"sms_otp_enroll_rejected:{exc.code}",
            session_token=session.token, request=request,
        )
        return templates.TemplateResponse(request, "auth/phone_enroll.html", {
            "request": request,
            "user_email": user.email,
            "next": _safe_next(next),
            "app_slug": app,
            "submitted_number": number,
            "error": message,
        }, status_code=400)

    # Upsert the UserPhone row (unconfirmed). If a previous unconfirmed
    # number exists, replace it; if a confirmed one exists for a different
    # number, treat as a number-change (admin-only by policy — but we
    # can't enforce that here without a feature flag, so we still allow
    # re-enrolment and bump key_num to invalidate any in-flight challenges).
    phone = await _get_phone(db, user.id)
    if phone is None:
        phone = UserPhone(user_id=user.id, e164=e164, confirmed_at=None, key_num=0)
        db.add(phone)
    else:
        if phone.e164 != e164:
            phone.key_num += 1
        phone.e164 = e164
        phone.confirmed_at = None
        phone.last_change_at = utcnow()
    await db.commit()

    # Invalidate any in-flight phone-enrol challenge for this session.
    await ch.invalidate_pending_for(
        db, user_id=user.id, app_slug=PHONE_ENROLL_PSEUDO_APP,
        session_token=session.token,
    )

    sent = await _send_sms(
        db, request=request, ip=ip, user=user, session=session,
        e164=e164, app_slug=PHONE_ENROLL_PSEUDO_APP,
    )
    if not isinstance(sent, tuple):
        return sent
    challenge_id, last4 = sent

    return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
        "app_slug": app,
        "target_last4": last4,
        "submit_url": "/_auth/phone/enroll/confirm",
        "resend_url": "/_auth/phone/enroll/resend",
        "heading": "Confirm your number",
        "notice": f"We sent a 6-digit code to {e164}. Enter it below to confirm.",
    })


@router.post("/_auth/phone/enroll/confirm")
async def enroll_confirm(
    request: Request,
    code: str = Form(...),
    next: str = Form("/"),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)

    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return _login_redirect(request, "/_auth/phone/enroll")

    challenge = await db.scalar(
        select(SmsOtpChallenge)
        .where(
            SmsOtpChallenge.user_id == user.id,
            SmsOtpChallenge.app_slug == PHONE_ENROLL_PSEUDO_APP,
            SmsOtpChallenge.gk_session_token == session.token,
            SmsOtpChallenge.status == "pending",
        )
        .order_by(SmsOtpChallenge.issued_at.desc())
        .limit(1)
    )
    if challenge is None:
        return RedirectResponse(
            url=f"/_auth/phone/enroll?next={quote(_safe_next(next))}&app={app}",
            status_code=302,
        )

    result = await ch.verify_challenge(
        db, challenge_id=challenge.id, submitted_code=code,
        session_token=session.token, secret_key=_config.secret_key,
    )
    return await _handle_verify_result(
        request=request, db=db, ip=ip, user=user, session=session,
        challenge=challenge, result=result, next_url=next, app=app,
        is_enrolment=True,
    )


@router.post("/_auth/phone/enroll/resend")
async def enroll_resend(
    request: Request,
    next: str = Form("/"),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return _login_redirect(request, "/_auth/phone/enroll")

    phone = await _get_phone(db, user.id)
    if phone is None:
        return RedirectResponse(
            url=f"/_auth/phone/enroll?next={quote(_safe_next(next))}&app={app}",
            status_code=302,
        )
    await ch.invalidate_pending_for(
        db, user_id=user.id, app_slug=PHONE_ENROLL_PSEUDO_APP,
        session_token=session.token,
    )
    await _record_event(
        db, ip=ip, app_slug=PHONE_ENROLL_PSEUDO_APP, user_email=user.email,
        status="sms_otp_invalidated_by_resend",
        session_token=session.token, request=request,
    )
    sent = await _send_sms(
        db, request=request, ip=ip, user=user, session=session,
        e164=phone.e164, app_slug=PHONE_ENROLL_PSEUDO_APP,
    )
    if not isinstance(sent, tuple):
        return sent
    _, last4 = sent
    return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
        "app_slug": app,
        "target_last4": last4,
        "submit_url": "/_auth/phone/enroll/confirm",
        "resend_url": "/_auth/phone/enroll/resend",
        "heading": "Confirm your number",
        "notice": "A fresh code has been sent.",
    })


# ---- step-up verify routes --------------------------------------------------

@router.get("/_auth/sms-otp/verify")
async def verify_get(
    request: Request,
    next: str = "/",
    app: str = "",
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return _login_redirect(request, request.url.path + f"?next={quote(next)}&app={app}")

    phone = await _get_phone(db, user.id)
    if phone is None or phone.confirmed_at is None:
        return RedirectResponse(
            url=f"/_auth/phone/enroll?next={quote(_safe_next(next))}&app={app}",
            status_code=302,
        )

    if not app:
        return HTMLResponse("Missing app context.", status_code=400)

    # If a fresh pending challenge already exists for this session, reuse
    # it — avoids spamming SMS on every page load when the user has the
    # form open in two tabs.
    existing = await db.scalar(
        select(SmsOtpChallenge)
        .where(
            SmsOtpChallenge.user_id == user.id,
            SmsOtpChallenge.app_slug == app,
            SmsOtpChallenge.gk_session_token == session.token,
            SmsOtpChallenge.status == "pending",
            SmsOtpChallenge.expires_at > utcnow(),
        )
        .order_by(SmsOtpChallenge.issued_at.desc())
        .limit(1)
    )
    if existing is None:
        sent = await _send_sms(
            db, request=request, ip=ip, user=user, session=session,
            e164=phone.e164, app_slug=app,
        )
        if not isinstance(sent, tuple):
            return sent
        _, last4 = sent
    else:
        last4 = existing.target_last4

    return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
        "app_slug": app,
        "target_last4": last4,
        "submit_url": "/_auth/sms-otp/verify",
        "resend_url": "/_auth/sms-otp/resend",
    })


@router.post("/_auth/sms-otp/verify")
async def verify_post(
    request: Request,
    code: str = Form(...),
    next: str = Form("/"),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return _login_redirect(request, "/_auth/sms-otp/verify")

    challenge = await db.scalar(
        select(SmsOtpChallenge)
        .where(
            SmsOtpChallenge.user_id == user.id,
            SmsOtpChallenge.app_slug == app,
            SmsOtpChallenge.gk_session_token == session.token,
            SmsOtpChallenge.status == "pending",
        )
        .order_by(SmsOtpChallenge.issued_at.desc())
        .limit(1)
    )
    if challenge is None:
        return RedirectResponse(
            url=f"/_auth/sms-otp/verify?app={app}&next={quote(_safe_next(next))}",
            status_code=302,
        )

    result = await ch.verify_challenge(
        db, challenge_id=challenge.id, submitted_code=code,
        session_token=session.token, secret_key=_config.secret_key,
    )
    return await _handle_verify_result(
        request=request, db=db, ip=ip, user=user, session=session,
        challenge=challenge, result=result, next_url=next, app=app,
        is_enrolment=False,
    )


@router.post("/_auth/sms-otp/resend")
async def verify_resend(
    request: Request,
    next: str = Form("/"),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    if await is_ip_blocked(db, ip):
        return HTMLResponse("Blocked", status_code=403)
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None or session is None:
        return _login_redirect(request, "/_auth/sms-otp/verify")

    phone = await _get_phone(db, user.id)
    if phone is None or phone.confirmed_at is None:
        return RedirectResponse(
            url=f"/_auth/phone/enroll?next={quote(_safe_next(next))}&app={app}",
            status_code=302,
        )
    if not app:
        return HTMLResponse("Missing app context.", status_code=400)

    await ch.invalidate_pending_for(
        db, user_id=user.id, app_slug=app, session_token=session.token,
    )
    await _record_event(
        db, ip=ip, app_slug=app, user_email=user.email,
        status="sms_otp_invalidated_by_resend",
        session_token=session.token, request=request,
    )
    sent = await _send_sms(
        db, request=request, ip=ip, user=user, session=session,
        e164=phone.e164, app_slug=app,
    )
    if not isinstance(sent, tuple):
        return sent
    _, last4 = sent
    return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
        "app_slug": app,
        "target_last4": last4,
        "submit_url": "/_auth/sms-otp/verify",
        "resend_url": "/_auth/sms-otp/resend",
        "notice": "A fresh code has been sent.",
    })


# ---- shared verify-result handler ------------------------------------------

async def _handle_verify_result(
    *, request: Request, db: AsyncSession, ip: str, user: User,
    session: Session, challenge: SmsOtpChallenge, result, next_url: str,
    app: str, is_enrolment: bool,
):
    """Dispatch a `Verified | VerifyFailed` to the right side-effects:
    bump UserPhone.confirmed_at on enrolment success, set
    session.totp_verified_at on step-up success, render error page or
    redirect on failure, escalate IP block on attempts_exceeded."""
    from gatekeeper.sms.challenges import Verified, VerifyFailed

    submit_url = (
        "/_auth/phone/enroll/confirm" if is_enrolment else "/_auth/sms-otp/verify"
    )
    resend_url = (
        "/_auth/phone/enroll/resend" if is_enrolment else "/_auth/sms-otp/resend"
    )

    import cyclops
    if isinstance(result, Verified):
        clear_failures(ip)
        if is_enrolment:
            phone = await _get_phone(db, user.id)
            if phone is not None:
                phone.confirmed_at = utcnow()
                await db.commit()
            await _record_event(
                db, ip=ip, app_slug=PHONE_ENROLL_PSEUDO_APP,
                user_email=user.email, status="sms_otp_verified",
                session_token=session.token, request=request,
            )
            # On enrolment success, send the user back to wherever they
            # came from. Forward_auth will re-evaluate the MFA gate and
            # (if the bound method is sms_otp) push them to the step-up
            # page next.
        else:
            session.totp_verified_at = utcnow()
            await db.commit()
            await _record_event(
                db, ip=ip, app_slug=app, user_email=user.email,
                status="sms_otp_verified",
                session_token=session.token, request=request,
            )
        cyclops.event(
            "gatekeeper.sms_otp.verified",
            outcome="success",
            app_slug=app or PHONE_ENROLL_PSEUDO_APP,
            masked_email=cyclops.redact_email(user.email),
            is_enrolment=is_enrolment,
        )
        return RedirectResponse(url=_safe_next(next_url), status_code=302)

    if isinstance(result, VerifyFailed):
        if result.reason == "bad_code":
            fails = record_failure(ip)
            if fails >= FAIL_BLOCK_THRESHOLD:
                await block_ip(
                    db, ip, reason="Exceeded MFA attempt limit",
                    blocked_by="gatekeeper-auto",
                )
                clear_failures(ip)
                await _record_event(
                    db, ip=ip, app_slug=app or PHONE_ENROLL_PSEUDO_APP,
                    user_email=user.email, status="sms_otp_failed_attempt:ip_blocked",
                    session_token=session.token, request=request,
                )
                cyclops.event(
                    "gatekeeper.sms_otp.verified",
                    outcome="failure",
                    app_slug=app or PHONE_ENROLL_PSEUDO_APP,
                    masked_email=cyclops.redact_email(user.email),
                    is_enrolment=is_enrolment,
                    reason="ip_blocked",
                )
                return HTMLResponse("Blocked", status_code=403)
            await _record_event(
                db, ip=ip, app_slug=app or PHONE_ENROLL_PSEUDO_APP,
                user_email=user.email, status="sms_otp_failed_attempt",
                session_token=session.token, request=request,
            )
            cyclops.event(
                "gatekeeper.sms_otp.verified",
                outcome="failure",
                app_slug=app or PHONE_ENROLL_PSEUDO_APP,
                masked_email=cyclops.redact_email(user.email),
                is_enrolment=is_enrolment,
                reason="bad_code",
                failures_in_window=fails,
            )
            return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
                "request": request,
                "user_email": user.email,
                "next": _safe_next(next_url),
                "app_slug": app,
                "target_last4": challenge.target_last4,
                "submit_url": submit_url,
                "resend_url": resend_url,
                "error": (
                    f"That code didn't match. {result.attempts_remaining} "
                    f"attempt{'s' if result.attempts_remaining != 1 else ''} left."
                ),
            }, status_code=400)

        if result.reason == "attempts_exceeded":
            await _record_event(
                db, ip=ip, app_slug=app or PHONE_ENROLL_PSEUDO_APP,
                user_email=user.email, status="sms_otp_attempts_exceeded",
                session_token=session.token, request=request,
            )
            return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
                "request": request,
                "user_email": user.email,
                "next": _safe_next(next_url),
                "app_slug": app,
                "target_last4": challenge.target_last4,
                "submit_url": submit_url,
                "resend_url": resend_url,
                "error": "Too many wrong attempts. Tap Resend to get a new code.",
            }, status_code=400)

        if result.reason == "expired":
            await _record_event(
                db, ip=ip, app_slug=app or PHONE_ENROLL_PSEUDO_APP,
                user_email=user.email, status="sms_otp_expired",
                session_token=session.token, request=request,
            )
            return templates.TemplateResponse(request, "auth/sms_otp_verify.html", {
                "request": request,
                "user_email": user.email,
                "next": _safe_next(next_url),
                "app_slug": app,
                "target_last4": challenge.target_last4,
                "submit_url": submit_url,
                "resend_url": resend_url,
                "error": "That code has expired. Tap Resend to get a new one.",
            }, status_code=400)

        # session_mismatch / not_found / not_pending — something is off,
        # bounce them back to enrol/issue.
        await _record_event(
            db, ip=ip, app_slug=app or PHONE_ENROLL_PSEUDO_APP,
            user_email=user.email,
            status=f"sms_otp_verify_rejected:{result.reason}",
            session_token=session.token, request=request,
        )
        if is_enrolment:
            return RedirectResponse(
                url=f"/_auth/phone/enroll?next={quote(_safe_next(next_url))}&app={app}",
                status_code=302,
            )
        return RedirectResponse(
            url=f"/_auth/sms-otp/verify?app={app}&next={quote(_safe_next(next_url))}",
            status_code=302,
        )

    # Should be unreachable.
    return HTMLResponse("Internal error", status_code=500)


# ---- delivery webhook -------------------------------------------------------

# ClickSend status values that mean "no point retrying — show the user
# a fresh-code prompt." We invalidate the challenge so the next user
# action gets a new code rather than wasting attempts on a dead one.
_TERMINAL_FAILURE_STATUSES = {
    "UNDELIVERABLE", "FAILED", "REJECTED", "CANCELLED", "EXPIRED",
}
_DELIVERED_STATUSES = {"DELIVERED", "SENT"}


@router.post("/_auth/sms/webhook/{secret}")
async def sms_webhook(
    secret: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """ClickSend delivery receipt sink. The path component `secret`
    must match `sms.webhook_secret` — ClickSend doesn't sign these
    natively, so we lock the endpoint behind a long random URL.

    Idempotent: webhooks may be retried by ClickSend on transient
    receipt failures, and an event for an already-finalised challenge
    is a no-op.
    """
    if not _config.sms.webhook_secret:
        # Misconfiguration — refuse rather than accept anonymous posts.
        return HTMLResponse("Webhook not configured", status_code=503)
    # Constant-time compare to keep the path secret out of timing oracles.
    import hmac as _hmac
    if not _hmac.compare_digest(secret, _config.sms.webhook_secret):
        # Don't echo anything that helps an attacker probe.
        return HTMLResponse("Not found", status_code=404)

    payload = await _parse_webhook_body(request)
    message_id = payload.get("message_id") or payload.get("messageId") or ""
    status_str = (payload.get("status") or payload.get("status_text") or "").upper()
    if not message_id:
        return HTMLResponse("Missing message_id", status_code=400)

    challenge = await db.scalar(
        select(SmsOtpChallenge).where(
            SmsOtpChallenge.provider_message_id == message_id,
        )
    )
    if challenge is None:
        # Unknown / pre-cleanup / spoofed — accept silently to avoid
        # giving the sender a confirmed-or-not signal.
        return HTMLResponse("OK", status_code=200)

    if status_str in _DELIVERED_STATUSES and challenge.delivered_at is None:
        await db.execute(
            update(SmsOtpChallenge)
            .where(SmsOtpChallenge.id == challenge.id)
            .values(delivered_at=utcnow())
        )
        await db.commit()
        await _record_event(
            db, ip="webhook", app_slug=challenge.app_slug,
            user_email=None, status="sms_otp_delivered",
            session_token=challenge.gk_session_token, request=request,
        )
        return HTMLResponse("OK", status_code=200)

    if status_str in _TERMINAL_FAILURE_STATUSES and challenge.status == "pending":
        await db.execute(
            update(SmsOtpChallenge)
            .where(
                SmsOtpChallenge.id == challenge.id,
                SmsOtpChallenge.status == "pending",
            )
            .values(status="invalidated")
        )
        await db.commit()
        await _record_event(
            db, ip="webhook", app_slug=challenge.app_slug,
            user_email=None, status=f"sms_otp_undeliverable:{status_str.lower()}",
            session_token=challenge.gk_session_token, request=request,
        )
    return HTMLResponse("OK", status_code=200)


async def _parse_webhook_body(request: Request) -> dict:
    """Accept JSON or form-encoded — ClickSend's delivery receipt config
    lets either be picked, and we don't want the choice to break parity."""
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/json" in ctype:
        try:
            return await request.json()
        except Exception:
            return {}
    form = await request.form()
    return {k: v for k, v in form.items()}
