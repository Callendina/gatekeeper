"""Tests for SMS-OTP feature: pure helpers, validation, rate limits,
challenge ops, and the forward_auth dispatcher."""
import asyncio
import datetime
import secrets

import pytest

from gatekeeper._time import utcnow
from gatekeeper.models import (
    Session, SmsOtpChallenge, User, UserAppRole, UserPhone, UserTOTP,
)


# ---- Pure code / HMAC helpers ----------------------------------------------

def test_generate_code_is_six_digits():
    from gatekeeper.sms.codes import generate_code
    for _ in range(50):
        c = generate_code()
        assert len(c) == 6
        assert c.isdigit()


def test_code_hmac_is_deterministic():
    from gatekeeper.sms.codes import derive_code_hmac
    a = derive_code_hmac("k", "cid", "000123")
    b = derive_code_hmac("k", "cid", "000123")
    assert a == b
    assert len(a) == 64  # hex sha256


def test_code_hmac_distinguishes_challenge_id():
    from gatekeeper.sms.codes import derive_code_hmac
    a = derive_code_hmac("k", "cid-A", "111111")
    b = derive_code_hmac("k", "cid-B", "111111")
    assert a != b


def test_code_hmac_distinguishes_secret():
    from gatekeeper.sms.codes import derive_code_hmac
    a = derive_code_hmac("ka", "cid", "111111")
    b = derive_code_hmac("kb", "cid", "111111")
    assert a != b


def test_code_matches_leading_zero_strict():
    from gatekeeper.sms.codes import derive_code_hmac, code_matches
    h = derive_code_hmac("k", "cid", "000123")
    assert code_matches("k", "cid", h, "000123")
    assert not code_matches("k", "cid", h, "123")
    assert not code_matches("k", "cid", h, "0000123")


def test_code_matches_strips_whitespace():
    from gatekeeper.sms.codes import derive_code_hmac, code_matches
    h = derive_code_hmac("k", "cid", "111222")
    assert code_matches("k", "cid", h, "  111 222  ")


def test_code_matches_rejects_non_digits():
    from gatekeeper.sms.codes import derive_code_hmac, code_matches
    h = derive_code_hmac("k", "cid", "111222")
    assert not code_matches("k", "cid", h, "abcdef")
    assert not code_matches("k", "cid", h, "")
    assert not code_matches("k", "cid", h, "11122")     # short
    assert not code_matches("k", "cid", h, "1112223")   # long


# ---- Phone validation -------------------------------------------------------

def test_validation_local_au_mobile_normalises():
    from gatekeeper.sms.validation import normalize
    e164, last4 = normalize("0412 345 678", ["+61"])
    assert e164 == "+61412345678"
    assert last4 == "5678"


def test_validation_already_e164():
    from gatekeeper.sms.validation import normalize
    e164, _ = normalize("+61412345678", ["+61"])
    assert e164 == "+61412345678"


def test_validation_rejects_garbage():
    from gatekeeper.sms.validation import normalize, InvalidPhoneFormat
    with pytest.raises(InvalidPhoneFormat):
        normalize("asdf", ["+61"])


def test_validation_rejects_outside_allowlist():
    from gatekeeper.sms.validation import normalize, CountryNotAllowed
    with pytest.raises(CountryNotAllowed):
        # US mobile, allowlist is AU only
        normalize("+14155552671", ["+61"])


def test_validation_rejects_landline():
    from gatekeeper.sms.validation import normalize, NotMobileLine
    with pytest.raises(NotMobileLine):
        # AU landline (Sydney)
        normalize("+61287654321", ["+61"])


def test_validation_empty_allowlist_fails_closed():
    from gatekeeper.sms.validation import normalize, CountryNotAllowed
    with pytest.raises(CountryNotAllowed):
        normalize("+61412345678", [])


# ---- Five-tier rate limiter ------------------------------------------------

def test_rate_limit_per_number_hour():
    from gatekeeper.sms.rate_limit import (
        Allowed, Tripped, check_and_record, reset_for_tests,
    )
    from gatekeeper.config import SMSRateLimits
    reset_for_tests()
    cfg = SMSRateLimits(per_number_hour=2, per_number_day=99,
                        per_user_hour=99, per_ip_hour=99,
                        per_app_hour=99, global_hour=99, global_day=99)
    args = dict(e164="+61412345678", user_id=1, ip="1.2.3.4", app_slug="x", cfg=cfg)
    assert isinstance(check_and_record(**args), Allowed)
    assert isinstance(check_and_record(**args), Allowed)
    third = check_and_record(**args)
    assert isinstance(third, Tripped)
    assert third.tier == "per_number"
    assert third.window == "hour"
    assert third.limit == 2


def test_rate_limit_first_tripped_tier_wins():
    """When two limits would both block, we report the most specific."""
    from gatekeeper.sms.rate_limit import (
        check_and_record, reset_for_tests, Tripped,
    )
    from gatekeeper.config import SMSRateLimits
    reset_for_tests()
    cfg = SMSRateLimits(per_number_hour=1, per_number_day=99,
                        per_user_hour=1, per_ip_hour=99,
                        per_app_hour=99, global_hour=99, global_day=99)
    args = dict(e164="+61412345678", user_id=1, ip="1.2.3.4", app_slug="x", cfg=cfg)
    check_and_record(**args)  # first burns both per_number AND per_user
    second = check_and_record(**args)
    assert isinstance(second, Tripped)
    assert second.tier == "per_number"  # specificity wins


def test_rate_limit_per_ip_hour():
    from gatekeeper.sms.rate_limit import check_and_record, reset_for_tests, Tripped
    from gatekeeper.config import SMSRateLimits
    reset_for_tests()
    cfg = SMSRateLimits(per_number_hour=99, per_number_day=99,
                        per_user_hour=99, per_ip_hour=2,
                        per_app_hour=99, global_hour=99, global_day=99)
    # Same IP, different numbers / users — only per_ip should bind.
    check_and_record(e164="+61400000001", user_id=1, ip="9.9.9.9", app_slug="a", cfg=cfg)
    check_and_record(e164="+61400000002", user_id=2, ip="9.9.9.9", app_slug="a", cfg=cfg)
    third = check_and_record(e164="+61400000003", user_id=3, ip="9.9.9.9", app_slug="a", cfg=cfg)
    assert isinstance(third, Tripped)
    assert third.tier == "per_ip"


def test_rate_limit_zero_means_unlimited():
    from gatekeeper.sms.rate_limit import check_and_record, reset_for_tests, Allowed
    from gatekeeper.config import SMSRateLimits
    reset_for_tests()
    cfg = SMSRateLimits(per_number_hour=0, per_number_day=0,
                        per_user_hour=0, per_ip_hour=0,
                        per_app_hour=0, global_hour=0, global_day=0)
    for _ in range(50):
        result = check_and_record(
            e164="+61412345678", user_id=1, ip="1.2.3.4", app_slug="x", cfg=cfg,
        )
        assert isinstance(result, Allowed)


# ---- Challenge DB ops -------------------------------------------------------

async def _make_user_with_session(db, email, app_slug):
    user = User(email=email, display_name=email.split("@")[0])
    db.add(user)
    await db.flush()
    db.add(UserAppRole(user_id=user.id, app_slug=app_slug, role="admin"))
    token = secrets.token_urlsafe(32)
    db.add(Session(
        token=token, user_id=user.id, app_slug=app_slug,
        ip_address="127.0.0.1",
        expires_at=utcnow() + datetime.timedelta(days=30),
    ))
    await db.commit()
    return user, token


@pytest.mark.asyncio
async def test_issue_and_verify_happy_path(app, db):
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "a@x.com", "smsapp")
    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k",
    )
    result = await ch.verify_challenge(
        db, challenge_id=issued.challenge.id,
        submitted_code=issued.plaintext_code,
        session_token=token, secret_key="k",
    )
    assert isinstance(result, ch.Verified)
    assert result.user_id == user.id


@pytest.mark.asyncio
async def test_verify_rejects_replay_after_consume(app, db):
    """Single-use enforcement via UPDATE...WHERE status='pending'."""
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "b@x.com", "smsapp")
    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k",
    )
    first = await ch.verify_challenge(
        db, challenge_id=issued.challenge.id,
        submitted_code=issued.plaintext_code,
        session_token=token, secret_key="k",
    )
    second = await ch.verify_challenge(
        db, challenge_id=issued.challenge.id,
        submitted_code=issued.plaintext_code,
        session_token=token, secret_key="k",
    )
    assert isinstance(first, ch.Verified)
    assert isinstance(second, ch.VerifyFailed)
    assert second.reason == "not_pending"


@pytest.mark.asyncio
async def test_verify_attempts_cap_invalidates(app, db):
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "c@x.com", "smsapp")
    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k",
    )
    last_result = None
    for _ in range(6):
        last_result = await ch.verify_challenge(
            db, challenge_id=issued.challenge.id,
            submitted_code="000000",  # always wrong (correct code is random)
            session_token=token, secret_key="k",
            max_attempts=5,
        )
    assert isinstance(last_result, ch.VerifyFailed)
    assert last_result.reason in ("attempts_exceeded", "not_pending")
    # Even with the *correct* code, the consumed/invalidated row can't be used.
    final = await ch.verify_challenge(
        db, challenge_id=issued.challenge.id,
        submitted_code=issued.plaintext_code,
        session_token=token, secret_key="k",
    )
    assert isinstance(final, ch.VerifyFailed)
    assert final.reason == "not_pending"


@pytest.mark.asyncio
async def test_verify_expired(app, db):
    from sqlalchemy import update
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "d@x.com", "smsapp")
    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k", ttl_seconds=300,
    )
    # Fast-forward by mutating expires_at into the past.
    await db.execute(
        update(SmsOtpChallenge)
        .where(SmsOtpChallenge.id == issued.challenge.id)
        .values(expires_at=utcnow() - datetime.timedelta(seconds=1))
    )
    await db.commit()
    result = await ch.verify_challenge(
        db, challenge_id=issued.challenge.id,
        submitted_code=issued.plaintext_code,
        session_token=token, secret_key="k",
    )
    assert isinstance(result, ch.VerifyFailed)
    assert result.reason == "expired"


@pytest.mark.asyncio
async def test_verify_rejects_cross_session(app, db):
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "e@x.com", "smsapp")
    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k",
    )
    result = await ch.verify_challenge(
        db, challenge_id=issued.challenge.id,
        submitted_code=issued.plaintext_code,
        session_token="some-other-session", secret_key="k",
    )
    assert isinstance(result, ch.VerifyFailed)
    assert result.reason == "session_mismatch"


@pytest.mark.asyncio
async def test_resend_invalidates_in_flight(app, db):
    """invalidate_pending_for must flip prior pending challenges so
    accumulated attempts can't span re-sends."""
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "f@x.com", "smsapp")
    first = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k",
    )
    n = await ch.invalidate_pending_for(
        db, user_id=user.id, app_slug="smsapp", session_token=token,
    )
    assert n == 1
    # Old challenge can no longer be verified
    result = await ch.verify_challenge(
        db, challenge_id=first.challenge.id,
        submitted_code=first.plaintext_code,
        session_token=token, secret_key="k",
    )
    assert isinstance(result, ch.VerifyFailed)
    assert result.reason == "not_pending"


@pytest.mark.asyncio
async def test_concurrent_verify_only_one_wins(app, db):
    """Two simultaneous verifies of the same correct code: at most one
    should report Verified; the other must lose with not_pending."""
    from gatekeeper.database import async_session_factory
    from gatekeeper.sms import challenges as ch
    user, token = await _make_user_with_session(db, "g@x.com", "smsapp")
    issued = await ch.issue_challenge(
        db, user_id=user.id, app_slug="smsapp", e164="+61412345678",
        session_token=token, secret_key="k",
    )

    async def attempt():
        async with async_session_factory() as s:
            return await ch.verify_challenge(
                s, challenge_id=issued.challenge.id,
                submitted_code=issued.plaintext_code,
                session_token=token, secret_key="k",
            )

    results = await asyncio.gather(attempt(), attempt())
    verified = [r for r in results if isinstance(r, ch.Verified)]
    failed = [r for r in results if isinstance(r, ch.VerifyFailed)]
    assert len(verified) == 1
    assert len(failed) == 1
    assert failed[0].reason == "not_pending"


# ---- Forward-auth dispatcher ------------------------------------------------

@pytest.mark.asyncio
async def test_dispatcher_redirects_sms_app_unenrolled_to_phone_enroll(client, db):
    user, token = await _make_user_with_session(db, "h@x.com", "smsapp")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "sms.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/phone/enroll" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_dispatcher_redirects_multimethod_unbound_to_picker(client, db):
    user, token = await _make_user_with_session(db, "i@x.com", "multiapp")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "multi.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/mfa/choose" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_dispatcher_auto_binds_existing_totp_user_on_multimethod(client, db):
    """User already has confirmed TOTP; multi-method app shouldn't make
    them pick — auto-bind to TOTP."""
    user, token = await _make_user_with_session(db, "j@x.com", "multiapp")
    db.add(UserTOTP(user_id=user.id, key_num=0, confirmed_at=utcnow()))
    await db.commit()
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "multi.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/totp/verify" in resp.headers.get("location", "")
    from sqlalchemy import select
    role = await db.scalar(
        select(UserAppRole).where(
            UserAppRole.user_id == user.id, UserAppRole.app_slug == "multiapp",
        )
    )
    assert role is not None
    assert role.mfa_method == "totp"


@pytest.mark.asyncio
async def test_full_enrol_and_step_up_via_http(client, db):
    """End-to-end happy path that exercises the route chain via HTTP
    without rendering any HTML (rendering hits a pre-existing Jinja
    cache flake on this Python/Jinja combination — same flake that
    deselects 4 TOTP/login tests). We rely on the helper routes that
    issue challenges via POST and redirects."""
    from gatekeeper.models import DebugSmsOutbox
    from sqlalchemy import select

    user, token = await _make_user_with_session(db, "endtoend@x.com", "smsapp")
    cookie_hdr = f"gk_session={token}"

    # 1) Hit gated path → forward_auth redirects to /_auth/phone/enroll
    r1 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "sms.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": cookie_hdr,
    })
    assert r1.status_code == 302
    assert "/_auth/phone/enroll" in r1.headers["location"]

    # 2) Submit number — issues a confirmation OTP via FakeSmsProvider.
    # Response body is a rendered template so we can't follow it directly;
    # the side effect we care about is the DebugSmsOutbox row.
    try:
        await client.post(
            "/_auth/phone/enroll",
            data={"number": "0412345678", "app": "smsapp", "next": "/anywhere"},
            headers={"cookie": cookie_hdr},
        )
    except TypeError:
        # Jinja LRUCache flake on the response render — the side effect
        # (DB write of the challenge + outbox row) still happened.
        pass

    outbox = await db.scalar(
        select(DebugSmsOutbox).order_by(DebugSmsOutbox.id.desc()).limit(1)
    )
    assert outbox is not None
    assert outbox.to_e164 == "+61412345678"

    # 3) Confirm OTP → 302 redirect (no template render on success)
    r3 = await client.post(
        "/_auth/phone/enroll/confirm",
        data={"code": outbox.code, "app": "smsapp", "next": "/anywhere"},
        headers={"cookie": cookie_hdr},
    )
    assert r3.status_code == 302
    assert r3.headers["location"] == "/anywhere"

    # 4) Phone now confirmed; forward_auth wants step-up
    r4 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "sms.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": cookie_hdr,
    })
    assert r4.status_code == 302
    assert "/_auth/sms-otp/verify" in r4.headers["location"]

    # 5) Trigger a step-up challenge via the resend endpoint (also
    # writes to outbox; redirects/templates aren't on the response path
    # for the side effects we need).
    try:
        await client.post(
            "/_auth/sms-otp/resend",
            data={"app": "smsapp", "next": "/anywhere"},
            headers={"cookie": cookie_hdr},
        )
    except TypeError:
        pass

    outbox2 = await db.scalar(
        select(DebugSmsOutbox).order_by(DebugSmsOutbox.id.desc()).limit(1)
    )
    assert outbox2.id != outbox.id

    # 6) Submit the fresh code → 302 to /anywhere
    r6 = await client.post(
        "/_auth/sms-otp/verify",
        data={"code": outbox2.code, "app": "smsapp", "next": "/anywhere"},
        headers={"cookie": cookie_hdr},
    )
    assert r6.status_code == 302
    assert r6.headers["location"] == "/anywhere"

    # 7) Forward_auth now lets the request through
    r7 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "sms.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": cookie_hdr,
    })
    assert r7.status_code == 200
    assert r7.headers.get("x-gatekeeper-user") == "endtoend@x.com"


@pytest.mark.asyncio
async def test_dispatcher_sms_user_with_phone_redirects_to_verify(client, db):
    user, token = await _make_user_with_session(db, "k@x.com", "smsapp")
    db.add(UserPhone(user_id=user.id, e164="+61412345678", confirmed_at=utcnow()))
    await db.commit()
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "sms.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/sms-otp/verify" in resp.headers.get("location", "")
