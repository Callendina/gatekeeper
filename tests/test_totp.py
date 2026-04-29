"""Tests for TOTP enrollment, verification, and forward_auth gating."""
import datetime
import secrets
import time

import pyotp
import pytest

from gatekeeper._time import utcnow
from gatekeeper.auth.totp import (
    derive_secret,
    issuer_for,
    otpauth_uri,
    qr_svg,
    _verify_code,
)
from gatekeeper.config import GatekeeperConfig, MFAConfig
from gatekeeper.models import Session, User, UserAppRole, UserTOTP


# ---- Pure function tests (no DB) ----


def test_derive_secret_deterministic():
    a = derive_secret("master", 1, 0)
    b = derive_secret("master", 1, 0)
    assert a == b


def test_derive_secret_changes_with_key_num():
    s0 = derive_secret("master", 1, 0)
    s1 = derive_secret("master", 1, 1)
    assert s0 != s1


def test_derive_secret_changes_with_user():
    a = derive_secret("master", 1, 0)
    b = derive_secret("master", 2, 0)
    assert a != b


def test_derive_secret_changes_with_master_key():
    a = derive_secret("master-a", 1, 0)
    b = derive_secret("master-b", 1, 0)
    assert a != b


def test_derive_secret_is_valid_base32():
    s = derive_secret("master", 42, 0)
    # pyotp will reject anything that isn't valid base32 when generating a code
    code = pyotp.TOTP(s).now()
    assert len(code) == 6
    assert code.isdigit()


def test_issuer_for_with_environment():
    c = GatekeeperConfig(secret_key="x", totp_issuer="Foo", environment="STAGING")
    assert issuer_for(c) == "Foo - STAGING"


def test_issuer_for_no_environment():
    c = GatekeeperConfig(secret_key="x", totp_issuer="Foo")
    assert issuer_for(c) == "Foo"


def test_otpauth_uri_format():
    uri = otpauth_uri("ABCDEFGH", "user@example.com", "MyIssuer")
    assert uri.startswith("otpauth://totp/MyIssuer%3Auser%40example.com?")
    assert "secret=ABCDEFGH" in uri
    assert "issuer=MyIssuer" in uri
    assert "algorithm=SHA1" in uri


def test_qr_svg_is_inline_svg():
    svg = qr_svg("otpauth://totp/test?secret=ABCDEFGH")
    assert svg.startswith("<svg")
    assert "</svg>" in svg


def test_verify_code_accepts_current():
    secret = derive_secret("master", 1, 0)
    code = pyotp.TOTP(secret).now()
    ok, counter = _verify_code(secret, code, 0)
    assert ok
    assert counter > 0


def test_verify_code_rejects_replay():
    secret = derive_secret("master", 1, 0)
    code = pyotp.TOTP(secret).now()
    ok, counter = _verify_code(secret, code, 0)
    assert ok
    # Same code at counter that was just accepted must fail.
    ok2, _ = _verify_code(secret, code, counter)
    assert not ok2


def test_verify_code_rejects_wrong():
    secret = derive_secret("master", 1, 0)
    ok, _ = _verify_code(secret, "000000", 0)
    assert not ok


def test_verify_code_rejects_garbage():
    secret = derive_secret("master", 1, 0)
    assert not _verify_code(secret, "abc123", 0)[0]
    assert not _verify_code(secret, "", 0)[0]
    assert not _verify_code(secret, "12345", 0)[0]   # wrong length
    assert not _verify_code(secret, "1234567", 0)[0]


def test_mfa_config_step_up_seconds():
    assert MFAConfig().step_up_seconds == 0
    assert MFAConfig(step_up_minutes=30).step_up_seconds == 1800
    assert MFAConfig(step_up_days=90).step_up_seconds == 7776000
    # minutes wins over days when both > 0
    assert MFAConfig(step_up_minutes=15, step_up_days=90).step_up_seconds == 900


def test_mfa_config_enabled():
    assert not MFAConfig().enabled
    assert MFAConfig(required_for_roles=["admin"]).enabled
    assert MFAConfig(required_for_paths=["/admin/*"]).enabled


# ---- Helpers for forward_auth tests ----

async def _make_user_with_session(db, email, app_slug, role="user", totp_verified_at=None):
    user = User(email=email, display_name=email.split("@")[0])
    db.add(user)
    await db.flush()
    db.add(UserAppRole(user_id=user.id, app_slug=app_slug, role=role))
    token = secrets.token_urlsafe(32)
    db.add(Session(
        token=token,
        user_id=user.id,
        app_slug=app_slug,
        ip_address="127.0.0.1",
        expires_at=utcnow() + datetime.timedelta(days=30),
        totp_verified_at=totp_verified_at,
    ))
    await db.commit()
    return user, token


async def _enroll_user(db, user_id, master_key="test-secret-key"):
    """Mark a user as TOTP-enrolled with a confirmed UserTOTP row."""
    rec = UserTOTP(
        user_id=user_id,
        key_num=0,
        confirmed_at=utcnow(),
        last_counter=0,
    )
    db.add(rec)
    await db.commit()
    return derive_secret(master_key, user_id, 0)


# ---- forward_auth gate tests ----


@pytest.mark.asyncio
async def test_role_triggered_mfa_redirects_unenrolled_to_enroll(client, db):
    """An admin user with no TOTP enrollment should be sent to /enroll on any page."""
    user, token = await _make_user_with_session(db, "admin@test.com", "mfaapp", role="admin")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/totp/enroll" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_role_triggered_mfa_redirects_enrolled_no_stepup_to_verify(client, db):
    """Admin user, enrolled, but session.totp_verified_at is null → /verify."""
    user, token = await _make_user_with_session(db, "admin@test.com", "mfaapp", role="admin")
    await _enroll_user(db, user.id)
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/totp/verify" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_role_triggered_mfa_passes_with_fresh_step_up(client, db):
    """Admin, enrolled, with a recent totp_verified_at → 200."""
    fresh = utcnow() - datetime.timedelta(minutes=5)
    user, token = await _make_user_with_session(
        db, "admin@test.com", "mfaapp", role="admin", totp_verified_at=fresh
    )
    await _enroll_user(db, user.id)
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 200
    assert resp.headers.get("x-gatekeeper-user") == "admin@test.com"


@pytest.mark.asyncio
async def test_role_triggered_mfa_step_up_expired(client, db):
    """Admin with step_up_minutes=30 and totp_verified_at older than that → /verify."""
    stale = utcnow() - datetime.timedelta(minutes=45)
    user, token = await _make_user_with_session(
        db, "admin@test.com", "mfaapp", role="admin", totp_verified_at=stale
    )
    await _enroll_user(db, user.id)
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/totp/verify" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_path_triggered_mfa_only_on_matching_path(client, db):
    """Regular user shouldn't be MFA-prompted on non-sensitive paths,
    even though /sensitive/* requires it."""
    user, token = await _make_user_with_session(db, "user@test.com", "mfaapp", role="user")
    # /anywhere is not in required_for_paths, user role isn't in required_for_roles
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/anywhere",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_path_triggered_mfa_redirects_unenrolled(client, db):
    """Regular user hitting /sensitive/* with no enrollment → /enroll."""
    user, token = await _make_user_with_session(db, "user@test.com", "mfaapp", role="user")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/sensitive/data",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 302
    assert "/_auth/totp/enroll" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_anonymous_user_skips_mfa_gate(client):
    """Anonymous request to a sensitive path is handled by other gates,
    not the MFA gate. /sensitive/* isn't in protected_paths so it's
    publicly accessible to anonymous users."""
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "mfa.example.com",
        "x-forwarded-uri": "/sensitive/data",
    })
    # No MFA prompt; anonymous user just sails through (no auth required for this path).
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_does_not_apply_to_apps_without_mfa_config(client, db):
    """testapp has no MFA config; an admin role there should not be prompted."""
    user, token = await _make_user_with_session(db, "admin@test.com", "testapp", role="admin")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "cookie": f"gk_session={token}",
    })
    assert resp.status_code == 200


# ---- Enrollment / verify route tests ----


@pytest.mark.asyncio
async def test_enroll_get_renders_qr(client, db):
    user, token = await _make_user_with_session(db, "u@test.com", "mfaapp", role="admin")
    resp = await client.get("/_auth/totp/enroll", cookies={"gk_session": token})
    assert resp.status_code == 200
    body = resp.text
    assert "<svg" in body
    assert "Set up two-factor authentication" in body


@pytest.mark.asyncio
async def test_enroll_confirm_with_valid_code(client, db):
    user, token = await _make_user_with_session(db, "u@test.com", "mfaapp", role="admin")
    # Trigger enroll page so the UserTOTP row exists with key_num=0.
    await client.get("/_auth/totp/enroll", cookies={"gk_session": token})
    secret = derive_secret("test-secret-key", user.id, 0)
    code = pyotp.TOTP(secret).now()
    resp = await client.post(
        "/_auth/totp/enroll/confirm",
        data={"code": code, "next": "/done"},
        cookies={"gk_session": token},
    )
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/done"
    # confirmed_at should now be set
    rec = await db.scalar(
        __import__('sqlalchemy').select(UserTOTP).where(UserTOTP.user_id == user.id)
    )
    assert rec.confirmed_at is not None


@pytest.mark.asyncio
async def test_enroll_confirm_rejects_wrong_code(client, db):
    user, token = await _make_user_with_session(db, "u@test.com", "mfaapp", role="admin")
    await client.get("/_auth/totp/enroll", cookies={"gk_session": token})
    resp = await client.post(
        "/_auth/totp/enroll/confirm",
        data={"code": "000000", "next": "/"},
        cookies={"gk_session": token},
    )
    assert resp.status_code == 400
    assert "didn&#39;t match" in resp.text or "didn't match" in resp.text


@pytest.mark.asyncio
async def test_verify_post_with_valid_code_sets_session_totp_verified_at(client, db):
    user, token = await _make_user_with_session(db, "u@test.com", "mfaapp", role="admin")
    await _enroll_user(db, user.id)
    secret = derive_secret("test-secret-key", user.id, 0)
    code = pyotp.TOTP(secret).now()
    resp = await client.post(
        "/_auth/totp/verify",
        data={"code": code, "next": "/somewhere"},
        cookies={"gk_session": token},
    )
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/somewhere"
    # session.totp_verified_at should be set now
    sess = await db.scalar(
        __import__('sqlalchemy').select(Session).where(Session.token == token)
    )
    assert sess.totp_verified_at is not None


@pytest.mark.asyncio
async def test_safe_next_strips_external_redirects(client, db):
    """next= must be a same-host relative path; absolute URLs collapse to /."""
    user, token = await _make_user_with_session(db, "u@test.com", "mfaapp", role="admin")
    await _enroll_user(db, user.id)
    secret = derive_secret("test-secret-key", user.id, 0)
    code = pyotp.TOTP(secret).now()
    resp = await client.post(
        "/_auth/totp/verify",
        data={"code": code, "next": "https://evil.example/steal"},
        cookies={"gk_session": token},
    )
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/"


# ---- Admin reset ----


@pytest.mark.asyncio
async def test_admin_reset_bumps_key_num(client, db):
    """reset_totp() should bump key_num and clear confirmed_at, invalidating
    the previous secret. The `client` fixture is required only to ensure the
    app/db is initialised; the test itself doesn't issue HTTP."""
    from gatekeeper.auth.totp import reset_totp
    user = User(email="r@test.com", display_name="r")
    db.add(user)
    await db.flush()
    rec = UserTOTP(
        user_id=user.id, key_num=0,
        confirmed_at=utcnow(), last_counter=999,
    )
    db.add(rec)
    await db.commit()

    old_secret = derive_secret("test-secret-key", user.id, 0)
    await reset_totp(db, user.id)

    refreshed = await db.scalar(
        __import__('sqlalchemy').select(UserTOTP).where(UserTOTP.user_id == user.id)
    )
    assert refreshed.key_num == 1
    assert refreshed.confirmed_at is None
    assert refreshed.last_counter == 0
    new_secret = derive_secret("test-secret-key", user.id, 1)
    assert new_secret != old_secret
