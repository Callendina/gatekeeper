"""Tests for the forward_auth verify endpoint."""
import datetime
import secrets
import pytest
from gatekeeper._time import utcnow
from gatekeeper.models import User, UserAppRole, APIKey


@pytest.mark.asyncio
async def test_unknown_host_returns_403(client):
    resp = await client.get("/_auth/verify", headers={"x-forwarded-host": "unknown.com"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_valid_host_returns_200(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
    })
    assert resp.status_code == 200
    assert resp.headers.get("x-gatekeeper-user") == ""
    assert resp.headers.get("x-gatekeeper-role") == ""


@pytest.mark.asyncio
async def test_protected_path_without_auth_returns_401(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/protected/secret",
    })
    assert resp.status_code == 302
    assert "/_auth/login" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_unprotected_path_allowed_anonymous(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/public/page",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_session_cookie_set_on_first_visit(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
    })
    assert resp.status_code == 200
    cookies = resp.headers.get_list("set-cookie")
    assert any("gk_session" in c for c in cookies)


@pytest.mark.asyncio
async def test_session_cookie_reused_on_revisit(client):
    # First visit — get cookie
    resp1 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
    })
    cookies = resp1.headers.get_list("set-cookie")
    cookie_val = None
    for c in cookies:
        if "gk_session=" in c:
            cookie_val = c.split("gk_session=")[1].split(";")[0]

    assert cookie_val is not None

    # Second visit — use cookie, should NOT get a new one
    resp2 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "cookie": f"gk_session={cookie_val}",
    })
    assert resp2.status_code == 200
    new_cookies = resp2.headers.get_list("set-cookie")
    assert not any("gk_session" in c for c in new_cookies)


# --- Protected path + API key fallback tests ---

async def _create_user_with_key(db, email, app_slug, role="user"):
    """Helper: create a user, app role, and registered API key. Returns the key string."""
    user = User(email=email, display_name=email.split("@")[0])
    db.add(user)
    await db.flush()
    db.add(UserAppRole(user_id=user.id, app_slug=app_slug, role=role))
    key_str = secrets.token_hex(16)
    db.add(APIKey(
        key=key_str, app_slug=app_slug, user_id=user.id,
        key_type="registered", ip_address="127.0.0.1",
        expires_at=utcnow() + datetime.timedelta(days=365),
    ))
    await db.commit()
    return key_str


async def _create_anon_temp_key(db, app_slug):
    """Helper: create an anonymous temp API key. Returns the key string."""
    key_str = secrets.token_hex(16)
    db.add(APIKey(
        key=key_str, app_slug=app_slug, user_id=None,
        key_type="temp", ip_address="127.0.0.1",
        expires_at=utcnow() + datetime.timedelta(minutes=30),
    ))
    await db.commit()
    return key_str


@pytest.mark.asyncio
async def test_protected_path_with_registered_api_key(client, db):
    """Registered API key should grant access to protected paths."""
    key = await _create_user_with_key(db, "apiuser@test.com", "hybridapp")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "hybrid.example.com",
        "x-forwarded-uri": "/dashboard/home",
        "x-forwarded-api-key": key,
    })
    assert resp.status_code == 200
    assert resp.headers.get("x-gatekeeper-user") == "apiuser@test.com"
    assert resp.headers.get("x-gatekeeper-role") == "user"


@pytest.mark.asyncio
async def test_protected_path_with_invalid_api_key(client):
    """Invalid API key on a protected path should return 401."""
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "hybrid.example.com",
        "x-forwarded-uri": "/dashboard/home",
        "x-forwarded-api-key": "bad-key",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_path_with_anon_temp_key_redirects(client, db):
    """Anonymous temp key on a protected path should redirect to login (needs real user)."""
    key = await _create_anon_temp_key(db, "hybridapp")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "hybrid.example.com",
        "x-forwarded-uri": "/dashboard/home",
        "x-forwarded-api-key": key,
    })
    assert resp.status_code == 302
    assert "/_auth/login" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_protected_path_no_key_no_session_redirects(client):
    """No auth at all on a protected path still redirects to login."""
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "hybrid.example.com",
        "x-forwarded-uri": "/dashboard/home",
    })
    assert resp.status_code == 302
    assert "/_auth/login" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_protected_path_api_key_ignored_when_mode_open(client, db):
    """If api_access.mode is not key_required, API key fallback doesn't apply."""
    # testapp has protected_paths but no api_access (mode=open)
    key = await _create_user_with_key(db, "openuser@test.com", "testapp")
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/protected/secret",
        "x-forwarded-api-key": key,
    })
    # Should redirect to login — API key not honoured in open mode
    assert resp.status_code == 302
    assert "/_auth/login" in resp.headers.get("location", "")
