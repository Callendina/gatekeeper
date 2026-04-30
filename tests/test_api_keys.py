"""Tests for API key issuance and validation."""
import pytest
from gatekeeper.models import User, UserAppRole
from gatekeeper.auth.sessions import create_session


@pytest.mark.asyncio
async def test_api_path_without_key_returns_401(client):
    """API paths on key_required apps need an X-API-Key."""
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "api.example.com",
        "x-forwarded-uri": "/api/data",
    })
    assert resp.status_code == 401
    assert "API key" in resp.text


@pytest.mark.asyncio
async def test_temp_key_without_session_auto_creates_one(client):
    """Requesting a temp key without a session auto-creates an anonymous session."""
    resp = await client.post("/_auth/api-key/temp", headers={
        "host": "api.example.com",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "temp"
    assert "api_key" in data
    # Should also set a gk_session cookie
    cookies = resp.headers.get_list("set-cookie")
    assert any("gk_session" in c for c in cookies)


@pytest.mark.asyncio
async def test_temp_key_with_anonymous_session(client, db):
    """Anonymous session can get a temp API key."""
    # Create an anonymous session
    token = await create_session(db, None, "apiapp", "10.3.0.1")

    resp = await client.post("/_auth/api-key/temp", headers={
        "host": "api.example.com",
    }, cookies={"gk_session": token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "temp"
    assert "api_key" in data


@pytest.mark.asyncio
async def test_temp_key_validates_on_api_path(client, db):
    """A valid temp key should allow access to API paths."""
    token = await create_session(db, None, "apiapp", "10.3.1.1")

    # Get a temp key
    resp = await client.post("/_auth/api-key/temp", headers={
        "host": "api.example.com",
    }, cookies={"gk_session": token})
    api_key = resp.json()["api_key"]

    # Use it on an API path
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "api.example.com",
        "x-forwarded-uri": "/api/data",
        "x-forwarded-api-key": api_key,
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_registered_key_for_authenticated_user(client, db):
    """Authenticated user can get a long-lived registered key."""
    # Create a user
    user = User(email="test@example.com", display_name="Test User")
    db.add(user)
    await db.flush()
    role = UserAppRole(user_id=user.id, app_slug="apiapp", role="user")
    db.add(role)
    await db.commit()

    # Create an authenticated session
    token = await create_session(db, user.id, "apiapp", "10.3.2.1")

    # Get a registered key
    resp = await client.post("/_auth/api-key", headers={
        "host": "api.example.com",
    }, cookies={"gk_session": token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "registered"

    # Use it
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "api.example.com",
        "x-forwarded-uri": "/api/data",
        "x-forwarded-api-key": data["api_key"],
    })
    assert resp.status_code == 200
    assert resp.headers.get("x-gatekeeper-user") == "test@example.com"
    assert resp.headers.get("x-gatekeeper-role") == "user"


@pytest.mark.asyncio
async def test_invalid_api_key_returns_401(client):
    """An invalid API key should be rejected."""
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "api.example.com",
        "x-forwarded-uri": "/api/data",
        "x-forwarded-api-key": "bogus-key-12345",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_non_api_path_does_not_require_key(client):
    """Non-API paths on the apiapp should not require a key."""
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "api.example.com",
        "x-forwarded-uri": "/",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_issue_registered_key_for_user_helper(client, db, config):
    """Admin-callable helper mints a registered key, replacing any existing one,
    and rejects when the per-app cap is hit unless force=True."""
    from gatekeeper.auth.api_keys import issue_registered_key_for_user
    from sqlalchemy import select, func
    from gatekeeper.models import APIKey

    user = User(email="apiuser@example.com", display_name="API User")
    db.add(user)
    await db.flush()
    db.add(UserAppRole(user_id=user.id, app_slug="apiapp", role="user"))
    await db.commit()

    app = config.apps["apiapp"]
    key1, exp1, err1 = await issue_registered_key_for_user(db, app, user, "1.2.3.4")
    assert err1 is None and key1 and exp1 is not None

    # Re-issue replaces the old key (same user+app)
    key2, exp2, err2 = await issue_registered_key_for_user(db, app, user, "1.2.3.4")
    assert err2 is None and key2 != key1
    count = await db.scalar(select(func.count(APIKey.id)).where(
        APIKey.user_id == user.id, APIKey.app_slug == "apiapp",
        APIKey.key_type == "registered",
    ))
    assert count == 1

    # Override expiry
    key3, exp3, err3 = await issue_registered_key_for_user(
        db, app, user, "1.2.3.4", override_expiry_seconds=60
    )
    assert err3 is None
    delta = (exp3 - exp2).total_seconds()
    assert delta < 0  # shorter than default

    # Hitting the cap returns an error; force=True bypasses it.
    # apiapp's max_registered defaults to 500, so simulate by patching it down.
    saved = app.api_access.api_rate_limits.max_registered
    app.api_access.api_rate_limits.max_registered = 1
    try:
        u2 = User(email="other@example.com", display_name="Other")
        db.add(u2)
        await db.flush()
        await db.commit()
        _, _, err = await issue_registered_key_for_user(db, app, u2, "1.2.3.4")
        assert err is not None and err["type"] == "max_active_keys"

        forced_key, _, err_forced = await issue_registered_key_for_user(
            db, app, u2, "1.2.3.4", force=True
        )
        assert err_forced is None and forced_key
    finally:
        app.api_access.api_rate_limits.max_registered = saved
