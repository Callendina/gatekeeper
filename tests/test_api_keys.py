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
async def test_temp_key_without_session_returns_401(client):
    """Can't get a temp key without a session cookie."""
    resp = await client.post("/_auth/api-key/temp", headers={
        "host": "api.example.com",
    })
    assert resp.status_code == 401


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
