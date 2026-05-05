"""Tests for gatekeeper-to-gatekeeper partner trust (issue #14).

Three layers:

1. `_ip_in_allowlist` — pure function on the inbound IP-allowlist text
   format (newline-separated, with optional `# hostname` comments
   from save-time DNS resolution).

2. `_resolve_staging_partner` — the WhatsApp handler's outbound
   resolver, which takes the per-app `whatsapp.staging_partner` name
   and looks up a `PartnerEndpoint` row.

3. End-to-end through `/_auth/verify` — exercising the full inbound
   path with `TrustedPartner` rows: path forbidden, key invalid,
   disabled partner, IP denied, path denied, success +
   `last_seen_at` bump.
"""
import hashlib
import logging

import pytest
import pytest_asyncio
from sqlalchemy import select

from gatekeeper.auth.forward_auth import _ip_in_allowlist
from gatekeeper.config import WhatsAppConfig
from gatekeeper.models import PartnerEndpoint, TrustedPartner
from gatekeeper.whatsapp.handler import _resolve_staging_partner


# ─── _ip_in_allowlist ─────────────────────────────────────────────────────────

def test_ip_in_allowlist_empty():
    assert not _ip_in_allowlist("203.0.113.7", "")


def test_ip_in_allowlist_exact_ip():
    assert _ip_in_allowlist("203.0.113.7", "203.0.113.7/32")


def test_ip_in_allowlist_cidr_match():
    assert _ip_in_allowlist("203.0.113.99", "203.0.113.0/24")


def test_ip_in_allowlist_no_match():
    assert not _ip_in_allowlist("198.51.100.5", "203.0.113.0/24")


def test_ip_in_allowlist_strips_hostname_comment():
    """save-time DNS annotates entries as `<cidr>  # hostname`. Match
    should ignore the comment."""
    allowlist = "203.0.113.0/24  # prod.callendina.com"
    assert _ip_in_allowlist("203.0.113.42", allowlist)
    assert not _ip_in_allowlist("198.51.100.42", allowlist)


def test_ip_in_allowlist_multi_line():
    allowlist = "10.0.0.0/8\n203.0.113.7/32  # bastion"
    assert _ip_in_allowlist("10.5.5.5", allowlist)
    assert _ip_in_allowlist("203.0.113.7", allowlist)
    assert not _ip_in_allowlist("203.0.113.8", allowlist)


def test_ip_in_allowlist_ipv6():
    assert _ip_in_allowlist("2001:db8::1", "2001:db8::/32")
    assert not _ip_in_allowlist("2001:db8::1", "fe80::/10")


def test_ip_in_allowlist_invalid_ip_returns_false():
    """A garbage `ip` value never matches — we don't try to be clever."""
    assert not _ip_in_allowlist("not-an-ip", "203.0.113.0/24")


def test_ip_in_allowlist_skips_unparseable_lines():
    """A malformed entry shouldn't crash the matcher; later valid lines
    must still be considered."""
    allowlist = "garbage-line\n203.0.113.0/24"
    assert _ip_in_allowlist("203.0.113.42", allowlist)


# ─── _resolve_staging_partner ────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db_session(app):
    """Reuse the test app's DB engine. The conftest `app` fixture sets
    up the DB; this fixture just hands out a session."""
    from gatekeeper.database import async_session_factory
    async with async_session_factory() as session:
        yield session


@pytest.mark.asyncio
async def test_resolve_staging_partner_no_config(db_session, caplog):
    """When the app has no staging_partner configured, the resolver
    returns None and warns — caller falls back to prod."""
    wa_cfg = WhatsAppConfig(chat_endpoint="http://prod/api/chat")
    with caplog.at_level(logging.WARNING, logger="gatekeeper.whatsapp"):
        result = await _resolve_staging_partner(db_session, wa_cfg, "scout")
    assert result is None
    assert "no staging_partner configured" in caplog.text


@pytest.mark.asyncio
async def test_resolve_staging_partner_missing_row(db_session, caplog):
    """staging_partner names a partner that doesn't exist → None + warn."""
    wa_cfg = WhatsAppConfig(
        chat_endpoint="http://prod/api/chat",
        staging_partner="nope",
    )
    with caplog.at_level(logging.WARNING, logger="gatekeeper.whatsapp"):
        result = await _resolve_staging_partner(db_session, wa_cfg, "scout")
    assert result is None
    assert "not found or disabled" in caplog.text


@pytest.mark.asyncio
async def test_resolve_staging_partner_disabled_row(db_session):
    """A row whose enabled=False is treated as missing."""
    db_session.add(PartnerEndpoint(
        name="staging", base_url="http://staging", api_key="k",
        enabled=False,
    ))
    await db_session.commit()

    wa_cfg = WhatsAppConfig(staging_partner="staging")
    result = await _resolve_staging_partner(db_session, wa_cfg, "scout")
    assert result is None


@pytest.mark.asyncio
async def test_resolve_staging_partner_present(db_session):
    """Happy path: enabled row with matching name is returned."""
    db_session.add(PartnerEndpoint(
        name="staging", base_url="http://staging:9002",
        api_key="secret-key", enabled=True,
    ))
    await db_session.commit()

    wa_cfg = WhatsAppConfig(staging_partner="staging")
    result = await _resolve_staging_partner(db_session, wa_cfg, "scout")
    assert result is not None
    assert result.name == "staging"
    assert result.api_key == "secret-key"


# ─── /_auth/verify — inbound partner-trust path ─────────────────────────────

def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@pytest_asyncio.fixture
async def trusted_partner(db_session):
    """Insert a TrustedPartner row whose key is `partner-secret-key`.
    Allows /api/chat from 10.0.0.0/8."""
    key = "partner-secret-key"
    row = TrustedPartner(
        name="prod-gk",
        api_key_hash=_hash(key),
        allowed_paths="/api/chat",
        allowed_ips="10.0.0.0/8",
        enabled=True,
    )
    db_session.add(row)
    await db_session.commit()
    return row, key


@pytest.mark.asyncio
async def test_partner_key_blocks_admin_paths(client, trusted_partner):
    """/_auth/admin/* must never be reachable via partner trust, even
    with a valid key. Hard guard — no allowed_paths config can override."""
    _, key = trusted_partner
    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/_auth/admin/users",
            "x-forwarded-method": "GET",
            "x-forwarded-for": "10.0.0.5",
            "x-forwarded-gatekeeper-partner-key": key,
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_partner_key_invalid_rejected(client):
    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/chat",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "10.0.0.5",
            "x-forwarded-gatekeeper-partner-key": "wrong-key",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_partner_key_disabled_partner_rejected(db_session, client):
    """Even a key that *would* validate is rejected when enabled=False."""
    key = "disabled-partner-key"
    db_session.add(TrustedPartner(
        name="off",
        api_key_hash=_hash(key),
        allowed_paths="/api/chat",
        enabled=False,
    ))
    await db_session.commit()

    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/chat",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "10.0.0.5",
            "x-forwarded-gatekeeper-partner-key": key,
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_partner_key_ip_denied(client, trusted_partner):
    """Valid key, but caller IP is outside allowed_ips → 403."""
    _, key = trusted_partner
    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/chat",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "203.0.113.7",
            "x-forwarded-gatekeeper-partner-key": key,
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_partner_key_path_denied(client, trusted_partner):
    """Valid key + IP, but path is not in allowed_paths → 403."""
    _, key = trusted_partner
    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/other",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "10.0.0.5",
            "x-forwarded-gatekeeper-partner-key": key,
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_partner_key_success_echoes_identity_headers(
    client, trusted_partner, db_session,
):
    """Happy path: gatekeeper returns 200 with the inbound
    X-Gatekeeper-* identity headers echoed back so Caddy passes them
    through to the upstream app."""
    row, key = trusted_partner
    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/chat",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "10.0.0.5",
            "x-forwarded-gatekeeper-partner-key": key,
            "x-forwarded-gatekeeper-user": "tester@example.com",
            "x-forwarded-gatekeeper-role": "full",
            "x-forwarded-gatekeeper-group": "CLUB.PEN",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["X-Gatekeeper-User"] == "tester@example.com"
    assert resp.headers["X-Gatekeeper-Role"] == "full"
    assert resp.headers["X-Gatekeeper-Group"] == "CLUB.PEN"

    # last_seen_at should be bumped from the initial NULL.
    refreshed = await db_session.scalar(
        select(TrustedPartner).where(TrustedPartner.id == row.id)
    )
    assert refreshed.last_seen_at is not None


@pytest.mark.asyncio
async def test_partner_key_success_when_no_ip_restriction(db_session, client):
    """allowed_ips empty → IP check is skipped, only key + path matter."""
    key = "no-ip-restriction-key"
    db_session.add(TrustedPartner(
        name="anywhere",
        api_key_hash=_hash(key),
        allowed_paths="/api/chat",
        allowed_ips="",
        enabled=True,
    ))
    await db_session.commit()

    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/chat",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "203.0.113.7",
            "x-forwarded-gatekeeper-partner-key": key,
            "x-forwarded-gatekeeper-user": "tester@example.com",
        },
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_partner_key_glob_paths(db_session, client):
    """allowed_paths uses fnmatch globs — `/api/*` matches /api/chat."""
    key = "glob-key"
    db_session.add(TrustedPartner(
        name="glob",
        api_key_hash=_hash(key),
        allowed_paths="/api/*",
        allowed_ips="",
        enabled=True,
    ))
    await db_session.commit()

    resp = await client.get(
        "/_auth/verify",
        headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/api/chat",
            "x-forwarded-method": "POST",
            "x-forwarded-for": "10.0.0.5",
            "x-forwarded-gatekeeper-partner-key": key,
            "x-forwarded-gatekeeper-user": "tester@example.com",
        },
    )
    assert resp.status_code == 200
