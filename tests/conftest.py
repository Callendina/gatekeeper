"""Test fixtures for gatekeeper tests."""
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI

from gatekeeper.config import (
    GatekeeperConfig, AppConfig, PaywallConfig, APIAccessConfig, RateLimitConfig,
)
from gatekeeper.database import init_db
from gatekeeper.auth.forward_auth import router as forward_auth_router, init_forward_auth
from gatekeeper.auth.login import router as login_router, init_login_routes
from gatekeeper.auth.api_keys import router as api_key_router, init_api_key_routes
from gatekeeper.admin.routes import router as admin_router, init_admin_routes
from gatekeeper.middleware.rate_limit import _request_log, _api_key_log
from gatekeeper.middleware.ip_block import _blocked_ips

TEST_DB = "test_gatekeeper.db"


def get_test_config() -> GatekeeperConfig:
    return GatekeeperConfig(
        host="127.0.0.1",
        port=9100,
        secret_key="test-secret-key",
        database_path=TEST_DB,
        apps={
            "testapp": AppConfig(
                slug="testapp",
                name="Test App",
                domains=["testapp.example.com"],
                protected_paths=["/protected/*", "/admin/*"],
                paywall=PaywallConfig(max_sessions_per_week=3),
                roles=["user", "admin"],
                default_role="user",
            ),
            "apiapp": AppConfig(
                slug="apiapp",
                name="API App",
                domains=["api.example.com"],
                paywall=PaywallConfig(max_api_calls_per_hour=5),
                api_access=APIAccessConfig(
                    mode="key_required",
                    paths=["/api/*"],
                    temp_key_duration_minutes=30,
                    registered_key_duration_days=365,
                ),
                roles=["user", "admin"],
                default_role="user",
            ),
        },
        rate_limit=RateLimitConfig(requests_per_minute=10, burst=5),
    )


@pytest_asyncio.fixture
async def config():
    return get_test_config()


@pytest_asyncio.fixture
async def app(config):
    import gatekeeper.database as db_module

    # Remove stale test DB
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except PermissionError:
            pass

    await init_db(config.database_path)
    init_forward_auth(config)
    init_login_routes(config)
    init_api_key_routes(config)
    init_admin_routes(config)

    # Build a test app directly (avoids importing gatekeeper.app which
    # reads config.yaml at module level and may hang on Windows)
    from starlette.middleware.sessions import SessionMiddleware
    test_app = FastAPI()
    test_app.add_middleware(SessionMiddleware, secret_key=config.secret_key)
    test_app.include_router(forward_auth_router)
    test_app.include_router(login_router)
    test_app.include_router(api_key_router)
    test_app.include_router(admin_router)

    @test_app.get("/_auth/health")
    async def health():
        return {"status": "ok"}

    yield test_app

    # Cleanup: dispose engine so Windows releases file lock
    _request_log.clear()
    _api_key_log.clear()
    _blocked_ips.clear()
    if db_module.engine:
        await db_module.engine.dispose()
        db_module.engine = None
        db_module.async_session_factory = None
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except PermissionError:
            pass


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def db():
    from gatekeeper.database import async_session_factory
    async with async_session_factory() as session:
        yield session
