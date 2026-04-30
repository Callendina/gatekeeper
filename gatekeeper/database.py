import logging

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


engine = None
async_session_factory = None


async def init_db(database_path: str):
    global engine, async_session_factory
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}", echo=False)
    async_session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        # Importing for side effect: each model class registers with Base.metadata.
        from gatekeeper.models import (  # noqa: F401
            User, OAuthAccount, Session, IPBlocklist, AnonymousUsage,
            AccessLog, APIKey, InviteCode, InviteUse, InviteWaitlist,
            InviteUserLimit, UserTOTP, UserPhone, SmsOtpChallenge,
            DebugSmsOutbox,
        )
        await conn.run_sync(Base.metadata.create_all)

        # Migrate: add columns that may be missing from older databases
        await _add_column_if_missing(conn, "api_keys", "rate_limit_override", "INTEGER DEFAULT 0")
        await _add_column_if_missing(conn, "access_log", "session_token", "VARCHAR(255)")
        await _add_column_if_missing(conn, "access_log", "referrer", "TEXT")
        await _add_column_if_missing(conn, "access_log", "user_agent", "TEXT")
        await _add_column_if_missing(conn, "invite_codes", "role", "VARCHAR(50)")
        await _add_column_if_missing(conn, "invite_codes", '"group"', "VARCHAR(100)")
        await _add_column_if_missing(conn, "user_app_roles", '"group"', "VARCHAR(100)")
        await _add_column_if_missing(conn, "sessions", "totp_verified_at", "DATETIME")
        # Phase 1 of SMS-OTP: per-(user, app) MFA method binding.
        await _add_column_if_missing(conn, "user_app_roles", "mfa_method", "VARCHAR(20)")


async def _add_column_if_missing(conn, table: str, column: str, col_type: str):
    """Add a column to an existing table if it doesn't exist (SQLite)."""
    import sqlalchemy
    result = await conn.execute(sqlalchemy.text(f"PRAGMA table_info({table})"))
    columns = [row[1] for row in result.fetchall()]
    # Strip quotes for comparison, but use quoted form in ALTER TABLE
    bare_column = column.strip('"')
    if bare_column not in columns:
        quoted = f'"{bare_column}"' if bare_column != column else column
        await conn.execute(sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {quoted} {col_type}"))
        import logging
        logging.getLogger("gatekeeper.database").info(f"Added column {table}.{bare_column}")


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        yield session


async def backfill_mfa_method(config) -> None:
    """One-shot, idempotent backfill: stamp UserAppRole.mfa_method='totp'
    for any (user, app) where the user has a confirmed UserTOTP and the
    app's configured mfa.methods includes 'totp'. Apps whose methods drop
    'totp' are left alone — admin must migrate those users explicitly.

    Safe to run on every startup: the WHERE-clause filters on NULL so
    already-stamped rows are skipped. New users (post-phase-1) will get
    their mfa_method set explicitly at first MFA encounter, so this
    backfill becomes a no-op once existing users are covered.
    """
    import sqlalchemy
    logger = logging.getLogger("gatekeeper.database")
    async with async_session_factory() as session:
        for app_slug, app_cfg in config.apps.items():
            if "totp" not in app_cfg.mfa.methods:
                continue
            result = await session.execute(
                sqlalchemy.text(
                    "UPDATE user_app_roles SET mfa_method = 'totp' "
                    "WHERE app_slug = :slug AND mfa_method IS NULL "
                    "AND user_id IN ("
                    "  SELECT user_id FROM user_totp WHERE confirmed_at IS NOT NULL"
                    ")"
                ),
                {"slug": app_slug},
            )
            if result.rowcount:
                logger.info(
                    f"Backfilled mfa_method='totp' on {result.rowcount} "
                    f"user_app_roles row(s) for app '{app_slug}'"
                )
        await session.commit()
