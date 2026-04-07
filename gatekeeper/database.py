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
        from gatekeeper.models import User, OAuthAccount, Session, IPBlocklist, AnonymousUsage, AccessLog, APIKey, InviteCode, InviteUse, InviteWaitlist, InviteUserLimit  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)

        # Migrate: add columns that may be missing from older databases
        await _add_column_if_missing(conn, "api_keys", "rate_limit_override", "INTEGER DEFAULT 0")
        await _add_column_if_missing(conn, "access_log", "session_token", "VARCHAR(255)")
        await _add_column_if_missing(conn, "access_log", "referrer", "TEXT")
        await _add_column_if_missing(conn, "access_log", "user_agent", "TEXT")
        await _add_column_if_missing(conn, "invite_codes", "role", "VARCHAR(50)")


async def _add_column_if_missing(conn, table: str, column: str, col_type: str):
    """Add a column to an existing table if it doesn't exist (SQLite)."""
    import sqlalchemy
    result = await conn.execute(sqlalchemy.text(f"PRAGMA table_info({table})"))
    columns = [row[1] for row in result.fetchall()]
    if column not in columns:
        await conn.execute(sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
        import logging
        logging.getLogger("gatekeeper.database").info(f"Added column {table}.{column}")


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        yield session
