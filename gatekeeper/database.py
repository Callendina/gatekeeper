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
        from gatekeeper.models import User, OAuthAccount, Session, IPBlocklist, AnonymousUsage, AccessLog  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        yield session
