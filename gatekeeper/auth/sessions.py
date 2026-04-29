import secrets
import datetime
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from gatekeeper._time import utcnow
from gatekeeper.models import Session, User, UserAppRole


SESSION_DURATION_HOURS = 24 * 180  # 6 months


async def create_session(
    db: AsyncSession, user_id: int | None, app_slug: str, ip_address: str
) -> str:
    token = secrets.token_urlsafe(32)
    session = Session(
        token=token,
        user_id=user_id,
        app_slug=app_slug,
        ip_address=ip_address,
        expires_at=utcnow()
        + datetime.timedelta(hours=SESSION_DURATION_HOURS),
    )
    db.add(session)
    await db.commit()
    return token


async def validate_session(
    db: AsyncSession, token: str, app_slug: str
) -> tuple[Session | None, User | None, str | None, str | None]:
    """Returns (session, user, role, group) or (None, None, None, None) if invalid."""
    stmt = select(Session).where(
        Session.token == token,
        Session.app_slug == app_slug,
        Session.expires_at > utcnow(),
    )
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()

    if session is None:
        return None, None, None, None

    if session.user_id is None:
        return session, None, None, None

    user_stmt = select(User).where(User.id == session.user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    if user is None:
        return None, None, None, None

    role_stmt = select(UserAppRole).where(
        UserAppRole.user_id == user.id,
        UserAppRole.app_slug == app_slug,
    )
    role_result = await db.execute(role_stmt)
    app_role = role_result.scalar_one_or_none()
    role = app_role.role if app_role else None
    group = app_role.group if app_role else None

    return session, user, role, group


async def delete_session(db: AsyncSession, token: str):
    await db.execute(delete(Session).where(Session.token == token))
    await db.commit()


async def cleanup_expired_sessions(db: AsyncSession):
    await db.execute(
        delete(Session).where(Session.expires_at < utcnow())
    )
    await db.commit()
