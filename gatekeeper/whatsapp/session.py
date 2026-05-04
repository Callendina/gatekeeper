"""WhatsApp session helpers — DB-backed conversation_id store.

One row per (phone_e164, app_slug) in whatsapp_sessions. Updated on
each message exchange so multi-turn chat survives Gatekeeper restarts.
"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.models import WhatsAppSession


async def get_conversation_id(
    db: AsyncSession, phone: str, app_slug: str
) -> int | None:
    row = await db.scalar(
        select(WhatsAppSession).where(
            WhatsAppSession.phone_e164 == phone,
            WhatsAppSession.app_slug == app_slug,
        )
    )
    return row.conversation_id if row is not None else None


async def set_conversation_id(
    db: AsyncSession, phone: str, app_slug: str, conv_id: int
) -> None:
    row = await db.scalar(
        select(WhatsAppSession).where(
            WhatsAppSession.phone_e164 == phone,
            WhatsAppSession.app_slug == app_slug,
        )
    )
    if row is None:
        db.add(WhatsAppSession(
            phone_e164=phone, app_slug=app_slug,
            conversation_id=conv_id, updated_at=utcnow(),
        ))
    else:
        row.conversation_id = conv_id
        row.updated_at = utcnow()
    await db.commit()


async def clear_session(
    db: AsyncSession, phone: str, app_slug: str
) -> None:
    row = await db.scalar(
        select(WhatsAppSession).where(
            WhatsAppSession.phone_e164 == phone,
            WhatsAppSession.app_slug == app_slug,
        )
    )
    if row is not None:
        row.conversation_id = None
        row.updated_at = utcnow()
        await db.commit()
