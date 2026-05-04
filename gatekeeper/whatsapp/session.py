"""WhatsApp session helpers — DB-backed conversation and routing state.

Two tables:
- whatsapp_sessions: one row per (phone_e164, app_slug) — conversation_id
  for each app the user has chatted with.
- whatsapp_phone_state: one row per phone — which app is currently selected
  and whether the user is in the middle of an app-selection menu.
"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.models import WhatsAppPhoneState, WhatsAppSession


# ── Conversation ID (per phone + app) ────────────────────────────────────────

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


# ── Phone routing state (per phone) ──────────────────────────────────────────

async def get_phone_state(
    db: AsyncSession, phone: str
) -> tuple[str | None, str | None]:
    """Return (selected_app_slug, state) for this phone. Both None if no row."""
    row = await db.scalar(
        select(WhatsAppPhoneState).where(WhatsAppPhoneState.phone_e164 == phone)
    )
    if row is None:
        return None, None
    return row.selected_app_slug, row.state


async def set_phone_state(
    db: AsyncSession,
    phone: str,
    selected_app_slug: str | None = None,
    state: str | None = None,
) -> None:
    row = await db.scalar(
        select(WhatsAppPhoneState).where(WhatsAppPhoneState.phone_e164 == phone)
    )
    if row is None:
        db.add(WhatsAppPhoneState(
            phone_e164=phone,
            selected_app_slug=selected_app_slug,
            state=state,
            updated_at=utcnow(),
        ))
    else:
        row.selected_app_slug = selected_app_slug
        row.state = state
        row.updated_at = utcnow()
    await db.commit()


async def clear_phone_state(
    db: AsyncSession, phone: str, app_slugs: list[str]
) -> None:
    """Clear routing state and all conversation IDs for this phone.

    Call on "reset" so the user starts completely fresh: no selected app,
    no active conversations in any app.
    """
    state_row = await db.scalar(
        select(WhatsAppPhoneState).where(WhatsAppPhoneState.phone_e164 == phone)
    )
    if state_row is not None:
        state_row.selected_app_slug = None
        state_row.state = None
        state_row.updated_at = utcnow()

    for slug in app_slugs:
        conv_row = await db.scalar(
            select(WhatsAppSession).where(
                WhatsAppSession.phone_e164 == phone,
                WhatsAppSession.app_slug == slug,
            )
        )
        if conv_row is not None:
            conv_row.conversation_id = None
            conv_row.updated_at = utcnow()

    await db.commit()
