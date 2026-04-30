"""DB-bound challenge lifecycle: issue, verify, invalidate.

Pure helpers (code generation, HMAC) live in `codes.py`. This module
holds the SQLAlchemy ops and the single-use consume invariant.
"""
import datetime
import logging
import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.models import SmsOtpChallenge
from gatekeeper.sms.codes import (
    code_matches, derive_code_hmac, derive_target_hmac, generate_code,
)


logger = logging.getLogger("gatekeeper.sms.challenges")


@dataclass
class IssuedChallenge:
    challenge: SmsOtpChallenge
    plaintext_code: str  # Caller hands this to the provider; never persisted.


# --- verify result types -----------------------------------------------------

@dataclass(frozen=True)
class Verified:
    user_id: int


@dataclass(frozen=True)
class VerifyFailed:
    reason: Literal[
        "not_found", "session_mismatch", "expired", "not_pending",
        "bad_code", "attempts_exceeded",
    ]
    attempts_remaining: int = 0


# --- issue -------------------------------------------------------------------

async def issue_challenge(
    db: AsyncSession,
    *,
    user_id: int,
    app_slug: str,
    e164: str,
    session_token: str,
    secret_key: str,
    ttl_seconds: int = 300,
) -> IssuedChallenge:
    """Insert a fresh `pending` challenge. Caller is responsible for:
      1. invalidating any in-flight pending challenge for this (user,
         app, session) BEFORE calling this — see `invalidate_pending_for`.
      2. handing `plaintext_code` to the provider.
      3. flipping the challenge to `invalidated` if the provider rejects.
    """
    challenge_id = str(uuid.uuid4())
    code = generate_code()
    now = utcnow()
    challenge = SmsOtpChallenge(
        id=challenge_id,
        user_id=user_id,
        app_slug=app_slug,
        channel="sms",
        code_hmac=derive_code_hmac(secret_key, challenge_id, code),
        target_hmac=derive_target_hmac(secret_key, e164),
        target_last4=e164[-4:],
        issued_at=now,
        expires_at=now + datetime.timedelta(seconds=ttl_seconds),
        attempts_used=0,
        status="pending",
        gk_session_token=session_token,
    )
    db.add(challenge)
    await db.commit()
    return IssuedChallenge(challenge=challenge, plaintext_code=code)


# --- invalidate (called before issuing a fresh one) --------------------------

async def invalidate_pending_for(
    db: AsyncSession,
    *,
    user_id: int,
    app_slug: str,
    session_token: str,
) -> int:
    """Flip every in-flight `pending` challenge for this (user, app,
    session) to `invalidated`. Returns rowcount. Idempotent. Called
    before issuing a fresh challenge so attempts can't accumulate across
    re-sends."""
    result = await db.execute(
        update(SmsOtpChallenge)
        .where(
            SmsOtpChallenge.user_id == user_id,
            SmsOtpChallenge.app_slug == app_slug,
            SmsOtpChallenge.gk_session_token == session_token,
            SmsOtpChallenge.status == "pending",
        )
        .values(status="invalidated")
    )
    await db.commit()
    return result.rowcount


# --- mark provider rejection -------------------------------------------------

async def mark_invalidated(db: AsyncSession, challenge_id: str) -> None:
    """Used when the provider rejects the send (InvalidNumber,
    InsufficientCredit, etc) — keeps the audit row but takes it out of
    play so the user can request a fresh one."""
    await db.execute(
        update(SmsOtpChallenge)
        .where(SmsOtpChallenge.id == challenge_id)
        .values(status="invalidated")
    )
    await db.commit()


async def attach_provider_message_id(
    db: AsyncSession, challenge_id: str, provider_message_id: str
) -> None:
    """Webhooks (phase 3) match on this. Set right after the provider
    accepts so any near-instant delivery webhook can correlate."""
    await db.execute(
        update(SmsOtpChallenge)
        .where(SmsOtpChallenge.id == challenge_id)
        .values(provider_message_id=provider_message_id)
    )
    await db.commit()


# --- verify ------------------------------------------------------------------

async def verify_challenge(
    db: AsyncSession,
    *,
    challenge_id: str,
    submitted_code: str,
    session_token: str,
    secret_key: str,
    max_attempts: int = 5,
) -> Verified | VerifyFailed:
    """Verify a submitted code against a pending challenge. Single-use
    consume is atomic: the winning verify flips status to `consumed`
    via UPDATE ... WHERE status='pending' and checks rowcount.

    Concurrent verifies of the same correct code: at most one wins.
    Concurrent failed verifies are not strictly serialised — attempt
    counts may undercount by 1 under high concurrency, which is OK
    (lockout is best-effort).
    """
    challenge = await db.scalar(
        select(SmsOtpChallenge).where(SmsOtpChallenge.id == challenge_id)
    )
    if challenge is None:
        return VerifyFailed(reason="not_found")
    if challenge.gk_session_token != session_token:
        return VerifyFailed(reason="session_mismatch")
    if challenge.status != "pending":
        return VerifyFailed(reason="not_pending")
    if challenge.expires_at <= utcnow():
        await db.execute(
            update(SmsOtpChallenge)
            .where(
                SmsOtpChallenge.id == challenge_id,
                SmsOtpChallenge.status == "pending",
            )
            .values(status="expired")
        )
        await db.commit()
        return VerifyFailed(reason="expired")

    if not code_matches(secret_key, challenge_id, challenge.code_hmac, submitted_code):
        challenge.attempts_used += 1
        attempts_remaining = max_attempts - challenge.attempts_used
        if attempts_remaining <= 0:
            challenge.status = "invalidated"
            await db.commit()
            return VerifyFailed(reason="attempts_exceeded", attempts_remaining=0)
        await db.commit()
        return VerifyFailed(reason="bad_code", attempts_remaining=attempts_remaining)

    # Atomic single-use consume. The race winner gets rowcount==1; any
    # concurrent verify of the same code sees status!='pending' on the
    # WHERE clause and rowcount==0.
    result = await db.execute(
        update(SmsOtpChallenge)
        .where(
            SmsOtpChallenge.id == challenge_id,
            SmsOtpChallenge.status == "pending",
        )
        .values(status="consumed")
    )
    await db.commit()
    if result.rowcount != 1:
        return VerifyFailed(reason="not_pending")
    return Verified(user_id=challenge.user_id)


# --- cleanup -----------------------------------------------------------------

async def cleanup_old_challenges(db: AsyncSession, retain_hours: int = 24) -> int:
    """Delete expired/consumed/invalidated/verified challenges older than
    `retain_hours`. Pending challenges are left alone (they'll either be
    resolved or aged out into 'expired' on the next verify attempt;
    there's no batch sweeper for that — it's not worth the complexity)."""
    cutoff = utcnow() - datetime.timedelta(hours=retain_hours)
    from sqlalchemy import delete
    result = await db.execute(
        delete(SmsOtpChallenge).where(
            SmsOtpChallenge.issued_at < cutoff,
            SmsOtpChallenge.status.in_(
                ("expired", "consumed", "invalidated", "verified")
            ),
        )
    )
    await db.commit()
    if result.rowcount:
        logger.info("Pruned %d old SMS-OTP challenge rows", result.rowcount)
    return result.rowcount


async def cleanup_debug_outbox(db: AsyncSession, retain_hours: int = 24) -> int:
    """Same retention as challenges — only relevant in dev/test where
    the FakeSmsProvider writes here."""
    cutoff = utcnow() - datetime.timedelta(hours=retain_hours)
    from sqlalchemy import delete
    from gatekeeper.models import DebugSmsOutbox
    result = await db.execute(
        delete(DebugSmsOutbox).where(DebugSmsOutbox.sent_at < cutoff)
    )
    await db.commit()
    return result.rowcount
