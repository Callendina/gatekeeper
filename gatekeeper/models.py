import datetime
from sqlalchemy import String, Integer, Boolean, DateTime, Text, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from gatekeeper._time import utcnow
from gatekeeper.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_system_admin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )

    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(back_populates="user")
    app_roles: Mapped[list["UserAppRole"]] = relationship(back_populates="user")
    sessions: Mapped[list["Session"]] = relationship(back_populates="user")


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)

    user: Mapped["User"] = relationship(back_populates="oauth_accounts")

    __table_args__ = (
        Index("ix_oauth_provider_uid", "provider", "provider_user_id", unique=True),
    )


class UserAppRole(Base):
    __tablename__ = "user_app_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="user")
    group: Mapped[str | None] = mapped_column(String(100), nullable=True)
    pending_invite: Mapped[bool] = mapped_column(Boolean, default=False)
    # Per-(user, app) MFA method binding. NULL = not yet picked, or
    # single-method app where the choice is implicit. One of: 'totp', 'sms_otp'.
    # Set on first MFA encounter; admin reset clears it.
    mfa_method: Mapped[str | None] = mapped_column(String(20), nullable=True)

    user: Mapped["User"] = relationship(back_populates="app_roles")

    __table_args__ = (
        Index("ix_user_app", "user_id", "app_slug", unique=True),
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    # Timestamp of the last successful MFA verification on this session.
    # Used by the step-up cadence check regardless of which method
    # (TOTP or SMS OTP) the user is bound to for the app. The column
    # name is historical — kept rather than renamed to avoid a
    # gratuitous schema migration.
    totp_verified_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User | None"] = relationship(back_populates="sessions")


class UserTOTP(Base):
    __tablename__ = "user_totp"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    # Bumped on admin reset; combined with user_id and master key to derive the secret.
    key_num: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Null = enrollment started (QR shown) but user has not yet entered a valid code.
    confirmed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    # Highest accepted TOTP counter (floor(unix_time / 30)). Rejects replay.
    last_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )


class UserPhone(Base):
    """Per-user phone number for SMS OTP. Mirrors UserTOTP shape: one row
    per user, key_num bumped on admin reset to invalidate any in-flight
    challenges and force re-confirmation of the number.

    The number is a global per-user artefact — the per-(user, app) choice
    of method (UserAppRole.mfa_method) points at this row when SMS is bound.
    """
    __tablename__ = "user_phone"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    # E.164-normalised, e.g. "+61412345678".
    e164: Mapped[str] = mapped_column(String(20), nullable=False)
    # Null = enrolment started but confirmation OTP not yet entered.
    confirmed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    # Bumped on admin reset; included in the HMAC challenge derivation so
    # bumping invalidates any in-flight pending challenge.
    key_num: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )
    last_change_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )


class SmsOtpChallenge(Base):
    """One row per issued SMS OTP challenge. Codes are never stored in
    plaintext — only HMAC-SHA256(secret_key, "smsotp-v1|" + id + "|" + code).

    Single-use is enforced by the verify path issuing
        UPDATE … SET status='consumed' WHERE id=? AND status='pending'
    and checking rowcount.
    """
    __tablename__ = "sms_otp_challenges"

    # UUID4 string. Public-ish (used in the HMAC's domain-separation), but
    # not transmitted to the user.
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    # App this challenge is bound to. Pseudo-slug "_system" for the
    # system-admin gate (admin UI, /_term/).
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    # Delivery channel. "sms" for now; reserved for future ("voice", etc).
    channel: Mapped[str] = mapped_column(String(20), nullable=False, default="sms")
    code_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    # HMAC of the destination E.164 number, plus last 4 digits in clear
    # for "code sent to ••••1234" UI without exposing the full number.
    target_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    target_last4: Mapped[str] = mapped_column(String(4), nullable=False)
    issued_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow, index=True
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    attempts_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # pending | verified | consumed | expired | invalidated
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    # Session token (Session.token) the challenge is bound to. Verification
    # rejects use from any other session.
    gk_session_token: Mapped[str] = mapped_column(String(255), nullable=False)
    # Provider message ID returned on send acceptance. Null until provider acks.
    provider_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Set when the provider webhook reports delivered.
    delivered_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_smsotp_user_status", "user_id", "status"),
        Index("ix_smsotp_session", "gk_session_token"),
    )


class WhatsAppSession(Base):
    """Persists the active conversation_id for a WhatsApp phone+app pair.

    One row per (phone_e164, app_slug). Updated in-place on each exchange
    so that multi-turn chat stays coherent across Gatekeeper restarts.
    conversation_id = NULL means no active conversation (user reset or
    first message).
    """
    __tablename__ = "whatsapp_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    phone_e164: Mapped[str] = mapped_column(String(20), nullable=False)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    # conversation_id returned by the app's chat endpoint. NULL = start fresh.
    conversation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    __table_args__ = (
        UniqueConstraint("phone_e164", "app_slug", name="uq_wa_phone_app"),
    )


class DebugSmsOutbox(Base):
    """Receives plaintext sends from FakeSmsProvider so dev/test can inspect
    codes without parsing logs. Never written to in production. Retention
    is short — pruned by the same periodic cleanup that drops expired
    challenges."""
    __tablename__ = "debug_sms_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    to_e164: Mapped[str] = mapped_column(String(20), nullable=False)
    code: Mapped[str] = mapped_column(String(6), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    sent_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow, index=True
    )


class IPBlocklist(Base):
    __tablename__ = "ip_blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=True)
    blocked_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )
    blocked_by: Mapped[str] = mapped_column(String(255), nullable=True)


class AnonymousUsage(Base):
    __tablename__ = "anonymous_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # For session-based apps: keyed by cookie token. For API-only: keyed by IP.
    tracking_key: Mapped[str] = mapped_column(String(255), nullable=False)
    tracking_type: Mapped[str] = mapped_column(String(10), nullable=False)  # "cookie" or "ip"
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    # Also record IP even for cookie-tracked entries (for cross-referencing)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    # For session-based tracking: count of new sessions in current window
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    # For API call tracking: count of calls in current window
    api_call_count: Mapped[int] = mapped_column(Integer, default=0)
    # Start of the current tracking window
    window_start: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )

    __table_args__ = (
        Index("ix_anon_key_app", "tracking_key", "app_slug", unique=True),
    )


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    # Authenticated user who owns this key (null for temp frontend keys)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    # "registered" (long-lived, user-owned) or "temp" (short-lived, frontend anonymous)
    key_type: Mapped[str] = mapped_column(String(20), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    # Optional per-key rate limit override (requests/min). 0 = use default.
    rate_limit_override: Mapped[int] = mapped_column(Integer, default=0)

    user: Mapped["User | None"] = relationship()

    __table_args__ = (
        Index("ix_apikey_user_app", "user_id", "app_slug"),
    )


class AccessLog(Base):
    __tablename__ = "access_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    user_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # allowed, blocked, rate_limited, paywall
    session_token: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    referrer: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)


class InviteCode(Base):
    __tablename__ = "invite_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    code: Mapped[str] = mapped_column(String(100), nullable=False)
    code_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "bulk" or "personal"
    created_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    role: Mapped[str | None] = mapped_column(String(50), nullable=True, default=None)
    group: Mapped[str | None] = mapped_column(String(100), nullable=True, default=None)
    expires_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )

    uses: Mapped[list["InviteUse"]] = relationship(back_populates="invite_code")

    __table_args__ = (
        Index("ix_invite_code_app_code", "app_slug", "code", unique=True),
    )


class InviteUse(Base):
    __tablename__ = "invite_uses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    invite_code_id: Mapped[int] = mapped_column(ForeignKey("invite_codes.id"), nullable=False)
    used_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    granted_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )

    invite_code: Mapped["InviteCode"] = relationship(back_populates="uses")


class InviteWaitlist(Base):
    __tablename__ = "invite_waitlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    invite_code_id: Mapped[int | None] = mapped_column(ForeignKey("invite_codes.id"), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )
    reviewed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_waitlist_app_email", "app_slug", "email", unique=True),
    )


class InviteUserLimit(Base):
    __tablename__ = "invite_user_limits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    max_invites: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        Index("ix_invite_user_limit", "user_id", "app_slug", unique=True),
    )


class MagicLink(Base):
    __tablename__ = "magic_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    has_invite: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utcnow
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
