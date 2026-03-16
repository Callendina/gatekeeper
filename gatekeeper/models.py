import datetime
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from gatekeeper.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_system_admin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
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
        DateTime, default=datetime.datetime.utcnow
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)

    user: Mapped["User | None"] = relationship(back_populates="sessions")


class IPBlocklist(Base):
    __tablename__ = "ip_blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=True)
    blocked_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    blocked_by: Mapped[str] = mapped_column(String(255), nullable=True)


class AnonymousUsage(Base):
    __tablename__ = "anonymous_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    # For session-based tracking: count of new sessions in current window
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    # For API call tracking: count of calls in current window
    api_call_count: Mapped[int] = mapped_column(Integer, default=0)
    # Start of the current tracking window
    window_start: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    __table_args__ = (
        Index("ix_anon_ip_app", "ip_address", "app_slug", unique=True),
    )


class AccessLog(Base):
    __tablename__ = "access_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    app_slug: Mapped[str] = mapped_column(String(100), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    user_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # allowed, blocked, rate_limited, paywall
