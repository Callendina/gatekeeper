"""SMS provider abstraction.

Phase 2 only ships the FakeSmsProvider — ClickSend lands in phase 3.
The interface intentionally keeps `send` returning enough metadata that
the caller can record cost / accepted-status / error-category in the
challenge row without re-querying the provider.
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.models import DebugSmsOutbox


# Error categories from the design's taxonomy. Mapping to action:
#   InvalidNumber       — fail visibly, do not retry, do not consume slot
#   CountryNotAllowed   — security event, generic user error, do not retry
#   InsufficientCredit  — operator alert, 5xx, do not consume challenge
#   ProviderRateLimit   — backoff + jitter, retry once, then 5xx
#   TransientUnknown    — log full response, retry once, then fail
ErrorCategory = Literal[
    "invalid_number",
    "country_not_allowed",
    "insufficient_credit",
    "provider_rate_limit",
    "transient_unknown",
]


@dataclass
class SendResult:
    accepted: bool
    provider_message_id: str | None
    cost_cents: int | None        # provider charge in cents, if known
    error_category: ErrorCategory | None
    raw_response: str | None      # opaque blob, useful for debugging
    error_message: str | None = None


@dataclass
class DeliveryStatus:
    state: Literal["pending", "delivered", "failed", "unknown"]
    failed_at: str | None = None
    error_category: ErrorCategory | None = None


class SmsProvider(ABC):
    """One concrete implementation per provider. Stateless — instances
    can be safely reused across requests."""

    name: str = "base"

    @abstractmethod
    async def send(
        self,
        *,
        to_e164: str,
        body: str,
        idempotency_key: str,
        db: AsyncSession,
    ) -> SendResult:
        """Send a single SMS. `idempotency_key` is the challenge id —
        callers ensure each challenge maps to at most one outbound send."""

    @abstractmethod
    async def lookup_status(
        self, provider_message_id: str
    ) -> DeliveryStatus:
        """Used by the reconciliation/admin UI when the webhook hasn't
        fired (or the deployment doesn't have one wired up yet)."""


class FakeSmsProvider(SmsProvider):
    """Writes the plaintext (to, code, body) to the DebugSmsOutbox table
    and stdout. Selected when `sms.provider == "fake"`. Never used in
    production — Caddy never gets in front of a fake provider since the
    config flip alone activates it.

    The "code" stored in DebugSmsOutbox is parsed back out of the body —
    callers don't pass it separately because the abstraction must work
    for ClickSend too. We pull it out of the body via a small heuristic
    (first 6-digit run) only for the dev/test convenience field; tests
    that want to be precise should generate the body themselves and grep
    for known markers.
    """

    name = "fake"

    def __init__(self):
        self._logger = logging.getLogger("gatekeeper.sms.fake")
        self._counter = 0

    async def send(
        self,
        *,
        to_e164: str,
        body: str,
        idempotency_key: str,
        db: AsyncSession,
    ) -> SendResult:
        self._counter += 1
        message_id = f"fake-{idempotency_key}-{self._counter}"
        code = _extract_code(body)
        outbox = DebugSmsOutbox(
            challenge_id=idempotency_key,
            to_e164=to_e164,
            code=code,
            body=body,
        )
        db.add(outbox)
        await db.commit()
        # Stdout line lets devs running locally see the code without
        # opening the DB. We deliberately log the *plaintext* code here
        # only because this provider is the dev/test fake.
        self._logger.warning(
            "FakeSmsProvider send → to=%s code=%s id=%s",
            to_e164, code, message_id,
        )
        return SendResult(
            accepted=True,
            provider_message_id=message_id,
            cost_cents=0,
            error_category=None,
            raw_response="fake-accepted",
        )

    async def lookup_status(self, provider_message_id: str) -> DeliveryStatus:
        # Fake provider never reports failure.
        return DeliveryStatus(state="delivered")


def _extract_code(body: str) -> str:
    """Pull the first 6-digit run out of the message body. Used only by
    FakeSmsProvider's debug outbox — never on the verify path."""
    run = ""
    for ch in body:
        if ch.isdigit():
            run += ch
            if len(run) == 6:
                return run
        else:
            run = ""
    return ""


_provider_singleton: SmsProvider | None = None


def get_provider(provider_name: str) -> SmsProvider:
    """Lazy singleton. Phase 2: only "fake" is wired. Phase 3 adds
    "clicksend" here."""
    global _provider_singleton
    if _provider_singleton is not None and _provider_singleton.name == provider_name:
        return _provider_singleton
    if provider_name == "fake":
        _provider_singleton = FakeSmsProvider()
        return _provider_singleton
    raise ValueError(
        f"Unknown sms.provider: {provider_name!r}. "
        f"Phase 2 only supports 'fake'; ClickSend lands in phase 3."
    )
