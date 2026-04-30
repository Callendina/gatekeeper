"""Pure helpers for SMS-OTP code generation and HMAC derivation.

Codes are 6-digit strings, generated via secrets.randbelow and zero-padded
once at the boundary. They are never compared as ints (000123 == 123 is
true as ints, which would silently invalidate a real code if the user
submitted "123" against a stored "000123").

Storage form is HMAC-SHA256 with the server.secret_key as pepper. The
domain-separation tag and challenge-id binding ensure the same plaintext
code in two different challenges produce different HMACs.
"""
import hmac
import hashlib
import secrets


_DOMAIN_TAG = "smsotp-v1"


def generate_code() -> str:
    """Return a fresh 6-digit code as a string. CSPRNG-backed."""
    n = secrets.randbelow(1_000_000)
    return f"{n:06d}"


def derive_code_hmac(secret_key: str, challenge_id: str, code: str) -> str:
    """HMAC-SHA256 of the zero-padded code, bound to challenge_id and tagged.

    Hex digest (64 chars) so it fits cleanly in a VARCHAR(64) column.
    """
    msg = f"{_DOMAIN_TAG}|{challenge_id}|{code}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def derive_target_hmac(secret_key: str, e164: str) -> str:
    """HMAC of the destination E.164 number. Used so DB compromise alone
    doesn't reveal which numbers were targeted by which challenges."""
    msg = f"{_DOMAIN_TAG}|target|{e164}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def code_matches(secret_key: str, challenge_id: str, stored_hmac: str, submitted: str) -> bool:
    """Constant-time compare of submitted code against stored HMAC. Strips
    spaces from submitted; rejects anything that isn't 6 digits."""
    cleaned = (submitted or "").strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != 6:
        return False
    candidate = derive_code_hmac(secret_key, challenge_id, cleaned)
    return hmac.compare_digest(candidate, stored_hmac)
