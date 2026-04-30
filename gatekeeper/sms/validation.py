"""Phone-number validation backed by libphonenumber.

Rejects:
  - Anything that doesn't parse as a phone number.
  - Any number whose country prefix isn't in the allowlist.
  - Anything that isn't a mobile or fixed-line-or-mobile.
  - VoIP lines (NIST SP 800-63B treats them as not a real subscriber line).

Returns the E.164-normalised string and the last 4 plaintext digits for
"sent to ••••1234" UI without storing the rest of the number in clear.
"""
import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException, PhoneNumberType


class PhoneValidationError(Exception):
    """Base class for all enrolment-time number rejections."""

    code = "invalid"


class InvalidPhoneFormat(PhoneValidationError):
    code = "invalid_format"


class CountryNotAllowed(PhoneValidationError):
    code = "country_not_allowed"


class NotMobileLine(PhoneValidationError):
    code = "not_mobile"


class VoIPRejected(PhoneValidationError):
    code = "voip_rejected"


# Mobile / fixed-line-or-mobile are accepted. Fixed-line is rejected
# (texts to a landline get dropped silently by carriers, wasting a slot).
_ACCEPTABLE_TYPES = (
    PhoneNumberType.MOBILE,
    PhoneNumberType.FIXED_LINE_OR_MOBILE,
)


def normalize(raw: str, country_allowlist: list[str]) -> tuple[str, str]:
    """Return (e164, last4) or raise PhoneValidationError.

    `country_allowlist` is a list of E.164 prefixes like "+61". Empty
    allowlist is treated as "no countries allowed" — fail closed."""
    if not country_allowlist:
        raise CountryNotAllowed("no countries are allowed")
    try:
        # Default region "AU" lets users enter "0412345678" without the +61.
        # Multi-country deployments should require explicit + prefix instead.
        default_region = _default_region(country_allowlist)
        parsed = phonenumbers.parse(raw or "", default_region)
    except NumberParseException:
        raise InvalidPhoneFormat("could not parse number")

    if not phonenumbers.is_valid_number(parsed):
        raise InvalidPhoneFormat("number is not a valid mobile number")

    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    if not _allowed_country(e164, country_allowlist):
        raise CountryNotAllowed(f"country prefix not in allowlist: {country_allowlist}")

    line_type = phonenumbers.number_type(parsed)
    if line_type == PhoneNumberType.VOIP:
        raise VoIPRejected("VoIP numbers are not accepted")
    if line_type not in _ACCEPTABLE_TYPES:
        raise NotMobileLine("only mobile-capable lines are accepted")

    return e164, e164[-4:]


def _default_region(country_allowlist: list[str]) -> str | None:
    """If the allowlist has exactly one entry, use it as the parse default
    so users can enter local-format numbers ("0412..."). Otherwise require
    the user to supply a + prefix."""
    if len(country_allowlist) == 1:
        return phonenumbers.region_code_for_country_code(
            int(country_allowlist[0].lstrip("+"))
        )
    return None


def _allowed_country(e164: str, country_allowlist: list[str]) -> bool:
    return any(e164.startswith(prefix) for prefix in country_allowlist)
