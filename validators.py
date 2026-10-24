"""Strict, allow-list based validation and classification of IoCs.

Design notes (defensive architecture):
    * Validation is an *allow-list*: input must positively match a known-good
      pattern. Anything else is rejected, rather than trying to "clean" it.
    * ``re.fullmatch`` is used everywhere so a valid prefix followed by
      junk (``8.8.8.8; rm -rf /``) can never slip through.
    * Input length is capped *before* any regex runs, which bounds the work
      an attacker-controlled string can force (ReDoS hardening).
    * Only values that were validated are ever passed to the cache or to the
      network layer, so injection payloads never reach SQL or URLs.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum

# Longest legal FQDN is 253 chars; allow slack for defanged notation.
MAX_INPUT_LENGTH = 300
MAX_DOMAIN_LENGTH = 253

# TLDs that can never exist on the public internet; lookups would be pointless.
_RESERVED_TLDS = frozenset(
    {"local", "localhost", "internal", "lan", "home", "corp", "test",
     "example", "invalid", "arpa"}
)

# Common "defanged" notations used when sharing IoCs safely in reports.
_REFANG_TOKENS = ("[.]", "(.)", "[dot]", "(dot)")


class IoCType(str, Enum):
    """Supported Indicator of Compromise categories."""

    IPV4 = "ipv4"
    DOMAIN = "domain"
    SHA256 = "sha256"


class ValidationError(ValueError):
    """Raised when user input is not a valid, supported IoC."""


@dataclass(frozen=True)
class ValidatedIoC:
    """An IoC that has passed validation, in its canonical form."""

    value: str
    ioc_type: IoCType


# Each octet: 250-255 | 200-249 | 100-199 | 0-99 (no leading zeros, which
# some parsers interpret as octal and which enable filter-bypass tricks).
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
_IPV4_RE = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}")

# RFC 1035-style label: 1-63 chars, alphanumeric or hyphen, no leading or
# trailing hyphen. The TLD must be alphabetic (or punycode "xn--").
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
_DOMAIN_RE = re.compile(rf"(?:{_LABEL}\.)+{_TLD}")

_SHA256_RE = re.compile(r"[a-f0-9]{64}")
_OTHER_HASH_RE = re.compile(r"(?:[a-f0-9]{32}|[a-f0-9]{40})")


def refang(raw: str) -> str:
    """Convert defanged notation (``example[.]com``) back to a plain IoC."""
    for token in _REFANG_TOKENS:
        raw = raw.replace(token, ".")
    return raw


def classify_ioc(raw: str) -> ValidatedIoC:
    """Validate ``raw`` and return its canonical value and type.

    Raises:
        ValidationError: if the input is not a supported, valid IoC.
    """
    if not isinstance(raw, str):
        raise ValidationError("Input must be a string.")

    candidate = raw.strip()
    if not candidate:
        raise ValidationError("Input is empty.")
    if len(candidate) > MAX_INPUT_LENGTH:
        raise ValidationError(
            f"Input exceeds the maximum length of {MAX_INPUT_LENGTH} characters."
        )
    # Rejects control characters, unicode homoglyphs and similar tricks.
    if not candidate.isascii() or not candidate.isprintable():
        raise ValidationError("Input contains non-printable or non-ASCII characters.")

    candidate = refang(candidate).lower()

    if _IPV4_RE.fullmatch(candidate):
        return _validate_ipv4(candidate)

    if _SHA256_RE.fullmatch(candidate):
        return ValidatedIoC(candidate, IoCType.SHA256)

    if _OTHER_HASH_RE.fullmatch(candidate):
        raise ValidationError(
            "MD5/SHA-1 hashes are not supported. Provide a SHA-256 hash."
        )

    # A single trailing dot is a legal FQDN form; normalise it away.
    candidate = candidate.rstrip(".") if candidate.endswith(".") else candidate
    if len(candidate) <= MAX_DOMAIN_LENGTH and _DOMAIN_RE.fullmatch(candidate):
        tld = candidate.rsplit(".", 1)[-1]
        if tld in _RESERVED_TLDS:
            raise ValidationError(f"Reserved/non-public TLD '.{tld}' is not allowed.")
        return ValidatedIoC(candidate, IoCType.DOMAIN)

    raise ValidationError(
        "Input is not a valid IPv4 address, domain name, or SHA-256 hash."
    )


def _validate_ipv4(candidate: str) -> ValidatedIoC:
    """Reject private/reserved ranges: public TI feeds have no data on them,
    and querying them would leak internal addressing to third parties."""
    if not ipaddress.ip_address(candidate).is_global:
        raise ValidationError(
            "Private, loopback or reserved IP addresses are not queried "
            "(avoids leaking internal addressing to third-party services)."
        )
    return ValidatedIoC(candidate, IoCType.IPV4)
