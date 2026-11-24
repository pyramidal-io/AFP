"""Canonical serialization and content-addressing helpers.

AFP atoms and KEL events are content-addressed: an identifier or digest is the
hash of the *canonical* serialization of the structure. This module fixes that
serialization once so every module (KEL digests, session-atom content hashes,
commitment outcome roots, envelope binding) agrees byte-for-byte.

Canonical JSON here means: UTF-8, keys sorted, no insignificant whitespace,
``ensure_ascii=False``. Digests are SHA-256 (the AFP reference digest; the spec
names Poseidon2 for the in-circuit ``outcome_root`` — that is a ZKA/ZKC concern
and is left as a documented seam, see ``commitment.outcome_root``).

That serialization is not RFC 8785 for every value (Python spells an integral
float ``1.0`` where JCS spells ``1``). Records whose signed bytes the
specification pins to RFC 8785, including §4.4.2 KEL event content and the
§12.2.1 stable session content, use
:func:`jcs_bytes` instead.
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import json
import math
import re
from typing import Any

__all__ = [
    "canonical_bytes",
    "canonical_json",
    "digest",
    "digest_hex",
    "jcs_bytes",
    "jcs_digest",
    "qb64",
    "qb64_payload",
]

# RFC 8785 serializes numbers as ECMAScript doubles. Integers in this range are
# exact there, so their JCS form is their plain decimal spelling.
_JCS_MAX_SAFE_INTEGER = 2**53 - 1


def canonical_json(value: Any) -> str:
    """Return the canonical JSON string for ``value`` (sorted keys, compact)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes for ``value``."""
    return canonical_json(value).encode("utf-8")


def digest(value: Any) -> bytes:
    """SHA-256 over the canonical serialization of ``value``."""
    return hashlib.sha256(canonical_bytes(value)).digest()


def digest_hex(value: Any) -> str:
    """Hex SHA-256 over the canonical serialization of ``value``."""
    return digest(value).hex()


def _jcs_utf16_key(key: str) -> bytes:
    # RFC 8785 §3.2.3 orders members by their UTF-16 code units.
    return key.encode("utf-16-be")


def _jcs_float(value: float) -> str:
    """RFC 8785 §3.2.2.3: ECMAScript Number.prototype.toString of a double."""
    if not math.isfinite(value):
        raise ValueError("JCS numbers must be finite")
    if value == 0:
        return "0"
    # repr() is the shortest round-trip decimal, as ECMAScript requires.
    # The value is digits * 10**(n - k) with k significant digits.
    _sign, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    raw = "".join(map(str, digit_tuple))
    digits = raw.rstrip("0")
    k = len(digits)
    n = k + exponent + (len(raw) - k)
    prefix = "-" if value < 0 else ""
    if k <= n <= 21:
        return prefix + digits + "0" * (n - k)
    if 0 < n <= 21:
        return prefix + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return prefix + "0." + "0" * -n + digits
    mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{prefix}{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"


def _jcs_text(value: Any, floats: bool = False) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -_JCS_MAX_SAFE_INTEGER <= value <= _JCS_MAX_SAFE_INTEGER:
            raise ValueError("JCS integer is outside the exact IEEE-754 range")
        return str(value)
    if isinstance(value, str):
        # json.dumps escapes exactly '"', '\\' and U+0000..U+001F, using the
        # short forms and lowercase \\u00xx that RFC 8785 §3.2.2.2 requires.
        value.encode("utf-8")  # rejects lone surrogates
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, float) and floats:
        return _jcs_float(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_text(item, floats) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JCS object member names must be strings")
        members = sorted(value.items(), key=lambda item: _jcs_utf16_key(item[0]))
        return "{" + ",".join(
            f"{_jcs_text(key)}:{_jcs_text(item, floats)}" for key, item in members
        ) + "}"
    # Floats are refused unless the caller opts in, which keeps a Python float
    # spelling from ever entering a JCS preimage by accident.
    raise TypeError(f"value of type {type(value).__name__} has no AFP JCS form")


def jcs_bytes(value: Any, *, floats: bool = False) -> bytes:
    """Return the RFC 8785 JCS UTF-8 bytes of ``value``.

    Supports null, booleans, exact-range integers, strings, arrays and objects
    with string member names. A float is rejected unless ``floats`` is true;
    then a finite float uses the RFC 8785 ECMAScript number form.
    """
    return _jcs_text(value, floats).encode("utf-8")


def jcs_digest(value: Any, *, floats: bool = False) -> bytes:
    """SHA-256 over the RFC 8785 JCS bytes of ``value``."""
    return hashlib.sha256(jcs_bytes(value, floats=floats)).digest()


def qb64(prefix: str, raw: bytes) -> str:
    """Format raw key/digest material as an AFP qualified value (§4.4.2).

    A qualified value is a one-letter derivation code, an underscore, and the
    lowercase hex of the raw bytes: ``E_`` for an AID, ``D_`` for a SHA-256
    digest, ``K_`` for an Ed25519 public key. This is AFP's normative KEL
    encoding, not KERI's CESR/qb64 despite the function's name.
    """
    return f"{prefix}_{raw.hex()}"


_QB64_VALUE_RE = re.compile(r"[A-Za-z0-9]+_(?:[0-9a-f]{2})+\Z")


def qb64_payload(value: str) -> bytes:
    """Return the raw payload bytes a qb64 ``<code>_<hex>`` value encodes.

    The derivation code is preserved by ``qb64`` for self-description but is
    not part of the payload; extraction is deliberately code-agnostic so
    callers that consume digest material (e.g. the §15.4 field mapping) work
    for any derivation code.  Only the canonical form ``qb64`` emits is
    accepted — lowercase compact hex, no whitespace; a non-canonical value is
    rejected, never silently normalized.
    """
    if not isinstance(value, str) or not _QB64_VALUE_RE.fullmatch(value):
        raise ValueError("qb64 value must be '<code>_<lowercase-hex>'")
    return bytes.fromhex(value.partition("_")[2])
