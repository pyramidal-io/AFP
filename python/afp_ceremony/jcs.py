"""RFC 8785 JSON Canonicalization Scheme (JCS), standard library only.

AFP §6.3.1 fixes the preimage of ``root_material_digest`` for
``root:publisher-manifest`` as "the RFC 8785 JCS bytes" of the
``afp:publisher-key-state:v1`` record, and requires that a verifier be able to
**recompute the identical digest** from key state it independently resolves out
of the signing AID's KEL. Determinism is therefore the whole point, and a
near-miss canonicalizer is a correctness bug, not a style choice.

``afp_session.canonical`` is deliberately *not* reused here. It emits
``json.dumps(sort_keys=True, ensure_ascii=False)``, which sorts object keys by
Unicode **code point**; RFC 8785 sorts by UTF-16 **code unit**. The two agree on
every key AFP currently emits and disagree above the BMP, so reusing it would
silently produce a non-RFC-8785 preimage the moment a key state carried an
astral character. §6.3.1 names RFC 8785, so this module implements RFC 8785.

Documented seam: number serialization is restricted to JSON integers that are
exactly representable as IEEE-754 doubles (|n| <= 2**53 - 1), for which ECMAScript
``Number::toString`` is plain decimal. Non-integral numbers raise
:class:`~afp_ceremony.errors.JcsError` rather than risk an inexact shortest
round-trip serialization. Every field §6.3.1 defines for the publisher key-state
record is a string, an array of strings, ``null``, or a KEL sequence number, so
the restriction does not narrow the normative surface.
"""

from __future__ import annotations

from typing import Any, List

from .errors import JcsError

__all__ = ["jcs_bytes", "jcs_string", "MAX_EXACT_INTEGER"]

# Largest integer for which IEEE-754 double arithmetic — and therefore ECMAScript
# ``Number::toString`` — is exact.
MAX_EXACT_INTEGER = 2**53 - 1

# ECMAScript ``JSON.stringify`` two-character escapes (RFC 8785 §3.2.2.2).
_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _serialize_string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogate — not valid JSON text
        raise JcsError(f"string is not encodable as UTF-8: {exc}") from exc
    out: List[str] = ['"']
    for char in value:
        code_point = ord(char)
        escape = _ESCAPES.get(code_point)
        if escape is not None:
            out.append(escape)
        elif code_point < 0x20:
            out.append("\\u%04x" % code_point)
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _serialize_number(value: int) -> str:
    if abs(value) > MAX_EXACT_INTEGER:
        raise JcsError(
            "integer outside the exactly-representable IEEE-754 range is a "
            "documented JCS seam in this reference implementation"
        )
    return str(value)


def _sort_key(name: str) -> bytes:
    """RFC 8785 §3.2.3: sort object members by UTF-16 code unit."""
    try:
        return name.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise JcsError(f"object member name is not encodable: {exc}") from exc


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, int):  # bool already handled above
        return _serialize_number(value)
    if isinstance(value, float):
        raise JcsError(
            "non-integral numbers are a documented seam; §6.3.1 defines no "
            "floating-point field in afp:publisher-key-state:v1"
        )
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        for name in value:
            if not isinstance(name, str):
                raise JcsError("object member names must be strings")
        members = [
            _serialize_string(name) + ":" + _serialize(value[name])
            for name in sorted(value, key=_sort_key)
        ]
        return "{" + ",".join(members) + "}"
    raise JcsError(f"value of type {type(value).__name__!r} is not JSON data")


def jcs_string(value: Any) -> str:
    """Return the RFC 8785 canonical JSON *text* for ``value``."""
    return _serialize(value)


def jcs_bytes(value: Any) -> bytes:
    """Return the RFC 8785 canonical JSON *bytes* (UTF-8) for ``value``."""
    return jcs_string(value).encode("utf-8")
