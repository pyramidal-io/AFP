"""Pure-Python Ed25519 (RFC 8032) signing and strict verification.

Standard library only — no third-party cryptography dependency, matching the
ZKC reference packages' stdlib-only discipline (see ``zkc_crypto.ecdsa_secp256k1``,
which is the analogous pure-Python secp256k1 reference). This is reference /
conformance tooling: it produces and verifies *real* Ed25519 signatures so the
AFP §12 session-core acceptance test exchanges a genuinely signature-verified
envelope, not a mock.

All AFP runtime consumers use :func:`verify_strict` as their verification
boundary. A production deployment may replace the arithmetic with an audited
backend only if the adapter preserves this module's exact acceptance semantics
and passes :func:`validate_verifier_backend`: canonical encodings, prime-order
membership for both ``A`` and ``R``, rejection of identity/torsion/mixed-order
points, and ``S < L``. Merely accepting the same wire sizes is not conformant.

Ed25519 is AFP's session-atom and commitment signature scheme (§12.2.1
``AfpPartyRef.signature``, §12.6.1 ``AfpCommitSignature.signature`` — "Ed25519,
KEL-anchored"). Keys here are the *signing* keys an entity's KEL pins; the KERI
AID/KEL layer (``afp_session.keri``) anchors them.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache

__all__ = [
    "SEED_SIZE",
    "PUBLIC_KEY_SIZE",
    "SIGNATURE_SIZE",
    "STRICT_VERIFICATION_CASES",
    "StrictVerificationCase",
    "generate_seed",
    "public_key_from_seed",
    "sign",
    "validate_verifier_backend",
    "validate_public_key",
    "verify",
    "verify_strict",
]

SEED_SIZE = 32
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64

# Curve / group constants (RFC 8032, edwards25519).
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
# Base point B.
_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = None  # computed below


def _h(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx % _P, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BX = _x_recover(_BY)
_B = (_BX % _P, _BY % _P)
_IDENTITY = (0, 1)


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    d_term = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d_term) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d_term) % _P
    return (x3, y3)


def _scalarmult(p, e: int):
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encode_point(p) -> bytes:
    x, y = p
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _decode_int(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _is_canonical_scalar(s: bytes) -> bool:
    return len(s) == 32 and _decode_int(s) < _L


def _decode_point(s: bytes):
    if len(s) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"encoded point must be {PUBLIC_KEY_SIZE} bytes, got {len(s)}"
        )
    y = _decode_int(s) & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("encoded point has a non-canonical y-coordinate")
    x = _x_recover(y)
    x_sign = (s[31] >> 7) & 1
    if x == 0 and x_sign:
        raise ValueError("encoded point uses a non-canonical sign for x=0")
    if x & 1 != x_sign:
        x = _P - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("decoded point is not on the edwards25519 curve")
    # Ed25519's cofactor is 8.  The identity and every non-identity torsion
    # point are therefore exactly the curve points annihilated by [8].
    if _scalarmult(point, 8) == _IDENTITY:
        raise ValueError("decoded point has small order")
    return point


def _decode_prime_order_point(s: bytes):
    """Decode ``s`` and require membership in the prime-order subgroup."""
    point = _decode_point(s)
    if _scalarmult(point, _L) != _IDENTITY:
        raise ValueError("decoded point is not in the prime-order subgroup")
    return point


@lru_cache(maxsize=256)
def _decode_public_key(public_key: bytes):
    """Decode one validated public key, caching the expensive subgroup check."""
    return _decode_prime_order_point(public_key)


def validate_public_key(public_key: bytes) -> None:
    """Require a canonical, non-small-order, prime-order Ed25519 public key.

    Unlike :func:`verify_strict`, this ingestion-boundary helper raises ``ValueError``
    for malformed material so callers can translate the failure into their
    protocol-specific error. Successful decoded points are cached with a
    bounded LRU because ingestion and signature verification commonly inspect
    the same public key and the ``[L]P`` subgroup check is intentionally costly.
    """
    if type(public_key) is not bytes:
        raise ValueError("public key must be bytes")
    _decode_public_key(public_key)


def _is_on_curve(p) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _secret_scalar(seed: bytes):
    h = _h(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h


def generate_seed() -> bytes:
    """Return a fresh 32-byte Ed25519 seed from the OS CSPRNG."""
    return os.urandom(SEED_SIZE)


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key for ``seed``."""
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    a, _ = _secret_scalar(seed)
    return _encode_point(_scalarmult(_B, a))


def sign(message: bytes, seed: bytes) -> bytes:
    """Return the 64-byte Ed25519 signature of ``message`` under ``seed``."""
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    a, h = _secret_scalar(seed)
    public = _encode_point(_scalarmult(_B, a))
    r = _decode_int(_h(h[32:] + message)) % _L
    big_r = _scalarmult(_B, r)
    enc_r = _encode_point(big_r)
    k = _decode_int(_h(enc_r + public + message)) % _L
    s = (r + k * a) % _L
    return enc_r + s.to_bytes(32, "little")


def verify_strict(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify under AFP's strict Ed25519 acceptance profile.

    ``message``, ``signature``, and ``public_key`` must be exact ``bytes``
    values. Both encoded points ``A`` and ``R`` must be canonical members of
    the prime-order subgroup (therefore never identity, torsion, or mixed
    order), and the signature scalar must satisfy ``S < L``. The function
    returns ``False`` rather than raising for every malformed input, so protocol
    callers can treat it as a total predicate.
    """
    try:
        if (
            type(message) is not bytes
            or type(signature) is not bytes
            or type(public_key) is not bytes
            or len(signature) != SIGNATURE_SIZE
            or len(public_key) != PUBLIC_KEY_SIZE
        ):
            return False
        enc_r = signature[:32]
        enc_s = signature[32:]
        if not _is_canonical_scalar(enc_s):
            return False
        s = _decode_int(enc_s)
        big_r = _decode_prime_order_point(enc_r)
        big_a = _decode_public_key(public_key)
        k = _decode_int(_h(enc_r + public_key + message)) % _L
        left = _scalarmult(_B, s)
        right = _edwards_add(big_r, _scalarmult(big_a, k))
        return left == right
    except (TypeError, ValueError, IndexError):
        return False


# ``verify`` remains a source-compatible name for callers outside this
# repository, but it is deliberately the same function object: there is no
# weaker reference path for a consumer to select accidentally.
verify = verify_strict


@dataclass(frozen=True)
class StrictVerificationCase:
    """One immutable vector in the audited-backend acceptance contract."""

    name: str
    message: bytes
    signature: bytes
    public_key: bytes
    expected: bool


_RFC8032_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
_RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
    "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
_RFC8032_NONEMPTY_MESSAGE = bytes.fromhex("72")
_RFC8032_NONEMPTY_PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
_RFC8032_NONEMPTY_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)
_SHORT_KEY_PADDING_MESSAGE = b"afp-ed25519-short-key-padding"
_SHORT_KEY_PADDING_PUBLIC_KEY = bytes.fromhex(
    "6745500eda4ab1ad47d2ce855c4a9f4604f89abca2a4561cf0d9ccaacb0c0700"
)
_SHORT_KEY_PADDING_SIGNATURE = bytes.fromhex(
    "269cf83488cf0526154c7d28691690e1f207bc7e458413e182a87c761c6c720b"
    "96bd2ea7f8b51b35c2612b71732461511dda569ff249ca887fe24e266d7f0c0c"
)
_CONFORMANCE_BASE_POINT = b"\x58" + b"\x66" * 31
_CONFORMANCE_IDENTITY = b"\x01" + b"\x00" * 31
_CONFORMANCE_R_B_S_1 = _CONFORMANCE_BASE_POINT + (1).to_bytes(32, "little")
_CONFORMANCE_TORSION = (
    (bytes.fromhex("00" * 32), 14),
    (bytes.fromhex("00" * 31 + "80"), 2),
    (bytes.fromhex("01" + "00" * 31), 0),
    (bytes.fromhex("ec" + "ff" * 30 + "7f"), 4),
    (
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
        ),
        3,
    ),
    (
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"
        ),
        2,
    ),
    (
        bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
        ),
        0,
    ),
    (
        bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
        ),
        0,
    ),
)
_CONFORMANCE_TORSION_R_SIGNATURES = tuple(
    bytes.fromhex(signature)
    for signature in (
        "00" * 32 + "d24f0647cd4e542c2330a570dc3ce88ca600f39a759c0d864b9df4e172eaf207",
        "00" * 31
        + "80"
        + "3230bd059eba546368a83e5b77a45b4df13ef8c7a960e84578f71c3747d25708",
        "01"
        + "00" * 31
        + "95723d79b134808bcff7e41d17ee002e346602f767f4f6b1c9d83f7aafbf570f",
        "ec"
        + "ff" * 30
        + "7f"
        + "833f56dfc4857597d942ccafc7b5f7a22b52de7b4b2c593359ddd1038084cb0f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
        "380e12c6fa2d5f5078f4af61092a05328317ffe74bb9bce8557ebcfd2f398c02",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"
        "36fc375219bdf4ad51bbdac797d3e88051ebfdc856152a9d2a25185b3d2f8d01",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
        "44f96ec5c234e40370b8b3e65bae4449a38c405f1e8db5b5377edf824ab1560f",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
        "53680f46bba8e3dc3a8fc34df05fa0fbb9cf5565e20750be2b1d0a28b54a7e09",
    )
)


STRICT_VERIFICATION_CASES = (
    StrictVerificationCase(
        "rfc8032-valid",
        b"",
        _RFC8032_SIGNATURE,
        _RFC8032_PUBLIC_KEY,
        True,
    ),
    StrictVerificationCase(
        "rfc8032-valid-nonempty-message",
        _RFC8032_NONEMPTY_MESSAGE,
        _RFC8032_NONEMPTY_SIGNATURE,
        _RFC8032_NONEMPTY_PUBLIC_KEY,
        True,
    ),
    StrictVerificationCase(
        "tampered-message",
        b"tampered",
        _RFC8032_SIGNATURE,
        _RFC8032_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "tampered-signature",
        b"",
        bytes([_RFC8032_SIGNATURE[0] ^ 1]) + _RFC8032_SIGNATURE[1:],
        _RFC8032_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "wrong-prime-order-public-key",
        b"",
        _RFC8032_SIGNATURE,
        _RFC8032_NONEMPTY_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "malformed-signature-length",
        _RFC8032_NONEMPTY_MESSAGE,
        _RFC8032_NONEMPTY_SIGNATURE[:-1],
        _RFC8032_NONEMPTY_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "malformed-signature-overlong",
        b"",
        _RFC8032_SIGNATURE + b"\x00",
        _RFC8032_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "malformed-public-key-length",
        _SHORT_KEY_PADDING_MESSAGE,
        _SHORT_KEY_PADDING_SIGNATURE,
        _SHORT_KEY_PADDING_PUBLIC_KEY[:-1],
        False,
    ),
    StrictVerificationCase(
        "malformed-public-key-overlong",
        b"",
        _RFC8032_SIGNATURE,
        _RFC8032_PUBLIC_KEY + b"\x00",
        False,
    ),
    StrictVerificationCase(
        "identity-public-key-forgery",
        b"afp-ed25519-identity-boundary",
        _CONFORMANCE_R_B_S_1,
        _CONFORMANCE_IDENTITY,
        False,
    ),
    *(
        StrictVerificationCase(
            f"torsion-public-key-{index}",
            f"afp-ed25519-torsion-key-forgery:{index}:".encode("ascii")
            + counter.to_bytes(4, "big"),
            _CONFORMANCE_R_B_S_1,
            public_key,
            False,
        )
        for index, (public_key, counter) in enumerate(_CONFORMANCE_TORSION)
    ),
    *(
        StrictVerificationCase(
            f"torsion-r-{index}",
            f"afp-ed25519-torsion-r:{index}".encode("ascii"),
            signature,
            _RFC8032_PUBLIC_KEY,
            False,
        )
        for index, signature in enumerate(_CONFORMANCE_TORSION_R_SIGNATURES)
    ),
    StrictVerificationCase(
        "noncanonical-public-key-y-p",
        b"afp-ed25519-noncanonical-a:\x14\x00",
        _CONFORMANCE_R_B_S_1,
        b"\xed" + b"\xff" * 30 + b"\x7f",
        False,
    ),
    StrictVerificationCase(
        "noncanonical-public-key-negative-zero",
        b"afp-ed25519-negative-zero-a",
        _CONFORMANCE_R_B_S_1,
        b"\x01" + b"\x00" * 30 + b"\x80",
        False,
    ),
    StrictVerificationCase(
        "noncanonical-r-negative-zero",
        b"afp-negative-zero-r-conformance-gap",
        bytes.fromhex(
            "0100000000000000000000000000000000000000000000000000000000000080"
            "7f5e42127c9f1d8870b3c2704f8f31436a10e7eb9422b7bc7d7dde36ac2cef0a"
        ),
        _RFC8032_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "noncanonical-r-y-p-plus-one",
        b"afp-ed25519-noncanonical-r:y=p+1",
        (b"\xee" + b"\xff" * 30 + b"\x7f")
        + bytes.fromhex(
            "5cff36833def3514e2eb5c3c6419792e6585d5a8bc2bc56a886c32ba00b70903"
        ),
        _RFC8032_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "mixed-order-public-key",
        b"afp-ed25519-mixed-order-a:\x02\x00",
        bytes.fromhex(
            "ce1a32994e835c193e2bf33909f44373ae2cf94ddef0fd922035c483670637c2"
            "5f4146805d928192fd9ba6909fc0c1db061f91cefe0d08138d9be32ea6765406"
        ),
        bytes.fromhex(
            "16a567fe7d4ef5482ab4012c369bf8c5f11e8d0c2559dcda50fde59708f8aee5"
        ),
        False,
    ),
    StrictVerificationCase(
        "mixed-order-r",
        bytes.fromhex(
            "6166702d656432353531392d6d697865642d6f726465722d723a7631"
        ),
        bytes.fromhex(
            "1fe5cd66b17ca3e6c1d40cc6f60bbc8c51d306b2210f026ddfca3b7c98f9c83d"
            "69e340dbfd61f1f4b40e79cc72b8d9acdd2b23d7c640a11a4516f7b8ae08b80a"
        ),
        _RFC8032_PUBLIC_KEY,
        False,
    ),
    StrictVerificationCase(
        "mixed-order-a-and-r",
        bytes.fromhex(
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"
        ),
        bytes.fromhex(
            "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
            "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"
        ),
        bytes.fromhex(
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
        ),
        False,
    ),
    StrictVerificationCase(
        "noncanonical-s-plus-l",
        b"",
        bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b"
        ),
        _RFC8032_PUBLIC_KEY,
        False,
    ),
)


def validate_verifier_backend(verifier) -> None:
    """Require ``verifier`` to implement AFP's strict acceptance contract.

    Run this deployment/build-time conformance gate once for an audited backend
    adapter, never once per signature. A conforming adapter must return exact
    booleans, accept the RFC 8032 known-answer vectors, and reject every strict
    negative vector. Passing this finite suite is required but does not replace
    an independent audit of the backend.
    """
    if not callable(verifier):
        raise TypeError("verifier backend must be callable")
    for case in STRICT_VERIFICATION_CASES:
        try:
            result = verifier(case.message, case.signature, case.public_key)
        except Exception as exc:
            raise ValueError(
                f"verifier backend raised for strict case {case.name!r}"
            ) from exc
        if type(result) is not bool:
            raise ValueError(
                f"verifier backend returned a non-boolean for strict case "
                f"{case.name!r}"
            )
        if result is not case.expected:
            raise ValueError(
                f"verifier backend failed strict case {case.name!r}"
            )
