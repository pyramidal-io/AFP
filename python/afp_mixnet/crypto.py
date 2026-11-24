"""Clean-room, stdlib-only crypto primitives for the AFP Sphinx mixnet (§8.4).

Sphinx needs a Diffie-Hellman group (for the per-hop shared secrets that make
layered onion encryption work), a key-derivation function, a deterministic
stream cipher (to encrypt the header routing-info and the payload), and a MAC
(the per-hop integrity tag that is also the replay tag). This module supplies all
four with the Python standard library only — no third-party ``cryptography``
dependency — matching the stdlib-only discipline of ``afp_session.ed25519`` and
the sibling ZKC reference packages.

What is real here:

  * **X25519** (RFC 7748, Curve25519 Montgomery ladder) — the DH group. Real
    scalar multiplication, real clamping, real shared secrets. A sender and a mix
    node derive the *same* shared secret without the sender revealing its long-
    term key, which is exactly what onion routing requires.
  * **HKDF-SHA256** (RFC 5869) — derives the per-hop sub-keys (header MAC key,
    header stream key, payload key, and the blinding factor) from the DH secret.
  * **A SHA-256-CTR stream cipher** — a clean-room keystream (counter-mode over
    SHA-256) for header/payload encryption. The standard library ships no AES, so
    rather than depend on one we build a keystream from a keyed hash. It is a real
    cipher (XOR with a pseudorandom, key-and-position-dependent keystream); it is
    *reference* strength, documented as such, and a production deployment swaps in
    the audited AES-CTR / ChaCha20 the Loopix/Sphinx literature uses. The Sphinx
    *construction* (layering, blinding, unlinkability, replay tags) is what this
    package proves, and that construction is cipher-agnostic.
  * **HMAC-SHA256** — the per-hop integrity MAC, truncated to the Sphinx tag size.

This is deliberately small and auditable. Nothing here invents a novel scheme;
each piece is a textbook standard implemented over stdlib ``hashlib`` / ``hmac``.
"""

from __future__ import annotations

import hashlib
import hmac
import os

__all__ = [
    "GROUP_ELEMENT_SIZE",
    "MAC_SIZE",
    "x25519_base_point",
    "x25519",
    "x25519_keypair",
    "hkdf",
    "stream_xor",
    "mac",
    "random_scalar",
]

GROUP_ELEMENT_SIZE = 32  # a Curve25519 u-coordinate / public key
MAC_SIZE = 16  # truncated HMAC-SHA256 — the Sphinx per-hop tag size

# Curve25519 field prime and curve constant (RFC 7748).
_P = 2**255 - 19
_A24 = 121665  # (486662 - 2) // 4
_NINE = (9).to_bytes(32, "little")


def _decode_u(data: bytes) -> int:
    # RFC 7748 decodeUCoordinate: mask the high bit of the last byte.
    u = bytearray(data[:32])
    u[31] &= 0x7F
    return int.from_bytes(u, "little") % _P


def _encode_u(u: int) -> bytes:
    return (u % _P).to_bytes(32, "little")


def _decode_scalar(data: bytes) -> int:
    # RFC 7748 X25519 clamping.
    k = bytearray(data[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _montgomery_ladder(k: int, u: int) -> int:
    """Constant-structure Montgomery ladder (RFC 7748). Real X25519 scalarmult."""
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + (_A24 * e) % _P) % _P)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P)) % _P


def x25519(scalar: bytes, u_point: bytes) -> bytes:
    """RFC 7748 X25519: scalar * u-point on Curve25519, returning a 32-byte u."""
    if len(scalar) != 32 or len(u_point) != 32:
        raise ValueError("X25519 scalar and point must each be 32 bytes")
    k = _decode_scalar(scalar)
    u = _decode_u(u_point)
    return _encode_u(_montgomery_ladder(k, u))


def x25519_base_point(scalar: bytes) -> bytes:
    """Public key for ``scalar``: X25519(scalar, 9) (RFC 7748 base point)."""
    return x25519(scalar, _NINE)


# Curve25519 prime-order subgroup order (RFC 7748 §5).
_L = 2**252 + 27742317777372353535851937790883648493


def x25519_raw(scalar_int: int, u_point: bytes) -> bytes:
    """Scalar mult by an *integer* scalar mod ``L``, **without** RFC 7748 clamping.

    The Sphinx blinding chain needs ``(g^x)^(b0*b1*...)`` to equal
    ``pub^(x*b0*b1*...)``, i.e. true multiplicative scalars. RFC 7748 clamping
    breaks that homomorphism (it mangles scalar bits), so the blinding factors and
    the sender's secret chain must be computed *unclamped* and identically on both
    sides. This is exactly how Sphinx-over-Curve25519 deployments (Nym/Loopix) run
    the blinding group: the long-term DH keys use ``x25519`` (clamped, RFC 7748),
    while the blinding exponentiation uses raw scalar mult in the prime-order
    subgroup. Multiplying into the cofactor-cleared subgroup keeps results in the
    safe subgroup.
    """
    if len(u_point) != 32:
        raise ValueError("X25519 point must be 32 bytes")
    u = _decode_u(u_point)
    return _encode_u(_montgomery_ladder(scalar_int % _L, u))


def scalar_from_bytes(raw: bytes) -> int:
    """Interpret 32 bytes as an unclamped scalar mod ``L`` (for the blind chain)."""
    return int.from_bytes(raw, "little") % _L


def x25519_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(private_scalar, public_point)``. ``seed`` allows deterministic tests."""
    priv = seed if seed is not None else os.urandom(32)
    if len(priv) != 32:
        raise ValueError("private scalar must be 32 bytes")
    return priv, x25519_base_point(priv)


def random_scalar() -> bytes:
    """A fresh 32-byte private scalar from the OS CSPRNG."""
    return os.urandom(32)


def hkdf(ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869): extract-then-expand to ``length`` bytes."""
    if salt == b"":
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _keystream(key: bytes, length: int) -> bytes:
    """SHA-256 counter-mode keystream of ``length`` bytes (clean-room stream cipher).

    Block i = SHA-256(key || i_be64). Real XOR keystream; reference-strength, see
    module docstring. Deterministic in (key, length) so encrypt and decrypt agree.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def stream_xor(key: bytes, data: bytes) -> bytes:
    """XOR ``data`` with the SHA-256-CTR keystream under ``key`` (encrypt == decrypt)."""
    ks = _keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def mac(key: bytes, data: bytes) -> bytes:
    """The Sphinx per-hop MAC: HMAC-SHA256 truncated to :data:`MAC_SIZE` bytes."""
    return hmac.new(key, data, hashlib.sha256).digest()[:MAC_SIZE]
