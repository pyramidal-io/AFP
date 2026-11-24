"""Sphinx packet format — layered encryption, per-hop unlinkability, replay tags.

This is a clean-room implementation of the **Sphinx** cryptographic packet format
(Danezis & Goldberg, 2009), the packet layer the AFP Federation Mixnet binds to
(§8.4: "All coordination traffic is carried as fixed-size **Sphinx** packets").
It delivers, with real cryptography (``afp_mixnet.crypto``):

  * **Layered (onion) encryption.** The sender, knowing each hop's public key,
    derives a per-hop shared secret via a *single* group element it carries in the
    header. Each hop peels exactly one layer of the header and one layer of the
    payload. (§8.4: "a mix node decrypts exactly one layer".)
  * **Per-hop unlinkability.** The single header group element is *blinded* at
    every hop by a hop-derived factor, so the element a hop forwards is
    cryptographically unlinkable to the element it received — a relay cannot link
    the packet it received to the packet it sent. This is §8.2 property 1/2 at the
    packet layer.
  * **Fixed size.** Header and payload are constant-size regardless of route
    length or message content (the routing-info string is pre-padded to a fixed
    length and re-padded at each hop). Every packet is "identical in size and
    form" (§8.4) — the precondition for cover/real indistinguishability (§8.5).
  * **Per-hop integrity MAC == replay tag.** Each hop carries an HMAC over its
    header; a hop verifies it (rejecting tampered packets) and the MAC doubles as
    the Sphinx **replay tag**: a hop that has seen a given tag within the epoch
    drops the packet (replay rejection, a §8.2 correlation-resistance aid).

Design choices vs. canonical Sphinx, made explicit:

  * Group: **X25519** (Curve25519) rather than a generic prime-order group; the
    blinding factor is the HKDF-derived scalar and blinding is scalar mult on the
    Montgomery curve. (Canonical Sphinx uses a prime-order group; Curve25519's
    cofactor is handled by clamping — adequate for this reference and standard in
    modern Sphinx variants.)
  * Stream cipher / MAC: the stdlib primitives in ``afp_mixnet.crypto`` (see that
    module's note on reference-strength clean-room ciphers).

The construction — not the cipher choice — is what carries the conformance
properties, and the construction here is real Sphinx.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import crypto

__all__ = [
    "SphinxError",
    "ReplayError",
    "IntegrityError",
    "MixNodeKeypair",
    "SphinxPacket",
    "ProcessedPacket",
    "SphinxParams",
    "DEFAULT_PARAMS",
    "create_packet",
    "process_packet",
]


class SphinxError(Exception):
    """Base class for Sphinx packet failures (§8.4)."""


class IntegrityError(SphinxError):
    """A per-hop MAC did not verify — the header was tampered (§8.4)."""


class ReplayError(SphinxError):
    """A packet's replay tag was already seen this epoch — replayed packet (§8.4)."""


# HKDF info labels — domain-separate the per-hop sub-keys derived from the DH secret.
_INFO_BLIND = b"afp-sphinx-blind"
_INFO_MAC = b"afp-sphinx-mac"
_INFO_HEADER = b"afp-sphinx-header"
_INFO_PAYLOAD = b"afp-sphinx-payload"

# A routing command per hop is a fixed-size record: a 1-byte flag (0=forward,
# 1=final/deliver) + a fixed-size next-hop address. The address is the next mix
# node's id (forward) or the recipient handle (final). Fixed size keeps the
# header length constant (§8.4).
_FLAG_FORWARD = 0
_FLAG_FINAL = 1
_ADDR_SIZE = 32  # a fixed hop address (mix-node digest or rendezvous handle)
_PAYLOAD_LENGTH_SIZE = 4  # fixed big-endian length prefix inside the payload


@dataclass(frozen=True)
class SphinxParams:
    """Sphinx geometry.

    ``payload_size`` is the fixed on-wire payload class.  Four bytes are
    reserved for the length prefix, so :attr:`usable_payload_size` is the
    maximum application payload that fits in one packet.
    """

    max_hops: int = 3
    payload_size: int = 4096  # §8.4 payload class: 4 KiB

    @property
    def usable_payload_size(self) -> int:
        """Maximum application payload bytes in the fixed payload class."""
        return self.payload_size - _PAYLOAD_LENGTH_SIZE

    @property
    def routing_info_size(self) -> int:
        """Fixed header routing-info length: one per-hop block * max_hops.

        Each per-hop block is: flag(1) + addr(_ADDR_SIZE) + mac(MAC_SIZE). The
        whole string is constant regardless of the actual route length; unused
        capacity is filled with sender-chosen padding that is indistinguishable
        from real routing info to any relay.
        """
        per_hop = 1 + _ADDR_SIZE + crypto.MAC_SIZE
        return per_hop * self.max_hops


DEFAULT_PARAMS = SphinxParams()


_BASE_POINT = (9).to_bytes(32, "little")  # Curve25519 base point u=9 (RFC 7748)


@dataclass(frozen=True)
class MixNodeKeypair:
    """A mix node's Sphinx Curve25519 keypair (the keys it publishes in the directory).

    The Sphinx blinding chain requires true multiplicative scalars, so these keys
    use *unclamped* prime-order-subgroup scalar mult (``crypto.x25519_raw``)
    consistently on both the sender and processor sides — see
    :func:`afp_mixnet.crypto.x25519_raw`. ``private_scalar`` is stored as an int
    (mod L); ``public_point`` is ``G^private`` with the same raw convention.
    """

    private_int: int
    public_point: bytes

    @classmethod
    def generate(cls, seed: Optional[bytes] = None) -> "MixNodeKeypair":
        raw = seed if seed is not None else crypto.random_scalar()
        priv = crypto.scalar_from_bytes(raw)
        pub = crypto.x25519_raw(priv, _BASE_POINT)
        return cls(private_int=priv, public_point=pub)


@dataclass
class SphinxPacket:
    """A fixed-size Sphinx packet: (alpha, header, payload).

    ``alpha`` is the (blinded) group element a hop uses to derive the shared
    secret; ``header`` is the encrypted, fixed-length routing-info string;
    ``payload`` is the onion-encrypted, fixed-size payload. All three are
    constant-size across packets, so cover and real packets are indistinguishable
    (§8.4 / §8.5).
    """

    alpha: bytes  # 32-byte X25519 element (blinded per hop)
    header: bytes  # fixed-length encrypted routing info
    payload: bytes  # fixed-size onion payload

    def to_bytes(self) -> bytes:
        return self.alpha + self.header + self.payload

    @property
    def replay_tag(self) -> bytes:
        """The packet's replay tag at this hop: the leading per-hop MAC in the header.

        A mix node records this per epoch; a repeat is a replay (dropped, §8.4).
        Because ``alpha`` is blinded per hop and the shared secret is per hop, the
        tag is hop-specific and stable for *this* hop only — exactly what replay
        detection needs.
        """
        return self.header[: crypto.MAC_SIZE]


@dataclass
class ProcessedPacket:
    """The result of a mix node processing one Sphinx layer.

    Either a forward instruction (``next_address`` and ``next_packet`` set) or a
    final delivery (``destination_address`` and ``delivered_payload`` set).
    Routing addresses are returned as the exact fixed-width 32 bytes recovered
    from the authenticated Sphinx layer; they are never stripped or normalized.
    A relay learns only the *next* hop — never the full route (§8.2 #1).
    """

    is_final: bool
    next_address: Optional[bytes] = None
    next_packet: Optional[SphinxPacket] = None
    delivered_payload: Optional[bytes] = None
    destination_address: Optional[bytes] = None


def _derive_keys(shared_secret: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """Derive (blind_scalar, mac_key, header_key, payload_key) from the DH secret."""
    blind = crypto.hkdf(shared_secret, info=_INFO_BLIND, length=32)
    mac_key = crypto.hkdf(shared_secret, info=_INFO_MAC, length=32)
    header_key = crypto.hkdf(shared_secret, info=_INFO_HEADER, length=32)
    payload_key = crypto.hkdf(shared_secret, info=_INFO_PAYLOAD, length=32)
    return blind, mac_key, header_key, payload_key


_ORDER = 2**252 + 27742317777372353535851937790883648493  # prime-order subgroup (L)


def _compute_shared_secrets(
    session_scalar_int: int,
    hop_public_keys: List[bytes],
) -> List[bytes]:
    """Sender side: the per-hop shared secrets, over the unclamped blinding chain.

    Implements the Sphinx blinding chain: alpha_0 = G^x; the secret with hop i is
    (hop_pub_i)^(x * prod(blind_0..i-1)); after hop i the running scalar is
    multiplied by blind_i. Each hop, given the alpha it receives and its own
    private key, recomputes the *same* secret via ``alpha^priv`` — without learning
    x or any other hop's secret. All exponentiation is raw (unclamped) so the
    multiplicative homomorphism holds (see ``crypto.x25519_raw``).
    """
    secrets: List[bytes] = []
    running = session_scalar_int % _ORDER
    for pub in hop_public_keys:
        shared = crypto.x25519_raw(running, pub)
        secrets.append(shared)
        blind, _, _, _ = _derive_keys(shared)
        running = (running * crypto.scalar_from_bytes(blind)) % _ORDER
    return secrets


def _pad_address(addr: bytes) -> bytes:
    if len(addr) > _ADDR_SIZE:
        raise SphinxError(f"hop address too long ({len(addr)} > {_ADDR_SIZE})")
    return addr + b"\x00" * (_ADDR_SIZE - len(addr))


def create_packet(
    *,
    session_scalar: bytes,
    hop_public_keys: List[bytes],
    hop_addresses: List[bytes],
    destination: bytes,
    payload: bytes,
    params: SphinxParams = DEFAULT_PARAMS,
) -> SphinxPacket:
    """Build a Sphinx packet routed through ``hop_public_keys`` to ``destination``.

    ``session_scalar`` is the sender's per-packet ephemeral (32 random bytes).
    ``hop_addresses[i]`` is the address a hop uses to forward to hop ``i+1``
    (i.e. the id of the *next* mix node); the last forwarding address is unused
    and the final block carries the ``destination`` (rendezvous handle) with the
    FINAL flag. The payload is onion-encrypted from the inside out so each hop
    peels exactly one layer; cover packets use the same construction with a random
    destination so they are byte-indistinguishable.

    Raises if the route exceeds ``params.max_hops`` (OB-2 requires >= 3 hops, and
    the fixed header sizes for exactly ``max_hops``).
    """
    n = len(hop_public_keys)
    if n == 0:
        raise SphinxError("a Sphinx route needs at least one hop")
    if n > params.max_hops:
        raise SphinxError(f"route length {n} exceeds max_hops {params.max_hops}")
    if len(hop_addresses) != n:
        raise SphinxError("hop_addresses must have one entry per hop")
    if params.usable_payload_size < 0:
        raise SphinxError(
            f"Sphinx payload size must be at least {_PAYLOAD_LENGTH_SIZE} bytes"
        )
    if len(payload) > params.usable_payload_size:
        raise SphinxError(
            f"payload {len(payload)} exceeds usable Sphinx payload size "
            f"{params.usable_payload_size} (fixed class: {params.payload_size})"
        )

    x_int = crypto.scalar_from_bytes(session_scalar)
    secrets = _compute_shared_secrets(x_int, hop_public_keys)
    keyset = [_derive_keys(s) for s in secrets]

    # --- build the routing-info header from the innermost hop outward ----------
    #
    # Canonical Sphinx header construction. The routing string ``beta`` is a fixed
    # ``total``-byte buffer. At process time a hop reads its leading ``per_hop``
    # block, XORs the whole string with its header keystream ``rho``, drops the
    # leading ``per_hop`` block (left shift), and appends ``per_hop`` keystream
    # bytes (the tail of ``rho``) to restore the length. For the sender's MACs to
    # match what each hop sees, the sender precomputes the *filler* ``phi`` — the
    # trailing bytes the cumulative hop processing leaves at the end of ``beta`` —
    # and lays the innermost layer down over exactly that filler.
    per_hop = 1 + _ADDR_SIZE + crypto.MAC_SIZE
    total = params.routing_info_size

    # Each hop's header keystream ``rho`` is ``total + per_hop`` bytes: the first
    # ``total`` encrypt the routing string; the trailing ``per_hop`` is the
    # deterministic padding the hop appends after the left shift.
    rho = [crypto.stream_xor(hk, b"\x00" * (total + per_hop)) for (_, _, hk, _) in keyset]

    # Filler phi grows by ``per_hop`` per forwarding hop (hops 0..n-2). At hop i the
    # left shift exposes the tail of rho[i]; phi accumulates exactly those tails.
    phi = b""
    for i in range(n - 1):
        # phi := (phi || zeros(per_hop)) XOR rho[i][ total - i*per_hop : total + per_hop ]
        zeros = phi + b"\x00" * per_hop
        seg = rho[i][total - i * per_hop : total + per_hop]
        phi = _xor(zeros, seg)

    # Lay down beta from the innermost hop outward.
    macs: List[bytes] = []
    beta = b""
    for i in reversed(range(n)):
        _, mac_key, _, _ = keyset[i]
        if i == n - 1:
            flag = _FLAG_FINAL
            addr = _pad_address(destination)
            next_mac = b"\x00" * crypto.MAC_SIZE  # no next hop
            block = bytes([flag]) + addr + next_mac
            # Innermost beta: the final block + random fill to (total - len(phi)),
            # XOR the head of rho, then append the precomputed filler verbatim.
            fill_len = total - per_hop - len(phi)
            body = block + os.urandom(fill_len)
            beta = _xor(body, rho[i][: len(body)]) + phi
        else:
            flag = _FLAG_FORWARD
            addr = _pad_address(hop_addresses[i])  # address of hop i+1
            next_mac = macs[0]  # MAC the next hop will check
            block = bytes([flag]) + addr + next_mac
            # Prepend this hop's block, drop the tail to keep length fixed, encrypt.
            beta = _xor((block + beta)[:total], rho[i][:total])
        this_mac = crypto.mac(mac_key, beta)
        macs.insert(0, this_mac)

    # The outermost MAC leads the header (the first hop checks it; it is the
    # packet's replay tag at the first hop).
    header = macs[0] + beta

    # --- onion-encrypt the payload from the innermost hop outward --------------
    # Prefix the exact application length so a payload ending in zero bytes is
    # not confused with padding.  Fill the remainder randomly: fixed-size cover
    # and real packets must not share a predictable padding pattern.
    body = (
        len(payload).to_bytes(_PAYLOAD_LENGTH_SIZE, "big")
        + payload
        + os.urandom(params.usable_payload_size - len(payload))
    )
    for i in reversed(range(n)):
        _, _, _, payload_key = keyset[i]
        body = crypto.stream_xor(payload_key, body)

    alpha = crypto.x25519_raw(x_int, _BASE_POINT)
    return SphinxPacket(alpha=alpha, header=header, payload=body)


def process_packet(
    packet: SphinxPacket,
    node_keypair: MixNodeKeypair,
    *,
    seen_tags: Optional[set] = None,
    params: SphinxParams = DEFAULT_PARAMS,
) -> ProcessedPacket:
    """A mix node peels one Sphinx layer (§8.4). Verifies MAC, rejects replays.

    Returns a :class:`ProcessedPacket`: a forward instruction with the *blinded*
    next packet (so the next hop's element is unlinkable to this one), or a final
    delivery. ``seen_tags`` is this node's per-epoch replay set; pass the node's
    own set so a repeated tag raises :class:`ReplayError`.

    Raises :class:`IntegrityError` on a bad MAC (tampered header) — the same
    single protocol consequence the spec gives identity failures: drop the packet.
    """
    if len(packet.payload) != params.payload_size:
        raise IntegrityError(
            f"malformed Sphinx payload length {len(packet.payload)} "
            f"(expected {params.payload_size})"
        )

    per_hop = 1 + _ADDR_SIZE + crypto.MAC_SIZE
    total = params.routing_info_size

    shared = crypto.x25519_raw(node_keypair.private_int, packet.alpha)
    blind, mac_key, header_key, payload_key = _derive_keys(shared)

    incoming_mac = packet.header[: crypto.MAC_SIZE]
    beta = packet.header[crypto.MAC_SIZE :]
    if len(beta) != total:
        raise IntegrityError("malformed Sphinx header length")

    # Verify the per-hop MAC (integrity + replay tag).
    expected_mac = crypto.mac(mac_key, beta)
    if not _ct_eq(expected_mac, incoming_mac):
        raise IntegrityError("Sphinx per-hop MAC failed (tampered header)")

    if seen_tags is not None:
        if incoming_mac in seen_tags:
            raise ReplayError("Sphinx replay tag already seen this epoch")
        seen_tags.add(incoming_mac)

    # Decrypt the routing string with the extended keystream rho; the leading
    # per_hop is this hop's command block, the remainder shifts left, and the
    # keystream tail supplies the deterministic re-padding (matching the filler).
    rho = crypto.stream_xor(header_key, b"\x00" * (total + per_hop))
    decrypted = _xor(beta + b"\x00" * per_hop, rho)
    flag = decrypted[0]
    addr = decrypted[1 : 1 + _ADDR_SIZE]
    next_mac = decrypted[1 + _ADDR_SIZE : per_hop]
    next_beta = decrypted[per_hop:]  # length total again (shift + appended tail)

    # Peel one payload layer.
    body = crypto.stream_xor(payload_key, packet.payload)

    if flag == _FLAG_FINAL:
        payload_length = int.from_bytes(body[:_PAYLOAD_LENGTH_SIZE], "big")
        if payload_length > params.usable_payload_size:
            raise IntegrityError("Sphinx payload length prefix is invalid")
        delivered = body[_PAYLOAD_LENGTH_SIZE : _PAYLOAD_LENGTH_SIZE + payload_length]
        return ProcessedPacket(
            is_final=True,
            delivered_payload=delivered,
            destination_address=addr,
        )

    if flag != _FLAG_FORWARD:
        raise IntegrityError(f"unknown Sphinx routing flag {flag}")

    # Blind alpha so the next hop's element is unlinkable to this one (raw mult so
    # the multiplicative homomorphism with the sender's secret chain holds).
    next_header = next_mac + next_beta
    next_alpha = crypto.x25519_raw(crypto.scalar_from_bytes(blind), packet.alpha)
    next_packet = SphinxPacket(alpha=next_alpha, header=next_header, payload=body)
    return ProcessedPacket(
        is_final=False,
        next_address=addr,
        next_packet=next_packet,
    )


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(a) != len(b):
        raise SphinxError(f"xor length mismatch {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def _ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time-ish equality for MAC comparison."""
    import hmac as _hmac

    return _hmac.compare_digest(a, b)
