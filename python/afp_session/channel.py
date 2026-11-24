"""Entity-to-entity authenticated encryption for an AFP bilateral session.

From the mutually authenticated session, the channel pins both parties'
entity-KEL ``kel_event_dig`` values for their then-current key-establishing
events and does not support in-session rekey.  If a seal, open, or evidence
validation observes that either pin changed because of an entity-KEL rotation,
it permanently closes the channel and clears its traffic-key references and
sealed-transit receipt ledger; interaction events do not change a
key-establishing pin.  The closed channel must be discarded.  Each
``ChannelEndpoint`` consumes one establishment attempt and wipes its private
scalar, so recovery requires a fresh AFP session signed under the rotated KEL
state, fresh endpoint objects for both roles, and a fresh channel.

Each endpoint's X25519 scalar is fresh CSPRNG output that is never transmitted
and never derived from the entity sub-seed ``M'``.  The KEL-current Ed25519 key
only authenticates the ephemeral public key, so a later compromise of ``M'`` or
of a KEL signing key does not recover a completed channel's traffic keys.

This module is standard-library-only.  Its private X25519 implementation
follows RFC 7748 and does not depend on the mixnet package.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import math
import secrets
import threading
import time
import weakref
from typing import Any

from . import ed25519, keri
from .atoms import (
    AfpSessionAtom,
    AfpSessionStatus,
    SESSION_KIND,
    compute_session_context,
    session_datetime_to_unix,
)
from .canonical import canonical_bytes

__all__ = [
    "ChannelError",
    "ChannelRole",
    "ChannelBinding",
    "ChannelKeyAttestation",
    "SealedTransitEvidence",
    "SealedChannelAttestation",
    "validate_sealed_channel_attestation",
    "ChannelEndpoint",
    "SessionChannel",
    "CHANNEL_KEY_KIND",
    "SEALED_FRAME_KIND",
    "SEALED_CHANNEL_ATTESTATION_KIND",
    "CHANNEL_SUITE",
    "SEALED_FRAME_OVERHEAD",
    "DEFAULT_REPLAY_WINDOW",
]


CHANNEL_KEY_KIND = "afp:channel-key:v1"
SEALED_FRAME_KIND = "afp:sealed:v1"
SEALED_CHANNEL_ATTESTATION_KIND = "afp:sealed-channel-attestation:v1"
CHANNEL_SUITE = "afp:x25519-sha256ctr-hmacsha256:v1"
SEALED_FRAME_OVERHEAD = 76
DEFAULT_REPLAY_WINDOW = 64

_FRAME_PREFIX = b"afp:sealed:v1\0"
_SUITE_ID = 1
_DIRECTION_I2R = 0
_DIRECTION_R2I = 1
_MAX_SEQUENCE = (1 << 64) - 1
_MAX_CIPHERTEXT = (1 << 32) - 1
_NONCE_LABEL = b"afp:sealed:nonce:v1\0"
_TRANSCRIPT_KIND = "afp:channel-transcript:v1"
_ATTESTATION_VALIDITY_SECONDS = 300.0
_KEY_INFO = {
    "i2r_cipher": b"afp:channel:i2r:cipher:v1",
    "i2r_mac": b"afp:channel:i2r:mac:v1",
    "i2r_nonce": b"afp:channel:i2r:nonce:v1",
    "r2i_cipher": b"afp:channel:r2i:cipher:v1",
    "r2i_mac": b"afp:channel:r2i:mac:v1",
    "r2i_nonce": b"afp:channel:r2i:nonce:v1",
}

# Curve25519 / RFC 7748 constants, kept private to afp_session.
_P = 2**255 - 19
_A24 = 121665
_BASE_POINT = (9).to_bytes(32, "little")


class ChannelError(Exception):
    """The sole public failure type for channel boundary operations."""


class ChannelRole(str, Enum):
    """A party's fixed role in the signed bilateral session."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ChannelError(f"{name} must be a non-empty string")
    return value


def _require_hex(value: object, length: int, name: str) -> str:
    if not isinstance(value, str) or len(value) != length * 2:
        raise ChannelError(f"{name} must be canonical {length}-byte lowercase hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ChannelError(
            f"{name} must be canonical {length}-byte lowercase hex"
        ) from exc
    if raw.hex() != value:
        raise ChannelError(f"{name} must be canonical {length}-byte lowercase hex")
    return value


def _key_establishing_digest(kel: Any) -> str:
    try:
        return keri.current_key_event_digest(kel)
    except (keri.KeriError, AttributeError, TypeError, ValueError) as exc:
        raise ChannelError("KEL key state is malformed") from exc


def _require_finite_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ChannelError(f"{name} must be a finite number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ChannelError(f"{name} must be a finite number") from exc
    if not math.isfinite(number):
        raise ChannelError(f"{name} must be a finite number")
    return number


@dataclass(frozen=True)
class SealedTransitEvidence:
    """Immutable facts from one successfully authenticated sealed-frame receive."""

    frame_kind: str
    frame_digest: str
    frame_size: int
    direction: int
    sequence: int
    message_class: str
    authenticated_at: float

    def __post_init__(self) -> None:
        if self.frame_kind != SEALED_FRAME_KIND:
            raise ChannelError("transit evidence has an unexpected frame kind")
        _require_hex(self.frame_digest, 32, "transit frame_digest")
        if type(self.frame_size) is not int or self.frame_size < SEALED_FRAME_OVERHEAD:
            raise ChannelError("transit frame_size is invalid")
        if type(self.direction) is not int or self.direction not in (
            _DIRECTION_I2R,
            _DIRECTION_R2I,
        ):
            raise ChannelError("transit direction is invalid")
        if (
            type(self.sequence) is not int
            or self.sequence < 0
            or self.sequence > _MAX_SEQUENCE
        ):
            raise ChannelError("transit sequence is invalid")
        _require_text(self.message_class, "transit message_class")
        _require_finite_number(self.authenticated_at, "transit authenticated_at")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical evidence fields recorded by the capability."""
        return {
            "frame_kind": self.frame_kind,
            "frame_digest": self.frame_digest,
            "frame_size": self.frame_size,
            "direction": self.direction,
            "sequence": self.sequence,
            "message_class": self.message_class,
            "authenticated_at": self.authenticated_at,
        }


@dataclass(frozen=True)
class _SealedChannelReceipt:
    """Authority-side immutable facts for one authenticated channel receive."""

    receipt_id: str
    attestation_ref: Any = field(repr=False, compare=False)
    issuer_id: str
    session_id: str
    session_content_hash: str
    session_context: str
    kel_event_dig: str
    suite: str
    suite_id: int
    frame_kind: str
    frame_digest: str
    frame_size: int
    direction: int
    sequence: int
    message_class: str
    authenticated_at: float
    authenticated_monotonic: float
    expires_at: float
    expires_monotonic: float


@dataclass(
    frozen=True,
    init=False,
    eq=False,
    repr=False,
)
class SealedChannelAttestation:
    """Opaque process-local capability for an authenticated sealed transit.

    The capability carries only an issuer and an identity-bound receipt handle;
    authoritative facts remain in the receiving channel's private receipt ledger.
    Public properties return immutable values copied from that ledger. This keeps
    construction, copied fields, and mutation from manufacturing evidence.

    Like all in-process Python authority, this assumes callers do not use
    reflection or native memory access to mutate private channel state. Hostile
    extensions need a separate process as their security boundary.
    """

    _issuer: Any = field(repr=False)
    _receipt_id: str = field(repr=False)

    def __new__(cls):
        raise TypeError(
            "SealedChannelAttestation is minted only by an authenticated "
            "channel receive"
        )

    def _receipt(self) -> _SealedChannelReceipt:
        try:
            issuer = object.__getattribute__(self, "_issuer")
        except AttributeError as exc:
            raise ChannelError("sealed-channel attestation is not registered") from exc
        if type(issuer) is not SessionChannel:
            raise ChannelError("sealed-channel attestation issuer is invalid")
        return issuer._sealed_channel_receipt(self)

    @property
    def kind(self) -> str:
        self._receipt()
        return SEALED_CHANNEL_ATTESTATION_KIND

    @property
    def session_id(self) -> str:
        return self._receipt().session_id

    @property
    def session_content_hash(self) -> str:
        return self._receipt().session_content_hash

    @property
    def session_context(self) -> str:
        return self._receipt().session_context

    @property
    def kel_event_dig(self) -> str:
        return self._receipt().kel_event_dig

    @property
    def suite(self) -> str:
        return self._receipt().suite

    @property
    def suite_id(self) -> int:
        return self._receipt().suite_id

    @property
    def transit_evidence(self) -> SealedTransitEvidence:
        receipt = self._receipt()
        return SealedTransitEvidence(
            frame_kind=receipt.frame_kind,
            frame_digest=receipt.frame_digest,
            frame_size=receipt.frame_size,
            direction=receipt.direction,
            sequence=receipt.sequence,
            message_class=receipt.message_class,
            authenticated_at=receipt.authenticated_at,
        )

    @property
    def expires_at(self) -> float:
        return self._receipt().expires_at

    def __reduce__(self) -> object:
        raise TypeError("SealedChannelAttestation is process-local authority")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("SealedChannelAttestation is process-local authority")


def validate_sealed_channel_attestation(
    attestation: object,
    *,
    session_context: object,
    kel_event_dig: object,
) -> bool:
    """Revalidate an exact, registered capability against live channel state."""
    try:
        if type(attestation) is not SealedChannelAttestation:
            return False
        if not isinstance(session_context, str) or not session_context:
            return False
        if not isinstance(kel_event_dig, str) or not kel_event_dig:
            return False
        issuer = object.__getattribute__(attestation, "_issuer")
        if type(issuer) is not SessionChannel:
            return False
        return issuer._revalidate_sealed_channel_attestation(
            attestation,
            session_context=session_context,
            kel_event_dig=kel_event_dig,
            now=time.time(),
            monotonic_now=time.monotonic(),
        )
    except (
        AttributeError,
        ChannelError,
        KeyError,
        OverflowError,
        ReferenceError,
        TypeError,
        ValueError,
    ):
        return False


_BINDING_MINT_TOKEN = object()


@dataclass(frozen=True)
class ChannelBinding:
    """Immutable projection of the exact signed AFP session and party pins."""

    session_id: str
    session_content_hash: str
    context: str
    profile: str
    initiator_tenant_aid: str
    initiator_entity_aid: str
    initiator_kel_event_dig: str
    responder_tenant_aid: str
    responder_entity_aid: str
    responder_kel_event_dig: str
    _session_wire: bytes = field(repr=False, compare=True)
    _mint_token: InitVar[object | None] = None

    def __post_init__(self, _mint_token: object | None) -> None:
        if _mint_token is not _BINDING_MINT_TOKEN:
            raise ChannelError("ChannelBinding must be created with from_session()")

    @classmethod
    def from_session(cls, session: AfpSessionAtom) -> "ChannelBinding":
        """Validate and freeze the identity-relevant signed session snapshot."""
        try:
            if not isinstance(session, AfpSessionAtom):
                raise ChannelError("session must be an AfpSessionAtom")
            if session.kind != SESSION_KIND:
                raise ChannelError("unexpected AFP session kind")
            if session.status not in (
                AfpSessionStatus.OPEN,
                AfpSessionStatus.ACTIVE,
            ):
                raise ChannelError("channel requires an OPEN or ACTIVE session")
            if session.closed_at is not None:
                raise ChannelError("channel session must not carry closed_at")
            expected_context = compute_session_context(
                session.initiator.entity_aid,
                session.responder.entity_aid,
                session.id,
                session.opened_at,
            )
            if not hmac.compare_digest(session.session_context, expected_context):
                raise ChannelError("session context does not recompute")

            fields = {
                "session_id": session.id,
                "session_content_hash": session.content_hash,
                "context": session.session_context,
                "profile": session.profile,
                "initiator_tenant_aid": session.initiator.tenant_aid,
                "initiator_entity_aid": session.initiator.entity_aid,
                "initiator_kel_event_dig": session.initiator.kel_event_dig,
                "responder_tenant_aid": session.responder.tenant_aid,
                "responder_entity_aid": session.responder.entity_aid,
                "responder_kel_event_dig": session.responder.kel_event_dig,
            }
            for name, value in fields.items():
                _require_text(value, name)
            session_datetime_to_unix(session.expires_at, "session expires_at")
            _require_hex(session.initiator.signature, 64, "initiator signature")
            _require_hex(session.responder.signature, 64, "responder signature")
            return cls(
                **fields,
                _session_wire=canonical_bytes(session.to_dict()),
                _mint_token=_BINDING_MINT_TOKEN,
            )
        except ChannelError:
            raise
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ChannelError("invalid AFP session channel binding") from exc

    @property
    def session_context(self) -> str:
        """Compatibility spelling for the bound AFP session context."""
        return self.context

    def _party(self, role: ChannelRole) -> tuple[str, str, str]:
        if role is ChannelRole.INITIATOR:
            return (
                self.initiator_tenant_aid,
                self.initiator_entity_aid,
                self.initiator_kel_event_dig,
            )
        if role is ChannelRole.RESPONDER:
            return (
                self.responder_tenant_aid,
                self.responder_entity_aid,
                self.responder_kel_event_dig,
            )
        raise ChannelError("invalid channel role")

    def _session_dict(self) -> dict[str, Any]:
        try:
            value = json.loads(self._session_wire.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise ChannelError("bound session snapshot is malformed") from exc
        if not isinstance(value, dict):
            raise ChannelError("bound session snapshot is malformed")
        return value

    def _transcript_dict(self) -> dict[str, Any]:
        """Return only immutable, signed session bindings for key derivation.

        Session lifecycle fields such as ``status`` and ``closed_at`` are
        intentionally excluded: AFP does not include them in ``content_hash``,
        and peers can legitimately observe those local fields at different
        points while still holding the same signed bilateral session.
        """
        return {
            "session_id": self.session_id,
            "session_content_hash": self.session_content_hash,
            "context": self.context,
            "profile": self.profile,
            "initiator": {
                "tenant_aid": self.initiator_tenant_aid,
                "entity_aid": self.initiator_entity_aid,
                "kel_event_dig": self.initiator_kel_event_dig,
            },
            "responder": {
                "tenant_aid": self.responder_tenant_aid,
                "entity_aid": self.responder_entity_aid,
                "kel_event_dig": self.responder_kel_event_dig,
            },
        }


_ATTESTATION_FIELDS = frozenset(
    {
        "kind",
        "suite",
        "role",
        "session_id",
        "session_content_hash",
        "context",
        "profile",
        "tenant_aid",
        "entity_aid",
        "kel_event_dig",
        "public_key",
        "generation_salt",
        "signature",
    }
)


@dataclass(frozen=True)
class ChannelKeyAttestation:
    """KEL-current Ed25519 attestation of one ephemeral X25519 channel key.

    ``generation_salt`` is 32 independent random octets.  It keeps the v1
    record's field set byte-identical and is not an input to any key.
    """

    role: ChannelRole
    session_id: str
    session_content_hash: str
    context: str
    profile: str
    tenant_aid: str
    entity_aid: str
    kel_event_dig: str
    public_key: str
    generation_salt: str
    signature: str
    kind: str = CHANNEL_KEY_KIND
    suite: str = CHANNEL_SUITE

    def __post_init__(self) -> None:
        if not isinstance(self.role, ChannelRole):
            raise ChannelError("attestation role must be a ChannelRole")
        if self.kind != CHANNEL_KEY_KIND:
            raise ChannelError("unexpected channel-key attestation kind")
        if self.suite != CHANNEL_SUITE:
            raise ChannelError("unexpected channel suite")
        for name in (
            "session_id",
            "session_content_hash",
            "context",
            "profile",
            "tenant_aid",
            "entity_aid",
            "kel_event_dig",
        ):
            _require_text(getattr(self, name), name)
        _require_hex(self.public_key, 32, "public_key")
        _require_hex(self.generation_salt, 32, "generation_salt")
        _require_hex(self.signature, 64, "signature")

    def content_for_signature(self) -> dict[str, str]:
        """Return the exact canonical-JSON preimage map (signature excluded)."""
        return {
            "kind": self.kind,
            "suite": self.suite,
            "role": self.role.value,
            "session_id": self.session_id,
            "session_content_hash": self.session_content_hash,
            "context": self.context,
            "profile": self.profile,
            "tenant_aid": self.tenant_aid,
            "entity_aid": self.entity_aid,
            "kel_event_dig": self.kel_event_dig,
            "public_key": self.public_key,
            "generation_salt": self.generation_salt,
        }

    def signing_bytes(self) -> bytes:
        """Return canonical bytes signed by the entity's current Ed25519 key."""
        return canonical_bytes(self.content_for_signature())

    def to_dict(self) -> dict[str, str]:
        """Return the exact wire mapping, including the Ed25519 signature."""
        result = self.content_for_signature()
        result["signature"] = self.signature
        return result

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "ChannelKeyAttestation":
        """Strictly parse an exact attestation mapping; extensions are rejected."""
        try:
            if not isinstance(data, dict) or set(data) != _ATTESTATION_FIELDS:
                raise ChannelError("attestation must contain exactly the v1 fields")
            if any(not isinstance(value, str) for value in data.values()):
                raise ChannelError("attestation fields must all be strings")
            return cls(
                kind=data["kind"],
                suite=data["suite"],
                role=ChannelRole(data["role"]),
                session_id=data["session_id"],
                session_content_hash=data["session_content_hash"],
                context=data["context"],
                profile=data["profile"],
                tenant_aid=data["tenant_aid"],
                entity_aid=data["entity_aid"],
                kel_event_dig=data["kel_event_dig"],
                public_key=data["public_key"],
                generation_salt=data["generation_salt"],
                signature=data["signature"],
            )
        except ChannelError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ChannelError("malformed channel-key attestation") from exc


def _hkdf(
    ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32
) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        if counter > 255:
            raise ChannelError("HKDF output is too long")
        block = hmac.new(
            prk, block + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def _x25519(scalar: bytes, u_point: bytes) -> bytes:
    if len(scalar) != 32 or len(u_point) != 32:
        raise ChannelError("X25519 scalar and public key must be 32 bytes")
    scalar_octets = bytearray(scalar)
    scalar_octets[0] &= 248
    scalar_octets[31] &= 127
    scalar_octets[31] |= 64
    k = int.from_bytes(scalar_octets, "little")
    u = int.from_bytes(u_point, "little") & ((1 << 255) - 1)

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for bit_index in reversed(range(255)):
        bit = (k >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = ((da + cb) ** 2) % _P
        z3 = (x1 * ((da - cb) ** 2)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + _A24 * e)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


def _role_direction(role: ChannelRole) -> int:
    return _DIRECTION_I2R if role is ChannelRole.INITIATOR else _DIRECTION_R2I


def _opposite_role(role: ChannelRole) -> ChannelRole:
    return (
        ChannelRole.RESPONDER
        if role is ChannelRole.INITIATOR
        else ChannelRole.INITIATOR
    )


def _identity_tenant_aid(signing_identity: Any) -> str:
    try:
        inception = signing_identity.kel.events[0]
        if inception.ilk == "dip":
            return inception.delegator_aid
    except (AttributeError, IndexError, TypeError) as exc:
        raise ChannelError("signing identity KEL is malformed") from exc
    # Session principals are entity delegated AIDs (§12.3); a tenant root
    # cannot be one.
    raise ChannelError("signing identity is not an entity delegated AID")


def _session_party_signature(binding: ChannelBinding, role: ChannelRole) -> bytes:
    session = binding._session_dict()
    try:
        party = session[role.value]
        if not isinstance(party, dict):
            raise ChannelError("bound session party ref is malformed")
        signature = party["signature"]
        _require_hex(signature, 64, f"{role.value} session signature")
        return bytes.fromhex(signature)
    except ChannelError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ChannelError("bound session party ref is malformed") from exc


def _verify_identity_matches_binding(
    binding: ChannelBinding, role: ChannelRole, signing_identity: Any
) -> None:
    tenant_aid, entity_aid, kel_event_dig = binding._party(role)
    try:
        if signing_identity.aid != entity_aid:
            raise ChannelError("signing identity does not match the session entity")
        if _identity_tenant_aid(signing_identity) != tenant_aid:
            raise ChannelError("signing identity does not match the session tenant")
        if _key_establishing_digest(signing_identity.kel) != kel_event_dig:
            raise ChannelError("local KEL key state differs from the session pin")
        public_key = keri.resolve_current_key(signing_identity.kel)
        if not ed25519.verify_strict(
            binding.session_content_hash.encode("utf-8"),
            _session_party_signature(binding, role),
            public_key,
        ):
            raise ChannelError("local session party signature does not verify")
    except ChannelError:
        raise
    except (keri.KeriError, AttributeError, TypeError, ValueError) as exc:
        raise ChannelError("local signing identity is invalid") from exc


def _verify_remote(
    binding: ChannelBinding,
    expected_role: ChannelRole,
    attestation: ChannelKeyAttestation,
    remote: Any,
) -> None:
    tenant_aid, entity_aid, kel_event_dig = binding._party(expected_role)
    expected = {
        "role": expected_role,
        "session_id": binding.session_id,
        "session_content_hash": binding.session_content_hash,
        "context": binding.context,
        "profile": binding.profile,
        "tenant_aid": tenant_aid,
        "entity_aid": entity_aid,
        "kel_event_dig": kel_event_dig,
    }
    for name, value in expected.items():
        if getattr(attestation, name) != value:
            raise ChannelError(f"peer attestation {name} does not match the session")
    try:
        entity_kel = remote.entity_kel
        tenant_kel = remote.tenant_kel
        witness_keys = remote.witness_keys
        if not isinstance(witness_keys, dict):
            raise ChannelError("peer witness key map must be explicitly supplied")
        if entity_kel.aid != entity_aid or tenant_kel.aid != tenant_aid:
            raise ChannelError("peer KEL identities do not match the session")
        keri.verify_kel(
            entity_kel,
            tenant_kel=tenant_kel,
            witness_keys=witness_keys,
            first_seen=getattr(remote, "kel_state", None),
        )
        keri.assert_keystate_current(entity_kel, kel_event_dig)
        if _key_establishing_digest(entity_kel) != kel_event_dig:
            raise ChannelError("peer KEL key state differs from the session pin")
        public_key = keri.resolve_current_key(entity_kel)
        if not ed25519.verify_strict(
            binding.session_content_hash.encode("utf-8"),
            _session_party_signature(binding, expected_role),
            public_key,
        ):
            raise ChannelError("peer session party signature does not verify")
        if not ed25519.verify_strict(
            attestation.signing_bytes(),
            bytes.fromhex(attestation.signature),
            public_key,
        ):
            raise ChannelError("peer channel-key attestation does not verify")
    except ChannelError:
        raise
    except (keri.KeriError, AttributeError, TypeError, ValueError) as exc:
        raise ChannelError("peer identity verification failed") from exc


_ENDPOINT_MINT_TOKEN = object()


class ChannelEndpoint:
    """One-shot producer of a role-bound channel-key attestation and channel."""

    def __init__(
        self,
        binding: ChannelBinding,
        role: ChannelRole,
        signing_identity: Any,
        private_scalar: bytes,
        attestation: ChannelKeyAttestation,
        *,
        _mint_token: object = None,
    ) -> None:
        if _mint_token is not _ENDPOINT_MINT_TOKEN:
            raise ChannelError("ChannelEndpoint must be created with create()")
        self.binding = binding
        self.role = role
        self.attestation = attestation
        self._signing_identity = signing_identity
        self._private_scalar: bytearray | None = bytearray(private_scalar)
        self._establish_attempted = False
        self._lock = threading.Lock()

    @classmethod
    def create(
        cls,
        binding: ChannelBinding,
        role: ChannelRole,
        signing_identity: Any,
    ) -> "ChannelEndpoint":
        """Generate and attest a fresh role-specific ephemeral X25519 key."""
        return cls._create(
            binding,
            role,
            signing_identity,
            ephemeral_scalar=secrets.token_bytes(32),
            generation_salt=secrets.token_bytes(32),
        )

    @classmethod
    def _create(
        cls,
        binding: ChannelBinding,
        role: ChannelRole,
        signing_identity: Any,
        *,
        ephemeral_scalar: bytes,
        generation_salt: bytes,
    ) -> "ChannelEndpoint":
        """Attest a supplied scalar; callers outside the KAT use ``create``."""
        try:
            if not isinstance(binding, ChannelBinding):
                raise ChannelError("binding must be a ChannelBinding")
            if not isinstance(role, ChannelRole):
                raise ChannelError("role must be a ChannelRole")
            if type(ephemeral_scalar) is not bytes or len(ephemeral_scalar) != 32:
                raise ChannelError("ephemeral_scalar must be exactly 32 bytes")
            if type(generation_salt) is not bytes or len(generation_salt) != 32:
                raise ChannelError("generation_salt must be exactly 32 bytes")
            _verify_identity_matches_binding(binding, role, signing_identity)
            tenant_aid, entity_aid, kel_event_dig = binding._party(role)
            public_key = _x25519(ephemeral_scalar, _BASE_POINT)
            unsigned = ChannelKeyAttestation(
                role=role,
                session_id=binding.session_id,
                session_content_hash=binding.session_content_hash,
                context=binding.context,
                profile=binding.profile,
                tenant_aid=tenant_aid,
                entity_aid=entity_aid,
                kel_event_dig=kel_event_dig,
                public_key=public_key.hex(),
                generation_salt=generation_salt.hex(),
                signature="00" * 64,
            )
            signature = signing_identity.sign(unsigned.signing_bytes())
            if type(signature) is not bytes or len(signature) != 64:
                raise ChannelError("signing identity returned an invalid signature")
            attestation = ChannelKeyAttestation(
                **{
                    **unsigned.content_for_signature(),
                    "role": role,
                    "signature": signature.hex(),
                }
            )
            # Fail closed if the supplied signer is not the KEL-current key.
            if not ed25519.verify_strict(
                attestation.signing_bytes(),
                signature,
                keri.resolve_current_key(signing_identity.kel),
            ):
                raise ChannelError("channel-key attestation signature does not verify")
            return cls(
                binding,
                role,
                signing_identity,
                ephemeral_scalar,
                attestation,
                _mint_token=_ENDPOINT_MINT_TOKEN,
            )
        except ChannelError:
            raise
        except (keri.KeriError, AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ChannelError("could not create channel endpoint") from exc

    def _wipe(self) -> None:
        if self._private_scalar is not None:
            self._private_scalar[:] = b"\x00" * len(self._private_scalar)
            self._private_scalar = None

    def establish(
        self, peer_attestation: ChannelKeyAttestation, peer: Any
    ) -> "SessionChannel":
        """Consume this endpoint once and establish the authenticated channel."""
        with self._lock:
            if self._establish_attempted:
                raise ChannelError("channel endpoint establish is one-shot")
            self._establish_attempted = True
            try:
                if not isinstance(peer_attestation, ChannelKeyAttestation):
                    raise ChannelError("peer attestation has the wrong type")
                _verify_identity_matches_binding(
                    self.binding, self.role, self._signing_identity
                )
                peer_role = _opposite_role(self.role)
                _verify_remote(self.binding, peer_role, peer_attestation, peer)
                if self._private_scalar is None:
                    raise ChannelError("channel endpoint key is unavailable")
                shared_secret = _x25519(
                    bytes(self._private_scalar),
                    bytes.fromhex(peer_attestation.public_key),
                )
                if hmac.compare_digest(shared_secret, b"\x00" * 32):
                    raise ChannelError("X25519 produced an all-zero shared secret")

                initiator_attestation = (
                    self.attestation
                    if self.role is ChannelRole.INITIATOR
                    else peer_attestation
                )
                responder_attestation = (
                    self.attestation
                    if self.role is ChannelRole.RESPONDER
                    else peer_attestation
                )
                transcript = canonical_bytes(
                    {
                        "kind": _TRANSCRIPT_KIND,
                        "suite": CHANNEL_SUITE,
                        "session": self.binding._transcript_dict(),
                        "initiator_attestation": initiator_attestation.to_dict(),
                        "responder_attestation": responder_attestation.to_dict(),
                    }
                )
                transcript_hash = hashlib.sha256(transcript).digest()
                keys = {
                    name: _hkdf(
                        shared_secret,
                        salt=transcript_hash,
                        info=label,
                        length=32,
                    )
                    for name, label in _KEY_INFO.items()
                }
                return SessionChannel(
                    binding=self.binding,
                    role=self.role,
                    signing_identity=self._signing_identity,
                    peer=peer,
                    local_kel_pin=self.attestation.kel_event_dig,
                    peer_kel_pin=peer_attestation.kel_event_dig,
                    keys=keys,
                    _mint_token=_CHANNEL_MINT_TOKEN,
                )
            except ChannelError:
                raise
            except (AttributeError, KeyError, TypeError, ValueError) as exc:
                raise ChannelError("channel establishment failed") from exc
            finally:
                self._wipe()


def _sha256_ctr(
    key: bytes, nonce: bytes, sequence: int, payload: bytes
) -> bytes:
    output = bytearray(len(payload))
    offset = 0
    counter = 0
    sequence_bytes = sequence.to_bytes(8, "big")
    while offset < len(payload):
        block = hashlib.sha256(
            key
            + nonce
            + sequence_bytes
            + counter.to_bytes(8, "big")
        ).digest()
        take = min(len(block), len(payload) - offset)
        for index in range(take):
            output[offset + index] = payload[offset + index] ^ block[index]
        offset += take
        counter += 1
    return bytes(output)


def _associated_data(
    binding: ChannelBinding,
    direction: int,
    sequence: int,
    message_class: str,
    sender_entity_aid: str,
) -> bytes:
    return canonical_bytes(
        {
            "frame_version": SEALED_FRAME_KIND,
            "suite": CHANNEL_SUITE,
            "direction": direction,
            "session_id": binding.session_id,
            "session_content_hash": binding.session_content_hash,
            "context": binding.context,
            "profile": binding.profile,
            "message_class": message_class,
            "sender_entity_aid": sender_entity_aid,
            "sequence": sequence,
        }
    )


_CHANNEL_MINT_TOKEN = object()


class SessionChannel:
    """Established session-bound channel with no rekey or serialization.

    KEL rotation permanently closes this object.  Reopening requires a fresh
    signed AFP session and fresh :class:`ChannelEndpoint` pair.
    """

    def __init__(
        self,
        *,
        binding: ChannelBinding,
        role: ChannelRole,
        signing_identity: Any,
        peer: Any,
        local_kel_pin: str,
        peer_kel_pin: str,
        keys: dict[str, bytes],
        _mint_token: object = None,
    ) -> None:
        if _mint_token is not _CHANNEL_MINT_TOKEN:
            raise ChannelError("SessionChannel can only be minted by establish()")
        self.binding = binding
        self.role = role
        self._signing_identity = signing_identity
        self._peer = peer
        self._local_kel_pin = local_kel_pin
        self._peer_kel_pin = peer_kel_pin
        if role is ChannelRole.INITIATOR:
            send_prefix, receive_prefix = "i2r", "r2i"
        else:
            send_prefix, receive_prefix = "r2i", "i2r"
        self._send_cipher_key: bytes | None = keys[f"{send_prefix}_cipher"]
        self._send_mac_key: bytes | None = keys[f"{send_prefix}_mac"]
        self._send_nonce_key: bytes | None = keys[f"{send_prefix}_nonce"]
        self._receive_cipher_key: bytes | None = keys[f"{receive_prefix}_cipher"]
        self._receive_mac_key: bytes | None = keys[f"{receive_prefix}_mac"]
        self._receive_nonce_key: bytes | None = keys[f"{receive_prefix}_nonce"]
        self._send_sequence = 0
        self._receive_highest = -1
        self._receive_bitmap = 0
        self._closed = False
        self._lock = threading.RLock()
        self._attestation_issuer_id = secrets.token_hex(32)
        self._attestation_receipts: dict[str, _SealedChannelReceipt] = {}
        self._attestation_wall_highwater = float("-inf")
        self._attestation_monotonic_highwater = float("-inf")

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def send_sequence(self) -> int:
        """The next sequence number that a successful seal will consume."""
        with self._lock:
            return self._send_sequence

    @property
    def receive_highest_sequence(self) -> int | None:
        """Highest authenticated receive sequence, or ``None`` before receipt."""
        with self._lock:
            return None if self._receive_highest < 0 else self._receive_highest

    def _close_locked(self) -> None:
        self._closed = True
        self._attestation_receipts.clear()
        self._send_cipher_key = None
        self._send_mac_key = None
        self._send_nonce_key = None
        self._receive_cipher_key = None
        self._receive_mac_key = None
        self._receive_nonce_key = None

    def close(self) -> None:
        """Permanently close the channel and discard its traffic keys."""
        with self._lock:
            self._close_locked()

    def _ensure_live_locked(self) -> None:
        if self._closed:
            raise ChannelError("channel is closed")
        try:
            local_digest = _key_establishing_digest(self._signing_identity.kel)
            peer_digest = _key_establishing_digest(self._peer.entity_kel)
        except ChannelError:
            self._close_locked()
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            self._close_locked()
            raise ChannelError("channel KEL state is unavailable") from exc
        if (
            local_digest != self._local_kel_pin
            or peer_digest != self._peer_kel_pin
        ):
            self._close_locked()
            raise ChannelError(
                "party KEL rotation closed the channel; open a fresh session"
            )

    def _attestation_session_expires_at(self) -> int:
        """Return the expiry Unix second from the signed session snapshot."""
        try:
            return session_datetime_to_unix(
                self.binding._session_dict()["expires_at"], "session expires_at"
            )
        except ChannelError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ChannelError("bound session expiry is malformed") from exc

    def _attestation_clock_locked(
        self,
        *,
        wall_time: object,
        monotonic_time: object,
        commit: bool = True,
    ) -> tuple[float, float]:
        """Check attestation clocks and optionally advance their high-water marks."""
        wall = _require_finite_number(wall_time, "attestation wall time")
        monotonic = _require_finite_number(
            monotonic_time, "attestation monotonic time"
        )
        if (
            wall < self._attestation_wall_highwater
            or monotonic < self._attestation_monotonic_highwater
        ):
            raise ChannelError("attestation clock rollback detected")
        if commit:
            self._attestation_wall_highwater = wall
            self._attestation_monotonic_highwater = monotonic
        return wall, monotonic

    def _sealed_channel_receipt(
        self, attestation: SealedChannelAttestation
    ) -> _SealedChannelReceipt:
        """Return authority facts only for this exact registered capability."""
        with self._lock:
            if type(attestation) is not SealedChannelAttestation:
                raise ChannelError("sealed-channel attestation has the wrong type")
            try:
                issuer = object.__getattribute__(attestation, "_issuer")
                receipt_id = object.__getattribute__(attestation, "_receipt_id")
            except AttributeError as exc:
                raise ChannelError(
                    "sealed-channel attestation is not registered"
                ) from exc
            if issuer is not self or type(receipt_id) is not str:
                raise ChannelError("sealed-channel attestation issuer is invalid")
            receipt = self._attestation_receipts.get(receipt_id)
            if receipt is None or receipt.attestation_ref() is not attestation:
                raise ChannelError(
                    "sealed-channel attestation identity is not registered"
                )
            return receipt

    def _discard_attestation_receipt(
        self, receipt_id: str, attestation_ref: Any
    ) -> None:
        """Prune a receipt after its exact capability has been collected."""
        with self._lock:
            receipt = self._attestation_receipts.get(receipt_id)
            if receipt is not None and receipt.attestation_ref is attestation_ref:
                self._attestation_receipts.pop(receipt_id, None)

    def _prune_attestation_receipts_locked(
        self, *, wall_time: float, monotonic_time: float
    ) -> None:
        """Drop collected, expired, or malformed receipts."""
        for receipt_id, receipt in tuple(self._attestation_receipts.items()):
            try:
                expired = (
                    receipt.attestation_ref() is None
                    or wall_time
                    >= _require_finite_number(
                        receipt.expires_at, "attestation expires_at"
                    )
                    or monotonic_time
                    >= _require_finite_number(
                        receipt.expires_monotonic,
                        "attestation monotonic expiry",
                    )
                )
            except (AttributeError, ChannelError, OverflowError, TypeError, ValueError):
                expired = True
            if expired:
                self._attestation_receipts.pop(receipt_id, None)

    def _revalidate_sealed_channel_attestation(
        self,
        attestation: SealedChannelAttestation,
        *,
        session_context: str,
        kel_event_dig: str,
        now: float,
        monotonic_now: float,
    ) -> bool:
        """Recheck receipt identity, liveness, and detached transit facts."""
        with self._lock:
            try:
                # A read-only live sample must not ratchet the mint-time clock
                # floor. Observed expiry remains irreversible because pruning
                # removes the receipt before this method can return.
                now, monotonic_now = self._attestation_clock_locked(
                    wall_time=now,
                    monotonic_time=monotonic_now,
                    commit=False,
                )
                self._prune_attestation_receipts_locked(
                    wall_time=now, monotonic_time=monotonic_now
                )
                receipt = self._sealed_channel_receipt(attestation)
                if (
                    receipt.issuer_id != self._attestation_issuer_id
                    or receipt.session_id != self.binding.session_id
                    or receipt.session_content_hash
                    != self.binding.session_content_hash
                    or receipt.session_context != self.binding.context
                    or receipt.session_context != session_context
                    or receipt.kel_event_dig != self._peer_kel_pin
                    or receipt.kel_event_dig != kel_event_dig
                    or receipt.suite != CHANNEL_SUITE
                    or receipt.suite_id != _SUITE_ID
                ):
                    return False
                self._ensure_live_locked()
                expires_at = _require_finite_number(
                    receipt.expires_at, "attestation expires_at"
                )
                authenticated_monotonic = _require_finite_number(
                    receipt.authenticated_monotonic,
                    "attestation authenticated monotonic time",
                )
                expires_monotonic = _require_finite_number(
                    receipt.expires_monotonic,
                    "attestation monotonic expiry",
                )
                evidence = SealedTransitEvidence(
                    frame_kind=receipt.frame_kind,
                    frame_digest=receipt.frame_digest,
                    frame_size=receipt.frame_size,
                    direction=receipt.direction,
                    sequence=receipt.sequence,
                    message_class=receipt.message_class,
                    authenticated_at=receipt.authenticated_at,
                )
                session_expires_at = self._attestation_session_expires_at()
                if not (
                    evidence.authenticated_at <= now < expires_at <= session_expires_at
                    and authenticated_monotonic
                    <= monotonic_now
                    < expires_monotonic
                ):
                    return False
                if evidence.direction != _role_direction(_opposite_role(self.role)):
                    return False
                if (
                    self._receive_highest < 0
                    or evidence.sequence > self._receive_highest
                ):
                    return False
                return True
            except (
                AttributeError,
                ChannelError,
                KeyError,
                OverflowError,
                TypeError,
                ValueError,
            ):
                return False

    @staticmethod
    def _message_class(value: object) -> str:
        if not isinstance(value, str) or not value:
            raise ChannelError("message_class must be a non-empty string")
        return value

    def seal(self, payload: bytes, message_class: str) -> bytes:
        """Encrypt and authenticate bytes into an exact ``afp:sealed:v1`` frame."""
        with self._lock:
            self._ensure_live_locked()
            if type(payload) is not bytes:
                raise ChannelError("payload must be bytes")
            message_class = self._message_class(message_class)
            if len(payload) > _MAX_CIPHERTEXT:
                raise ChannelError("payload is too large for a sealed frame")
            if self._send_sequence > _MAX_SEQUENCE:
                self._close_locked()
                raise ChannelError("channel send sequence exhausted")
            if (
                self._send_cipher_key is None
                or self._send_mac_key is None
                or self._send_nonce_key is None
            ):
                self._close_locked()
                raise ChannelError("channel traffic keys are unavailable")

            sequence = self._send_sequence
            direction = _role_direction(self.role)
            sequence_bytes = sequence.to_bytes(8, "big")
            nonce = hmac.new(
                self._send_nonce_key,
                _NONCE_LABEL + sequence_bytes,
                hashlib.sha256,
            ).digest()[:16]
            ciphertext = _sha256_ctr(
                self._send_cipher_key, nonce, sequence, payload
            )
            header = (
                _FRAME_PREFIX
                + bytes((_SUITE_ID, direction))
                + sequence_bytes
                + nonce
                + len(ciphertext).to_bytes(4, "big")
            )
            sender_aid = self.binding._party(self.role)[1]
            associated_data = _associated_data(
                self.binding,
                direction,
                sequence,
                message_class,
                sender_aid,
            )
            authenticated = header + ciphertext
            tag = hmac.new(
                self._send_mac_key,
                associated_data + authenticated,
                hashlib.sha256,
            ).digest()
            frame = authenticated + tag
            self._send_sequence += 1
            return frame

    def open(self, frame: bytes, message_class: str) -> bytes:
        """Authenticate and decrypt one frame, discarding its evidence handle."""
        plaintext, _attestation = self._open_authenticated(
            frame, message_class=message_class, require_attestation=False
        )
        return plaintext

    def open_with_attestation(
        self, frame: bytes, message_class: str
    ) -> tuple[bytes, SealedChannelAttestation]:
        """Authenticate one frame and atomically mint its process-local evidence."""
        plaintext, attestation = self._open_authenticated(
            frame, message_class=message_class, require_attestation=True
        )
        if attestation is None:  # Internal invariant; strict path always mints.
            raise ChannelError("authenticated receive did not mint evidence")
        return plaintext, attestation

    def _open_authenticated(
        self,
        frame: bytes,
        *,
        message_class: str,
        require_attestation: bool,
    ) -> tuple[bytes, SealedChannelAttestation | None]:
        """Shared receive path with optional strict evidence minting."""
        with self._lock:
            self._ensure_live_locked()
            authenticated_at = None
            authenticated_monotonic = None
            expires_at = None
            expires_monotonic = None
            if require_attestation:
                authenticated_at, authenticated_monotonic = (
                    self._attestation_clock_locked(
                        wall_time=time.time(),
                        monotonic_time=time.monotonic(),
                        commit=False,
                    )
                )
                session_expires_at = self._attestation_session_expires_at()
                expires_at = min(
                    authenticated_at + _ATTESTATION_VALIDITY_SECONDS,
                    session_expires_at,
                )
                if expires_at <= authenticated_at:
                    raise ChannelError(
                        "cannot attest a transit for an expired session"
                    )
                expires_monotonic = authenticated_monotonic + (
                    expires_at - authenticated_at
                )
            if type(frame) is not bytes:
                raise ChannelError("frame must be bytes")
            message_class = self._message_class(message_class)
            if len(frame) < SEALED_FRAME_OVERHEAD:
                raise ChannelError("sealed frame is truncated")
            if frame[: len(_FRAME_PREFIX)] != _FRAME_PREFIX:
                raise ChannelError("unexpected sealed frame version")
            suite_offset = len(_FRAME_PREFIX)
            if frame[suite_offset] != _SUITE_ID:
                raise ChannelError("unexpected sealed frame suite")
            direction = frame[suite_offset + 1]
            expected_direction = _role_direction(_opposite_role(self.role))
            if direction != expected_direction:
                raise ChannelError("sealed frame direction is invalid")
            sequence_offset = suite_offset + 2
            sequence = int.from_bytes(
                frame[sequence_offset : sequence_offset + 8], "big"
            )
            nonce_offset = sequence_offset + 8
            nonce = frame[nonce_offset : nonce_offset + 16]
            length_offset = nonce_offset + 16
            ciphertext_length = int.from_bytes(
                frame[length_offset : length_offset + 4], "big"
            )
            expected_length = SEALED_FRAME_OVERHEAD + ciphertext_length
            if len(frame) != expected_length:
                raise ChannelError("sealed frame length is invalid")
            ciphertext_offset = length_offset + 4
            tag_offset = ciphertext_offset + ciphertext_length
            ciphertext = frame[ciphertext_offset:tag_offset]
            tag = frame[tag_offset:]
            if (
                self._receive_cipher_key is None
                or self._receive_mac_key is None
                or self._receive_nonce_key is None
            ):
                self._close_locked()
                raise ChannelError("channel traffic keys are unavailable")

            sender_role = _opposite_role(self.role)
            sender_aid = self.binding._party(sender_role)[1]
            associated_data = _associated_data(
                self.binding,
                direction,
                sequence,
                message_class,
                sender_aid,
            )
            expected_tag = hmac.new(
                self._receive_mac_key,
                associated_data + frame[:tag_offset],
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ChannelError("sealed frame authentication failed")
            expected_nonce = hmac.new(
                self._receive_nonce_key,
                _NONCE_LABEL + sequence.to_bytes(8, "big"),
                hashlib.sha256,
            ).digest()[:16]
            if not hmac.compare_digest(nonce, expected_nonce):
                raise ChannelError("sealed frame nonce is invalid")

            # Replay state is considered only after authentication.  Compute the
            # prospective update locally and commit it immediately before return.
            # An authenticated frame ahead of the window slides it forward: only
            # the peer can produce one, and the frames it skips may simply have
            # been lost in transit.
            highest = self._receive_highest
            bitmap = self._receive_bitmap
            mask = (1 << DEFAULT_REPLAY_WINDOW) - 1
            if highest < 0:
                new_highest = sequence
                new_bitmap = 1
            elif sequence > highest:
                shift = sequence - highest
                new_highest = sequence
                if shift >= DEFAULT_REPLAY_WINDOW:
                    new_bitmap = 1
                else:
                    new_bitmap = ((bitmap << shift) | 1) & mask
            else:
                distance = highest - sequence
                if distance >= DEFAULT_REPLAY_WINDOW:
                    raise ChannelError("sealed frame sequence is too old")
                bit = 1 << distance
                if bitmap & bit:
                    raise ChannelError("sealed frame is a replay")
                new_highest = highest
                new_bitmap = bitmap | bit

            plaintext = _sha256_ctr(
                self._receive_cipher_key, nonce, sequence, ciphertext
            )
            attestation = None
            receipt = None
            if require_attestation:
                if (
                    authenticated_at is None
                    or authenticated_monotonic is None
                    or expires_at is None
                    or expires_monotonic is None
                ):
                    raise ChannelError("attestation clock state is unavailable")

                receipt_id = secrets.token_hex(32)
                while receipt_id in self._attestation_receipts:
                    receipt_id = secrets.token_hex(32)
                attestation = object.__new__(SealedChannelAttestation)
                object.__setattr__(attestation, "_issuer", self)
                object.__setattr__(attestation, "_receipt_id", receipt_id)
                issuer_ref = weakref.ref(self)

                def discard_receipt(
                    attestation_ref: Any,
                    *,
                    issuer_ref: Any = issuer_ref,
                    receipt_id: str = receipt_id,
                ) -> None:
                    issuer = issuer_ref()
                    if issuer is not None:
                        issuer._discard_attestation_receipt(
                            receipt_id, attestation_ref
                        )

                attestation_ref = weakref.ref(attestation, discard_receipt)
                receipt = _SealedChannelReceipt(
                    receipt_id=receipt_id,
                    attestation_ref=attestation_ref,
                    issuer_id=self._attestation_issuer_id,
                    session_id=self.binding.session_id,
                    session_content_hash=self.binding.session_content_hash,
                    session_context=self.binding.context,
                    kel_event_dig=self._peer_kel_pin,
                    suite=CHANNEL_SUITE,
                    suite_id=_SUITE_ID,
                    frame_kind=SEALED_FRAME_KIND,
                    frame_digest=hashlib.sha256(frame).hexdigest(),
                    frame_size=len(frame),
                    direction=direction,
                    sequence=sequence,
                    message_class=message_class,
                    authenticated_at=authenticated_at,
                    authenticated_monotonic=authenticated_monotonic,
                    expires_at=expires_at,
                    expires_monotonic=expires_monotonic,
                )

            # Commit replay state and the receipt ledger only after every strict
            # evidence check and allocation has succeeded.
            if receipt is not None:
                self._attestation_clock_locked(
                    wall_time=receipt.authenticated_at,
                    monotonic_time=receipt.authenticated_monotonic,
                )
                self._prune_attestation_receipts_locked(
                    wall_time=receipt.authenticated_at,
                    monotonic_time=receipt.authenticated_monotonic,
                )
                self._attestation_receipts[receipt.receipt_id] = receipt
            self._receive_highest = new_highest
            self._receive_bitmap = new_bitmap
            return plaintext, attestation

    def __reduce__(self) -> object:
        raise TypeError("SessionChannel cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("SessionChannel cannot be serialized")
