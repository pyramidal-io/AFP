"""AFP core atoms — session, envelope, commitment, anchor (§12.2/12.6/12.7).

These are the durable, queryable AKG structures of the Bilateral Session Core.
Each signed atom carries an :class:`AfpPartyRef` (§12.2.1): the tenant root AID,
the acting entity delegated AID, the ``kel_event_dig`` pinning the key state, and
a KEL-anchored Ed25519 signature over the atom's content hash (§12.3).

Signatures here are *real* (``afp_session.ed25519``) and the verification path
goes through the KERI layer (``afp_session.keri``) so a signature bound to a
superseded KEL event is rejected (``kel_keystate_stale``, §12.3).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional

from .bundle import (
    BUNDLE_VERSION,
    ZkaBundle,
    session_context_field,
)
from .canonical import _jcs_float, digest, jcs_digest, qb64

__all__ = [
    "AfpSessionStatus",
    "AfpPartyRef",
    "AfpSessionAtom",
    "AfpEnvelope",
    "AfpCommitSignature",
    "AfpCommitmentAtom",
    "AfpAnchorAtom",
    "SESSION_KIND",
    "ENVELOPE_KIND",
    "COMMITMENT_KIND",
    "ANCHOR_KIND",
    "MIN_OPENED_AT",
    "MAX_OPENED_AT",
    "SESSION_STABLE_CONTENT_MEMBERS",
    "validate_opened_at",
    "opened_at_to_rfc3339",
    "validate_session_datetime",
    "session_datetime_to_unix",
    "unix_to_session_datetime",
    "MIN_UTC_DATETIME_SECONDS",
    "MAX_UTC_DATETIME_SECONDS",
    "MAX_JSON_SAFE_INTEGER",
    "utc_datetime_to_unix",
    "validate_utc_datetime",
    "unix_to_utc_datetime",
    "validate_signed_at",
    "validate_signed_at_number",
    "compute_session_context",
]

SESSION_KIND = "afp:session:v1"
ENVELOPE_KIND = "afp:envelope:v1"
COMMITMENT_KIND = "afp:commitment:v1"
ANCHOR_KIND = "afp:anchor:v1"

# 9999-12-31T23:59:59Z.  Pinning this range keeps the signed context portable
# across runtimes whose platform timestamp conversion supports a smaller range.
MIN_OPENED_AT = 0
MAX_OPENED_AT = 253_402_300_799
_UNIX_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_OPENED_AT_JSON_TOKEN_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_SESSION_DATETIME_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z"
)
# §1.6.1: the full UTC datetime string range, and the largest integer that a
# JCS integer token carries without passing through the float form.
MIN_UTC_DATETIME_SECONDS = -62_135_596_800  # 0001-01-01T00:00:00Z
MAX_UTC_DATETIME_SECONDS = MAX_OPENED_AT  # 9999-12-31T23:59:59Z
MAX_JSON_SAFE_INTEGER = 9_007_199_254_740_991

# The §12.2.1 stable session content, in no particular order (JCS sorts it).
SESSION_STABLE_CONTENT_MEMBERS = (
    "kind",
    "id",
    "agreement_ref",
    "agreement_version",
    "profile",
    "profile_policy_hash",
    "opened_at",
    "expires_at",
    "session_context",
)


@dataclass(frozen=True)
class _JsonNumberToken:
    spelling: str
    is_integer: bool


def _reject_duplicate_json_members(pairs: List[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_non_json_number(token: str) -> None:
    raise ValueError(f"non-JSON numeric token {token!r}")


class AfpSessionStatus(str, Enum):
    """Core session lifecycle states (§12.2.1)."""

    PROPOSED = "proposed"
    OPEN = "open"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"
    EXPIRED = "expired"
    ABORTED = "aborted"


def validate_opened_at(value: object) -> int:
    """Return a canonical session ``opened_at`` Unix-second value.

    ``opened_at`` is a JSON number on the AFP wire, but its signed form admits
    only Python ``int`` values in the inclusive UTC range supported by the
    protocol.  In particular, booleans are rejected even though they subclass
    ``int`` in Python.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("opened_at must be a whole Unix second integer")
    if not MIN_OPENED_AT <= value <= MAX_OPENED_AT:
        raise ValueError(
            f"opened_at must be between {MIN_OPENED_AT} and {MAX_OPENED_AT} inclusive"
        )
    return value


def opened_at_to_rfc3339(value: object) -> str:
    """Render a canonical ``opened_at`` without platform timestamp APIs."""
    opened_at = validate_opened_at(value)
    timestamp_utc = _UNIX_EPOCH_UTC + timedelta(seconds=opened_at)
    # Do not use fromtimestamp()/strftime(): both can defer to platform C
    # libraries with range or formatting differences near the protocol limit.
    return (
        f"{timestamp_utc.year:04d}-{timestamp_utc.month:02d}-{timestamp_utc.day:02d}"
        f"T{timestamp_utc.hour:02d}:{timestamp_utc.minute:02d}:{timestamp_utc.second:02d}Z"
    )


def utc_datetime_to_unix(value: object, name: str = "datetime") -> int:
    """Return the Unix second named by a §1.6.1 UTC datetime string.

    The only accepted form is whole-second UTC ``YYYY-MM-DDTHH:MM:SSZ`` naming
    a real proleptic Gregorian instant from ``0001-01-01T00:00:00Z`` through
    ``9999-12-31T23:59:59Z``. Numbers, fractional seconds, offsets, lowercase
    designators and leap seconds are rejected, never normalized. Instants
    before 1970 return a negative count.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a whole-second UTC RFC 3339 string")
    match = _SESSION_DATETIME_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"{name} must match YYYY-MM-DDTHH:MM:SSZ")
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    try:
        instant = datetime(
            year, month, day, hour, minute, second, tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(f"{name} is not a valid UTC calendar instant") from exc
    return (instant - _UNIX_EPOCH_UTC) // timedelta(seconds=1)


def validate_utc_datetime(value: object, name: str = "datetime") -> str:
    """Return ``value`` unchanged if it is a canonical §1.6.1 UTC datetime string."""
    utc_datetime_to_unix(value, name)
    return value  # type: ignore[return-value]


def unix_to_utc_datetime(value: object) -> str:
    """Render a whole Unix second as a §1.6.1 UTC datetime string."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("UTC datetime must be a whole Unix second integer")
    if not MIN_UTC_DATETIME_SECONDS <= value <= MAX_UTC_DATETIME_SECONDS:
        raise ValueError(
            "UTC datetime must be between 0001-01-01T00:00:00Z and "
            "9999-12-31T23:59:59Z"
        )
    instant = _UNIX_EPOCH_UTC + timedelta(seconds=value)
    # Do not use fromtimestamp()/strftime(): both can defer to platform C
    # libraries with range or formatting differences near the protocol limit.
    return (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}"
        f"T{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}Z"
    )


def validate_signed_at(value: object) -> int | float:
    """Return a §1.6.1 ``signed_at`` JSON number in its RFC 8785 form.

    ``signed_at`` is observational metadata outside every signature payload.
    It is a finite RFC 8785 number, that is an IEEE 754 binary64 value.
    Booleans, strings, ``None``, NaN and infinities are rejected, never
    coerced. Python's JSON reader returns an integer token as ``int``; beyond
    2^53-1 such a token is accepted only when it is the RFC 8785 spelling of
    a binary64 value (JCS writes 2^60 as ``1152921504606847000``), and that
    value is returned as a float with the same JCS spelling. Any other large
    integer token is not RFC 8785 number form and is rejected.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("signed_at must be a finite JSON number")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("signed_at must be a finite JSON number")
        return value
    if -MAX_JSON_SAFE_INTEGER <= value <= MAX_JSON_SAFE_INTEGER:
        return value
    try:
        as_float = float(value)
    except OverflowError as exc:
        raise ValueError("signed_at is outside the IEEE 754 binary64 range") from exc
    if _jcs_float(as_float) != str(value):
        raise ValueError("signed_at is not an RFC 8785 number token")
    return as_float


def validate_signed_at_number(value: object) -> int | float:
    """Return a caller's native ``signed_at`` number as its §1.6.1 value.

    This is the producer-side rule, for a number made in process rather than
    read from JSON (use :func:`validate_signed_at` for a received token). A
    float must be finite. An integer is accepted only when IEEE 754 binary64
    represents it exactly, so it is never rounded on the way to the wire:
    ``2**60`` is accepted and ``2**53 + 1`` is rejected. Beyond 2^53-1 the
    integer is returned as the float of the same value, which RFC 8785 then
    writes in its own spelling. Booleans and non-numbers are rejected.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("signed_at must be a finite JSON number")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("signed_at must be a finite JSON number")
        return value
    if -MAX_JSON_SAFE_INTEGER <= value <= MAX_JSON_SAFE_INTEGER:
        return value
    try:
        as_float = float(value)
    except OverflowError as exc:
        raise ValueError("signed_at is outside the IEEE 754 binary64 range") from exc
    if int(as_float) != value:
        raise ValueError("signed_at is not exactly representable in IEEE 754 binary64")
    return as_float


def session_datetime_to_unix(value: object, name: str = "datetime") -> int:
    """Return the Unix second named by a §12.2.1 session ``datetime`` string.

    The session form is the §1.6.1 UTC datetime string narrowed to the
    ``opened_at`` range, from 1970 through 9999.
    """
    seconds = utc_datetime_to_unix(value, name)
    if not MIN_OPENED_AT <= seconds <= MAX_OPENED_AT:
        raise ValueError(
            f"{name} must be between 1970-01-01T00:00:00Z and 9999-12-31T23:59:59Z"
        )
    return seconds


def validate_session_datetime(value: object, name: str = "datetime") -> str:
    """Return ``value`` unchanged if it is a canonical session ``datetime``."""
    session_datetime_to_unix(value, name)
    return value  # type: ignore[return-value]


def unix_to_session_datetime(value: object) -> str:
    """Render a whole Unix second as a §12.2.1 session ``datetime`` string."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("session datetime must be a whole Unix second integer")
    if not MIN_OPENED_AT <= value <= MAX_OPENED_AT:
        raise ValueError(
            "session datetime must be between 1970-01-01T00:00:00Z and "
            "9999-12-31T23:59:59Z"
        )
    return opened_at_to_rfc3339(value)


def compute_session_context(
    initiator_entity_aid: str,
    responder_entity_aid: str,
    session_id: str,
    timestamp: int,
) -> str:
    """Derive the §5.2 / §12.3 session context from a whole Unix second.

    The SHA-256 preimage is the UTF-8 JSON object with the four fixed string
    members specified in §5.2; its timestamp member is whole-second UTC RFC
    3339 text.  Restricting the object to strings keeps this reference's
    canonical JSON encoding byte-identical to RFC 8785 JCS for the preimage.

    The canonical ``X_`` value is bound into every envelope and session atom.
    ZKA field-valued context slots bind its §12.7 big-endian BN254 projection,
    preventing replay to another session or counterparty without inventing a
    parallel session context.
    """
    timestamp_text = opened_at_to_rfc3339(timestamp)

    session_context = qb64(
        "X",
        digest(
            {
                "initiator_entity_aid": initiator_entity_aid,
                "responder_entity_aid": responder_entity_aid,
                "session_id": session_id,
                "timestamp": timestamp_text,
            }
        ),
    )
    # ZKA and ZKC reserve field zero as the missing-context sentinel.  AFP does
    # not retry or substitute another digest if the canonical §5.2 value maps
    # there; session establishment fails closed instead.
    session_context_field(session_context)
    return session_context


@dataclass
class AfpPartyRef:
    """Canonical session identity binding (§12.2.1 / §12.3).

    ``signature`` is an Ed25519 signature, KEL-anchored, over the content hash of
    the atom this ref appears in; ``kel_event_dig`` pins the key state.
    """

    tenant_aid: str
    entity_aid: str
    kel_event_dig: str
    signature: str  # hex Ed25519 signature over the atom content hash

    def to_dict(self) -> dict:
        return {
            "tenant_aid": self.tenant_aid,
            "entity_aid": self.entity_aid,
            "kel_event_dig": self.kel_event_dig,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AfpPartyRef":
        return cls(
            tenant_aid=data["tenant_aid"],
            entity_aid=data["entity_aid"],
            kel_event_dig=data["kel_event_dig"],
            signature=data["signature"],
        )

    def unsigned(self) -> dict:
        """The ref fields excluding the signature (what the signature covers context for)."""
        return {
            "tenant_aid": self.tenant_aid,
            "entity_aid": self.entity_aid,
            "kel_event_dig": self.kel_event_dig,
        }


@dataclass
class AfpSessionAtom:
    """``afp:session:v1`` — durable bilateral-session state (§12.2.1)."""

    id: str
    initiator: AfpPartyRef
    responder: AfpPartyRef
    agreement_ref: str
    agreement_version: str
    profile: str
    profile_policy_hash: str
    status: AfpSessionStatus
    opened_at: int
    expires_at: str
    session_context: str
    closed_at: Optional[str] = None
    kind: str = SESSION_KIND

    def __post_init__(self) -> None:
        """Reject noncanonical wire values at the object boundary."""
        self.opened_at = validate_opened_at(self.opened_at)
        if self.expires_at_seconds <= self.opened_at:
            raise ValueError("expires_at must be strictly later than opened_at")
        if self.closed_at is not None:
            validate_session_datetime(self.closed_at, "closed_at")
        session_context_field(self.session_context)

    @property
    def expires_at_seconds(self) -> int:
        """The validated ``expires_at`` instant as a whole Unix second."""
        return session_datetime_to_unix(self.expires_at, "expires_at")

    def content_for_party(self) -> dict:
        """The §12.2.1 stable session content each party signs.

        Excludes the party refs and mutable lifecycle fields (status/closed_at)
        so each side signs the stable session identity, not a moving target. The
        signed ``session_context`` commits both entity AIDs; acceptance verifies
        each party ref independently before relying on that commitment.
        """
        return {
            "kind": self.kind,
            "id": self.id,
            "agreement_ref": self.agreement_ref,
            "agreement_version": self.agreement_version,
            "profile": self.profile,
            "profile_policy_hash": self.profile_policy_hash,
            "opened_at": validate_opened_at(self.opened_at),
            "expires_at": validate_session_datetime(self.expires_at, "expires_at"),
            "session_context": self.session_context,
        }

    @property
    def content_hash(self) -> str:
        """``D_`` + SHA-256 of the RFC 8785 JCS stable content (§12.2.1)."""
        return qb64("D", jcs_digest(self.content_for_party()))

    def to_dict(self) -> dict:
        """Serialize the full atom (with party refs + lifecycle) for the wire.

        ``closed_at`` is optional on the wire and appears only once set.
        """
        data = {
            "kind": self.kind,
            "id": self.id,
            "initiator": self.initiator.to_dict(),
            "responder": self.responder.to_dict(),
            "agreement_ref": self.agreement_ref,
            "agreement_version": self.agreement_version,
            "profile": self.profile,
            "profile_policy_hash": self.profile_policy_hash,
            "status": self.status.value,
            "opened_at": validate_opened_at(self.opened_at),
            "expires_at": validate_session_datetime(self.expires_at, "expires_at"),
            "session_context": self.session_context,
        }
        if self.closed_at is not None:
            data["closed_at"] = validate_session_datetime(self.closed_at, "closed_at")
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AfpSessionAtom":
        """Construct from a decoded map whose number tokens were validated.

        External JSON consumers MUST use :meth:`from_json`, which validates the
        original ``opened_at`` token before a JSON decoder can erase spellings
        such as ``-0``. This map-level helper remains useful for trusted local
        copies and callers whose decoder already enforces the §5.2 JCS token.
        """
        responder = data.get("responder")
        if not isinstance(responder, dict):
            raise ValueError("session responder party ref is required")
        return cls(
            id=data["id"],
            initiator=AfpPartyRef.from_dict(data["initiator"]),
            responder=AfpPartyRef.from_dict(responder),
            agreement_ref=data["agreement_ref"],
            agreement_version=data["agreement_version"],
            profile=data["profile"],
            profile_policy_hash=data["profile_policy_hash"],
            status=AfpSessionStatus(data["status"]),
            opened_at=data["opened_at"],
            expires_at=data["expires_at"],
            session_context=data["session_context"],
            closed_at=data.get("closed_at"),
            kind=data.get("kind", SESSION_KIND),
        )

    @classmethod
    def from_json(cls, payload: bytes | bytearray | str) -> "AfpSessionAtom":
        """Parse a wire atom while preserving and validating numeric lexemes."""
        if isinstance(payload, (bytes, bytearray)):
            try:
                text = bytes(payload).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("session atom JSON must be UTF-8") from exc
        elif isinstance(payload, str):
            text = payload
        else:
            raise ValueError("session atom JSON must be bytes or text")

        try:
            tokenized = json.loads(
                text,
                parse_int=lambda token: _JsonNumberToken(token, True),
                parse_float=lambda token: _JsonNumberToken(token, False),
                parse_constant=_reject_non_json_number,
                object_pairs_hook=_reject_duplicate_json_members,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("session atom JSON is malformed") from exc
        if not isinstance(tokenized, dict):
            raise ValueError("session atom JSON must be an object")

        opened_at_token = tokenized.get("opened_at")
        if (
            not isinstance(opened_at_token, _JsonNumberToken)
            or not opened_at_token.is_integer
            or _OPENED_AT_JSON_TOKEN_RE.fullmatch(opened_at_token.spelling) is None
        ):
            raise ValueError(
                "opened_at must use a canonical unsigned JSON integer token"
            )
        if "closed_at" in tokenized and tokenized["closed_at"] is None:
            raise ValueError("closed_at is absent until set; null is not an encoding")

        try:
            data = json.loads(
                text,
                parse_constant=_reject_non_json_number,
                object_pairs_hook=_reject_duplicate_json_members,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("session atom JSON is malformed") from exc
        return cls.from_dict(data)


@dataclass
class AfpEnvelope:
    """``afp:envelope:v1`` — session framing over a ZKA bundle (§12.7).

    AFP owns this envelope; it carries a ``zka:bundle:v1`` verbatim, binds the
    envelope's canonical ``X_`` session digest to the bundle's canonical BN254
    projection (§12.3/§12.7), and routes it on the §12.4 namespace. The
    envelope is signed by the sending party (KEL-anchored, §12.3) so the
    counterparty verifies *who* sent it and that it has not been tampered.
    """

    session_ref: str
    session_context: str
    profile: str
    bundle: ZkaBundle
    message_class: str
    generated_at: float
    expires_at: float
    sender: Optional[AfpPartyRef] = None  # populated on sign
    bundle_version: str = BUNDLE_VERSION
    kind: str = ENVELOPE_KIND

    def __post_init__(self) -> None:
        """Reject noncanonical context and timestamp values on parse."""
        session_context_field(self.session_context)
        for value in (self.generated_at, self.expires_at):
            if (
                type(value) not in (int, float)
                or (type(value) is float and not math.isfinite(value))
            ):
                raise ValueError("envelope timestamps must be finite JSON numbers")

    def content_to_sign(self) -> dict:
        """Deterministic envelope content the sender signs (excludes the signature)."""
        return {
            "kind": self.kind,
            "session_ref": self.session_ref,
            "session_context": self.session_context,
            "profile": self.profile,
            "bundle": self.bundle.to_dict(),
            "bundle_version": self.bundle_version,
            "message_class": self.message_class,
            "generated_at": self.generated_at,
            "expires_at": self.expires_at,
            "sender": self.sender.unsigned() if self.sender else None,
        }

    @property
    def content_hash(self) -> str:
        return qb64("D", digest(self.content_to_sign()))

    def to_dict(self) -> dict:
        data = self.content_to_sign()
        data["sender"] = self.sender.to_dict() if self.sender else None
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AfpEnvelope":
        return cls(
            session_ref=data["session_ref"],
            session_context=data["session_context"],
            profile=data["profile"],
            bundle=ZkaBundle.from_dict(data["bundle"]),
            message_class=data["message_class"],
            generated_at=data["generated_at"],
            expires_at=data["expires_at"],
            sender=AfpPartyRef.from_dict(data["sender"]) if data.get("sender") else None,
            bundle_version=data.get("bundle_version", BUNDLE_VERSION),
            kind=data.get("kind", ENVELOPE_KIND),
        )


@dataclass
class AfpCommitSignature:
    """A bilateral commitment signature (§12.6.1).

    ``signed_at`` is observational metadata outside the Ed25519 payload; callers
    must not treat it as authenticated time or use it for freshness decisions.
    """

    signed_by: str  # tenant/entity AID
    kel_event_dig: str
    signature: str  # hex Ed25519, KEL-anchored
    signed_at: float  # the §1.6.1 JSON number as it appears on the wire

    def to_dict(self) -> dict:
        # ``signed_at`` holds the wire value: a received token, or a signer's
        # number already checked by validate_signed_at_number. The dataclass
        # is mutable, so check it again here; a value that is not RFC 8785
        # number form cannot leave.
        return {
            "signed_by": self.signed_by,
            "kel_event_dig": self.kel_event_dig,
            "signature": self.signature,
            "signed_at": validate_signed_at(self.signed_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AfpCommitSignature":
        return cls(
            signed_by=data["signed_by"],
            kel_event_dig=data["kel_event_dig"],
            signature=data["signature"],
            # §1.6.1: a received token is checked as RFC 8785 number form.
            signed_at=validate_signed_at(data["signed_at"]),
        )


@dataclass
class AfpCommitmentAtom:
    """``afp:commitment:v1`` — bilaterally-signed agreed outcome (§12.6.1).

    BOTH party signatures are REQUIRED; ``sequence_number`` + ``previous_commitment_ref``
    form a replay-resistant ordered history per AID-pair. ``outcome_root`` commits
    to the agreed outcome (Poseidon2 in-spec — see seam note in ``commitment``).
    """

    id: str
    session_ref: str
    outcome_root: str
    profile: str
    sequence_number: int
    initiator_signature: Optional[AfpCommitSignature] = None
    responder_signature: Optional[AfpCommitSignature] = None
    arbiter_signature: Optional[AfpCommitSignature] = None
    previous_commitment_ref: Optional[str] = None
    anchor_ref: Optional[str] = None
    kind: str = COMMITMENT_KIND

    def content_to_sign(self) -> dict:
        """The commitment content both parties sign (§12.6.1)."""
        return {
            "kind": self.kind,
            "id": self.id,
            "session_ref": self.session_ref,
            "outcome_root": self.outcome_root,
            "profile": self.profile,
            "sequence_number": self.sequence_number,
            "previous_commitment_ref": self.previous_commitment_ref,
        }

    @property
    def content_hash(self) -> str:
        return qb64("D", digest(self.content_to_sign()))

    @property
    def is_fully_signed(self) -> bool:
        """A commitment is valid only with BOTH party signatures (§12.6.1)."""
        return (
            self.initiator_signature is not None
            and self.responder_signature is not None
        )


@dataclass
class AfpAnchorAtom:
    """``afp:anchor:v1`` — optional DLT anchor of a commitment (§12.6.2).

    Hashes only — never atom content. Anchoring is optional; the protocol is fully
    functional without it. Ethereum L2 via APL is the mandatory baseline *when a
    deployment anchors*. The actual DLT submission is an APL concern (a seam);
    this atom is the verifier-facing record.
    """

    id: str
    commitment_ref: str
    chain: str
    transaction_id: str
    block_number: int
    block_timestamp: str  # §1.6.1 UTC datetime string
    commitment_hash: str
    outcome_root: str
    parties: List[str]  # hashed AIDs
    sequence_number: int
    inclusion_proof: str
    via: str = "apl"
    kind: str = ANCHOR_KIND

    def __post_init__(self) -> None:
        validate_utc_datetime(self.block_timestamp, "block_timestamp")

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "id": self.id,
            "commitment_ref": self.commitment_ref,
            "chain": self.chain,
            "via": self.via,
            "transaction_id": self.transaction_id,
            "block_number": self.block_number,
            # The dataclass is mutable, so check the wire value where it leaves.
            "block_timestamp": validate_utc_datetime(
                self.block_timestamp, "block_timestamp"
            ),
            "anchored_data": {
                "commitment_hash": self.commitment_hash,
                "outcome_root": self.outcome_root,
                "parties": list(self.parties),
                "sequence_number": self.sequence_number,
            },
            "inclusion_proof": self.inclusion_proof,
        }
