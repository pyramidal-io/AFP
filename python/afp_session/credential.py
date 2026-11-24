"""Native ZKC credential carriage inside an authenticated AFP session.

AFP owns this signed carrier, while the deployment's ZKC adapter verifies the
exact native presentation and APR. No ZKA bundle, settlement claim, or generic
subject-AID proof is manufactured by this module.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
from copy import deepcopy
from enum import Enum
import hashlib
import json
import re
import weakref
from typing import Callable, Mapping, Optional

from .atoms import AfpPartyRef
from .bundle import session_context_field
from .canonical import jcs_bytes, qb64
from .presentation import (
    AfpTrustFlow,
    RequiredPredicatePolicy,
    VerifiedPresentation,
    ZkcPresentationEvidence,
    ZkcVerifiedPublicStatement,
)


CREDENTIAL_ENVELOPE_KIND = "afp:credential-envelope:v1"
_WIRE_KEYS = frozenset({
    "kind", "session_ref", "session_context", "profile", "message_class",
    "generated_at", "expires_at", "presentation", "apr", "sender",
})
_PARTY_KEYS = frozenset({"tenant_aid", "entity_aid", "kel_event_dig", "signature"})
_SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}\Z")


class CredentialEnvelopeError(ValueError):
    """A native carrier or its credential acceptance boundary failed."""


def _json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialEnvelopeError("duplicate JSON member")
        result[key] = value
    return result


def _json_constant(_value: str) -> None:
    raise CredentialEnvelopeError("non-finite JSON number")


def _json_snapshot(value: object) -> dict:
    if type(value) is not dict:
        raise CredentialEnvelopeError("native artifact must be a JSON object")
    try:
        def validate(item: object) -> None:
            if type(item) is dict:
                if any(type(key) is not str for key in item):
                    raise TypeError
                for child in item.values():
                    validate(child)
            elif type(item) is list:
                for child in item:
                    validate(child)
            elif item is not None and type(item) not in (str, int, float, bool):
                raise TypeError

        validate(value)
        # Validate the signature preimage without reparsing JCS: JCS spells an
        # integral float as an integer, but a lower verifier must still see the
        # original JSON primitive type and reject it where exact ints are due.
        jcs_bytes(value, floats=True)
        return deepcopy(value)
    except (TypeError, ValueError, UnicodeError, OverflowError):
        raise CredentialEnvelopeError("native artifact is not canonical JSON") from None


@dataclass
class AfpCredentialEnvelope:
    """Closed signed carrier, retaining native ZKC/APR objects without rewriting.

    ``profile`` names the AFP session profile. Native presentation versions and
    privacy profiles remain ZKC-owned. ``sender.signature`` covers the JCS
    content hash including the unsigned sender reference and both native objects.
    """

    session_ref: str
    session_context: str
    profile: str
    message_class: str
    generated_at: int
    expires_at: int
    presentation: dict
    apr: dict
    sender: AfpPartyRef
    kind: str = CREDENTIAL_ENVELOPE_KIND

    def __post_init__(self) -> None:
        if self.kind != CREDENTIAL_ENVELOPE_KIND or type(self.kind) is not str:
            raise CredentialEnvelopeError("unsupported credential carrier kind")
        for name in ("session_ref", "session_context", "profile", "message_class"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise CredentialEnvelopeError("credential carrier text field is malformed")
        try:
            session_context_field(self.session_context)
        except ValueError:
            raise CredentialEnvelopeError("credential session context is malformed") from None
        for value in (self.generated_at, self.expires_at):
            if type(value) is not int or not 0 < value <= 2**53 - 1:
                raise CredentialEnvelopeError("credential timestamps must be positive exact seconds")
        if self.generated_at >= self.expires_at:
            raise CredentialEnvelopeError("credential expiry must follow generation")
        if type(self.sender) is not AfpPartyRef:
            raise CredentialEnvelopeError("credential sender must be an AfpPartyRef")
        if any(type(value) is not str or not value for value in self.sender.unsigned().values()):
            raise CredentialEnvelopeError("credential sender identity is malformed")
        if type(self.sender.signature) is not str:
            raise CredentialEnvelopeError("credential signature is malformed")
        if self.sender.signature and _SIGNATURE_HEX.fullmatch(self.sender.signature) is None:
            raise CredentialEnvelopeError("credential signature is not canonical lowercase hex")
        self.sender = AfpPartyRef.from_dict(self.sender.to_dict())
        self.presentation = _json_snapshot(self.presentation)
        self.apr = _json_snapshot(self.apr)
        if self.presentation.get("version") not in {"zkc:proof:v1", "zkc:proof:v2"}:
            raise CredentialEnvelopeError("unsupported native ZKC presentation version")

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "session_ref": self.session_ref,
            "session_context": self.session_context,
            "profile": self.profile,
            "message_class": self.message_class,
            "generated_at": self.generated_at,
            "expires_at": self.expires_at,
            "presentation": _json_snapshot(self.presentation),
            "apr": _json_snapshot(self.apr),
            "sender": self.sender.to_dict(),
        }

    @property
    def content_hash(self) -> str:
        content = self.to_dict()
        content["sender"] = self.sender.unsigned()
        return qb64("D", hashlib.sha256(jcs_bytes(content, floats=True)).digest())

    def to_json(self) -> bytes:
        # Wire serialization preserves native primitive types; only the signed
        # content hash uses JCS. Parsing does not silently repair invalid native
        # input types for the deployment's ZKC verifier.
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "AfpCredentialEnvelope":
        try:
            if type(raw) is not bytes:
                raise TypeError
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs,
                              parse_constant=_json_constant)
            if type(data) is not dict or set(data) != _WIRE_KEYS:
                raise ValueError
            if type(data["sender"]) is not dict or set(data["sender"]) != _PARTY_KEYS:
                raise ValueError
            data["sender"] = AfpPartyRef.from_dict(data["sender"])
            envelope = cls(**data)
            if not envelope.sender.signature:
                raise ValueError
            return envelope
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
            raise CredentialEnvelopeError("invalid native credential envelope") from None


@dataclass(frozen=True)
class NativeCredentialVerificationRequest:
    """Detached adapter input; all expected values come from the local verifier.

    The adapter MUST verify the exact native presentation and APR retained in
    ``envelope_wire`` and derive evidence from authenticated proof/APR contents.
    It MUST reject a generic predicate lacking AFP's authenticated subject-AID
    mechanism. Neither this request nor its carrier labels prove a credential.
    """

    envelope_wire: bytes
    expected_flow: AfpTrustFlow
    expected_presenter_aid: str
    expected_verifier_aid: str
    expected_apr_signer_public_key: bytes
    expected_session_context: str
    expected_session_policy_hash: str
    required_predicates: RequiredPredicatePolicy
    carrier_kind: str = CREDENTIAL_ENVELOPE_KIND
    zka_bundle_kind: None = None

    @property
    def envelope(self) -> AfpCredentialEnvelope:
        return AfpCredentialEnvelope.from_json(self.envelope_wire)


@dataclass(frozen=True)
class NativeCredentialVerification:
    """Structured adapter result bound to the exact signed carrier content.

    This is the trusted deployment adapter seam, not a portable proof object.
    ``statement`` must be proof-authenticated, not copied from evidence labels.
    """

    envelope_content_hash: str
    evidence: ZkcPresentationEvidence
    statement: ZkcVerifiedPublicStatement


NativeCredentialVerifier = Callable[
    [NativeCredentialVerificationRequest], Optional[NativeCredentialVerification]
]


@dataclass(frozen=True)
class NativeAprSignerBindingRequest:
    """Local resolver inputs; received APR keys cannot bootstrap their authority."""

    expected_verifier_aid: str
    expected_kel_event_dig: str
    expected_keri_public_key: bytes
    expected_session_ref: str
    expected_session_context: str
    expected_session_policy_hash: str
    expected_flow: AfpTrustFlow


@dataclass(frozen=True)
class NativeAprSignerBinding:
    """Deployment-authenticated APR key association to a current verifier KEL.

    No production association mechanism is supplied here. A resolver must
    independently authenticate this binding rather than copying APR labels.
    """

    public_key: bytes
    verifier_aid: str
    kel_event_dig: str


AprSignerBindingResolver = Callable[
    [NativeAprSignerBindingRequest], Optional[NativeAprSignerBinding]
]


_ACCEPTED_MINT_TOKEN = object()
_RESULT_ISSUERS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _record_json(value: object) -> object:
    """Integrity snapshot of reference records; this is not a wire artifact."""
    if isinstance(value, Enum):
        return value.value
    if type(value) is bytes:
        return value.hex()
    if type(value) is int and abs(value) > 2**53 - 1:
        return {"exact_integer": str(value)}
    if is_dataclass(value):
        return {field.name: _record_json(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {key: _record_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_record_json(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_record_json(item) for item in value)
    return value


@dataclass(frozen=True, init=False, eq=False)
class AcceptedCredentialEnvelope:
    """Receive-issued capability, revalidated against its owning Instance.

    Accessors return detached records. Direct construction and reconstructed
    lookalikes are not acceptance evidence. Like the session capability, this
    is process-local API hardening, not a sandbox against trusted adapter code.
    """

    _owner: object
    _envelope_wire: bytes
    _verified_presentation: VerifiedPresentation
    _evidence: ZkcPresentationEvidence
    _statement: ZkcVerifiedPublicStatement
    _session_content_hash: str

    def __init__(self, owner: object, envelope_wire: bytes,
                 verified_presentation: VerifiedPresentation,
                 evidence: ZkcPresentationEvidence,
                 statement: ZkcVerifiedPublicStatement,
                 session_content_hash: str, *, _mint_token: object = None):
        if _mint_token is not _ACCEPTED_MINT_TOKEN:
            raise CredentialEnvelopeError("native credential result must be receive-issued")
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_envelope_wire", bytes(envelope_wire))
        object.__setattr__(self, "_verified_presentation", replace(verified_presentation))
        object.__setattr__(self, "_evidence", replace(evidence))
        object.__setattr__(self, "_statement", replace(statement))
        object.__setattr__(self, "_session_content_hash", session_content_hash)
        _RESULT_ISSUERS[self] = owner

    def _snapshot(self) -> bytes:
        return jcs_bytes({
            "envelope_wire": self._envelope_wire.hex(),
            "verified_presentation": _record_json(self._verified_presentation),
            "evidence": _record_json(self._evidence),
            "statement": _record_json(self._statement),
            "session_content_hash": self._session_content_hash,
        }, floats=True)

    @property
    def envelope_wire(self) -> bytes:
        require_verified_native_credential(self)
        return self._envelope_wire

    @property
    def verified_presentation(self) -> VerifiedPresentation:
        require_verified_native_credential(self)
        return replace(self._verified_presentation)

    @property
    def evidence(self) -> ZkcPresentationEvidence:
        require_verified_native_credential(self)
        return replace(self._evidence)

    @property
    def statement(self) -> ZkcVerifiedPublicStatement:
        require_verified_native_credential(self)
        return replace(self._statement)

    @property
    def proven_predicates(self) -> tuple:
        return self.statement.proven_predicates

    @property
    def envelope(self) -> AfpCredentialEnvelope:
        return AfpCredentialEnvelope.from_json(self.envelope_wire)

    def __reduce__(self) -> object:
        raise TypeError("native credential acceptance cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("native credential acceptance cannot be serialized")


def require_verified_native_credential(result: AcceptedCredentialEnvelope) -> AcceptedCredentialEnvelope:
    """Require an unchanged receive-issued result and its current live session."""
    if type(result) is not AcceptedCredentialEnvelope:
        raise CredentialEnvelopeError("native credential result is not receive-issued")
    try:
        issuer = _RESULT_ISSUERS.get(result)
        if issuer is None or issuer is not result._owner:
            raise CredentialEnvelopeError("native credential result issuer changed")
        issuer._revalidate_native_credential(result)
    except CredentialEnvelopeError:
        raise
    except Exception:
        raise CredentialEnvelopeError("native credential result cannot be revalidated") from None
    return result


__all__ = [
    "CREDENTIAL_ENVELOPE_KIND", "CredentialEnvelopeError", "AfpCredentialEnvelope",
    "NativeCredentialVerificationRequest", "NativeCredentialVerification",
    "NativeCredentialVerifier", "AcceptedCredentialEnvelope",
    "require_verified_native_credential",
    "NativeAprSignerBindingRequest", "NativeAprSignerBinding", "AprSignerBindingResolver",
]
