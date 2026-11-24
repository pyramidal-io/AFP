"""AFP §14 Introduction-Tier atoms.

The seven atom kinds of the ``afp.introduction.v1`` profile (§14.2): the
willingness-directory offer (§14.1), the handshake request + credential
presentation (§14.3), the provisional agreement + its policy block (§14.4), and
the limit-adjustment / downgrade / termination records (§14.6/§14.7).

These mirror the conventions of ``afp_session.atoms``: ``@dataclass`` records,
``*_KIND`` discriminator constants, and content addressing via the *reused*
canonical hashing of the session core (``afp_session.canonical``). The
provisional agreement's content hash is the §14.4 ``D_`` digest of its RFC 8785
JCS bytes, which both agreement signatures cover (``afp_introduction.signing``).
Bilateral signatures reuse ``afp_session.atoms.AfpCommitSignature`` (§12.6.1) —
the introduction tier never re-derives a signature primitive.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

# Reuse the session core's canonical hashing + bilateral-signature type — do NOT
# reimplement crypto (§2.2; §12.6.1).
from afp_session.canonical import digest, jcs_bytes, qb64
from afp_session.atoms import (
    AfpCommitSignature,
    session_datetime_to_unix,
    validate_signed_at,
)

__all__ = [
    "OFFER_KIND",
    "REQUEST_KIND",
    "CREDENTIAL_PRESENTATION_KIND",
    "PROVISIONAL_AGREEMENT_KIND",
    "LIMIT_ADJUSTMENT_KIND",
    "DOWNGRADE_KIND",
    "TERMINATION_KIND",
    "INTRODUCTION_ATOM_KINDS",
    "Envelope",
    "AttestationWindow",
    "InstanceAttestationRoot",
    "AcceptedCredential",
    "IntroductionWireError",
    "IntroductionOffer",
    "IntroductionRequest",
    "CredentialPresentation",
    "IntroductionPolicy",
    "ReputationState",
    "ProvisionalAgreement",
    "LimitAdjustment",
    "Downgrade",
    "Termination",
    "content_digest",
]

OFFER_KIND = "afp:introduction-offer:v1"
REQUEST_KIND = "afp:introduction-request:v1"
CREDENTIAL_PRESENTATION_KIND = "afp:credential-presentation:v1"
PROVISIONAL_AGREEMENT_KIND = "afp:provisional-agreement:v1"
LIMIT_ADJUSTMENT_KIND = "afp:limit-adjustment:v1"
DOWNGRADE_KIND = "afp:downgrade:v1"
TERMINATION_KIND = "afp:termination:v1"

#: The seven atom kinds the profile descriptor (§14.2) registers.
INTRODUCTION_ATOM_KINDS = [
    OFFER_KIND,
    REQUEST_KIND,
    CREDENTIAL_PRESENTATION_KIND,
    PROVISIONAL_AGREEMENT_KIND,
    LIMIT_ADJUSTMENT_KIND,
    DOWNGRADE_KIND,
    TERMINATION_KIND,
]

# Money amounts are decimal strings, never floats — the protocol never loses a
# cent to binary float rounding.


@dataclass(frozen=True)
class Envelope:
    """The negotiated (or entertained) scope ceiling (§14.3/§14.4)."""

    assets: List[str]
    max_per_interaction: str
    max_cumulative: str
    collateral_required: bool


@dataclass(frozen=True)
class AttestationWindow:
    """The explicit v2 credential-validity interval on an introduction request."""

    starts_at: str  # §1.6.1 UTC datetime string, 1970..9999
    ends_at: str

    def __post_init__(self) -> None:
        # §1.6.1 / §14.3 (AFP-0029): checked at construction, so a request is
        # never digested with a noncanonical or unordered window.
        starts = session_datetime_to_unix(self.starts_at, "attestation_window.starts_at")
        ends = session_datetime_to_unix(self.ends_at, "attestation_window.ends_at")
        if starts >= ends:
            raise ValueError("attestation_window.starts_at must precede ends_at")


@dataclass(frozen=True)
class InstanceAttestationRoot:
    """One signed §6.3.1 root constraint in an introduction policy."""

    root_class: str
    root_authority_identifier: str


@dataclass
class IntroductionOffer:
    """``afp:introduction-offer:v1`` — an opt-in willingness record (§14.1).

    Carries *consent to be approached*, never a work descriptor or open call
    (§5.1 reconciliation) — there is deliberately no ``work_descriptor`` field.
    """

    tenant_aid: str
    accepted_credential_classes: List[str]
    entertained_envelope: Envelope
    route_handle: str
    directory_epoch: int
    kind: str = OFFER_KIND


@dataclass
class IntroductionRequest:
    """``afp:introduction-request:v1`` — the PROPOSED-state opener (§14.3)."""

    initiator_tenant_aid: str
    responder_tenant_aid: str
    offered_credential_classes: List[str]
    required_credential_classes: List[str]
    proposed_envelope: Envelope
    attestation_window: AttestationWindow
    kind: str = REQUEST_KIND


@dataclass
class CredentialPresentation:
    """Historical ``afp:credential-presentation:v1`` comparison record.

    Native credential-only wire uses ``afp:credential-envelope:v1``. Historical
    ZKA wire payloads require a transaction or Coord proof. The native policy
    adapter also uses a temporary, never-serialized comparison record holding
    its process-local receive capability; that does not create a ZKA bundle.

    The bundle is carried *verbatim and opaque* (the §12.7 ZKA-prover seam): this
    reference frames/binds it (session-context binding, atomicity), while
    ``evaluate_credentialing`` invokes its required ``presentation_verifier`` on
    this exact object and consumes the verifier's structured public statement.
    """

    presenter_aid: str
    session_context: str
    bundle: object  # an opaque zka:bundle:v1 (proofs verified by the ZKA seam)
    predicate_classes: List[str]  # one predicate per proof (Safeguard 2)
    kind: str = CREDENTIAL_PRESENTATION_KIND


class IntroductionWireError(ValueError):
    """A §14.4 agreement value outside the published shape, emitted or read."""


def _exact_members(data: object, required: set, optional: set, name: str) -> dict:
    """Return ``data`` if it is a JSON object with exactly these members."""
    if type(data) is not dict:
        raise IntroductionWireError(f"{name} must be a JSON object")
    keys = set(data)
    if not required <= keys or not keys <= required | optional:
        raise IntroductionWireError(
            f"{name} must have the members {sorted(required)}"
            + (f" and optionally {sorted(optional)}" if optional else "")
        )
    return data


def _string(value: object, name: str) -> str:
    if type(value) is not str:
        raise IntroductionWireError(f"{name} must be a string")
    return value


def _optional_string(value: object, name: str) -> Optional[str]:
    """An optional member: ``None`` in memory, absent on the wire, never null."""
    return None if value is None else _string(value, name)


def _strings(value: object, name: str) -> List[str]:
    if type(value) is not list:
        raise IntroductionWireError(f"{name} must be an array of strings")
    return [_string(item, f"{name}[]") for item in value]


def _count(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise IntroductionWireError(f"{name} must be a non-negative integer")
    return value


_MAX_SAFE_INTEGER = 2**53 - 1


def _jcs_spelled_integer(value: int) -> Optional[int]:
    """The exact integer an RFC 8785 integer token stands for, if it is one.

    ``1152921504606847000`` is the RFC 8785 spelling of the binary64 value
    2^60, so it stands for ``1152921504606846976``. A token that is the exact
    integer, or that no binary64 value spells this way, gives ``None``.
    """
    if -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
        return None
    try:
        as_float = float(value)
    except OverflowError:
        return None
    if int(as_float) == value or jcs_bytes(as_float, floats=True) != str(value).encode():
        return None
    return int(as_float)


def _received_count(value: object, name: str) -> object:
    """A received §14.4 count as the exact integer its binary64 value equals.

    Counts are binary64 numbers (§14.4 declares ``number``). Python's JSON
    reader gives an exponent token such as RFC 8785's ``1e+21`` as a float and
    the RFC 8785 spelling ``1152921504606847000`` as an int that is not 2^60;
    both are read as the integer of the binary64 value, so the native and the
    RFC 8785 spellings expose the same count. A finite, integral, non-negative
    float is read as its integer; any other float is refused. Other values
    pass unchanged to the constructor's checks.
    """
    if type(value) is float:
        if not math.isfinite(value) or value != math.floor(value) or value < 0:
            raise IntroductionWireError(f"{name} must be a non-negative integer")
        return int(value)
    if type(value) is int:
        exact = _jcs_spelled_integer(value)
        return value if exact is None else exact
    return value


def _received_policy(policy: object) -> object:
    """An agreement's received policy with growth_curve read as binary64 numbers.

    Applied only when parsing a provisional agreement, whose content hash
    covers binary64 values; a standalone :meth:`IntroductionPolicy.from_dict`
    keeps the values as read.
    """
    if type(policy) is dict and "growth_curve" in policy:
        return dict(policy, growth_curve=_received_numbers(policy["growth_curve"]))
    return policy


def _received_numbers(value: object) -> object:
    """``value`` with each RFC 8785-spelled large integer read as its exact integer."""
    if type(value) is dict:
        return {key: _received_numbers(item) for key, item in value.items()}
    if type(value) is list:
        return [_received_numbers(item) for item in value]
    if type(value) is int:
        exact = _jcs_spelled_integer(value)
        return value if exact is None else exact
    return value


def _json_value(value: object, name: str) -> object:
    """A copy of ``value`` if it is a JSON value that reads back unchanged."""
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise IntroductionWireError(f"{name} must not be NaN or infinite")
        return value
    if type(value) is list:
        return [_json_value(item, f"{name}[]") for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise IntroductionWireError(f"{name} member names must be strings")
        return {key: _json_value(item, f"{name}.{key}") for key, item in value.items()}
    raise IntroductionWireError(f"{name} must be a JSON value")


def _json_object(value: object, name: str) -> dict:
    if type(value) is not dict:
        raise IntroductionWireError(f"{name} must be a JSON object")
    return _json_value(value, name)  # type: ignore[return-value]


@dataclass(frozen=True)
class AcceptedCredential:
    """One ``accepted_credentials`` entry of the §14.4 policy block.

    The wire form is the object ``{class: string; valid_until: string}``;
    ``class`` is a Python keyword, so the attribute is ``credential_class``.
    §14.4 types ``valid_until`` as ``string`` and §1.6.1 leaves its spelling
    unresolved, so this reference checks only that it is a string and carries
    it verbatim. It never parses, normalizes or compares the value. Fixtures
    use the §1.6.1 UTC datetime string, one conforming choice.
    """

    credential_class: str
    valid_until: str

    def __post_init__(self) -> None:
        self.to_dict()

    def to_dict(self) -> dict:
        return {
            "class": _string(self.credential_class, "accepted_credentials[].class"),
            "valid_until": _string(
                self.valid_until, "accepted_credentials[].valid_until"
            ),
        }

    @classmethod
    def from_dict(cls, data: object) -> "AcceptedCredential":
        entry = _exact_members(
            data, {"class", "valid_until"}, set(), "accepted_credentials[]"
        )
        return cls(credential_class=entry["class"], valid_until=entry["valid_until"])


def _root_wire(root: object) -> dict:
    if type(root) is not InstanceAttestationRoot:
        raise IntroductionWireError(
            "accepted_instance_attestation_roots entries must be InstanceAttestationRoot"
        )
    return {
        "root_class": _string(root.root_class, "root_class"),
        "root_authority_identifier": _string(
            root.root_authority_identifier, "root_authority_identifier"
        ),
    }


_POLICY_REQUIRED = {
    "permitted_entities",
    "permitted_assets",
    "max_per_interaction",
    "max_cumulative_outstanding",
    "accepted_credentials",
    "accepted_instance_attestation_roots",
    "rotation_policy",
    "growth_curve",
    "agreement_expires_at",
}


@dataclass
class IntroductionPolicy:
    """``afp:introduction-policy:v1`` — the policy block on the agreement (§14.4).

    Every member is checked against the published §14.4 type at construction
    and again by :meth:`to_dict`, with the same checks :meth:`from_dict`
    applies, so the emitter never writes what the reader refuses and a digest
    never covers an excluded value. ``accepted_credentials`` holds
    :class:`AcceptedCredential` entries; ``agreement_expires_at`` is a string
    carried verbatim like ``valid_until``; ``bond_ref`` is absent when unset.
    """

    permitted_entities: List[str]
    permitted_assets: List[str]
    max_per_interaction: str
    max_cumulative_outstanding: str
    bond_ref: Optional[str]
    accepted_credentials: List[AcceptedCredential]
    accepted_instance_attestation_roots: List[InstanceAttestationRoot]
    rotation_policy: str
    growth_curve: Dict[str, str]  # negotiated step/cap/decay (§14.6)
    agreement_expires_at: str

    def __post_init__(self) -> None:
        self.to_dict()

    def to_dict(self) -> dict:
        """The §14.4 wire object; raises :class:`IntroductionWireError` otherwise."""
        if type(self.accepted_credentials) is not list or any(
            type(entry) is not AcceptedCredential for entry in self.accepted_credentials
        ):
            raise IntroductionWireError(
                "accepted_credentials must be a list of AcceptedCredential "
                "{class, valid_until} entries"
            )
        roots = self.accepted_instance_attestation_roots
        if type(roots) is not list:
            raise IntroductionWireError("accepted_instance_attestation_roots must be a list")
        data = {
            "permitted_entities": _strings(self.permitted_entities, "permitted_entities"),
            "permitted_assets": _strings(self.permitted_assets, "permitted_assets"),
            "max_per_interaction": _string(
                self.max_per_interaction, "max_per_interaction"
            ),
            "max_cumulative_outstanding": _string(
                self.max_cumulative_outstanding, "max_cumulative_outstanding"
            ),
            "accepted_credentials": [
                entry.to_dict() for entry in self.accepted_credentials
            ],
            "accepted_instance_attestation_roots": [_root_wire(root) for root in roots],
            "rotation_policy": _string(self.rotation_policy, "rotation_policy"),
            "growth_curve": _json_object(self.growth_curve, "growth_curve"),
            "agreement_expires_at": _string(
                self.agreement_expires_at, "agreement_expires_at"
            ),
        }
        bond_ref = _optional_string(self.bond_ref, "bond_ref")
        if bond_ref is not None:
            data["bond_ref"] = bond_ref
        return data

    @classmethod
    def from_dict(cls, data: object) -> "IntroductionPolicy":
        """Parse a received policy object; the constructor applies the emitter's checks."""
        policy = _exact_members(data, _POLICY_REQUIRED, {"bond_ref"}, "policy")
        if "bond_ref" in policy:
            _string(policy["bond_ref"], "bond_ref")  # present means a string, not null
        credentials = policy["accepted_credentials"]
        if type(credentials) is not list:
            raise IntroductionWireError("accepted_credentials must be an array")
        roots = policy["accepted_instance_attestation_roots"]
        if type(roots) is not list:
            raise IntroductionWireError(
                "accepted_instance_attestation_roots must be an array"
            )
        parsed_roots = []
        for root in roots:
            pair = _exact_members(
                root,
                {"root_class", "root_authority_identifier"},
                set(),
                "accepted_instance_attestation_roots[]",
            )
            parsed_roots.append(
                InstanceAttestationRoot(
                    root_class=pair["root_class"],
                    root_authority_identifier=pair["root_authority_identifier"],
                )
            )
        return cls(
            permitted_entities=policy["permitted_entities"],
            permitted_assets=policy["permitted_assets"],
            max_per_interaction=policy["max_per_interaction"],
            max_cumulative_outstanding=policy["max_cumulative_outstanding"],
            bond_ref=policy.get("bond_ref"),
            accepted_credentials=[
                AcceptedCredential.from_dict(entry) for entry in credentials
            ],
            accepted_instance_attestation_roots=parsed_roots,
            rotation_policy=policy["rotation_policy"],
            growth_curve=policy["growth_curve"],
            agreement_expires_at=policy["agreement_expires_at"],
        )


@dataclass
class ReputationState:
    """The running, signed basis for §14.6 growth (carried on the agreement).

    Checked at construction and by :meth:`to_dict` with the reader's checks;
    ``last_commitment_ref`` is absent on the wire when unset, never null.
    """

    settled_interactions: int
    cumulative_settled_value: str
    slash_events: int
    last_commitment_ref: Optional[str]

    def __post_init__(self) -> None:
        self.to_dict()

    def to_dict(self) -> dict:
        data = {
            "settled_interactions": _count(
                self.settled_interactions, "settled_interactions"
            ),
            "cumulative_settled_value": _string(
                self.cumulative_settled_value, "cumulative_settled_value"
            ),
            "slash_events": _count(self.slash_events, "slash_events"),
        }
        ref = _optional_string(self.last_commitment_ref, "last_commitment_ref")
        if ref is not None:
            data["last_commitment_ref"] = ref
        return data

    @classmethod
    def from_dict(cls, data: object) -> "ReputationState":
        state = _exact_members(
            data,
            {"settled_interactions", "cumulative_settled_value", "slash_events"},
            {"last_commitment_ref"},
            "reputation_state",
        )
        if "last_commitment_ref" in state:
            _string(state["last_commitment_ref"], "last_commitment_ref")
        return cls(
            settled_interactions=_received_count(
                state["settled_interactions"], "settled_interactions"
            ),
            cumulative_settled_value=state["cumulative_settled_value"],
            slash_events=_received_count(state["slash_events"], "slash_events"),
            last_commitment_ref=state.get("last_commitment_ref"),
        )


_AGREEMENT_SIGNATURES = ("initiator_signature", "responder_signature")


def _signature_wire(data: object, name: str) -> dict:
    """One §12.6.1 signature object of the agreement, checked on emit and read.

    ``signed_at`` is returned in the form :func:`validate_signed_at` gives
    it, which is the form the reader stores, so a re-emission is identical.
    """
    signature = _exact_members(
        data, {"signed_by", "kel_event_dig", "signature", "signed_at"}, set(), name
    )
    wire = {
        member: _string(signature[member], f"{name}.{member}")
        for member in ("signed_by", "kel_event_dig", "signature")
    }
    try:
        wire["signed_at"] = validate_signed_at(signature["signed_at"])
    except ValueError as exc:
        raise IntroductionWireError(f"{name}.signed_at: {exc}") from exc
    return wire


def _binary64(value: object, name: str) -> object:
    """``value`` with each number as the IEEE 754 binary64 value it stands for.

    §14.4 numbers are binary64 values in the RFC 8785 number form. An integer
    within 2^53 - 1 stays as it is. A larger integer is accepted only when
    binary64 represents it exactly (``2**60``), and is returned as that float.
    The reader has already turned an RFC 8785 spelling such as
    ``1152921504606847000`` into its exact integer. Any other integer, such as
    ``2**53 + 1``, has no RFC 8785 form that keeps its value and is refused,
    never rounded.
    """
    if type(value) is dict:
        return {key: _binary64(item, f"{name}.{key}") for key, item in value.items()}
    if type(value) is list:
        return [_binary64(item, f"{name}[]") for item in value]
    if type(value) is not int or -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
        return value
    try:
        as_float = float(value)
    except OverflowError as exc:
        raise IntroductionWireError(f"{name} is outside the binary64 range") from exc
    if int(as_float) != value:
        raise IntroductionWireError(
            f"{name} is not a binary64 value: it has no RFC 8785 number form"
        )
    return as_float


@dataclass
class ProvisionalAgreement:
    """``afp:provisional-agreement:v1`` — a §5.5 agreement specialization (§14.4).

    ``tier == "introduction"`` and the bilateral signatures use the §12.6.1
    ``AfpCommitSignature`` shape. Private to the two tenants; never published.

    An agreement under negotiation may lack one or both signatures; its
    unsigned form is :meth:`content`, the §14.4 agreement content.
    :meth:`content_hash` is its ``D_`` RFC 8785 JCS digest, the value both
    signatures cover, and :func:`content_digest` returns it. :meth:`to_dict` emits only the published record, signed by both parties,
    and applies every check :meth:`from_dict` applies, so whatever it emits
    reads back and re-emits unchanged. :meth:`from_dict` never rewrites a
    value: an agreement in the earlier reference shape (array entries,
    numeric times) is rejected, not translated, and parties that want to
    continue under it sign a fresh one.
    """

    tier: str
    policy: IntroductionPolicy
    reputation_state: ReputationState
    initiator_signature: Optional[AfpCommitSignature]
    responder_signature: Optional[AfpCommitSignature]
    kind: str = PROVISIONAL_AGREEMENT_KIND

    def __post_init__(self) -> None:
        self._check_discriminators()

    def _check_discriminators(self) -> None:
        if self.kind != PROVISIONAL_AGREEMENT_KIND:
            raise IntroductionWireError(f"kind must be {PROVISIONAL_AGREEMENT_KIND!r}")
        if self.tier != "introduction":
            raise IntroductionWireError("tier must be 'introduction'")

    def content(self) -> dict:
        """The wire object without the two signatures (what is digested)."""
        self._check_discriminators()
        if type(self.policy) is not IntroductionPolicy:
            raise IntroductionWireError("policy must be an IntroductionPolicy")
        if type(self.reputation_state) is not ReputationState:
            raise IntroductionWireError("reputation_state must be a ReputationState")
        return {
            "kind": self.kind,
            "tier": self.tier,
            "policy": self.policy.to_dict(),
            "reputation_state": self.reputation_state.to_dict(),
        }

    def signer_aids(
        self,
        initiator_signed_by: Optional[str] = None,
        responder_signed_by: Optional[str] = None,
    ) -> tuple:
        """The two ``signed_by`` AIDs the §14.4 agreement content binds.

        Each is taken from its signature when present. A draft without a
        signature takes the planned AID as an argument; an argument that
        differs from a present signature's ``signed_by`` is refused.
        """
        aids = []
        for name, planned in zip(
            _AGREEMENT_SIGNATURES, (initiator_signed_by, responder_signed_by)
        ):
            signature = getattr(self, name)
            present = None
            if signature is not None:
                if type(signature) is not AfpCommitSignature:
                    raise IntroductionWireError(f"{name} must be an AfpCommitSignature")
                present = _string(signature.signed_by, f"{name}.signed_by")
            if planned is not None:
                _string(planned, f"{name}.signed_by")
                if present is not None and planned != present:
                    raise IntroductionWireError(
                        f"{name}.signed_by is {present!r}, not the planned {planned!r}"
                    )
            aid = present if present is not None else planned
            if aid is None:
                raise IntroductionWireError(
                    f"{name}.signed_by is needed: the agreement content binds both signers"
                )
            aids.append(aid)
        return tuple(aids)

    def signed_content(
        self,
        initiator_signed_by: Optional[str] = None,
        responder_signed_by: Optional[str] = None,
    ) -> dict:
        """The §14.4 agreement content both signatures cover.

        :meth:`content` plus each signature object reduced to its
        ``signed_by`` member; ``kel_event_dig``, ``signature`` and
        ``signed_at`` are outside it.
        """
        initiator, responder = self.signer_aids(initiator_signed_by, responder_signed_by)
        data = self.content()
        data["initiator_signature"] = {"signed_by": initiator}
        data["responder_signature"] = {"signed_by": responder}
        return data

    def content_bytes(
        self,
        initiator_signed_by: Optional[str] = None,
        responder_signed_by: Optional[str] = None,
    ) -> bytes:
        """The RFC 8785 JCS UTF-8 bytes of :meth:`signed_content` (§14.4).

        Strings are serialized as carried, including the two policy time
        members. Each number is the binary64 value :func:`_binary64` gives it,
        in the RFC 8785 number form. Content with no RFC 8785 form raises
        :class:`IntroductionWireError`.
        """
        content = _binary64(
            self.signed_content(initiator_signed_by, responder_signed_by), "agreement"
        )
        try:
            return jcs_bytes(content, floats=True)
        except (TypeError, ValueError) as exc:
            raise IntroductionWireError(
                f"agreement content has no RFC 8785 serialization: {exc}"
            ) from exc

    def content_hash(
        self,
        initiator_signed_by: Optional[str] = None,
        responder_signed_by: Optional[str] = None,
    ) -> str:
        """``D_`` + SHA-256 of :meth:`content_bytes`, the §14.4 content hash."""
        return qb64(
            "D",
            hashlib.sha256(
                self.content_bytes(initiator_signed_by, responder_signed_by)
            ).digest(),
        )

    def to_dict(self) -> dict:
        """The published wire record; both signatures are required."""
        data = self.content()
        for name in _AGREEMENT_SIGNATURES:
            signature = getattr(self, name)
            if type(signature) is not AfpCommitSignature:
                raise IntroductionWireError(
                    f"{name} is required: the wire record is signed by both parties"
                )
            try:
                # AfpCommitSignature.to_dict re-checks signed_at (§1.6.1).
                emitted = signature.to_dict()
            except ValueError as exc:
                raise IntroductionWireError(f"{name}.signed_at: {exc}") from exc
            data[name] = _signature_wire(emitted, name)
        return data

    @classmethod
    def from_dict(cls, data: object) -> "ProvisionalAgreement":
        """Parse a received, bilaterally signed agreement (both signatures required)."""
        agreement = _exact_members(
            data,
            {"kind", "tier", "policy", "reputation_state", *_AGREEMENT_SIGNATURES},
            set(),
            "provisional agreement",
        )
        signatures = {
            name: AfpCommitSignature(**_signature_wire(agreement[name], name))
            for name in _AGREEMENT_SIGNATURES
        }
        return cls(
            tier=agreement["tier"],
            policy=IntroductionPolicy.from_dict(_received_policy(agreement["policy"])),
            reputation_state=ReputationState.from_dict(agreement["reputation_state"]),
            kind=agreement["kind"],
            **signatures,
        )


@dataclass
class LimitAdjustment:
    """``afp:limit-adjustment:v1`` — a both-signed envelope change (§14.6)."""

    agreement_ref: str
    new_envelope: Envelope
    reputation_ref: str  # the reputation proof that justified the raise
    sequence_number: int  # monotonic per agreement (non-replay, §12.6.1 chaining)
    initiator_signature: Optional[AfpCommitSignature] = None
    responder_signature: Optional[AfpCommitSignature] = None
    kind: str = LIMIT_ADJUSTMENT_KIND


@dataclass
class Downgrade:
    """``afp:downgrade:v1`` — a go-forward envelope contraction (§14.7)."""

    agreement_ref: str
    new_envelope: Envelope
    trigger: str  # e.g. 'credential_expiry' | 'missed_settlement' | 'dispute' | ...
    unilateral: bool  # True = protective contraction (offer less); never compels the peer
    initiator_signature: Optional[AfpCommitSignature] = None
    responder_signature: Optional[AfpCommitSignature] = None
    kind: str = DOWNGRADE_KIND


@dataclass
class Termination:
    """``afp:termination:v1`` — unconditional exit (§14.7, Safeguard 5)."""

    agreement_ref: str
    terminated_by: str
    residual_settles_against: Optional[str]  # the escrow ref, or None if nothing outstanding
    default: bool = False  # marks a termination that follows a default; AFP defines no portable reputation record of it
    kind: str = TERMINATION_KIND


def content_digest(atom) -> str:
    """Stable content hash over an atom's public fields.

    The provisional agreement returns its §14.4 content hash
    (:meth:`ProvisionalAgreement.content_hash`): ``D_`` over the RFC 8785 JCS
    bytes of its wire form with each signature reduced to ``signed_by``, the
    value both agreement signatures cover. It needs both ``signed_by`` AIDs, so
    a draft without them has no digest here; call ``content_hash`` with the
    planned AIDs instead. Every other atom reuses the session core's canonical
    digest (sorted-key JSON), with the policy block in its wire form
    (``to_dict()``), and excludes any signature members.
    """
    if isinstance(atom, ProvisionalAgreement):
        return atom.content_hash()
    excluded = {"initiator_signature", "responder_signature"}
    if hasattr(atom, "to_dict"):
        fields = atom.to_dict()
    else:
        fields = asdict(atom)
    payload = {k: v for k, v in fields.items() if k not in excluded}
    return qb64("X", digest(payload))
