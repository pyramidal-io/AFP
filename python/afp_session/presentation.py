"""ZKC v0.4 presentation-profile policy and AFP request binding.

ZKC verifies proof cryptography. AFP verifies that the verified result belongs
to the KERI-authenticated presenter, APR signer, session, and AFP flow that is
about to consume it, *and* that the predicate it proves is the one this flow
requires (§5.9 / §6.3 / §14.4). This module is deliberately stdlib-only.

The seam is a split, not a delegation of everything: AFP compares public inputs
against caller-authenticated comparands and never proves anything, while the
deployment-supplied :data:`ZkcVerifier` callback owns the cryptography and owns
the claims that ``evidence.proven_predicates`` is what the circuit actually
proved and that its returned credential-subject AID came from authenticated
proof material. Neither half is sufficient alone.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Callable, FrozenSet, Mapping, Optional, Tuple

from .atoms import session_datetime_to_unix
from .bundle import BundleError, session_context_field
from .canonical import canonical_bytes, digest_hex

ANONYMOUS_PROFILE = "zkc:presentation:anonymous:v1"
SCOPED_PROFILE = "zkc:presentation:scoped:v1"
LINKABLE_PROFILE = "zkc:presentation:linkable:v1"
AFP_ZKC_PRESENTATION_CONTEXT_V2 = "afp:zkc-presentation-context:v2"
ZKA_BUNDLE_VERSION = "zka:bundle:v1"
NATIVE_CREDENTIAL_CARRIER = "afp:credential-envelope:v1"

_BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
_HANDLE_FIELDS = frozenset(
    {"holderCommitment", "presentationPseudonym", "scopeId"}
)
_UNSUPPORTED_REBIND_FIELDS = frozenset(
    {
        "oldPresentationPseudonym",
        "newPresentationPseudonym",
        "oldHolderCommitment",
        "newHolderCommitment",
        "zkcCredentialRebind",
        "zkc_credential_rebind",
    }
)


class AfpTrustFlow(str, Enum):
    TELEMETRY = "telemetry"
    BILATERAL = "bilateral"
    INTRODUCTION = "introduction"
    OPEN_FEDERATION = "open-federation"


class PresentationBindingError(ValueError):
    """A verified ZKC presentation is not valid for this AFP interaction."""


#: The §6.3 telemetry predicate catalog, which is **closed**: a telemetry proof
#: using an unregistered predicate identifier is not AFP-conforming. The closure
#: is a tenant protection — it bounds what an operator may demand as a condition
#: of service — so it constrains only :attr:`AfpTrustFlow.TELEMETRY`. Safeguard 1
#: (Predicate Pluralism, §12.8) reserves the counterparty-facing flows for a
#: caller-supplied :class:`RequiredPredicatePolicy`, and AFP fixes no catalog for
#: them. ``tests/python/test_public_input_classification.py`` re-derives this set
#: from ``protocol-family/afp-interface-surface-v1.json`` so it cannot drift.
AFP_TELEMETRY_PREDICATE_CATALOG = frozenset(
    {
        "afp.telemetry.instance_attestation.v1",
        "afp.telemetry.instance_attestation.v2",
        "afp.telemetry.build_currency.v1",
        "afp.telemetry.compute_quota.v1",
        "afp.telemetry.audit_log_integrity.v1",
    }
)

#: The three literal §6.3.1 root classes. "The `root class` MUST be one of the
#: three literal values above" — anything else is an unknown class and MUST be
#: rejected.
INSTANCE_ATTESTATION_ROOT_CLASSES = frozenset(
    {"root:build-provenance", "root:tee-attestation", "root:publisher-manifest"}
)

#: The one predicate whose public statement carries a §6.3.1 root class. §6.3.1
#: freezes v1 semantically as well as textually: a v1 proof MUST NOT be
#: reinterpreted as carrying a generic root class, so only v2 may name one.
INSTANCE_ATTESTATION_PREDICATE_V2 = "afp.telemetry.instance_attestation.v2"

# A predicate identifier ends in its own version token, in either the AFP dotted
# namespace (afp.telemetry.build_currency.v1) or the ZKC colon namespace
# (zkc:proof:kyc:v2). Binding the two together is what makes "an unsupported
# predicate version" (§6.3) detectable rather than a free label.
_PREDICATE_VERSION = re.compile(r"[.:]v(?P<version>\d+)$")
_WHOLE_SECOND_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _require_whole_second_utc(label: str, value: object) -> str:
    """Return ``value`` if it is a canonical whole-second UTC timestamp (§6.3.1)."""
    if type(value) is not str or not _WHOLE_SECOND_UTC.match(value):
        raise PresentationBindingError(
            f"{label} must be a canonical whole-second UTC YYYY-MM-DDTHH:MM:SSZ timestamp"
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PresentationBindingError(f"{label} is not a real UTC instant") from exc
    return value


@dataclass(frozen=True)
class ProvenPredicate:
    """One atomic predicate a presentation claims to have proven (Safeguard 2).

    This is the meaning-bearing public input. AFP compares it against the
    caller's :class:`RequiredPredicatePolicy`; the :data:`ZkcVerifier` callback
    is what makes it more than a label, by refusing any evidence whose declared
    statements are not exactly what its circuit proved.

    ``attestation_window`` is ``(starts_at, ends_at)`` in canonical whole-second
    UTC. For §6.3.1 v2 instance attestation the root fields, window, and subject
    are all mandatory; for every other predicate the root fields are forbidden,
    because only v2 carries a root class.
    """

    predicate_id: str
    predicate_version: str
    root_class: Optional[str] = None
    root_authority_identifier: Optional[str] = None
    attestation_window: Optional[Tuple[str, str]] = None
    subject_aid: Optional[str] = None

    def __post_init__(self) -> None:
        # An exact str: a subclass can carry its own __eq__/__hash__ and satisfy a
        # set-membership test while reporting a different identifier.
        if type(self.predicate_id) is not str or not self.predicate_id:
            raise PresentationBindingError("predicate_id must be a non-empty string")
        if type(self.predicate_version) is not str or not self.predicate_version:
            raise PresentationBindingError(
                "predicate_version must be a non-empty string"
            )
        match = _PREDICATE_VERSION.search(self.predicate_id)
        if match is None:
            raise PresentationBindingError(
                f"predicate {self.predicate_id!r} does not carry a version token"
            )
        if match.group("version") != self.predicate_version:
            raise PresentationBindingError(
                f"predicate {self.predicate_id!r} declares version "
                f"{self.predicate_version!r}, which its identifier contradicts"
            )

        is_attestation_v2 = self.predicate_id == INSTANCE_ATTESTATION_PREDICATE_V2
        if is_attestation_v2:
            if self.root_class is None:
                raise PresentationBindingError(
                    "instance attestation must name a root class"
                )
            if (
                type(self.root_class) is not str
                or self.root_class not in INSTANCE_ATTESTATION_ROOT_CLASSES
            ):
                raise PresentationBindingError(
                    f"unknown instance-attestation root class {self.root_class!r}"
                )
            if (
                type(self.root_authority_identifier) is not str
                or not self.root_authority_identifier
            ):
                raise PresentationBindingError(
                    "instance attestation must name a root authority identifier"
                )
            if self.attestation_window is None:
                raise PresentationBindingError(
                    "instance attestation must carry an attestation window"
                )
            if type(self.subject_aid) is not str or not self.subject_aid:
                raise PresentationBindingError(
                    "instance attestation must name its machine subject AID"
                )
        elif self.root_class is not None or self.root_authority_identifier is not None:
            if any(
                value is not None and type(value) is not str
                for value in (self.root_class, self.root_authority_identifier)
            ):
                raise PresentationBindingError(
                    "predicate root fields must be exact strings or None"
                )
            raise PresentationBindingError(
                f"predicate {self.predicate_id!r} MUST NOT carry a root class; only "
                f"{INSTANCE_ATTESTATION_PREDICATE_V2} does"
            )

        if self.attestation_window is not None:
            if type(self.attestation_window) is not tuple:
                raise PresentationBindingError(
                    "attestation_window must be an exact (starts_at, ends_at) tuple"
                )
            window = self.attestation_window
            if len(window) != 2:
                raise PresentationBindingError(
                    "attestation_window must be a (starts_at, ends_at) pair"
                )
            starts_at = _require_whole_second_utc(
                "attestation_window.starts_at", window[0]
            )
            ends_at = _require_whole_second_utc(
                "attestation_window.ends_at", window[1]
            )
            if starts_at >= ends_at:
                raise PresentationBindingError(
                    "attestation_window.starts_at MUST precede ends_at"
                )
            if self.predicate_id == INSTANCE_ATTESTATION_PREDICATE_V2:
                # §1.6.1 / AFP-0220: the v2 circuit also exposes both endpoints
                # as unsigned 64-bit Unix seconds, so neither precedes 1970.
                for label, value in (
                    ("attestation_window.starts_at", starts_at),
                    ("attestation_window.ends_at", ends_at),
                ):
                    try:
                        session_datetime_to_unix(value, label)
                    except ValueError as exc:
                        raise PresentationBindingError(str(exc)) from exc
            object.__setattr__(self, "attestation_window", (starts_at, ends_at))


def _predicate_wire(predicate: ProvenPredicate) -> tuple[object, ...]:
    """Snapshot predicate scalars with exact primitive-type validation."""
    if type(predicate) is not ProvenPredicate:
        raise PresentationBindingError(
            "proven_predicates must contain ProvenPredicate records"
        )
    values = (
        predicate.predicate_id,
        predicate.predicate_version,
        predicate.root_class,
        predicate.root_authority_identifier,
        predicate.attestation_window,
        predicate.subject_aid,
    )
    if any(type(value) is not str or not value for value in values[:2]):
        raise PresentationBindingError(
            "predicate identifier and version must be exact non-empty strings"
        )
    for value in values[2:4] + values[5:6]:
        if value is not None and (type(value) is not str or not value):
            raise PresentationBindingError(
                "predicate scalar fields must be exact non-empty strings or None"
            )
    if values[4] is not None and (
        type(values[4]) is not tuple
        or len(values[4]) != 2
        or any(type(item) is not str or not item for item in values[4])
    ):
        raise PresentationBindingError("predicate attestation window is malformed")
    return values


def _snapshot_predicates(
    predicates: object,
) -> Tuple[Tuple[ProvenPredicate, ...], Tuple[tuple[object, ...], ...]]:
    """Return validated predicate records plus immutable comparison wires."""
    if type(predicates) is not tuple:
        raise PresentationBindingError("proven_predicates must be an exact tuple")
    wires = tuple(_predicate_wire(predicate) for predicate in predicates)
    canonical = tuple(ProvenPredicate(*wire) for wire in wires)
    return canonical, wires


def root_pair_of(predicate: "ProvenPredicate") -> Optional[Tuple[str, str]]:
    """The §14.4 ``(root_class, root_authority_identifier)`` pair, or None.

    A module function reading the fields directly, not a method: a §14.4 gate
    that dispatched through an overridable attribute could be answered by the
    object it is meant to constrain.
    """
    root_class = predicate.root_class
    if root_class is None:
        return None
    return (root_class, predicate.root_authority_identifier or "")


@dataclass(frozen=True)
class RequiredPredicatePolicy:
    """What the *verifier* requires a presentation to prove, for one flow.

    Caller-supplied by construction: Safeguard 1 (§12.8) protects a verifier's
    freedom to choose predicates in a bilateral interaction between equals, so
    AFP never fixes this set for a counterparty-facing flow. It is the only
    trusted input to the meaning comparison — everything on the evidence record
    is holder-declared.

    ``accepted_predicate_ids`` is a closed allow-list: a presentation proving
    something outside it is rejected rather than silently authorized (§14.4).
    ``required_predicate_ids`` is what MUST appear. The §14.4 biconditional is
    enforced here: v2 instance attestation is acceptable only where at least one
    ``(root_class, root_authority_identifier)`` pair is pinned, and the pairs are
    empty wherever v2 is not acceptable.
    """

    accepted_predicate_ids: FrozenSet[str]
    required_predicate_ids: FrozenSet[str] = frozenset()
    accepted_instance_attestation_roots: FrozenSet[Tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        try:
            accepted_values = tuple(self.accepted_predicate_ids)
            required_values = tuple(self.required_predicate_ids)
            raw_roots = tuple(self.accepted_instance_attestation_roots)
        except TypeError as exc:
            raise PresentationBindingError(
                "required-predicate policy fields must be iterable collections"
            ) from exc
        if any(
            type(value) is not str or not value
            for value in accepted_values + required_values
        ):
            raise PresentationBindingError(
                "policy predicate identifiers must be exact non-empty strings"
            )
        if any(
            type(pair) is not tuple
            or len(pair) != 2
            or any(type(item) is not str or not item for item in pair)
            for pair in raw_roots
        ):
            raise PresentationBindingError(
                "accepted attestation roots must contain exact string pairs"
            )
        accepted = frozenset(accepted_values)
        required = frozenset(required_values)
        roots = frozenset(raw_roots)
        object.__setattr__(self, "accepted_predicate_ids", accepted)
        object.__setattr__(self, "required_predicate_ids", required)
        object.__setattr__(self, "accepted_instance_attestation_roots", roots)

        if not accepted:
            raise PresentationBindingError(
                "a required-predicate policy MUST accept at least one predicate; an "
                "empty allow-list can only authorize a boolean 'verified' label (§5.9)"
            )
        unsatisfiable = required - accepted
        if unsatisfiable:
            raise PresentationBindingError(
                f"required predicates {sorted(unsatisfiable)!r} are not in the "
                f"accepted set, so the policy can never be satisfied"
            )
        for root_class, authority in roots:
            if root_class not in INSTANCE_ATTESTATION_ROOT_CLASSES:
                raise PresentationBindingError(
                    f"unknown instance-attestation root class {root_class!r}"
                )
        # §14.4: "When accepted_credentials contains afp.telemetry.instance_
        # attestation.v2, accepted_instance_attestation_roots MUST contain at
        # least one pair ... If v2 is not required the array MUST be empty; it
        # MUST NOT silently authorize an attestation predicate."
        if INSTANCE_ATTESTATION_PREDICATE_V2 in accepted and not roots:
            raise PresentationBindingError(
                f"accepting {INSTANCE_ATTESTATION_PREDICATE_V2} requires at least one "
                f"signed (root_class, root_authority_identifier) pair (§14.4)"
            )
        if roots and INSTANCE_ATTESTATION_PREDICATE_V2 not in accepted:
            raise PresentationBindingError(
                f"attestation roots are pinned but {INSTANCE_ATTESTATION_PREDICATE_V2} "
                f"is not accepted; the pairs MUST be empty where v2 is not required (§14.4)"
            )

    @property
    def digest(self) -> str:
        """A stable content hash of this policy, carried on the verified result."""
        return "0x" + digest_hex(
            {
                "kind": "afp:required-predicate-policy:v1",
                "accepted_predicate_ids": sorted(self.accepted_predicate_ids),
                "required_predicate_ids": sorted(self.required_predicate_ids),
                "accepted_instance_attestation_roots": sorted(
                    list(pair) for pair in self.accepted_instance_attestation_roots
                ),
            }
        )


def _snapshot_required_predicates(
    policy: RequiredPredicatePolicy,
) -> RequiredPredicatePolicy:
    """Rebuild caller policy from exact primitives at the verification boundary."""
    if type(policy) is not RequiredPredicatePolicy:
        raise PresentationBindingError(
            "required_predicates must be a RequiredPredicatePolicy"
        )
    try:
        accepted = tuple(policy.accepted_predicate_ids)
        required = tuple(policy.required_predicate_ids)
        roots = tuple(policy.accepted_instance_attestation_roots)
    except TypeError as exc:
        raise PresentationBindingError(
            "required predicate policy snapshot is malformed"
        ) from exc
    if any(
        type(value) is not str or not value for value in accepted + required
    ) or any(
        type(pair) is not tuple
        or len(pair) != 2
        or any(type(value) is not str or not value for value in pair)
        for pair in roots
    ):
        raise PresentationBindingError(
            "required predicate policy contains mutable scalar aliases"
        )
    return RequiredPredicatePolicy(
        accepted_predicate_ids=frozenset(accepted),
        required_predicate_ids=frozenset(required),
        accepted_instance_attestation_roots=frozenset(roots),
    )


@dataclass(frozen=True)
class VerifiedPresentation:
    """The verified public statement a caller may act on (§5.9).

    Returned only by :func:`verify_presentation_binding`. "A boolean envelope
    label that merely says 'verified' is insufficient" (§5.9) — a caller that
    consumes this record consumes *what* was proven, for *which* flow, under
    *which* policy.
    """

    flow: AfpTrustFlow
    profile: str
    credential_subject_aid: str
    session_context: str
    proven_predicate_ids: FrozenSet[str]
    required_predicates_digest: str


@dataclass(frozen=True)
class ZkcVerifiedPublicStatement:
    """The exact public statement authenticated by the deployment's ZKC verifier.

    ``credential_subject_aid`` MUST come from an issuer-authenticated claim or
    an independently verified companion subject-binding proof.  A verifier
    MUST NOT copy the holder-declared value from
    :class:`ZkcPresentationEvidence`.  The current generic ZKC KYC and
    jurisdiction profiles do not prove an AID by themselves, so an adapter
    using only either profile cannot construct this statement successfully.

    Rebind proofs are intentionally outside this reference verifier's accepted
    surface and are rejected by :func:`verify_presentation_binding`.
    """

    proof_context: str
    credential_subject_aid: str
    proven_predicates: Tuple[ProvenPredicate, ...]

    def __post_init__(self) -> None:
        if type(self.proof_context) is not str or not self.proof_context:
            raise PresentationBindingError(
                "verified proof context must be a non-empty exact string"
            )
        if (
            type(self.credential_subject_aid) is not str
            or not self.credential_subject_aid
        ):
            raise PresentationBindingError(
                "verified credential subject AID must be a non-empty exact string"
            )
        predicates, _ = _snapshot_predicates(self.proven_predicates)
        object.__setattr__(self, "proven_predicates", predicates)


@dataclass(frozen=True)
class PresentationPolicy:
    accepted_profiles: frozenset[str]
    default_profile: str
    downgrades: frozenset[tuple[str, str]]

    def allows_downgrade(self, requested: str, active: str) -> bool:
        return (requested, active) in self.downgrades


_ALL_PROFILES = frozenset(
    {ANONYMOUS_PROFILE, SCOPED_PROFILE, LINKABLE_PROFILE}
)
_FLOW_POLICIES = MappingProxyType(
    {
        AfpTrustFlow.TELEMETRY: PresentationPolicy(
            accepted_profiles=_ALL_PROFILES,
            default_profile=ANONYMOUS_PROFILE,
            downgrades=frozenset({(SCOPED_PROFILE, ANONYMOUS_PROFILE)}),
        ),
        AfpTrustFlow.BILATERAL: PresentationPolicy(
            accepted_profiles=_ALL_PROFILES,
            default_profile=ANONYMOUS_PROFILE,
            downgrades=frozenset({(SCOPED_PROFILE, ANONYMOUS_PROFILE)}),
        ),
        AfpTrustFlow.INTRODUCTION: PresentationPolicy(
            accepted_profiles=frozenset({SCOPED_PROFILE, LINKABLE_PROFILE}),
            default_profile=SCOPED_PROFILE,
            downgrades=frozenset(),
        ),
        AfpTrustFlow.OPEN_FEDERATION: PresentationPolicy(
            accepted_profiles=frozenset({SCOPED_PROFILE, LINKABLE_PROFILE}),
            default_profile=SCOPED_PROFILE,
            downgrades=frozenset(),
        ),
    }
)


def as_trust_flow(flow: object) -> AfpTrustFlow:
    """Coerce ``flow`` to :class:`AfpTrustFlow`, failing closed on an unknown one.

    ``AfpTrustFlow`` subclasses ``str``, so an equality test against a bare
    string succeeds while an identity test does not. Every flow comparison runs
    through this, so a caller that passes ``"telemetry"`` reaches the same policy
    and the same closed-catalog rule as one that passes the member.
    """
    if type(flow) is AfpTrustFlow:
        return flow
    if type(flow) is not str:
        raise PresentationBindingError(
            "AFP trust flow must be an AfpTrustFlow value or exact string"
        )
    try:
        return AfpTrustFlow(flow)
    except ValueError as exc:
        raise PresentationBindingError(f"unknown AFP trust flow {flow!r}") from exc


def flow_policy(flow: AfpTrustFlow) -> PresentationPolicy:
    try:
        return _FLOW_POLICIES[as_trust_flow(flow)]
    except KeyError as exc:  # pragma: no cover - every member has a policy
        raise PresentationBindingError(f"unknown AFP trust flow {flow!r}") from exc


def afp_scope_policy(session_policy_hash: str) -> str:
    """Return the signed ZKC scope policy for one AFP session policy."""
    if type(session_policy_hash) is not str or not session_policy_hash:
        raise ValueError("session_policy_hash must be a non-empty exact string")
    return f"protocol:afp:{session_policy_hash}"


def _string_to_field(value: str) -> int:
    digest = hashlib.blake2b(
        b"ZKC-String-" + value.encode("utf-8"), digest_size=64
    ).digest()
    return int.from_bytes(digest, "little") % _BN254_SCALAR_MODULUS


def _hash_bytes_to_field(domain: str, payload: bytes) -> int:
    digest = hashlib.blake2b(
        domain.encode("utf-8") + b"\x00" + payload, digest_size=64
    ).digest()
    return int.from_bytes(digest, "big") % _BN254_SCALAR_MODULUS


def derive_scope_id(
    apr_signer_public_key: bytes, scope_policy: str, rotation_epoch: int
) -> int:
    """Reproduce ZKC v0.4 §5.9.1's native scoped-identifier derivation."""
    if (
        type(apr_signer_public_key) is not bytes
        or len(apr_signer_public_key) != 33
        or apr_signer_public_key[0] not in (2, 3)
    ):
        raise ValueError("APR signer must use a SEC1 compressed public key")
    if type(scope_policy) is not str or not scope_policy:
        raise ValueError("scope_policy must be a non-empty exact string")
    if type(rotation_epoch) is not int or rotation_epoch < 0:
        raise ValueError("rotation_epoch must be a non-negative exact integer")

    verifier_identity = _hash_bytes_to_field(
        "zkc/verifier-id:v1", apr_signer_public_key
    )
    payload = (
        verifier_identity.to_bytes(32, "big")
        + _string_to_field(scope_policy).to_bytes(32, "big")
        + rotation_epoch.to_bytes(8, "big")
    )
    scope_id = _hash_bytes_to_field("zkc/scope:v1", payload)
    if scope_id == 0:
        raise ValueError("derived scope_id collided with the anonymous sentinel")
    return scope_id


def presentation_proof_context(
    *,
    flow: AfpTrustFlow,
    responder_aid: str,
    session_context: str,
    apr_verifier_aid: str,
    profile: str,
    scope_policy: Optional[str],
) -> str:
    """Bind a ZKC proof to one authoritative AFP trust-flow interaction."""
    flow = as_trust_flow(flow)
    for label, value in (
        ("responder_aid", responder_aid),
        ("session_context", session_context),
        ("apr_verifier_aid", apr_verifier_aid),
        ("profile", profile),
    ):
        if type(value) is not str or not value:
            raise ValueError(f"{label} must be a non-empty exact string")
    if scope_policy is not None and (
        type(scope_policy) is not str or not scope_policy
    ):
        raise ValueError("scope_policy must be a non-empty exact string or None")
    try:
        # The presentation transcript binds the original, authenticated AFP
        # ``X_`` value below.  The projection is intentionally discarded here:
        # calling the shared §12.7 helper first proves that the session value is
        # canonical and does not map to ZKA/ZKC's zero field sentinel.
        session_context_field(session_context)
    except BundleError as exc:
        raise PresentationBindingError(
            "session_context is not a canonical nonzero-projecting AFP session digest"
        ) from exc
    statement = {
        "kind": AFP_ZKC_PRESENTATION_CONTEXT_V2,
        "purpose": f"afp:trust-flow:{flow.value}",
        "credential_subject_aid": responder_aid,
        "session_context": session_context,
        "apr_verifier_aid": apr_verifier_aid,
        "presentation_profile": profile,
        "scope_policy": scope_policy,
    }
    digest = hashlib.sha256(canonical_bytes(statement)).digest()
    context = int.from_bytes(digest, "big") % _BN254_SCALAR_MODULUS
    if context == 0:
        # ZKC reserves zero as the missing-context sentinel.  Do not retry,
        # rehash, or substitute another value: any of those would define a
        # second, implicit encoding profile.
        raise PresentationBindingError(
            "AFP presentation proof context reduced to ZKC's zero sentinel"
        )
    return f"0x{context:064x}"


def _snapshot_artifact_mapping(
    label: str, artifact: Mapping[str, object]
) -> Mapping[str, object]:
    """Copy a receipt/rotation map and validate behavior-selecting members."""
    try:
        snapshot = dict(artifact)
    except (TypeError, ValueError) as exc:
        raise PresentationBindingError(f"{label} must be a mapping") from exc
    if any(type(key) is not str for key in snapshot):
        raise PresentationBindingError(f"{label} keys must be exact strings")
    for key in _HANDLE_FIELDS.intersection(snapshot):
        if type(snapshot[key]) is not int:
            raise PresentationBindingError(
                f"{label}.{key} must be an exact integer"
            )
    return MappingProxyType(snapshot)


@dataclass(frozen=True)
class ZkcPresentationEvidence:
    """Result of successful ZKC proof/APR verification at the AFP boundary.

    ``credential_subject_aid`` is the holder-declared mirror of the credential
    claim.  It gains no cryptographic authority from this record: the
    ``zkc_verifier`` below must independently return the proof-authenticated
    subject AID, and AFP compares both values to the authenticated responder.

    ``flow`` is a holder-declared label with exactly one job: to be compared
    against the caller's ``expected_flow``. Policy selection MUST use the
    caller's value, never this one, or a presenter picks its own policy.

    ``proven_predicates`` is the meaning-bearing public statement — which atomic
    predicates this presentation claims to prove (Safeguard 2: one per proof).
    :func:`verify_presentation_binding` matches it against the caller's policy;
    the :data:`ZkcVerifier` callback is what binds it to the circuit.
    """

    flow: AfpTrustFlow
    profile: str
    requested_profile: str
    presenter_aid: str
    credential_subject_aid: str
    proven_predicates: Tuple[ProvenPredicate, ...]
    session_context: str
    proof_context: str
    apr_verifier_aid: str
    apr_signer_public_key: bytes
    scope_policy: Optional[str]
    rotation_epoch: int
    scope_id: Optional[int]
    presentation_pseudonym: Optional[int]
    holder_commitment: Optional[int]
    zkc_envelope_version: str
    zka_bundle_kind: Optional[str]
    linkable_consent: bool
    receipt_response: Mapping[str, object]
    rotation_binding: Mapping[str, object]
    carrier_kind: str = ZKA_BUNDLE_VERSION

    def __post_init__(self) -> None:
        if type(self.flow) is str:
            object.__setattr__(self, "flow", as_trust_flow(self.flow))
        elif type(self.flow) is not AfpTrustFlow:
            raise PresentationBindingError(
                "flow must be an AfpTrustFlow value or exact string"
            )
        for label in (
            "profile",
            "requested_profile",
            "presenter_aid",
            "credential_subject_aid",
            "session_context",
            "proof_context",
            "apr_verifier_aid",
            "zkc_envelope_version",
            "carrier_kind",
        ):
            value = getattr(self, label)
            if type(value) is not str or not value:
                raise PresentationBindingError(
                    f"{label} must be a non-empty exact string"
                )
        if self.zka_bundle_kind is not None and type(self.zka_bundle_kind) is not str:
            raise PresentationBindingError("zka_bundle_kind must be exact text or None")
        if (
            self.carrier_kind == ZKA_BUNDLE_VERSION
            and self.zka_bundle_kind != ZKA_BUNDLE_VERSION
        ) or (
            self.carrier_kind == NATIVE_CREDENTIAL_CARRIER
            and self.zka_bundle_kind is not None
        ) or self.carrier_kind not in {ZKA_BUNDLE_VERSION, NATIVE_CREDENTIAL_CARRIER}:
            raise PresentationBindingError(
                "presentation carrier must match zka:bundle:v1 or native credential carriage"
            )
        try:
            session_context_field(self.session_context)
        except BundleError as exc:
            raise PresentationBindingError(
                "session_context is not a canonical nonzero-projecting AFP session digest"
            ) from exc
        if self.scope_policy is not None and (
            type(self.scope_policy) is not str or not self.scope_policy
        ):
            raise PresentationBindingError(
                "scope_policy must be a non-empty exact string or None"
            )
        if type(self.apr_signer_public_key) is not bytes:
            raise PresentationBindingError("apr_signer_public_key must be exact bytes")
        if type(self.linkable_consent) is not bool:
            raise PresentationBindingError("linkable_consent must be a boolean")
        if type(self.rotation_epoch) is not int:
            raise PresentationBindingError("rotation_epoch must be an exact integer")
        for label in ("scope_id", "presentation_pseudonym", "holder_commitment"):
            value = getattr(self, label)
            if value is not None and type(value) is not int:
                raise PresentationBindingError(
                    f"{label} must be an exact integer or None"
                )
        # Snapshot every container the checks below iterate more than once.
        # ``frozen=True`` prevents rebinding an attribute, not mutation through
        # it, and a one-shot iterable would be exhausted by the first check and
        # read as empty by every later one.
        try:
            supplied_predicates = tuple(self.proven_predicates)
        except TypeError as exc:
            raise PresentationBindingError(
                "proven_predicates must be an iterable of ProvenPredicate records"
            ) from exc
        predicates, _ = _snapshot_predicates(supplied_predicates)
        object.__setattr__(self, "proven_predicates", predicates)
        object.__setattr__(
            self,
            "receipt_response",
            _snapshot_artifact_mapping("receipt_response", self.receipt_response),
        )
        object.__setattr__(
            self,
            "rotation_binding",
            _snapshot_artifact_mapping("rotation_binding", self.rotation_binding),
        )

    @property
    def proven_predicate_ids(self) -> FrozenSet[str]:
        return frozenset(item.predicate_id for item in self.proven_predicates)


ZkcVerifier = Callable[
    [ZkcPresentationEvidence], Optional[ZkcVerifiedPublicStatement]
]
"""The deployment-supplied ZKC proof/APR verifier (§5.9).

AFP never implements this. The callback MUST return a
:class:`ZkcVerifiedPublicStatement` only after the circuit verifies the exact
proof context and predicate set and after an issuer-authenticated claim or
independently verified companion proof establishes the credential-subject AID.
It MUST NOT copy that AID from the holder-declared evidence. It MUST return
``None`` (never a boolean) for rejection. Rotation-rebind proofs are outside
this reference callback contract, and any such declaration fails closed before
the callback runs.
"""


def _validate_active_handles(
    *,
    profile: str,
    artifact_name: str,
    artifact: Mapping[str, object],
    evidence: ZkcPresentationEvidence,
) -> None:
    present = _HANDLE_FIELDS.intersection(artifact)
    if profile == ANONYMOUS_PROFILE:
        expected = frozenset()
    elif profile == SCOPED_PROFILE:
        expected = frozenset({"presentationPseudonym", "scopeId"})
    elif profile == LINKABLE_PROFILE:
        expected = frozenset({"holderCommitment"})
    else:
        raise PresentationBindingError(f"unsupported presentation profile {profile!r}")

    if present != expected:
        raise PresentationBindingError(
            f"{artifact_name} exposes handles {sorted(present)!r}; "
            f"active {profile} permits exactly {sorted(expected)!r}"
        )
    if profile == SCOPED_PROFILE and (
        artifact["presentationPseudonym"] != evidence.presentation_pseudonym
        or artifact["scopeId"] != evidence.scope_id
    ):
        raise PresentationBindingError(f"{artifact_name} scoped handle mismatch")
    if profile == LINKABLE_PROFILE and (
        artifact["holderCommitment"] != evidence.holder_commitment
    ):
        raise PresentationBindingError(f"{artifact_name} linkable handle mismatch")


def _verify_predicate_meaning(
    predicates: Tuple[ProvenPredicate, ...],
    *,
    expected_flow: AfpTrustFlow,
    required_predicates: RequiredPredicatePolicy,
) -> FrozenSet[str]:
    """Bind what was proven to what this flow requires (§6.3 / §6.3.1 / §14.4).

    Every comparand here is either the caller's authenticated policy or a
    literal the specification fixes; nothing on the evidence record is trusted
    against itself.
    """
    # §5.9: a presentation that proves nothing is the boolean "verified" label
    # the specification rejects, whatever the policy happens to require.
    if not predicates:
        raise PresentationBindingError(
            "presentation proves no predicate; a verified label is not a statement"
        )

    proven_ids = frozenset(item.predicate_id for item in predicates)
    if len(proven_ids) != len(predicates):
        raise PresentationBindingError(
            "presentation repeats a predicate; §14.3 proofs are atomic, one "
            "predicate each (Safeguard 2)"
        )

    # §6.3: the telemetry catalog is closed. This bounds what an operator may
    # demand of a tenant, so it applies to the tenant->operator flow only —
    # Safeguard 1 reserves the counterparty-facing flows for the caller policy.
    if as_trust_flow(expected_flow) is AfpTrustFlow.TELEMETRY:
        off_catalog = sorted(proven_ids - AFP_TELEMETRY_PREDICATE_CATALOG)
        if off_catalog:
            raise PresentationBindingError(
                f"predicate(s) {off_catalog!r} are outside the closed §6.3 telemetry "
                f"catalog and are not AFP-conforming for {expected_flow.value}"
            )

    unaccepted = sorted(proven_ids - required_predicates.accepted_predicate_ids)
    if unaccepted:
        raise PresentationBindingError(
            f"presentation proves {unaccepted!r}, which this flow does not accept"
        )

    unmet = sorted(required_predicates.required_predicate_ids - proven_ids)
    if unmet:
        raise PresentationBindingError(
            f"presentation does not prove required predicate(s) {unmet!r}"
        )

    # §14.4: accept only a proof whose public root_class and root_authority_
    # identifier exactly match one signed pair. Keyed on the predicate's own
    # identity, not on whether it happens to carry a root: a v2 attestation that
    # presents no root class must be rejected, never skipped, or the absence
    # silently authorizes the attestation predicate that §14.4 forbids by name.
    for predicate in predicates:
        pair = root_pair_of(predicate)
        if predicate.predicate_id == INSTANCE_ATTESTATION_PREDICATE_V2:
            if pair is None:
                raise PresentationBindingError(
                    f"{INSTANCE_ATTESTATION_PREDICATE_V2} must name a root class and "
                    f"root authority identifier (§6.3.1)"
                )
            if pair not in required_predicates.accepted_instance_attestation_roots:
                raise PresentationBindingError(
                    f"instance-attestation root {pair!r} does not exactly match a "
                    f"signed accepted (root_class, root_authority_identifier) pair "
                    f"(§14.4)"
                )
        elif pair is not None:
            raise PresentationBindingError(
                f"predicate {predicate.predicate_id!r} MUST NOT carry a root class; "
                f"only {INSTANCE_ATTESTATION_PREDICATE_V2} does (§6.3.1)"
            )
    return proven_ids


def verify_presentation_binding(
    evidence: ZkcPresentationEvidence,
    *,
    expected_flow: AfpTrustFlow,
    expected_responder_aid: str,
    expected_verifier_aid: str,
    expected_apr_signer_public_key: bytes,
    expected_session_context: str,
    expected_session_policy_hash: str,
    required_predicates: RequiredPredicatePolicy,
    zkc_verifier: ZkcVerifier,
) -> VerifiedPresentation:
    """Verify ZKC v0.4 evidence before an AFP flow consumes it.

    Binds the verified result to the AFP interaction on two axes. *Identity* —
    presenter, credential subject, session, APR verifier and signer, scope, and
    profile — is compared or re-derived against the caller's authenticated
    values. *Meaning* — which predicates were proven — is matched against
    ``required_predicates`` for ``expected_flow`` (§6.3 / §6.3.1 / §14.4).

    ``expected_flow`` is authoritative for policy selection. ``evidence.flow`` is
    a holder-declared label and is only checked for agreement, so relabelling it
    cannot reach a more permissive profile policy.

    Returns the verified public statement (§5.9). Raises
    :class:`PresentationBindingError` on any mismatch; the cryptographic gate
    runs last and unconditionally.
    """
    # Exact type: the construction invariants below (predicate types, container
    # snapshots) run in __post_init__, and a subclass could shadow the very
    # attributes the checks read. A record that did not pass through those
    # invariants is not evidence.
    if type(evidence) is not ZkcPresentationEvidence:
        raise PresentationBindingError(
            "evidence must be a ZkcPresentationEvidence record"
        )
    # Re-run every construction invariant over a fresh value snapshot. Frozen
    # dataclasses can still be altered with ``object.__setattr__``; verification
    # must not rely on an earlier constructor call remaining true forever.
    try:
        evidence = replace(evidence)
    except (TypeError, ValueError, PresentationBindingError) as exc:
        raise PresentationBindingError("presentation evidence snapshot is malformed") from exc
    required_predicates = _snapshot_required_predicates(required_predicates)
    canonical_predicates, expected_predicate_wires = _snapshot_predicates(
        evidence.proven_predicates
    )

    expected_flow = as_trust_flow(expected_flow)
    for label, value in (
        ("expected_responder_aid", expected_responder_aid),
        ("expected_verifier_aid", expected_verifier_aid),
        ("expected_session_context", expected_session_context),
        ("expected_session_policy_hash", expected_session_policy_hash),
    ):
        if type(value) is not str or not value:
            raise PresentationBindingError(
                f"{label} must be a non-empty exact string"
            )
    if type(expected_apr_signer_public_key) is not bytes:
        raise PresentationBindingError(
            "expected_apr_signer_public_key must be exact bytes"
        )

    if as_trust_flow(evidence.flow) is not expected_flow:
        raise PresentationBindingError(
            f"presentation declares flow {evidence.flow} but this interaction is "
            f"{expected_flow}"
        )
    if evidence.carrier_kind not in {ZKA_BUNDLE_VERSION, NATIVE_CREDENTIAL_CARRIER}:
        raise PresentationBindingError(
            "ZKC presentation has an unsupported credential carrier"
        )
    if evidence.presenter_aid != expected_responder_aid:
        raise PresentationBindingError("presenter AID does not match the AFP responder")
    if evidence.credential_subject_aid != expected_responder_aid:
        raise PresentationBindingError(
            "ZKC credential subject does not match the AFP responder AID"
        )
    if evidence.session_context != expected_session_context:
        raise PresentationBindingError("presentation session context mismatch")
    if evidence.apr_verifier_aid != expected_verifier_aid:
        raise PresentationBindingError("APR verifier AID mismatch")
    if evidence.apr_signer_public_key != expected_apr_signer_public_key:
        raise PresentationBindingError("APR signer key is not the authenticated AFP verifier key")

    expected_scope_policy = (
        afp_scope_policy(expected_session_policy_hash)
        if evidence.profile == SCOPED_PROFILE
        else None
    )
    expected_proof_context = presentation_proof_context(
        flow=expected_flow,
        responder_aid=expected_responder_aid,
        session_context=expected_session_context,
        apr_verifier_aid=expected_verifier_aid,
        profile=evidence.profile,
        scope_policy=expected_scope_policy,
    )
    if evidence.proof_context != expected_proof_context:
        raise PresentationBindingError("ZKC proof context does not match the AFP binding")

    # Selected from the caller's authenticated flow. Reading evidence.flow here
    # would let a presenter name the flow whose policy suits it.
    policy = flow_policy(expected_flow)
    if evidence.profile != evidence.requested_profile and not policy.allows_downgrade(
        evidence.requested_profile, evidence.profile
    ):
        raise PresentationBindingError(
            f"presentation downgrade {evidence.requested_profile} -> "
            f"{evidence.profile} is not permitted for {expected_flow.value}"
        )
    if evidence.profile not in policy.accepted_profiles:
        raise PresentationBindingError(
            f"{evidence.profile} is not accepted for {expected_flow.value}"
        )

    proven_predicate_ids = _verify_predicate_meaning(
        canonical_predicates,
        expected_flow=expected_flow,
        required_predicates=required_predicates,
    )

    if evidence.profile == ANONYMOUS_PROFILE:
        if evidence.zkc_envelope_version != "zkc:proof:v2":
            raise PresentationBindingError("anonymous presentations require zkc:proof:v2")
        if evidence.scope_id != 0 or evidence.presentation_pseudonym != 0:
            raise PresentationBindingError("anonymous presentation must use zero sentinels")
        if evidence.holder_commitment is not None or evidence.scope_policy is not None:
            raise PresentationBindingError("anonymous presentation leaks a holder handle")
    elif evidence.profile == SCOPED_PROFILE:
        if evidence.zkc_envelope_version != "zkc:proof:v2":
            raise PresentationBindingError("scoped presentations require zkc:proof:v2")
        if evidence.scope_policy != expected_scope_policy:
            raise PresentationBindingError("scope policy is not bound to AFP session policy")
        expected_scope_id = derive_scope_id(
            expected_apr_signer_public_key,
            expected_scope_policy,
            evidence.rotation_epoch,
        )
        if evidence.scope_id != expected_scope_id:
            raise PresentationBindingError(
                "scope identifier does not match APR identity and policy"
            )
        if not evidence.presentation_pseudonym:
            raise PresentationBindingError("scoped presentation lacks a non-zero pseudonym")
        if evidence.holder_commitment is not None:
            raise PresentationBindingError("scoped presentation leaks holderCommitment")
    elif evidence.profile == LINKABLE_PROFILE:
        if evidence.zkc_envelope_version != "zkc:proof:v1":
            raise PresentationBindingError("linkable presentations require zkc:proof:v1")
        if not evidence.linkable_consent:
            raise PresentationBindingError("linkable presentation requires explicit consent")
        if not evidence.holder_commitment:
            raise PresentationBindingError("linkable presentation lacks holderCommitment")
        if evidence.scope_id is not None or evidence.presentation_pseudonym is not None:
            raise PresentationBindingError("linkable presentation mixes scoped handles")
    else:
        raise PresentationBindingError(
            f"unsupported presentation profile {evidence.profile!r}"
        )

    _validate_active_handles(
        profile=evidence.profile,
        artifact_name="receipt",
        artifact=evidence.receipt_response,
        evidence=evidence,
    )
    _validate_active_handles(
        profile=evidence.profile,
        artifact_name="rotation",
        artifact=evidence.rotation_binding,
        evidence=evidence,
    )

    rebind_fields = {
        key
        for key in evidence.rotation_binding
        if type(key) is str
        and ("rebind" in key.lower() or key in _UNSUPPORTED_REBIND_FIELDS)
    }
    if rebind_fields:
        raise PresentationBindingError(
            "credential rebind declarations are unsupported by this reference verifier"
        )

    # Snapshot what was checked BEFORE handing the record to third-party adapter
    # code. ``frozen=True`` does not stop ``object.__setattr__``, so a statement
    # read back afterwards would not be the statement that was verified.  Keep
    # the values returned to AFP callers in locals too: the callback receives
    # the live record and must not be able to rewrite the accepted result.
    bound_profile = evidence.profile
    bound_session_context = evidence.session_context
    bound_proof_context = evidence.proof_context
    bound_credential_subject_aid = evidence.credential_subject_aid
    if zkc_verifier is None or not callable(zkc_verifier):
        raise PresentationBindingError("a callable ZKC verifier is required")
    verified_statement = zkc_verifier(evidence)
    if (
        evidence.profile != bound_profile
        or evidence.session_context != bound_session_context
        or evidence.proof_context != bound_proof_context
    ):
        raise PresentationBindingError(
            "ZKC verifier mutated presentation evidence after AFP bound it"
        )
    if type(verified_statement) is not ZkcVerifiedPublicStatement:
        raise PresentationBindingError(
            "ZKC verifier must return a ZkcVerifiedPublicStatement or None"
        )
    try:
        _, verified_predicate_wires = _snapshot_predicates(
            verified_statement.proven_predicates
        )
    except PresentationBindingError as exc:
        raise PresentationBindingError(
            "ZKC verifier returned a malformed public statement"
        ) from exc
    if type(verified_statement.proof_context) is not str or (
        verified_statement.proof_context != expected_proof_context
        or verified_statement.credential_subject_aid != expected_responder_aid
        or verified_statement.credential_subject_aid
        != bound_credential_subject_aid
        or verified_predicate_wires != expected_predicate_wires
    ):
        raise PresentationBindingError(
            "ZKC verifier result does not match the verified presentation"
        )
    return VerifiedPresentation(
        flow=expected_flow,
        profile=bound_profile,
        credential_subject_aid=verified_statement.credential_subject_aid,
        session_context=bound_session_context,
        proven_predicate_ids=proven_predicate_ids,
        required_predicates_digest=required_predicates.digest,
    )


__all__ = [
    "AFP_TELEMETRY_PREDICATE_CATALOG",
    "AFP_ZKC_PRESENTATION_CONTEXT_V2",
    "ANONYMOUS_PROFILE",
    "INSTANCE_ATTESTATION_PREDICATE_V2",
    "INSTANCE_ATTESTATION_ROOT_CLASSES",
    "SCOPED_PROFILE",
    "LINKABLE_PROFILE",
    "AfpTrustFlow",
    "PresentationPolicy",
    "PresentationBindingError",
    "ProvenPredicate",
    "RequiredPredicatePolicy",
    "VerifiedPresentation",
    "ZkcVerifiedPublicStatement",
    "ZkcPresentationEvidence",
    "ZkcVerifier",
    "flow_policy",
    "afp_scope_policy",
    "as_trust_flow",
    "derive_scope_id",
    "presentation_proof_context",
    "root_pair_of",
    "verify_presentation_binding",
]
