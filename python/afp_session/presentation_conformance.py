"""§5.9 presentation-binding conformance vectors.

§5.9 requires an implementation to "include negative cases for a swapped
presenter AID, credential subject/holder, scope, APR signer key or AID,
session/proof context, and presentation profile". Those cases test *identity*
binding. They are satisfiable by an implementation that never checks which
predicate a presentation proves, so on their own they cannot distinguish a
conforming verifier from a meaning-blind one.

This module carries both halves as executable vectors and runs them against a
*supplied* verifier rather than against this package's own. That is what makes it
a conformance suite instead of a unit test: point it at an implementation and it
reports which obligations that implementation discharges. A verifier that skips
the §6.3/§6.3.1/§14.4 meaning obligations accepts the ``meaning-*`` vectors and
fails conformance here, which is the property the identity-only cases lack.

Every vector fixes one variable against a valid baseline, so a rejection is
attributable to the obligation named in its ``spec_reference``.
If the reference types refuse to construct a vector, the supplied verifier is
not exercised. That result is reported separately and prevents a full
conformance verdict; it is never credited as a verifier rejection.

The §12.7 bundle vectors live here too, in their own suite. §12.7 verification
is two-layer, and an implementation that discharges §5.9 while skipping the
proof layer has not verified anything — so both suites belong to one answer
about whether a verifier pair conforms.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from .bundle import BundleVerificationResult, ZkaBundle, session_context_field
from .presentation import (
    ANONYMOUS_PROFILE,
    INSTANCE_ATTESTATION_PREDICATE_V2,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    AfpTrustFlow,
    PresentationBindingError,
    ProvenPredicate,
    RequiredPredicatePolicy,
    ZkcVerifiedPublicStatement,
    ZkcPresentationEvidence,
    afp_scope_policy,
    derive_scope_id,
    presentation_proof_context,
)

__all__ = [
    "BUNDLE_REJECTION_VECTORS",
    "BundleVector",
    "PROFILE_BASELINES",
    "VectorStatus",
    "ConformanceVector",
    "VectorResult",
    "PresentationConformance",
    "PRESENTATION_REJECTION_VECTORS",
    "run_bundle_conformance",
    "run_presentation_conformance",
    "baseline_case",
    "anonymous_baseline_case",
    "linkable_baseline_case",
]

# A deterministic, self-contained baseline. The values are structural, not
# secret: a SEC1-compressed APR key, a scoped open-federation presentation, and
# one proven predicate.
_APR_KEY = bytes.fromhex("02" + "11" * 32)
_OTHER_APR_KEY = bytes.fromhex("03" + "22" * 32)
_RESPONDER_AID = "E-conformance-responder"
_VERIFIER_AID = "E-conformance-verifier"
_SESSION_CONTEXT = "X_" + "ab" * 32
_SESSION_POLICY_HASH = "0x" + "cd" * 32
_SCOPE_POLICY = afp_scope_policy(_SESSION_POLICY_HASH)
_ROTATION_EPOCH = 7
_SCOPE_ID = derive_scope_id(_APR_KEY, _SCOPE_POLICY, _ROTATION_EPOCH)
_PSEUDONYM = 0x5EED

_KYC = ProvenPredicate(predicate_id="zkc:proof:kyc:v2", predicate_version="2")
_LINKABLE_KYC = ProvenPredicate(
    predicate_id="zkc:proof:kyc:v1", predicate_version="1"
)
_JURISDICTION = ProvenPredicate(
    predicate_id="zkc:proof:jurisdiction:v2", predicate_version="2"
)
_ATTESTATION_WINDOW = ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
_ACCEPTED_ROOT = ("root:publisher-manifest", "E-accountable-authority")
_ATTESTATION = ProvenPredicate(
    predicate_id=INSTANCE_ATTESTATION_PREDICATE_V2,
    predicate_version="2",
    root_class=_ACCEPTED_ROOT[0],
    root_authority_identifier=_ACCEPTED_ROOT[1],
    attestation_window=_ATTESTATION_WINDOW,
    subject_aid=_RESPONDER_AID,
)

_BASE_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset(
        {"zkc:proof:kyc:v2", "zkc:proof:jurisdiction:v2"}
    ),
    required_predicate_ids=frozenset({"zkc:proof:kyc:v2"}),
)
_LINKABLE_BASE_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset({"zkc:proof:kyc:v1"}),
    required_predicate_ids=frozenset({"zkc:proof:kyc:v1"}),
)
_ATTESTATION_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset(
        {"zkc:proof:kyc:v2", INSTANCE_ATTESTATION_PREDICATE_V2}
    ),
    required_predicate_ids=frozenset({INSTANCE_ATTESTATION_PREDICATE_V2}),
    accepted_instance_attestation_roots=frozenset({_ACCEPTED_ROOT}),
)
_TELEMETRY_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset(
        {"afp.telemetry.compute_quota.v1", "zkc:proof:kyc:v2"}
    ),
    required_predicate_ids=frozenset({"afp.telemetry.compute_quota.v1"}),
)
_QUOTA = ProvenPredicate(
    predicate_id="afp.telemetry.compute_quota.v1", predicate_version="1"
)


def _accept(_evidence: ZkcPresentationEvidence) -> Optional[ZkcVerifiedPublicStatement]:
    """A ZKC seam that verifies the proof cryptography successfully.

    Every vector below runs with the cryptography *passing*, so a rejection is
    attributable to AFP's own request binding and never to the proof itself.
    The fixed subject represents an independently authenticated fixture; it is
    deliberately not copied from the holder-declared evidence field.
    """
    return ZkcVerifiedPublicStatement(
        proof_context=_evidence.proof_context,
        credential_subject_aid=_RESPONDER_AID,
        proven_predicates=_evidence.proven_predicates,
    )


def _reject(_evidence: ZkcPresentationEvidence) -> Optional[ZkcVerifiedPublicStatement]:
    return None


def baseline_case() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
    """A valid scoped open-federation presentation and its verifier arguments."""
    evidence = ZkcPresentationEvidence(
        flow=AfpTrustFlow.OPEN_FEDERATION,
        profile=SCOPED_PROFILE,
        requested_profile=SCOPED_PROFILE,
        presenter_aid=_RESPONDER_AID,
        credential_subject_aid=_RESPONDER_AID,
        proven_predicates=(_KYC,),
        session_context=_SESSION_CONTEXT,
        proof_context=presentation_proof_context(
            flow=AfpTrustFlow.OPEN_FEDERATION,
            responder_aid=_RESPONDER_AID,
            session_context=_SESSION_CONTEXT,
            apr_verifier_aid=_VERIFIER_AID,
            profile=SCOPED_PROFILE,
            scope_policy=_SCOPE_POLICY,
        ),
        apr_verifier_aid=_VERIFIER_AID,
        apr_signer_public_key=_APR_KEY,
        scope_policy=_SCOPE_POLICY,
        rotation_epoch=_ROTATION_EPOCH,
        scope_id=_SCOPE_ID,
        presentation_pseudonym=_PSEUDONYM,
        holder_commitment=None,
        zkc_envelope_version="zkc:proof:v2",
        zka_bundle_kind="zka:bundle:v1",
        linkable_consent=False,
        receipt_response={"presentationPseudonym": _PSEUDONYM, "scopeId": _SCOPE_ID},
        rotation_binding={"presentationPseudonym": _PSEUDONYM, "scopeId": _SCOPE_ID},
    )
    arguments: Dict[str, object] = {
        "expected_flow": AfpTrustFlow.OPEN_FEDERATION,
        "expected_responder_aid": _RESPONDER_AID,
        "expected_verifier_aid": _VERIFIER_AID,
        "expected_apr_signer_public_key": _APR_KEY,
        "expected_session_context": _SESSION_CONTEXT,
        "expected_session_policy_hash": _SESSION_POLICY_HASH,
        "required_predicates": _BASE_POLICY,
        "zkc_verifier": _accept,
    }
    return evidence, arguments


def anonymous_baseline_case() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
    """A valid anonymous telemetry presentation and its verifier arguments.

    Telemetry is the flow whose policy accepts the anonymous profile, so this is
    where the anonymous handle sentinels can be exercised.
    """
    evidence = ZkcPresentationEvidence(
        flow=AfpTrustFlow.TELEMETRY,
        profile=ANONYMOUS_PROFILE,
        requested_profile=ANONYMOUS_PROFILE,
        presenter_aid=_RESPONDER_AID,
        credential_subject_aid=_RESPONDER_AID,
        proven_predicates=(_QUOTA,),
        session_context=_SESSION_CONTEXT,
        proof_context=presentation_proof_context(
            flow=AfpTrustFlow.TELEMETRY,
            responder_aid=_RESPONDER_AID,
            session_context=_SESSION_CONTEXT,
            apr_verifier_aid=_VERIFIER_AID,
            profile=ANONYMOUS_PROFILE,
            scope_policy=None,
        ),
        apr_verifier_aid=_VERIFIER_AID,
        apr_signer_public_key=_APR_KEY,
        scope_policy=None,
        rotation_epoch=_ROTATION_EPOCH,
        scope_id=0,
        presentation_pseudonym=0,
        holder_commitment=None,
        zkc_envelope_version="zkc:proof:v2",
        zka_bundle_kind="zka:bundle:v1",
        linkable_consent=False,
        receipt_response={},
        rotation_binding={},
    )
    arguments: Dict[str, object] = {
        "expected_flow": AfpTrustFlow.TELEMETRY,
        "expected_responder_aid": _RESPONDER_AID,
        "expected_verifier_aid": _VERIFIER_AID,
        "expected_apr_signer_public_key": _APR_KEY,
        "expected_session_context": _SESSION_CONTEXT,
        "expected_session_policy_hash": _SESSION_POLICY_HASH,
        "required_predicates": _TELEMETRY_POLICY,
        "zkc_verifier": _accept,
    }
    return evidence, arguments


def linkable_baseline_case() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
    """A valid, consented linkable open-federation presentation."""
    evidence = ZkcPresentationEvidence(
        flow=AfpTrustFlow.OPEN_FEDERATION,
        profile=LINKABLE_PROFILE,
        requested_profile=LINKABLE_PROFILE,
        presenter_aid=_RESPONDER_AID,
        credential_subject_aid=_RESPONDER_AID,
        proven_predicates=(_LINKABLE_KYC,),
        session_context=_SESSION_CONTEXT,
        proof_context=presentation_proof_context(
            flow=AfpTrustFlow.OPEN_FEDERATION,
            responder_aid=_RESPONDER_AID,
            session_context=_SESSION_CONTEXT,
            apr_verifier_aid=_VERIFIER_AID,
            profile=LINKABLE_PROFILE,
            scope_policy=None,
        ),
        apr_verifier_aid=_VERIFIER_AID,
        apr_signer_public_key=_APR_KEY,
        scope_policy=None,
        rotation_epoch=_ROTATION_EPOCH,
        scope_id=None,
        presentation_pseudonym=None,
        holder_commitment=0xC0FFEE,
        zkc_envelope_version="zkc:proof:v1",
        zka_bundle_kind="zka:bundle:v1",
        linkable_consent=True,
        receipt_response={"holderCommitment": 0xC0FFEE},
        rotation_binding={"holderCommitment": 0xC0FFEE},
    )
    arguments: Dict[str, object] = {
        "expected_flow": AfpTrustFlow.OPEN_FEDERATION,
        "expected_responder_aid": _RESPONDER_AID,
        "expected_verifier_aid": _VERIFIER_AID,
        "expected_apr_signer_public_key": _APR_KEY,
        "expected_session_context": _SESSION_CONTEXT,
        "expected_session_policy_hash": _SESSION_POLICY_HASH,
        "required_predicates": _LINKABLE_BASE_POLICY,
        "zkc_verifier": _accept,
    }
    return evidence, arguments


#: The active-profile baselines the classification table's ``by_profile`` claims
#: are demonstrated against.
PROFILE_BASELINES = {
    "scoped": baseline_case,
    "anonymous": anonymous_baseline_case,
    "linkable": linkable_baseline_case,
}


class VectorStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_EXERCISED = "not_exercised"


@dataclass(frozen=True)
class ConformanceVector:
    """One executable obligation: a case, and whether it must be rejected."""

    vector_id: str
    name: str
    spec_reference: str
    must_reject: bool
    build: Callable[[], Tuple[ZkcPresentationEvidence, Dict[str, object]]]


@dataclass(frozen=True)
class VectorResult:
    vector: ConformanceVector
    status: VectorStatus
    evidence: str

    @property
    def ok(self) -> bool:
        return self.status is VectorStatus.PASSED


@dataclass(frozen=True)
class PresentationConformance:
    """The aggregate verdict for one implementation under test."""

    results: Tuple[VectorResult, ...]

    @property
    def conforms(self) -> bool:
        return all(result.ok for result in self.results)

    def failures(self) -> List[VectorResult]:
        return [result for result in self.results if result.status is VectorStatus.FAILED]

    def not_exercised(self) -> List[VectorResult]:
        return [
            result for result in self.results
            if result.status is VectorStatus.NOT_EXERCISED
        ]

    def result(self, vector_id: str) -> VectorResult:
        for result in self.results:
            if result.vector.vector_id == vector_id:
                return result
        raise KeyError(vector_id)

    def summary(self) -> str:
        lines = [
            f"{result.vector.vector_id} {result.vector.name}: {result.status.value}"
            for result in self.results
        ]
        lines.append(
            f"conforms={self.conforms} ({len(self.failures())} failed, "
            f"{len(self.not_exercised())} not exercised)"
        )
        return "\n".join(lines)


def _mutate(**overrides) -> Callable[[], Tuple[ZkcPresentationEvidence, Dict[str, object]]]:
    """A vector that changes one evidence field against the baseline."""

    def build() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
        evidence, arguments = baseline_case()
        return replace(evidence, **overrides), arguments

    return build


def _rebind(**argument_overrides) -> Callable[
    [], Tuple[ZkcPresentationEvidence, Dict[str, object]]
]:
    """A vector that changes what the verifier is told to expect."""

    def build() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
        evidence, arguments = baseline_case()
        arguments.update(argument_overrides)
        return evidence, arguments

    return build


def _case(evidence_overrides: Dict[str, object], **argument_overrides):
    def build() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
        evidence, arguments = baseline_case()
        arguments.update(argument_overrides)
        return replace(evidence, **evidence_overrides), arguments

    return build


def _unknown_root_class_case() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
    """§6.3.1: "The `root class` MUST be one of the three literal values"."""
    evidence, arguments = baseline_case()
    arguments["required_predicates"] = _ATTESTATION_POLICY
    return (
        replace(
            evidence,
            proven_predicates=(
                ProvenPredicate(
                    predicate_id=INSTANCE_ATTESTATION_PREDICATE_V2,
                    predicate_version="2",
                    root_class="root:unregistered",
                    root_authority_identifier=_ACCEPTED_ROOT[1],
                    attestation_window=_ATTESTATION_WINDOW,
                    subject_aid=_RESPONDER_AID,
                ),
            ),
        ),
        arguments,
    )


def _telemetry_catalog_case() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
    """A correctly transcript-bound telemetry proof remains an honest control."""
    evidence, arguments = baseline_case()
    return (
        replace(
            evidence,
            flow=AfpTrustFlow.TELEMETRY,
            proven_predicates=(_QUOTA,),
            proof_context=presentation_proof_context(
                flow=AfpTrustFlow.TELEMETRY,
                responder_aid=_RESPONDER_AID,
                session_context=_SESSION_CONTEXT,
                apr_verifier_aid=_VERIFIER_AID,
                profile=SCOPED_PROFILE,
                scope_policy=_SCOPE_POLICY,
            ),
        ),
        {
            **arguments,
            "expected_flow": AfpTrustFlow.TELEMETRY,
            "required_predicates": _TELEMETRY_POLICY,
        },
    )


def _flow_context_mismatch_case() -> Tuple[ZkcPresentationEvidence, Dict[str, object]]:
    """A proof minted for another flow cannot enter the expected flow."""
    evidence, arguments = baseline_case()
    return (
        replace(evidence, flow=AfpTrustFlow.BILATERAL),
        {
            **arguments,
            "expected_flow": AfpTrustFlow.BILATERAL,
        },
    )


def _relabel_both_flow_fields_case() -> Tuple[
    ZkcPresentationEvidence, Dict[str, object]
]:
    """The lower-layer verified statement catches a relabelled context too."""
    evidence, arguments = baseline_case()
    original_context = evidence.proof_context
    relabelled_context = presentation_proof_context(
        flow=AfpTrustFlow.BILATERAL,
        responder_aid=_RESPONDER_AID,
        session_context=_SESSION_CONTEXT,
        apr_verifier_aid=_VERIFIER_AID,
        profile=SCOPED_PROFILE,
        scope_policy=_SCOPE_POLICY,
    )

    def proof_bound_to_original_context(
        _evidence: ZkcPresentationEvidence,
    ) -> ZkcVerifiedPublicStatement:
        return ZkcVerifiedPublicStatement(
            proof_context=original_context,
            credential_subject_aid=_RESPONDER_AID,
            proven_predicates=_evidence.proven_predicates,
        )

    return (
        replace(evidence, flow=AfpTrustFlow.BILATERAL, proof_context=relabelled_context),
        {
            **arguments,
            "expected_flow": AfpTrustFlow.BILATERAL,
            "zkc_verifier": proof_bound_to_original_context,
        },
    )


def _verified_subject_mismatch_case() -> Tuple[
    ZkcPresentationEvidence, Dict[str, object]
]:
    """The evidence label cannot substitute for a proof-authenticated subject."""
    evidence, arguments = baseline_case()

    def proof_for_another_subject(
        _evidence: ZkcPresentationEvidence,
    ) -> ZkcVerifiedPublicStatement:
        return ZkcVerifiedPublicStatement(
            proof_context=_evidence.proof_context,
            credential_subject_aid="E-credential-owner",
            proven_predicates=_evidence.proven_predicates,
        )

    return evidence, {**arguments, "zkc_verifier": proof_for_another_subject}


def _verified_predicate_mismatch_case() -> Tuple[
    ZkcPresentationEvidence, Dict[str, object]
]:
    """The callback must authenticate the same predicate wires AFP checked."""
    evidence, arguments = baseline_case()

    def proof_of_another_predicate(
        _evidence: ZkcPresentationEvidence,
    ) -> ZkcVerifiedPublicStatement:
        return ZkcVerifiedPublicStatement(
            proof_context=_evidence.proof_context,
            credential_subject_aid=_evidence.credential_subject_aid,
            proven_predicates=(_JURISDICTION,),
        )

    return evidence, {**arguments, "zkc_verifier": proof_of_another_predicate}


PRESENTATION_REJECTION_VECTORS: Tuple[ConformanceVector, ...] = (
    # -- honest controls -----------------------------------------------------
    ConformanceVector(
        "honest-valid", "a correctly bound presentation is accepted", "§5.9",
        False, baseline_case),
    ConformanceVector(
        "honest-crypto-rejected", "a failed ZKC verification is rejected", "§5.9",
        True, _rebind(zkc_verifier=_reject)),
    ConformanceVector(
        "honest-required-and-proven",
        "a required predicate that was proven is accepted", "§6.3/§14.4",
        False, _case({"proven_predicates": (_KYC, _JURISDICTION)})),
    ConformanceVector(
        "honest-attestation-matched",
        "an attestation matching a signed root pair is accepted", "§14.4",
        False, _case(
            {"proven_predicates": (_ATTESTATION,)},
            required_predicates=_ATTESTATION_POLICY)),
    ConformanceVector(
        "honest-telemetry-catalog",
        "a catalog predicate on the telemetry flow is accepted", "§6.3",
        False, _telemetry_catalog_case),

    # -- §5.9 identity binding (the cases the specification already names) ----
    ConformanceVector(
        "identity-presenter-aid", "a swapped presenter AID is rejected", "§5.9",
        True, _mutate(presenter_aid="E-attacker")),
    ConformanceVector(
        "identity-credential-subject",
        "a swapped credential subject is rejected", "§5.9",
        True, _mutate(credential_subject_aid="E-attacker")),
    ConformanceVector(
        "identity-verified-credential-subject",
        "a proof-authenticated subject differing from the responder is rejected",
        "§5.9",
        True,
        _verified_subject_mismatch_case,
    ),
    ConformanceVector(
        "identity-scope", "a forged scope identifier is rejected", "§5.9.1",
        True, _mutate(scope_id=_SCOPE_ID ^ 1)),
    ConformanceVector(
        "identity-apr-signer", "a swapped APR signer key is rejected", "§5.9",
        True, _mutate(apr_signer_public_key=_OTHER_APR_KEY)),
    ConformanceVector(
        "identity-apr-verifier-aid", "a swapped APR verifier AID is rejected", "§5.9",
        True, _mutate(apr_verifier_aid="E-other-verifier")),
    ConformanceVector(
        "identity-session-context",
        "a swapped session context is rejected", "§5.9/§12.3",
        True, _mutate(session_context="X_" + "ee" * 32)),
    ConformanceVector(
        "identity-proof-context", "a swapped proof context is rejected", "§5.9",
        True, _mutate(proof_context="0x" + "ff" * 32)),
    ConformanceVector(
        "identity-flow-context",
        "a proof context minted for another flow is rejected", "§5.9",
        True, _flow_context_mismatch_case),
    ConformanceVector(
        "identity-flow-relabel-both-fields",
        "relabeling flow and its context cannot rewrite a verified proof", "§5.9",
        True, _relabel_both_flow_fields_case),
    ConformanceVector(
        "identity-profile-downgrade",
        "an open-federation anonymous downgrade is rejected", "§5.9",
        True, _mutate(profile="zkc:presentation:anonymous:v1")),

    # -- meaning binding (what an identity-only suite cannot distinguish) -----
    ConformanceVector(
        "meaning-unaccepted-predicate",
        "a predicate outside the accepted set is rejected", "§14.4",
        True, _mutate(
            proven_predicates=(
                ProvenPredicate(
                    predicate_id="zkc:proof:accreditation:v2", predicate_version="2"
                ),
            ))),
    ConformanceVector(
        "meaning-verified-predicate-disagreement",
        "a verifier result proving another predicate is rejected",
        "§5.9/§6.3",
        True,
        _verified_predicate_mismatch_case,
    ),
    ConformanceVector(
        "meaning-required-not-proven",
        "a presentation missing the required predicate is rejected", "§14.4",
        True, _mutate(proven_predicates=(_JURISDICTION,))),
    ConformanceVector(
        "meaning-empty-proof-set",
        "a presentation that proves nothing is rejected", "§5.9",
        True, _mutate(proven_predicates=())),
    ConformanceVector(
        "identity-flow-relabel",
        "a relabelled flow cannot select a more permissive policy", "§5.9",
        True, _case(
            {
                "flow": AfpTrustFlow.TELEMETRY,
                "profile": ANONYMOUS_PROFILE,
                "scope_policy": None,
                "scope_id": 0,
                "presentation_pseudonym": 0,
                "proof_context": presentation_proof_context(
                    flow=AfpTrustFlow.TELEMETRY,
                    responder_aid=_RESPONDER_AID,
                    session_context=_SESSION_CONTEXT,
                    apr_verifier_aid=_VERIFIER_AID,
                    profile=ANONYMOUS_PROFILE,
                    scope_policy=None,
                ),
                "receipt_response": {},
                "rotation_binding": {},
            })),
    ConformanceVector(
        "meaning-telemetry-off-catalog",
        "a non-catalog predicate on the telemetry flow is rejected", "§6.3",
        True, _case(
            {
                "flow": AfpTrustFlow.TELEMETRY,
                "proven_predicates": (_KYC,),
                "proof_context": presentation_proof_context(
                    flow=AfpTrustFlow.TELEMETRY,
                    responder_aid=_RESPONDER_AID,
                    session_context=_SESSION_CONTEXT,
                    apr_verifier_aid=_VERIFIER_AID,
                    profile=SCOPED_PROFILE,
                    scope_policy=_SCOPE_POLICY,
                ),
            },
            expected_flow=AfpTrustFlow.TELEMETRY,
            required_predicates=_TELEMETRY_POLICY)),
    ConformanceVector(
        "meaning-unmatched-attestation-root",
        "an attestation root outside the signed pairs is rejected", "§14.4",
        True, _case(
            {
                "proven_predicates": (
                    replace(
                        _ATTESTATION, root_authority_identifier="E-unsigned-authority"
                    ),
                )
            },
            required_predicates=_ATTESTATION_POLICY)),
    ConformanceVector(
        "meaning-unmatched-attestation-class",
        "an attestation of another root class is rejected", "§6.3.1",
        True, _case(
            {"proven_predicates": (replace(_ATTESTATION, root_class="root:tee-attestation"),)},
            required_predicates=_ATTESTATION_POLICY)),
    ConformanceVector(
        "meaning-unknown-root-class",
        "an unknown instance-attestation root class is rejected", "§6.3.1",
        True, _unknown_root_class_case),
    ConformanceVector(
        "meaning-repeated-predicate",
        "a repeated predicate is rejected (Safeguard 2 atomicity)", "§14.3",
        True, _mutate(proven_predicates=(_KYC, _KYC))),
    ConformanceVector(
        "meaning-unchecked-rebind-claim",
        "a declared credential rebind with no continuity requirement is rejected",
        "§4.6.2",
        True, _mutate(
            rotation_binding={
                "presentationPseudonym": _PSEUDONYM,
                "scopeId": _SCOPE_ID,
                "rebindProofKind": "zkc:proof:rebind:v2",
            })),
)


def run_presentation_conformance(
    verify: Callable[..., object],
    *,
    vectors: Optional[Tuple[ConformanceVector, ...]] = None,
) -> PresentationConformance:
    """Run the §5.9 vectors against ``verify`` and report what it discharges.

    ``verify`` takes the signature of
    :func:`afp_session.presentation.verify_presentation_binding`. A vector passes
    when the implementation's accept/reject matches the obligation; anything
    other than :class:`PresentationBindingError` propagates, because a crash is
    not a rejection. A construction-time :class:`PresentationBindingError` is
    ``NOT_EXERCISED`` regardless of the expected outcome: only a call to
    ``verify`` can establish whether that implementation discharges an obligation.
    """
    results: List[VectorResult] = []
    for vector in vectors or PRESENTATION_REJECTION_VECTORS:
        try:
            evidence, arguments = vector.build()
        except PresentationBindingError as exc:
            results.append(
                VectorResult(
                    vector,
                    VectorStatus.NOT_EXERCISED,
                    f"verifier not called; rejected at construction: {exc}",
                )
            )
            continue
        try:
            verify(evidence, **arguments)
        except PresentationBindingError as exc:
            results.append(
                VectorResult(
                    vector,
                    VectorStatus.PASSED if vector.must_reject else VectorStatus.FAILED,
                    f"rejected: {exc}",
                )
            )
            continue
        results.append(
            VectorResult(
                vector,
                VectorStatus.FAILED if vector.must_reject else VectorStatus.PASSED,
                "accepted",
            )
        )
    return PresentationConformance(results=tuple(results))


# --- §12.7 bundle vectors -----------------------------------------------------

_BUNDLE_SESSION_CONTEXT = "X_" + "7e" * 32
_BUNDLE_CONTEXT = session_context_field(_BUNDLE_SESSION_CONTEXT)


@dataclass(frozen=True)
class BundleVector:
    """One §12.7 obligation over the AFP-side bundle boundary."""

    vector_id: str
    name: str
    spec_reference: str
    must_reject: bool
    build: Callable[[], Tuple["ZkaBundle", Dict[str, object]]]


def _bundle_case(**overrides) -> Callable[[], Tuple["ZkaBundle", Dict[str, object]]]:
    # Every vector builds from scratch on each call; nothing here mutates the
    # captured overrides, so a suite can be run more than once and mean the same
    # thing each time.
    argument_overrides = dict(overrides.pop("arguments", {}))
    field_overrides = dict(overrides)

    def build():
        bundle = ZkaBundle(
            kind="zka:bundle:v1",
            context=_BUNDLE_CONTEXT,
            transaction="opaque-transaction-proof",
            compliance_proofs=["opaque-zkc-proof"],
        )
        arguments: Dict[str, object] = {
            "expected_session_context": _BUNDLE_SESSION_CONTEXT,
            "bundle_verifier": BundleVerificationResult.accepted,
        }
        arguments.update(argument_overrides)
        for field_name, value in field_overrides.items():
            setattr(bundle, field_name, value)
        return bundle, arguments

    return build


BUNDLE_REJECTION_VECTORS: Tuple[BundleVector, ...] = (
    BundleVector(
        "bundle-honest-valid", "a structurally valid, ZKA-verified bundle is accepted",
        "§12.7", False, _bundle_case()),
    BundleVector(
        "bundle-default-deny",
        "a bundle with no ZKA verifier is rejected; §12.7 verification is two-layer",
        "§12.7", True, _bundle_case(arguments={"bundle_verifier": None})),
    BundleVector(
        "bundle-verifier-rejects", "a ZKA-rejected bundle is rejected", "§12.7",
        True,
        _bundle_case(arguments={"bundle_verifier": BundleVerificationResult.rejected}),
    ),
    BundleVector(
        "bundle-context-mismatch",
        "a bundle bound to another session context is rejected", "§12.7",
        True, _bundle_case(context="0x" + "11" * 32)),
    BundleVector(
        "bundle-empty-proof-set", "a bundle carrying no proofs is rejected", "§12.7",
        True, _bundle_case(transaction=None, compliance_proofs=[])),
)


def run_bundle_conformance(
    verify: Callable[..., object],
    *,
    vectors: Optional[Tuple[BundleVector, ...]] = None,
) -> PresentationConformance:
    """Run the §12.7 bundle vectors against ``verify``.

    ``verify`` takes the signature of :func:`afp_session.bundle.verify_bundle`.
    An implementation that treats an absent ZKA verifier as a pass fails
    ``bundle-default-deny``.
    """
    from .bundle import BundleError

    results: List[VectorResult] = []
    for vector in vectors or BUNDLE_REJECTION_VECTORS:
        bundle, arguments = vector.build()
        try:
            verify(bundle, **arguments)
        except (BundleError, TypeError) as exc:
            results.append(
                VectorResult(
                    vector,
                    VectorStatus.PASSED if vector.must_reject else VectorStatus.FAILED,
                    f"rejected: {exc}",
                )
            )
            continue
        results.append(
            VectorResult(
                vector,
                VectorStatus.FAILED if vector.must_reject else VectorStatus.PASSED,
                "accepted",
            )
        )
    return PresentationConformance(results=tuple(results))
