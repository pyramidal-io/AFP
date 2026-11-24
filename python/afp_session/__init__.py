"""AFP §12 Bilateral Session Core — Python reference implementation.

A stdlib-only reference implementation of the AFP (Agent Federation Protocol)
**Bilateral Session Core** (specification §12), the substrate the VXP, PRP, and
work profiles (§13) all build on. It implements, to the spec's normative §12
semantics:

  * **KERI AID + KEL verification to a tenant root** (§4 / §12.3) — self-
    certifying identifiers, pre-rotation-enforced Key Event Logs, two-level
    tenant→entity delegation, witness thresholds, and stale-keystate rejection.
    See :mod:`afp_session.keri`.
  * **Session lifecycle** propose→open→active→closing→closed with abort/expire
    and timeout (§12.2). See :mod:`afp_session.session` (:class:`SessionFSM`,
    :class:`Instance`).
  * **``afp:envelope:v1``** carrying an opaque ``zka:bundle:v1`` payload (§12.7),
    bound to the session context and signature-verified. See
    :mod:`afp_session.atoms` and :mod:`afp_session.bundle`.
  * **NATS namespace** ``afp.{tenant}.{profile}.*`` (§12.4) over an abstract
    transport (in-memory for tests; nats-py seam). See
    :mod:`afp_session.namespace`, :mod:`afp_session.transport`.
  * **Bilateral dispute + optional pre-agreed arbiter** (§12.5). See
    :mod:`afp_session.dispute`.
  * **Commitment + optional anchor** (§12.6). See :mod:`afp_session.commitment`.
  * **Profiles registry** (§13.2) and **honest OB-1/OB-2 disclosure conformance**
    (§3.5 / §8.9). See :mod:`afp_session.profiles`, :mod:`afp_session.conformance`.
  * **ZKC v0.4 presentation binding** (§5.9): per-flow profile/downgrade policy,
    KERI presenter + credential-subject + APR signer + session/scope checks, and
    profile-minimized receipt/rotation handles. See :mod:`afp_session.presentation`.
  * **AFP-KDC v1.0.3 domain tags** (Appendix A): clean-room Blake2b512 field-tag
    derivation and complete family-registry validation. See :mod:`afp_session.kdc`.
  * **Coord v2 PRP/VXP completion acceptance** (§12.7.1): exact signed-policy,
    profile/artifact, evidence-reference, context, and replay bindings around an
    independently supplied ZKA verifier. See :mod:`afp_session.coord`.

Cryptography is real (pure-Python Ed25519, RFC 8032, :mod:`afp_session.ed25519`),
matching the stdlib-only discipline of the sibling ZKC reference packages.
Documented seams (where AFP frames/binds but a lower layer proves): the ZKA
prover/verifier (proof bytes remain opaque, §12.7), Poseidon2 in-circuit hashing
(``outcome_root`` uses SHA-256 here, §12.6.1), the §8 mixnet wire form, and the
APL on-chain anchor submission (§12.6.2).
"""

from __future__ import annotations

from .atoms import (
    AfpAnchorAtom,
    AfpCommitmentAtom,
    AfpCommitSignature,
    AfpEnvelope,
    AfpPartyRef,
    AfpSessionAtom,
    AfpSessionStatus,
    MAX_OPENED_AT,
    MIN_OPENED_AT,
    SESSION_STABLE_CONTENT_MEMBERS,
    compute_session_context,
    opened_at_to_rfc3339,
    session_datetime_to_unix,
    unix_to_session_datetime,
    validate_opened_at,
    validate_session_datetime,
)
from .bundle import (
    BUNDLE_VERSION,
    BundleError,
    BundleVerificationResult,
    BundleVerifier,
    ZkaBundle,
    session_context_field,
    verify_bundle,
)
from .commitment import (
    CommitmentError,
    SequenceError,
    anchor_commitment,
    build_commitment,
    outcome_root_for,
    sign_commitment,
    verify_commitment,
)
from .credential import (
    CREDENTIAL_ENVELOPE_KIND,
    AcceptedCredentialEnvelope,
    AprSignerBindingResolver,
    AfpCredentialEnvelope,
    CredentialEnvelopeError,
    NativeCredentialVerification,
    NativeCredentialVerificationRequest,
    NativeCredentialVerifier,
    NativeAprSignerBinding,
    NativeAprSignerBindingRequest,
    require_verified_native_credential,
)
from .channel import (
    CHANNEL_KEY_KIND,
    CHANNEL_SUITE,
    DEFAULT_REPLAY_WINDOW,
    SEALED_CHANNEL_ATTESTATION_KIND,
    SEALED_FRAME_KIND,
    SEALED_FRAME_OVERHEAD,
    ChannelBinding,
    ChannelEndpoint,
    ChannelError,
    ChannelKeyAttestation,
    ChannelRole,
    SealedChannelAttestation,
    SealedTransitEvidence,
    SessionChannel,
    validate_sealed_channel_attestation,
)
from .conformance import (
    ConformanceViolation,
    DeploymentProfile,
    ObClaim,
    ObLevel,
    assess_ob_disclosure,
    guard_ob_claim,
)
from .coord import (
    BN254_ZERO_FIELD,
    COORD_ACCEPTANCE_POLICY,
    COORD_COMPLETION_MESSAGE_CLASS,
    COORD_PRIVATE_RECONCILIATION_PROFILE,
    COORD_PRIVATE_RECONCILIATION_PROFILE_BINDING,
    COORD_PRIVATE_RECONCILIATION_PROFILE_FIELD,
    COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH,
    COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH,
    COORD_RECURSIVE_ARTIFACT_ROLE,
    COORD_RECURSIVE_CIRCUIT,
    COORD_RECURSIVE_VERIFICATION_KEY_HASH,
    COORD_V2_RECEIPT,
    COORD_V2_RECEIPT_KIND,
    COORD_VXP_RECIPROCAL_ACK_PROFILE,
    COORD_VXP_RECIPROCAL_ACK_PROFILE_BINDING,
    COORD_VXP_RECIPROCAL_ACK_PROFILE_FIELD,
    COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH,
    COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH,
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE,
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_BINDING,
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_FIELD,
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH,
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH,
    CoordAcceptancePolicy,
    CoordArtifactBinding,
    CoordAssurance,
    CoordCompletion,
    CoordCompletionRecord,
    CoordCompletionStore,
    CoordCompletionVerificationContext,
    CoordEvidenceReference,
    CoordFailureCode,
    CoordFinalProof,
    CoordFinalProofVerifier,
    CoordProfileBinding,
    CoordRecordResult,
    CoordVerificationError,
    CoordVerificationReport,
    CoordVerifierRequest,
    CoordVerifierRejected,
    CoordVerifierResult,
    CoordVerifierUnavailable,
    InMemoryCoordCompletionStore,
    SqliteCoordCompletionStore,
    derive_coord_context,
)
from .dispute import Arbiter, ArbiterDecision, DisputeError, DivergenceRecord
from .keri import (
    EventAuthorizationError,
    Identity,
    Kel,
    KeriError,
    KeyPair,
    StaleKeyStateError,
    Witness,
    resolve_current_key,
    verify_kel,
)
from .namespace import NamespaceError, session_subject, subject
from .profiles import AfpProfileDescriptor, ProfileRegistry, default_registry
from .presentation import (
    AFP_TELEMETRY_PREDICATE_CATALOG,
    AFP_ZKC_PRESENTATION_CONTEXT_V2,
    ANONYMOUS_PROFILE,
    INSTANCE_ATTESTATION_PREDICATE_V2,
    INSTANCE_ATTESTATION_ROOT_CLASSES,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    AfpTrustFlow,
    PresentationBindingError,
    PresentationPolicy,
    ProvenPredicate,
    RequiredPredicatePolicy,
    VerifiedPresentation,
    ZkcVerifiedPublicStatement,
    ZkcPresentationEvidence,
    ZkcVerifier,
    afp_scope_policy,
    as_trust_flow,
    derive_scope_id,
    flow_policy,
    presentation_proof_context,
    root_pair_of,
    verify_presentation_binding,
)
from .session import (
    EnvelopeError,
    IdentityBindingError,
    Instance,
    RemoteParty,
    SessionError,
    SessionExpired,
    SessionFSM,
    TransitionError,
    VerifiedLiveSession,
    verify_party_ref,
)
from .transport import InMemoryTransport, NatsTransport, Transport

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # identity (KERI)
    "Identity",
    "Kel",
    "KeyPair",
    "Witness",
    "KeriError",
    "EventAuthorizationError",
    "StaleKeyStateError",
    "verify_kel",
    "resolve_current_key",
    # atoms
    "AfpSessionAtom",
    "AfpSessionStatus",
    "AfpPartyRef",
    "AfpEnvelope",
    "AfpCommitmentAtom",
    "AfpCommitSignature",
    "AfpAnchorAtom",
    "MIN_OPENED_AT",
    "MAX_OPENED_AT",
    "SESSION_STABLE_CONTENT_MEMBERS",
    "validate_opened_at",
    "opened_at_to_rfc3339",
    "validate_session_datetime",
    "session_datetime_to_unix",
    "unix_to_session_datetime",
    "compute_session_context",
    # bundle
    "BUNDLE_VERSION",
    "ZkaBundle",
    "BundleError",
    "BundleVerifier",
    "BundleVerificationResult",
    "session_context_field",
    "verify_bundle",
    # native credential-only carriage
    "CREDENTIAL_ENVELOPE_KIND",
    "AfpCredentialEnvelope",
    "CredentialEnvelopeError",
    "NativeCredentialVerificationRequest",
    "NativeCredentialVerification",
    "NativeCredentialVerifier",
    "AcceptedCredentialEnvelope",
    "require_verified_native_credential",
    "NativeAprSignerBindingRequest",
    "NativeAprSignerBinding",
    "AprSignerBindingResolver",
    # Coord v2 completion integration
    "COORD_V2_RECEIPT",
    "COORD_V2_RECEIPT_KIND",
    "COORD_ACCEPTANCE_POLICY",
    "COORD_COMPLETION_MESSAGE_CLASS",
    "COORD_RECURSIVE_ARTIFACT_ROLE",
    "COORD_RECURSIVE_CIRCUIT",
    "COORD_RECURSIVE_VERIFICATION_KEY_HASH",
    "COORD_PRIVATE_RECONCILIATION_PROFILE",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_FIELD",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_BINDING",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_FIELD",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_BINDING",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_FIELD",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_BINDING",
    "BN254_ZERO_FIELD",
    "CoordAssurance",
    "CoordFailureCode",
    "CoordVerificationError",
    "CoordVerifierRejected",
    "CoordVerifierUnavailable",
    "CoordProfileBinding",
    "CoordArtifactBinding",
    "CoordAcceptancePolicy",
    "CoordFinalProof",
    "CoordEvidenceReference",
    "CoordVerifierResult",
    "CoordVerifierRequest",
    "CoordVerificationReport",
    "CoordFinalProofVerifier",
    "CoordCompletionVerificationContext",
    "CoordCompletionRecord",
    "CoordRecordResult",
    "CoordCompletionStore",
    "InMemoryCoordCompletionStore",
    "SqliteCoordCompletionStore",
    "CoordCompletion",
    "derive_coord_context",
    # session
    "Instance",
    "RemoteParty",
    "SessionFSM",
    "SessionError",
    "TransitionError",
    "SessionExpired",
    "IdentityBindingError",
    "EnvelopeError",
    "verify_party_ref",
    "VerifiedLiveSession",
    # dispute
    "Arbiter",
    "ArbiterDecision",
    "DivergenceRecord",
    "DisputeError",
    # commitment
    "build_commitment",
    "sign_commitment",
    "verify_commitment",
    "anchor_commitment",
    "outcome_root_for",
    "CommitmentError",
    "SequenceError",
    # entity-to-entity sealed channel
    "CHANNEL_KEY_KIND",
    "SEALED_FRAME_KIND",
    "SEALED_CHANNEL_ATTESTATION_KIND",
    "CHANNEL_SUITE",
    "SEALED_FRAME_OVERHEAD",
    "DEFAULT_REPLAY_WINDOW",
    "ChannelError",
    "ChannelRole",
    "ChannelBinding",
    "ChannelKeyAttestation",
    "SealedTransitEvidence",
    "SealedChannelAttestation",
    "validate_sealed_channel_attestation",
    "ChannelEndpoint",
    "SessionChannel",
    # namespace / transport
    "subject",
    "session_subject",
    "NamespaceError",
    "Transport",
    "InMemoryTransport",
    "NatsTransport",
    # profiles
    "AfpProfileDescriptor",
    "ProfileRegistry",
    "default_registry",
    # ZKC v0.4 presentation profiles
    "ANONYMOUS_PROFILE",
    "SCOPED_PROFILE",
    "LINKABLE_PROFILE",
    "AFP_ZKC_PRESENTATION_CONTEXT_V2",
    "AfpTrustFlow",
    "PresentationPolicy",
    "PresentationBindingError",
    "ZkcPresentationEvidence",
    "ZkcVerifiedPublicStatement",
    "ZkcVerifier",
    "flow_policy",
    "as_trust_flow",
    "afp_scope_policy",
    "derive_scope_id",
    "presentation_proof_context",
    "verify_presentation_binding",
    # predicate meaning binding (§6.3 / §6.3.1 / §14.4)
    "AFP_TELEMETRY_PREDICATE_CATALOG",
    "INSTANCE_ATTESTATION_PREDICATE_V2",
    "INSTANCE_ATTESTATION_ROOT_CLASSES",
    "ProvenPredicate",
    "RequiredPredicatePolicy",
    "VerifiedPresentation",
    "root_pair_of",
    # conformance (OB disclosure)
    "ObLevel",
    "ObClaim",
    "DeploymentProfile",
    "ConformanceViolation",
    "assess_ob_disclosure",
    "guard_ob_claim",
]
