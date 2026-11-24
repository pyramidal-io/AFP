"""AFP §14 Introduction Tier — Python reference.

Stranger onboarding over the §12 Bilateral Session Core: a credential + ZKC-proof
handshake that auto-negotiates a scoped, collateral-priced provisional §5.5
agreement (§14.4), grows the envelope with provable history (§14.6), and degrades
or terminates safely (§14.7). Standard-library-only, mirroring ``afp_session`` and
``afp_mixnet``; the ZK reputation circuit, the on-chain bilateral escrow, and the
instance-attestation circuit are honestly-disclosed lower-layer seams (§14.9).

The public surface is assembled across this package's modules; see the
``__all__`` below.
"""

from __future__ import annotations

from .atoms import (
    INTRODUCTION_ATOM_KINDS,
    AcceptedCredential,
    CredentialPresentation,
    Downgrade,
    Envelope,
    IntroductionOffer,
    IntroductionPolicy,
    IntroductionRequest,
    IntroductionWireError,
    LimitAdjustment,
    ProvisionalAgreement,
    ReputationState,
    Termination,
    content_digest,
)
from .agreement import GrowthRejected, apply_limit_adjustment, graduate
from .conformance import (
    IntroductionConformance,
    PropertyResult,
    PropertyStatus,
    assess_introduction,
)
from .credentialing import (
    CredentialingDecision,
    CredentialingError,
    CredentialPresentationVerifier,
    RootAuthorityResolver,
    VerifiedCredentialPresentation,
    evaluate_credentialing,
    evaluate_native_credentialing,
    required_predicate_policy,
)
from .directory import DirectoryError, IntroductionDirectory
from .handshake import IntroductionFSM, State, TransitionError
from .settlement import DefaultOutcome, Rail, RecourseError, resolve_default, within_floor
from .signing import (
    AGREEMENT_SIGNATURE_ROLES,
    AgreementSignatureError,
    agreement_signing_input,
    sign_provisional_agreement,
    verify_provisional_agreement,
)

__all__ = [
    # atoms (§14.1–§14.7)
    "INTRODUCTION_ATOM_KINDS",
    "Envelope",
    "IntroductionOffer",
    "IntroductionRequest",
    "CredentialPresentation",
    "IntroductionPolicy",
    "AcceptedCredential",
    "IntroductionWireError",
    "ReputationState",
    "ProvisionalAgreement",
    "LimitAdjustment",
    "Downgrade",
    "Termination",
    "content_digest",
    # agreement signatures (§14.4)
    "AGREEMENT_SIGNATURE_ROLES",
    "AgreementSignatureError",
    "agreement_signing_input",
    "sign_provisional_agreement",
    "verify_provisional_agreement",
    # directory (§14.1)
    "IntroductionDirectory",
    "DirectoryError",
    # handshake (§14.3)
    "IntroductionFSM",
    "State",
    "TransitionError",
    # §14.3 credentialing (required-vs-presented matching)
    "CredentialingDecision",
    "CredentialingError",
    "CredentialPresentationVerifier",
    "RootAuthorityResolver",
    "VerifiedCredentialPresentation",
    "evaluate_credentialing",
    "evaluate_native_credentialing",
    "required_predicate_policy",
    # agreement growth + graduation (§14.6)
    "apply_limit_adjustment",
    "graduate",
    "GrowthRejected",
    # settlement floor + recourse (§14.5/§14.7)
    "Rail",
    "RecourseError",
    "DefaultOutcome",
    "within_floor",
    "resolve_default",
    # conformance (§14, honest seams §14.9)
    "assess_introduction",
    "IntroductionConformance",
    "PropertyResult",
    "PropertyStatus",
]
