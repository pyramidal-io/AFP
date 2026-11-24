"""Honest OB disclosure conformance guard (§3.5 / §3.1 / §8.9).

AFP defines two distinct operator-blindness properties (§3.1):

  * **OB-1 (content)** — the operator cannot learn the *content* of tenant work.
    Delivered in **every** deployment by §5.2 end-to-end channel encryption plus
    the ZKA/ZKC substrate. Does not depend on §8.
  * **OB-2 (graph)** — the operator cannot learn the *coordination graph* (which
    tenant coordinates with which). Delivered **only** by the §8 metadata-privacy
    mixnet routing layer.

§3.5 (honest disclosure) and §8.9 are normative: a deployment whose mixnet is
**not operational** does NOT satisfy OB-2 and **MUST** disclose this — it claims
OB-1 and states OB-2 as *not-yet-met*. Claiming OB-2 (appliance-/routing-grade
metadata privacy) without it is a conformance violation *independent of any
cryptographic correctness* (§3.5).

This module is the conformance guard: a deployment self-describes its operational
state, and :func:`assess_ob_disclosure` derives the OB level the deployment is
*permitted* to claim — never letting a deployment overclaim OB-2. The capability
discipline of §3.2 ("capability, not conduct") is enforced structurally here:
OB-2 is permitted only when the mixnet is *operational and adequately sized*, not
when the operator merely *intends* metadata privacy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List

from .channel import (
    SealedChannelAttestation,
    validate_sealed_channel_attestation,
)

__all__ = [
    "ObLevel",
    "ObClaim",
    "DeploymentProfile",
    "ConformanceViolation",
    "assess_ob_disclosure",
    "guard_ob_claim",
]


class ObLevel(str, Enum):
    """The OB tiers a deployment can honestly claim (§3.1 / §3.5)."""

    NONE = "none"  # neither OB-1 nor OB-2 (non-conforming as an AFP deployment)
    OB1 = "ob-1"  # content confidentiality only (the valid lesser tier, §3.5)
    OB2 = "ob-2"  # content + coordination-graph privacy (full OB, §3.1)


class MetState(str, Enum):
    MET = "met"
    NOT_MET = "not-met"


@dataclass(frozen=True)
class DeploymentProfile:
    """A deployment's self-described operational state, the input to the guard.

    The guard treats these as *capability* facts (§3.2), not intentions:

      * ``channel_encryption_operational`` — receiver-minted evidence that §5.2
        E2E encryption carried a real authenticated transit (OB-1), never a bool.
      * ``channel_session_context`` / ``channel_kel_event_dig`` — authoritative
        expected bindings against which that evidence is revalidated.
      * ``mixnet_operational`` — the §8 routing layer is running.
      * ``mandatory_cover_traffic`` — every tenant emits cover traffic (§8.5),
        required for OB-2's capability guarantee.
      * ``mix_node_count`` — the operational mix-node set size; OB-2 requires a
        *sufficient* set (§8.9 "a sufficient mix-node set").
    """

    name: str
    channel_encryption_operational: SealedChannelAttestation | None
    mixnet_operational: bool
    channel_session_context: str | None = None
    channel_kel_event_dig: str | None = None
    mandatory_cover_traffic: bool = False
    mix_node_count: int = 0
    # Minimum mix nodes for the mixnet to be considered a "sufficient" set (§8.9).
    min_mix_nodes_for_ob2: int = 3

    def __post_init__(self) -> None:
        evidence = self.channel_encryption_operational
        if evidence is not None and type(evidence) is not SealedChannelAttestation:
            raise TypeError(
                "channel_encryption_operational must be a receiver-minted "
                "SealedChannelAttestation or None"
            )


@dataclass(frozen=True)
class ObClaim:
    """The OB level a deployment is *permitted* to claim, with per-property state.

    ``ob1`` / ``ob2`` are MET / NOT_MET. ``claimed_level`` is the highest tier the
    deployment may honestly advertise. ``disclosures`` carries the §3.5 honest-
    disclosure statements a deployment MUST surface to its tenants.
    """

    deployment: str
    claimed_level: ObLevel
    ob1: MetState
    ob2: MetState
    disclosures: List[str]

    @property
    def overclaims_ob2(self) -> bool:
        return self.claimed_level == ObLevel.OB2 and self.ob2 != MetState.MET


class ConformanceViolation(Exception):
    """A deployment attempted to claim an OB level it does not satisfy (§3.5)."""


def assess_ob_disclosure(profile: DeploymentProfile) -> ObClaim:
    """Derive the OB level a deployment may honestly claim (§3.5 / §8.9).

    This is the honest-disclosure logic the spec mandates:

      * OB-1 is MET iff a receiver-minted channel attestation revalidates against
        its live issuer and the expected session/KEL binding (§3.3 / §5.2).
      * OB-2 is MET iff OB-1 is MET, the mixnet is operational, mandatory cover
        traffic is on, and the mix-node set is sufficient (§3.3 / §8.5 / §8.9).
        Otherwise it is explicitly NOT_MET and the deployment cannot claim OB-2.

    The returned claim never overclaims OB-2: a deployment with valid OB-1
    evidence but no operational mixnet is limited to ``ObLevel.OB1`` with an
    OB-2 not-yet-met disclosure (§8.9), even if it believes its metadata is
    private (capability, not conduct, §3.2).
    """
    disclosures: List[str] = []

    ob1_evidence_valid = validate_sealed_channel_attestation(
        profile.channel_encryption_operational,
        session_context=profile.channel_session_context,
        kel_event_dig=profile.channel_kel_event_dig,
    )
    ob1 = MetState.MET if ob1_evidence_valid else MetState.NOT_MET
    if ob1 != MetState.MET:
        disclosures.append(
            "OB-1 (content) NOT met: §5.2 sealed-channel evidence is absent, "
            "invalid, expired, or not bound to the expected session/KEL. "
            "This deployment does not satisfy the operator-blindness invariant "
            "and MUST disclose that fact (§3.5)."
        )

    ob2_met = (
        ob1 == MetState.MET
        and profile.mixnet_operational
        and profile.mandatory_cover_traffic
        and profile.mix_node_count >= profile.min_mix_nodes_for_ob2
    )
    ob2 = MetState.MET if ob2_met else MetState.NOT_MET

    if not ob2_met:
        # §3.5 / §8.9: state OB-2 as not-yet-met and explain why.
        reasons = []
        if ob1 != MetState.MET:
            reasons.append("the OB-1 sealed-channel prerequisite is not met")
        if not profile.mixnet_operational:
            reasons.append("the §8 mixnet routing layer is not operational")
        else:
            if not profile.mandatory_cover_traffic:
                reasons.append("mandatory cover traffic (§8.5) is not enabled")
            if profile.mix_node_count < profile.min_mix_nodes_for_ob2:
                reasons.append(
                    f"the mix-node set ({profile.mix_node_count}) is below the "
                    f"sufficient-set threshold ({profile.min_mix_nodes_for_ob2}) (§8.9)"
                )
        if ob1 == MetState.MET:
            permitted_claim = (
                "This deployment claims OB-1 (content) only and MUST NOT "
                "represent OB-2 as satisfied"
            )
        else:
            permitted_claim = (
                "This deployment claims no OB level and MUST NOT represent "
                "OB-1 or OB-2 as satisfied"
            )
        disclosures.append(
            "OB-2 (coordination-graph privacy) NOT YET MET: "
            + "; ".join(reasons)
            + f". {permitted_claim} (§3.5 / §8.9)."
        )

    if ob1 == MetState.MET and ob2 == MetState.MET:
        claimed = ObLevel.OB2
    elif ob1 == MetState.MET:
        claimed = ObLevel.OB1
    else:
        claimed = ObLevel.NONE

    return ObClaim(
        deployment=profile.name,
        claimed_level=claimed,
        ob1=ob1,
        ob2=ob2,
        disclosures=disclosures,
    )


def guard_ob_claim(profile: DeploymentProfile, intended_level: ObLevel) -> ObClaim:
    """Reject an over-claim (§3.5): a deployment MUST NOT claim more than it satisfies.

    Returns the honest :class:`ObClaim` if ``intended_level`` is permitted; raises
    :class:`ConformanceViolation` if the deployment tries to claim OB-2 (or
    OB-1) it does not structurally satisfy. This is the guard a deployment runs
    before advertising its OB tier.
    """
    claim = assess_ob_disclosure(profile)
    _order = {ObLevel.NONE: 0, ObLevel.OB1: 1, ObLevel.OB2: 2}
    if _order[intended_level] > _order[claim.claimed_level]:
        raise ConformanceViolation(
            f"deployment {profile.name!r} cannot claim {intended_level.value}: "
            f"honest level is {claim.claimed_level.value}. "
            + " ".join(claim.disclosures)
        )
    return claim
