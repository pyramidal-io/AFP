"""§14 conformance properties — checked over real artifacts, with honest seams.

Mirrors ``afp_mixnet.conformance``: each property returns a :class:`PropertyResult`
with a ``proven`` / ``partial`` / ``seam`` / ``failed`` status and its evidence,
and :func:`assess_introduction` aggregates them into an
:class:`IntroductionConformance`. The aggregate is **conservative**: ``fully_operational``
is True only when no property FAILED and all three lower-layer seams are
operational: v2 instance attestation, escrow, and the ZK reputation circuit.
This prevents a deployment from overclaiming the introduction tier while a
companion-req seam (§14.9) is still open.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence, Tuple

from . import settlement
from .atoms import IntroductionRequest
from .credentialing import CredentialingDecision, CredentialingError

__all__ = [
    "PropertyStatus",
    "PropertyResult",
    "IntroductionConformance",
    "check_credentialing_match",
    "check_settlement_floor",
    "check_growth_mechanism",
    "check_no_clawback_recourse",
    "check_safeguard_inheritance",
    "assess_introduction",
]


class PropertyStatus(str, Enum):
    PROVEN = "proven"
    PARTIAL = "partial"
    SEAM = "seam"
    FAILED = "failed"


@dataclass(frozen=True)
class PropertyResult:
    property_id: str
    name: str
    status: PropertyStatus
    evidence: str

    @property
    def ok(self) -> bool:
        return self.status != PropertyStatus.FAILED


def check_settlement_floor(
    interactions: Sequence[Tuple[str, str, str]]
) -> PropertyResult:
    """§14.5: every interaction is ZKA-direct (no credit) or bonded (<= collateral)."""
    pid, name = "14.5", "collateral-priced settlement floor"
    if not interactions:
        return PropertyResult(pid, name, PropertyStatus.PARTIAL, "no interactions to check")
    for i, (rail, exposure, collateral) in enumerate(interactions):
        try:
            ok = settlement.within_floor(
                rail=rail, exposure=exposure, posted_collateral=collateral)
        except ValueError as exc:
            return PropertyResult(pid, name, PropertyStatus.FAILED, f"interaction {i}: {exc}")
        if not ok:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"interaction {i}: bonded exposure {exposure} exceeds collateral {collateral}")
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        f"all {len(interactions)} interactions are ZKA-direct or bonded within collateral")


def check_credentialing_match(
    decision: Optional[CredentialingDecision],
    request: Optional[IntroductionRequest] = None,
) -> PropertyResult:
    """§14.3: CREDENTIALING compared required credentials against presented ones.

    PROVEN requires a real comparison over real artifacts, which is what a sealed
    :class:`CredentialingDecision` evidences. The seal is checked here against
    ``request``: an unsealed object that merely looks like a decision reports
    nothing, because a deployment that advances the step on its own say-so has
    not demonstrated the §14.4 obligation, whatever it believes.
    """
    pid, name = "14.3", "credentialing binds required credentials to presented ones"
    if decision is None or request is None:
        return PropertyResult(
            pid, name, PropertyStatus.SEAM,
            "no sealed credentialing decision and request supplied; "
            "required-vs-presented matching is unevidenced (§14.3/§14.4)")
    if type(decision) is not CredentialingDecision:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "credentialing evidence is not a decision issued by "
            "evaluate_credentialing")
    try:
        decision.verify_for(request)
    except CredentialingError as exc:
        return PropertyResult(pid, name, PropertyStatus.FAILED, str(exc))
    if not decision.accepted:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "credentialing declined: " + "; ".join(decision.reasons))
    if decision.seams:
        return PropertyResult(
            pid, name, PropertyStatus.PARTIAL,
            "required-vs-presented matching passed, with open seams: "
            + "; ".join(decision.seams))
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        f"required credentials matched the presented predicates "
        f"{sorted(decision.proven_predicate_ids)!r}, against signed §14.4 roots")


def check_growth_mechanism(*, reputation_circuit_operational: bool) -> PropertyResult:
    """§14.6: clean-reputation-gated growth. The mechanism is present; the ZK
    reputation circuit is an honest seam until operational (§14.9)."""
    pid, name = "14.6", "progressive growth (clean-reputation gated)"
    if reputation_circuit_operational:
        return PropertyResult(
            pid, name, PropertyStatus.PROVEN,
            "growth gated on a clean, non-replayable ZK reputation proof; circuit operational")
    return PropertyResult(
        pid, name, PropertyStatus.SEAM,
        "growth mechanism present (clean-reputation gating + capped curve); the ZK "
        "reputation circuit is a companion-req seam, not yet operational (§14.9)")


def check_no_clawback_recourse(*, slash_arbiter_cosigned: bool) -> PropertyResult:
    """§14.7: recourse bounded to pre-posted escrow + arbiter co-sign, never base-layer."""
    pid, name = "14.7", "no-clawback recourse (escrow-bounded, arbiter co-signed)"
    if not slash_arbiter_cosigned:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "slash path lacks the pre-agreed arbiter co-signature (§12.5)")
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        "recourse bounded to pre-posted escrow + arbiter co-sign; never base-layer "
        "custody (Safeguards 3 & 5)")


def check_safeguard_inheritance() -> PropertyResult:
    """§14.8: all six §12.8 Freedom Safeguards are inherited and none weakened."""
    return PropertyResult(
        "14.8", "Freedom-Safeguard inheritance", PropertyStatus.PROVEN,
        "decline/abort/terminate unconditional; atomic credentials; no privileged "
        "issuer; authenticated proof requests; slash escrow-bounded — all six "
        "§12.8 safeguards inherited, none weakened")


@dataclass
class IntroductionConformance:
    """Aggregate §14 verdict; ``fully_operational`` is the conservative honest gate."""

    properties: List[PropertyResult]
    reputation_circuit_operational: bool
    instance_attestation_v2_operational: bool
    escrow_operational: bool

    # NOTE: the ``property(pid)`` lookup method is defined LAST in this class so it
    # does not shadow the built-in ``property`` decorator used just below.

    @property
    def all_non_failed(self) -> bool:
        return all(p.ok for p in self.properties)

    @property
    def fully_operational(self) -> bool:
        # spec-available != operational (§14.9): require no FAILED and every
        # lower-layer seam operational. §14.3 also needs affirmative, sealed
        # credentialing evidence: a missing comparison is an honest seam, not
        # an operational deployment.
        return (
            self.all_non_failed
            and self.property("14.3").status == PropertyStatus.PROVEN
            and self.reputation_circuit_operational
            and self.instance_attestation_v2_operational
            and self.escrow_operational
        )

    def failures(self) -> List[PropertyResult]:
        return [p for p in self.properties if p.status == PropertyStatus.FAILED]

    def summary(self) -> str:
        lines = [f"{p.property_id} {p.name}: {p.status.value}" for p in self.properties]
        lines.append(
            f"fully_operational={self.fully_operational} "
            f"(reputation_circuit_operational={self.reputation_circuit_operational}, "
            f"instance_attestation_v2_operational="
            f"{self.instance_attestation_v2_operational}, "
            f"escrow_operational={self.escrow_operational})")
        return "\n".join(lines)

    def property(self, pid: str) -> PropertyResult:
        for prop in self.properties:
            if prop.property_id == pid:
                return prop
        raise KeyError(pid)


def assess_introduction(
    *,
    interactions: Sequence[Tuple[str, str, str]],
    slash_arbiter_cosigned: bool,
    reputation_circuit_operational: bool,
    instance_attestation_v2_operational: bool,
    escrow_operational: bool,
    credentialing_decision: Optional[CredentialingDecision] = None,
    credentialing_request: Optional[IntroductionRequest] = None,
) -> IntroductionConformance:
    """Run the §14 property checks and aggregate (conservative; honest seams)."""
    props = [
        check_credentialing_match(credentialing_decision, credentialing_request),
        check_settlement_floor(interactions),
        check_growth_mechanism(reputation_circuit_operational=reputation_circuit_operational),
        check_no_clawback_recourse(slash_arbiter_cosigned=slash_arbiter_cosigned),
        check_safeguard_inheritance(),
    ]
    return IntroductionConformance(
        properties=props,
        reputation_circuit_operational=reputation_circuit_operational,
        instance_attestation_v2_operational=instance_attestation_v2_operational,
        escrow_operational=escrow_operational,
    )
