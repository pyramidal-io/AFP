"""Honest conformance report for the ceremony tooling (§3.5, §4, §6.3.1).

Mirrors ``afp_mixnet.conformance`` and ``afp_introduction.conformance``: each
property returns a :class:`PropertyResult` with a ``proven`` / ``partial`` /
``seam`` / ``failed`` status and its evidence.

§3.5 makes honest disclosure a conformance obligation, and §6.3.1 restates it
for this exact class — a deployment "MUST NOT describe the result as third-party
attestation", and where an authority's "KEL and published trust material do not
yet exist, a deployment selecting that authority MUST disclose the path as
*spec-available but not operational*". Misrepresenting what this tooling does
would therefore itself be a conformance violation, so this module is written to
make overclaiming impossible: :func:`assess_ceremony` never reports the ceremony
as operational, because the production ceremony has not happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence

from afp_session import keri
from afp_session.canonical import digest as _canonical_digest
from afp_session.canonical import qb64 as _qb64

from .authority import verify_pinned_witness_threshold
from .ceremony import CeremonyResult, kel_from_dict, kel_to_dict
from .errors import CeremonyError
from .keystate import (
    find_delegation_anchor,
    find_rotation_anchor,
    resolve_publisher_key_state,
)

__all__ = [
    "PropertyStatus",
    "PropertyResult",
    "CeremonyConformance",
    "check_self_certifying_identifiers",
    "check_pre_rotation_enforced",
    "check_witness_threshold_enforced",
    "check_delegation_anchoring",
    "check_root_material_digest_determinism",
    "check_kel_native_threshold_resolution",
    "check_multisig_signing_custody",
    "check_wire_encoding_interoperability",
    "check_controller_event_signatures",
    "check_guardian_recovery_events",
    "check_witness_kel_walking",
    "assess_ceremony",
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


# -- properties this tooling genuinely establishes -------------------------
#
# Every PROVEN verdict below is *computed* from ``result``, not asserted about
# it. A check whose property stopped holding — receipts no longer gathered, an
# anchor no longer written, a digest no longer deterministic — reports FAILED,
# which is the only way an evidence string can be trusted to describe a
# computation that actually ran.


def check_self_certifying_identifiers(result: Optional[CeremonyResult]) -> PropertyResult:
    pid, name = "4.1", "self-certifying AID derivation"
    if result is None:
        return PropertyResult(pid, name, PropertyStatus.PARTIAL, "no ceremony supplied")
    for identity in (result.authority, result.published_signer):
        inception = identity.kel.events[0]
        rederived = _qb64("E", _canonical_digest(inception.content()))
        if rederived != identity.kel.aid:
            return PropertyResult(
                pid,
                name,
                PropertyStatus.FAILED,
                f"{identity.label} AID does not re-derive from its inception event",
            )
    return PropertyResult(
        pid,
        name,
        PropertyStatus.PROVEN,
        "both AIDs were re-derived here from their own inception event content and "
        "matched, and are re-derived again by afp_session.keri.verify_kel",
    )


def check_pre_rotation_enforced(result: Optional[CeremonyResult]) -> PropertyResult:
    pid, name = "4.4", "pre-rotation is REQUIRED and enforced"
    if result is None or result.rotated_key_state is None:
        return PropertyResult(
            pid, name, PropertyStatus.PARTIAL, "no rotation exercised in this run"
        )
    rotations = [event for event in result.publisher.kel.events if event.ilk == "rot"]
    if not rotations:
        return PropertyResult(
            pid,
            name,
            PropertyStatus.FAILED,
            "rotated_key_state is present but the publisher KEL contains no rotation",
        )
    try:
        keri.verify_kel(
            result.publisher.kel,
            tenant_kel=result.authority.kel,
            witness_keys=result.witness_material,
        )
    except keri.KeriError as exc:
        return PropertyResult(pid, name, PropertyStatus.FAILED, str(exc))
    return PropertyResult(
        pid,
        name,
        PropertyStatus.PROVEN,
        "the rotation reveals the key set the prior event committed to; "
        "afp_session.keri raises PreRotationError otherwise",
    )


def check_controller_event_signatures(
    result: Optional[CeremonyResult] = None,
) -> PropertyResult:
    pid, name = "4.4", "controller signatures on KEL events"
    if result is None:
        return PropertyResult(pid, name, PropertyStatus.PARTIAL, "no ceremony supplied")
    delegated = [result.publisher]
    if result.successor is not None:
        delegated.append(result.successor)
    try:
        keri.verify_kel(result.authority.kel, witness_keys=result.witness_material)
        for signer in delegated:
            keri.verify_kel(
                signer.kel,
                tenant_kel=result.authority.kel,
                witness_keys=result.witness_material,
            )
    except keri.KeriError as exc:
        return PropertyResult(pid, name, PropertyStatus.FAILED, str(exc))
    return PropertyResult(
        pid,
        name,
        PropertyStatus.PROVEN,
        "every authority and delegated-signer KEL event verified under the key set "
        "that authorizes it: inceptions under their own key, rotations under the "
        "revealed pre-rotated key, interactions under the current key, which they "
        "may not change; afp_session.keri raises EventAuthorizationError otherwise",
    )


def check_witness_threshold_enforced(result: Optional[CeremonyResult]) -> PropertyResult:
    pid, name = "4.5", "witness receipt threshold"
    if result is None:
        return PropertyResult(pid, name, PropertyStatus.PARTIAL, "no ceremony supplied")
    material = result.trust_material
    try:
        verify_pinned_witness_threshold(
            result.authority.kel,
            pinned_witness_aids=material.pinned_witness_aids,
            pinned_threshold=material.pinned_witness_threshold,
            witness_material=material.pinned_witness_material,
            label="authority KEL",
        )
        signing_kels = {result.publisher.aid: result.publisher.kel}
        if result.successor is not None:
            signing_kels[result.successor.aid] = result.successor.kel
        for signer in material.anchored_signers:
            kel = signing_kels.get(signer.signing_aid)
            if kel is None:
                return PropertyResult(
                    pid,
                    name,
                    PropertyStatus.FAILED,
                    f"anchored signer {signer.signing_aid} has no KEL in the result",
                )
            verify_pinned_witness_threshold(
                kel,
                pinned_witness_aids=material.pinned_witness_aids,
                pinned_threshold=material.pinned_witness_threshold,
                witness_material=material.pinned_witness_material,
                label=f"anchored KEL {signer.signing_aid}",
            )
    except CeremonyError as exc:
        return PropertyResult(pid, name, PropertyStatus.FAILED, str(exc))
    return PropertyResult(
        pid,
        name,
        PropertyStatus.PROVEN,
        f"every authority-KEL and authority-anchored KEL event was re-checked for "
        f"{material.pinned_witness_threshold} valid Ed25519 receipts from the "
        f"{len(material.pinned_witnesses)} witnesses pinned in the accepted authority "
        "trust material, using that material's own verification material (§6.3.1 "
        "applying §4.5)",
    )


def check_delegation_anchoring(result: Optional[CeremonyResult]) -> PropertyResult:
    pid, name = "4.2", "delegated inception anchored in the authority KEL"
    if result is None:
        return PropertyResult(pid, name, PropertyStatus.PARTIAL, "no ceremony supplied")
    signer = result.published_signer
    try:
        find_delegation_anchor(result.authority.kel, signer.kel)
        rotations = [e for e in signer.kel.events if e.ilk == "rot"]
        for event in rotations:
            find_rotation_anchor(
                result.authority.kel,
                delegate_aid=signer.aid,
                rotation_dig=event.digest,
            )
    except CeremonyError as exc:
        return PropertyResult(pid, name, PropertyStatus.FAILED, str(exc))
    return PropertyResult(
        pid,
        name,
        PropertyStatus.PROVEN,
        "the published signer's dip anchor was located here in the authority KEL and "
        f"is unique, and each of its {len(rotations)} delegated rotation(s) was found "
        "anchored by its own distinct rotation seal (§6.3.1)",
    )


def check_root_material_digest_determinism(
    result: Optional[CeremonyResult],
) -> PropertyResult:
    pid, name = "6.3.1", "root_material_digest recomputes from resolved KEL state"
    if result is None:
        return PropertyResult(pid, name, PropertyStatus.PARTIAL, "no ceremony supplied")
    # Two genuinely independent computations: the ceremony's own resolution, and
    # a second one made from KELs serialized to artifacts and reloaded, exactly
    # as a verifier holding only published bytes would. Comparing a memoized
    # value against itself would make FAILED unreachable and the verdict a
    # tautology, which is the failure this module exists to avoid.
    try:
        authority_kel = kel_from_dict(kel_to_dict(result.authority.kel))
        signing_kel = kel_from_dict(kel_to_dict(result.published_signer.kel))
        reloaded = resolve_publisher_key_state(
            authority_kel=authority_kel,
            signing_kel=signing_kel,
            witness_keys=result.witness_material,
        )
    except CeremonyError as exc:
        return PropertyResult(pid, name, PropertyStatus.FAILED, str(exc))
    published = result.published_key_state
    if reloaded.to_dict() != published.to_dict():
        return PropertyResult(
            pid, name, PropertyStatus.FAILED, "resolved records disagree"
        )
    if reloaded.root_material_digest() != published.root_material_digest():
        return PropertyResult(
            pid,
            name,
            PropertyStatus.FAILED,
            "the digest does not recompute from serialized-and-reloaded KEL state",
        )
    return PropertyResult(
        pid,
        name,
        PropertyStatus.PROVEN,
        "afp:publisher-key-state:v1 was resolved twice — once in memory and once from "
        "KELs serialized to artifacts and reloaded — and both the record and its "
        "RFC 8785 JCS digest matched. Seven of the nine fields are resolved from the "
        "two published KELs; signing_threshold and next_threshold are the "
        "implicit §4.4.2 single-key threshold; explicit or weighted thresholds "
        "remain unsupported (see the "
        "kel-native-threshold seam)",
    )


# -- declared seams: real gaps versus a production KERI ceremony -----------


def check_kel_native_threshold_resolution(
    _: Optional[CeremonyResult] = None,
) -> PropertyResult:
    return PropertyResult(
        "6.3.1",
        "kt/nt resolved from published KEL state",
        PropertyStatus.SEAM,
        "Explicit kt/nt are not carried on KEL events in the current §4.4.2 encoding "
        "(afp_session.keri.KelEvent has no such field — its 'threshold' is the WITNESS "
        "receipt threshold), so two of the nine §6.3.1 key-state fields — "
        "signing_threshold and next_threshold — are fixed by the normative "
        "single-key profile to "
        "\"1\" by resolve_publisher_key_state rather than resolved from published KEL "
        "state. Seven of nine are KEL-derived. The resolver takes no parameter for "
        "them, so a published record asserting a different threshold fails to "
        "reproduce the digest rather than being echoed back; what is missing is the "
        "ability to resolve explicit or weighted kt/nt in a future encoding",
    )


def check_multisig_signing_custody(_: Optional[CeremonyResult] = None) -> PropertyResult:
    return PropertyResult(
        "custody",
        "M-of-N signing threshold (kt/nt)",
        PropertyStatus.SEAM,
        "NOT exercised. afp_session.keri is single-signing-key ('threshold 1 in this "
        "subset'; its helpers index keys[0]), and AFP's own 'threshold' language is "
        "about WITNESS receipts. Multi-sig custody of the organizational root is an "
        "obligation on the production ceremony stated in the custody policy, and the "
        "staging run cannot demonstrate it",
    )


def check_wire_encoding_interoperability(
    _: Optional[CeremonyResult] = None,
) -> PropertyResult:
    return PropertyResult(
        "encoding",
        "CESR/qb64 wire interoperability",
        PropertyStatus.SEAM,
        "NOT provided. Identifiers use afp_session.canonical.qb64's readable "
        "<code>_<hex> form, so staging AIDs are not valid KERI AIDs and no artifact "
        "here is KERI-wire-interoperable. An AFP production implementation must "
        "preserve §4.4.2; a KERI "
        "implementation with different bytes cannot substitute for it",
    )


def check_guardian_recovery_events(_: Optional[CeremonyResult] = None) -> PropertyResult:
    return PropertyResult(
        "4.6",
        "guardian designation and recovery events",
        PropertyStatus.SEAM,
        "NOT defined. Recovery of a root AID that has lost its pre-rotated keys is an "
        "AFP §10 open item and AFP defines no guardian event; a delegated signer is "
        "recovered by revocation and re-delegation (§4.2). The compromise-response "
        "runbook therefore treats root-key loss as a production-ceremony obligation "
        "rather than something this run can demonstrate",
    )


def check_witness_kel_walking(_: Optional[CeremonyResult] = None) -> PropertyResult:
    return PropertyResult(
        "4.5.3",
        "walking each witness's own KEL",
        PropertyStatus.SEAM,
        "NOT provided (§4.5.3 step 5). Receipts are verified against witness "
        "verification material carried in the pinned trust material; the witnesses' "
        "own KELs are not walked",
    )


@dataclass(frozen=True)
class CeremonyConformance:
    """Aggregate verdict. ``production_ceremony_performed`` is always ``False``."""

    properties: Sequence[PropertyResult]

    @property
    def failed(self) -> Sequence[PropertyResult]:
        return [p for p in self.properties if p.status is PropertyStatus.FAILED]

    @property
    def seams(self) -> Sequence[PropertyResult]:
        return [p for p in self.properties if p.status is PropertyStatus.SEAM]

    @property
    def staging_only(self) -> bool:
        return True

    @property
    def production_ceremony_performed(self) -> bool:
        """Always ``False``.

        The production ceremony is an air-gapped human event. No code path in
        this repository performs it, and this requirement cannot be completed on
        the strength of a dry run.
        """
        return False

    @property
    def disclosure(self) -> str:
        return (
            "Spec-available but NOT operational (§6.3.1, §3.5): the authority KEL and "
            "published trust material do not exist. This tooling performs a "
            "non-production staging dry run — a structurally faithful, "
            "cryptographically real simulation in AFP's own encoding, not a "
            "keripy/CESR ceremony. Attestation under root:publisher-manifest is "
            "platform-layer self-attestation and MUST NOT be described as "
            "third-party attestation."
        )


def assess_ceremony(result: Optional[CeremonyResult] = None) -> CeremonyConformance:
    """Aggregate every property into an honest, non-overclaiming verdict."""
    properties: List[PropertyResult] = [
        check_self_certifying_identifiers(result),
        check_pre_rotation_enforced(result),
        check_controller_event_signatures(result),
        check_witness_threshold_enforced(result),
        check_delegation_anchoring(result),
        check_root_material_digest_determinism(result),
        check_kel_native_threshold_resolution(result),
        check_multisig_signing_custody(result),
        check_wire_encoding_interoperability(result),
        check_guardian_recovery_events(result),
        check_witness_kel_walking(result),
    ]
    return CeremonyConformance(properties=tuple(properties))
