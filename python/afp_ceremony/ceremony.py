"""Staging dry run of the AFP attestation-authority key ceremony (§4.2, §4.4, §6.3.1).

This module materializes, end to end, the two-AID construction §6.3.1 describes
for an organizational attestation root authority:

* an **organizational root AID** for the accountable legal entity, incepted with
  a pre-rotation commitment (§4.4) and a witness set at a declared threshold
  (§4.5); and
* a **delegated, product-scoped publisher AID** whose inception is a ``dip``
  event anchored by a seal in the organizational KEL — "exactly as an entity is
  delegated from a tenant root (§4.2)" — which signs release build manifests.

It also performs two of the lifecycle transitions the rotation /
compromise-response / succession runbook references: a publisher-key rotation
re-anchored in the authority KEL ("each delegated rotation as events in the
**signing AID's** KEL, each anchored by a seal in the **authority's** KEL"), and
succession by standing up a replacement delegated signer while the superseded one
is marked in the authority's trust material. It does **not** rotate the
organizational root key: :func:`rotate_identity` is applied only to the delegated
publisher, so the separate production root-rotation procedure — the
highest-blast-radius ceremony operation — is unrehearsed here and says so.

**What this is, exactly.** It is a *structurally faithful, cryptographically real
simulation in AFP's own encoding* — not a keripy/CESR ceremony, and not the
production ceremony. Every signature is real RFC 8032 Ed25519
(``afp_session.ed25519``, pure Python, KAT-pinned); self-certifying AID
derivation, controller signatures on every KEL event (§4.4), pre-rotation
enforcement, delegation anchoring, and witness receipt thresholds are genuinely
computed and genuinely enforced. What differs from a production KERI ceremony,
and what :mod:`afp_ceremony.conformance` reports as seams rather than proven
properties:

* the encoding is ``afp_session.canonical.qb64``'s readable ``<code>_<hex>``,
  **not** CESR/qb64 — a staging AID is not a valid KERI AID, and controller
  signatures use the reference attachment (``afp_session.keri.sign_event``)
  rather than KERI indexed signatures;
* the reference subset is **single-signing-key** ("threshold 1 in this subset"),
  so true M-of-N ``kt``/``nt`` signing custody cannot be exercised here at all;
  it is an obligation on the production ceremony, stated in the custody policy;
* there is no guardian/recovery event and no duplicity detection; and
* witness KELs are not walked (§4.5.3 step 5).

Pyramidal Inc.'s organizational root AID **does not exist**, is not created here,
and must not be created here. Every guard in :mod:`afp_ceremony.staging` applies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from afp_session import keri
from afp_session.canonical import digest as _canonical_digest
from afp_session.canonical import qb64 as _qb64

# Reused, never re-derived: the pre-rotation commitment rule (§4.4) is owned by
# ``afp_session.keri`` and its verifier checks events against exactly this
# function. Recomputing it here would create a second normative text for one rule.
from afp_session.keri import _next_key_digest as next_key_digest

from .authority import (
    AfpAuthorityTrustMaterial,
    AnchoredSigner,
    PinnedWitness,
    SIGNER_ACTIVE,
    SIGNER_SUPERSEDED,
    accept_publisher_key_state,
    build_authority_trust_material,
    verify_authority_trust_material,
)
from .errors import ArtifactError, CeremonyError
from .keystate import (
    AfpPublisherKeyState,
    find_rotation_anchor,
    resolve_publisher_key_state,
    rotation_anchor_seal,
)
from .staging import (
    STAGING_AUTHORITY_LABEL,
    derive_staging_material,
    enforce_not_production,
    stamp_not_production,
    staging_endpoint,
    staging_markers,
)

__all__ = [
    "STAGING_EVENT_TIMESTAMP",
    "STAGING_ISSUED_AT",
    "STAGING_EXPIRES_AT",
    "STAGING_NOW",
    "KEL_ARTIFACT_KIND",
    "TRANSCRIPT_KIND",
    "WITNESS_DIRECTORY_KIND",
    "KEY_STATE_ARTIFACT_KIND",
    "ARTIFACT_FILENAMES",
    "StagedIdentity",
    "CeremonyResult",
    "rotation_anchor_seal",
    "make_staging_witnesses",
    "incept_authority_root",
    "incept_delegated_signer",
    "rotate_identity",
    "anchor_rotation",
    "find_rotation_anchor",
    "run_staging_ceremony",
    "kel_to_dict",
    "kel_from_dict",
    "write_ceremony_artifacts",
    "load_ceremony_artifacts",
    "verify_ceremony_artifacts",
]

#: Fixed event timestamp for staging. KEL event timestamps are **not** part of
#: ``KelEvent.content()`` and therefore never affect a SAID; pinning them keeps
#: emitted artifacts byte-reproducible from the published derivation phrase.
STAGING_EVENT_TIMESTAMP = 0.0

STAGING_ISSUED_AT = "2026-01-01T00:00:00Z"
STAGING_EXPIRES_AT = "2027-01-01T00:00:00Z"
STAGING_NOW = "2026-06-01T00:00:00Z"

#: Staging-only artifact discriminators. They deliberately do **not** wear the
#: protocol's ``afp:`` prefix: AFP defines none of these records, and a staging
#: file whose most prominent field read ``afp:…`` would invite a reader to
#: implement a verifier against a repo-local convention. ``x-afp-staging:`` says
#: what they are — an experimental, staging-scoped encoding of this tooling's
#: own scratch output, checked only by ``kel_from_dict`` and
#: :func:`verify_ceremony_artifacts`.
KEL_ARTIFACT_KIND = "x-afp-staging:kel-transcript:v1"
TRANSCRIPT_KIND = "x-afp-staging:ceremony-transcript:v1"
WITNESS_DIRECTORY_KIND = "x-afp-staging:witness-directory:v1"
KEY_STATE_ARTIFACT_KIND = "x-afp-staging:publisher-key-state-artifact:v1"

ARTIFACT_FILENAMES: Mapping[str, str] = {
    "authority_kel": "staging-authority-root-kel.json",
    "publisher_kel": "staging-publisher-kel.json",
    "trust_material": "staging-authority-trust-material.json",
    "key_state": "staging-publisher-key-state.json",
    "witness_directory": "staging-witness-directory.json",
    "transcript": "staging-ceremony-transcript.json",
}

_AUTHORITY_LABEL = "authority-root"
_PUBLISHER_LABEL = "adamas-publisher"
_SUCCESSOR_LABEL = "adamas-publisher-successor"


# -- identities ------------------------------------------------------------


@dataclass(frozen=True)
class StagedIdentity:
    """A staging AID: its KEL, its current and pre-committed next key material.

    The wrapper owns the derived keypairs so nothing here ever reads private
    state off ``afp_session.keri.Identity``. ``current``/``next`` are derived
    from the published staging phrase, so they are reproducible and worthless.
    """

    label: str
    kel: keri.Kel
    current: keri.KeyPair
    next: keri.KeyPair
    generation: int
    witnesses: Tuple[keri.Witness, ...]
    threshold: int

    @property
    def aid(self) -> str:
        return self.kel.aid

    @property
    def inception_dig(self) -> str:
        return self.kel.events[0].digest

    def as_keri_identity(self) -> keri.Identity:
        """A ``keri.Identity`` view over this KEL, for reference-owned operations."""
        return keri.Identity(
            kel=self.kel,
            current=self.current,
            next_keypair=self.next,
            witnesses=list(self.witnesses),
        )

    def sign(self, message: bytes) -> bytes:
        return self.current.sign(message)


def _gather_receipts(
    kel: keri.Kel, event: keri.KelEvent, witnesses: Sequence[keri.Witness]
) -> None:
    for witness in witnesses:
        kel.add_receipt(witness.receipt(event.digest))


def make_staging_witnesses(count: int) -> Tuple[keri.Witness, ...]:
    """Derive ``count`` deterministic staging witnesses (§4.5)."""
    if count < 1:
        raise CeremonyError("a witness set must have at least one witness")
    witnesses = []
    for index in range(count):
        current = derive_staging_material(f"witness/{index}")
        nxt = derive_staging_material(f"witness/{index}/next")
        inception = keri.KelEvent(
            ilk="icp", sn=0, keys=[current.public_qb64],
            next_key_digest=next_key_digest(nxt.public_key), prior_dig=None,
        )
        witnesses.append(keri.Witness("E_" + inception.digest[2:], current))
    return tuple(witnesses)


def incept_authority_root(
    *,
    label: str = _AUTHORITY_LABEL,
    witnesses: Sequence[keri.Witness],
    threshold: int,
) -> StagedIdentity:
    """Incept the organizational root AID (§4.2 tenant-root pattern, §4.4, §4.5)."""
    current = derive_staging_material(f"{label}/gen0")
    following = derive_staging_material(f"{label}/gen1")
    event = keri.KelEvent(
        ilk="icp",
        sn=0,
        keys=[current.public_qb64],
        next_key_digest=next_key_digest(following.public_key),
        prior_dig=None,
        witnesses=[w.aid for w in witnesses],
        threshold=threshold,
        timestamp=STAGING_EVENT_TIMESTAMP,
    )
    keri.sign_event(event, current)
    aid = _qb64("E", _canonical_digest(event.content()))
    kel = keri.Kel(aid=aid, events=[event])
    _gather_receipts(kel, event, witnesses)
    return StagedIdentity(
        label=label,
        kel=kel,
        current=current,
        next=following,
        generation=0,
        witnesses=tuple(witnesses),
        threshold=threshold,
    )


def incept_delegated_signer(
    authority: StagedIdentity,
    *,
    label: str = _PUBLISHER_LABEL,
    witnesses: Optional[Sequence[keri.Witness]] = None,
    threshold: Optional[int] = None,
) -> Tuple[StagedIdentity, str]:
    """Incept a product-scoped delegated signing AID anchored in ``authority``'s KEL.

    Returns the delegated identity and the SAID of the authority-KEL interaction
    event that anchors its inception — the ``delegation_anchor_dig`` of §6.3.1.
    """
    witness_set = tuple(witnesses) if witnesses is not None else authority.witnesses
    thr = threshold if threshold is not None else authority.threshold
    current = derive_staging_material(f"{label}/gen0")
    following = derive_staging_material(f"{label}/gen1")
    event = keri.KelEvent(
        ilk="dip",
        sn=0,
        keys=[current.public_qb64],
        next_key_digest=next_key_digest(following.public_key),
        prior_dig=None,
        witnesses=[w.aid for w in witness_set],
        threshold=thr,
        delegator_aid=authority.aid,
        timestamp=STAGING_EVENT_TIMESTAMP,
    )
    keri.sign_event(event, current)
    aid = _qb64("E", _canonical_digest(event.content()))
    kel = keri.Kel(aid=aid, events=[event])
    _gather_receipts(kel, event, witness_set)
    # The anchoring seal shape is owned by ``afp_session.keri``; delegate to it
    # rather than restating the rule its own verifier enforces.
    anchor = authority.as_keri_identity()._anchor_delegation(aid, event.digest)
    signer = StagedIdentity(
        label=label,
        kel=kel,
        current=current,
        next=following,
        generation=0,
        witnesses=witness_set,
        threshold=thr,
    )
    return signer, anchor.digest


def rotate_identity(staged: StagedIdentity) -> StagedIdentity:
    """Rotate ``staged``, revealing the pre-committed next key set (§4.4, §4.6).

    The rotation event is appended to ``staged.kel`` in place, and the returned
    identity shares that KEL. Callers must use the returned identity because the
    input object's ``current`` and ``next`` fields are stale after this call.
    """
    revealed = staged.next
    following = derive_staging_material(f"{staged.label}/gen{staged.generation + 2}")
    prior = staged.kel.latest
    event = keri.KelEvent(
        ilk="rot",
        sn=prior.sn + 1,
        keys=[revealed.public_qb64],
        next_key_digest=next_key_digest(following.public_key),
        prior_dig=prior.digest,
        witnesses=list(prior.witnesses),
        threshold=prior.threshold,
        timestamp=STAGING_EVENT_TIMESTAMP,
    )
    # A rotation is authorized by the key it reveals (§4.4).
    keri.sign_event(event, revealed)
    staged.kel.events.append(event)
    _gather_receipts(staged.kel, event, staged.witnesses)
    return replace(
        staged, current=revealed, next=following, generation=staged.generation + 1
    )


def anchor_rotation(
    authority: StagedIdentity, *, delegate_aid: str, rotation_dig: str
) -> str:
    """Anchor a delegated rotation in the authority KEL; return the anchor SAID."""
    prior = authority.kel.latest
    event = keri.KelEvent(
        ilk="ixn",
        sn=prior.sn + 1,
        keys=[authority.current.public_qb64],
        next_key_digest=prior.next_key_digest,  # an ixn does not rotate
        prior_dig=prior.digest,
        witnesses=list(prior.witnesses),
        threshold=prior.threshold,
        seal=rotation_anchor_seal(delegate_aid, rotation_dig),
        timestamp=STAGING_EVENT_TIMESTAMP,
    )
    keri.sign_event(event, authority.current)
    authority.kel.events.append(event)
    _gather_receipts(authority.kel, event, authority.witnesses)
    return event.digest


# -- orchestration ---------------------------------------------------------


@dataclass
class CeremonyResult:
    """Everything a staging dry run produced, in the order it was produced."""

    witnesses: Tuple[keri.Witness, ...]
    threshold: int
    authority: StagedIdentity
    publisher: StagedIdentity
    delegation_anchor_dig: str
    trust_material: AfpAuthorityTrustMaterial
    key_state: AfpPublisherKeyState
    root_material_digest: str
    steps: List[Dict[str, Any]]
    rotated_key_state: Optional[AfpPublisherKeyState] = None
    rotated_root_material_digest: Optional[str] = None
    successor: Optional[StagedIdentity] = None
    # Memo for :attr:`published_key_state`. Resolution re-verifies both KELs
    # (every event, every receipt, real Ed25519), which is deliberately not free;
    # resolving once per ceremony keeps the reference suite inside its CI budget.
    _published_key_state: Optional[AfpPublisherKeyState] = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def witness_material(self) -> Dict[str, bytes]:
        return {w.aid: w.public_key for w in self.witnesses}

    @property
    def published_signer(self) -> StagedIdentity:
        """The signing AID the emitted artifacts describe — the currently active one.

        After a succession the superseded publisher remains recorded in the
        authority's trust material (status ``superseded``) and its delegation
        anchor stays in the authority KEL forever, but the *published* key state
        is the active signer's: §6.3.1 requires rejecting "a proof whose
        committed signing-key state is superseded by a published rotation" or
        "whose delegated signing AID's delegation has been revoked".
        """
        return self.successor if self.successor is not None else self.publisher

    @property
    def published_key_state(self) -> AfpPublisherKeyState:
        if self._published_key_state is None:
            self._published_key_state = resolve_publisher_key_state(
                authority_kel=self.authority.kel,
                signing_kel=self.published_signer.kel,
                witness_keys=self.witness_material,
            )
        return self._published_key_state


def _pinned_witnesses(
    witnesses: Sequence[keri.Witness], kel: keri.Kel
) -> Tuple[PinnedWitness, ...]:
    return tuple(
        PinnedWitness(
            witness_aid=witness.aid,
            witness_endpoint=staging_endpoint(witness.aid.lower()),
            # The reference subset does not maintain per-witness KELs (§4.5.3
            # step 5 is a declared seam); the pinned event is the authority
            # inception event this witness receipted.
            witness_kel_dig=kel.events[0].digest,
            witness_verification_material=witness.keypair.public_qb64,
        )
        for witness in witnesses
    )


def _legal_entity_statement() -> str:
    return (
        "STAGING PLACEHOLDER — this AID denotes no legal entity. It is "
        f"{STAGING_AUTHORITY_LABEL!r} and MUST NOT be accepted into any "
        "verification policy. Pyramidal Inc.'s organizational root AID has not "
        "been incepted; §6.3.1 establishes the AID-to-legal-entity binding "
        "out-of-band when a verifier accepts an authority's trust material, and "
        "no such binding exists or is asserted here."
    )


def run_staging_ceremony(
    *,
    witness_count: int = 5,
    threshold: int = 3,
    include_rotation: bool = True,
    include_succession: bool = True,
) -> CeremonyResult:
    """Perform the full staging dry run and return every artifact it produced.

    The sequence mirrors the production ceremony script step for step, so the
    runbook can reference the same numbered stages:

    1. derive and publish the witness set (§4.5);
    2. incept the organizational root AID with a pre-rotation commitment (§4.4);
    3. incept the product-scoped publisher AID as a ``dip`` anchored in the
       organizational KEL (§4.2, §6.3.1);
    4. resolve ``afp:publisher-key-state:v1`` and compute ``root_material_digest``
       from published KEL state alone (§6.3.1);
    5. publish authority trust material pinning the witness set and threshold and
       characterizing the attestation truthfully (§6.3.1);
    6. rotate the publisher signing key and re-anchor the rotation (§4.6, §6.3.1);
    7. succeed the publisher AID with a replacement delegated signer, marking the
       superseded one in the trust material (§4.6).

    The ``--staging``/``CI`` refusals of :func:`afp_ceremony.staging.require_staging`
    live on the *executable* (``scripts/run_key_ceremony.py``), not here, and that
    split is deliberate: this function cannot produce production material under
    any arguments — every secret it uses derives from the published staging
    phrase and every artifact it emits is marker-stamped — while the reference
    test suite must be able to exercise it inside CI. The guard exists to stop an
    operator from pointing the *tool* at a production ceremony, which is a thing
    only the executable could be asked to do.
    """
    steps: List[Dict[str, Any]] = []

    witnesses = make_staging_witnesses(witness_count)
    if not 1 <= threshold <= witness_count:
        raise CeremonyError("witness threshold must be between 1 and the set size")
    steps.append(
        {
            "step": 1,
            "action": "derive witness set",
            "spec": "§4.5",
            "witness_aids": [w.aid for w in witnesses],
            "threshold": threshold,
        }
    )

    authority = incept_authority_root(witnesses=witnesses, threshold=threshold)
    steps.append(
        {
            "step": 2,
            "action": "incept organizational root AID",
            "spec": "§4.2, §4.4, §4.5",
            "aid": authority.aid,
            "inception_dig": authority.inception_dig,
        }
    )

    publisher, anchor_dig = incept_delegated_signer(authority)
    steps.append(
        {
            "step": 3,
            "action": "incept product-scoped delegated publisher AID",
            "spec": "§4.2, §6.3.1",
            "aid": publisher.aid,
            "delegation_anchor_dig": anchor_dig,
        }
    )

    witness_material = {w.aid: w.public_key for w in witnesses}
    key_state = resolve_publisher_key_state(
        authority_kel=authority.kel,
        signing_kel=publisher.kel,
        witness_keys=witness_material,
    )
    root_material_digest = key_state.root_material_digest()
    steps.append(
        {
            "step": 4,
            "action": "resolve afp:publisher-key-state:v1 and compute root_material_digest",
            "spec": "§6.3.1",
            "root_material_digest": root_material_digest,
        }
    )

    trust_material = build_authority_trust_material(
        authority_kel=authority.kel,
        signing_material=authority.current,
        legal_entity_binding_statement=_legal_entity_statement(),
        pinned_witnesses=_pinned_witnesses(witnesses, authority.kel),
        pinned_witness_threshold=threshold,
        anchored_signers=(
            AnchoredSigner(
                signing_aid=publisher.aid,
                delegation_anchor_dig=anchor_dig,
                purpose="ADAMAS release build manifest signing",
                status=SIGNER_ACTIVE,
            ),
        ),
        issued_at=STAGING_ISSUED_AT,
        expires_at=STAGING_EXPIRES_AT,
    )
    steps.append(
        {
            "step": 5,
            "action": "publish authority trust material (pinned witness set + threshold)",
            "spec": "§6.3.1 'Authority-KEL integrity is not assumed'",
            "note": (
                "NOT afp:witness-bootstrap:v1 — that record is tenant-scoped and an "
                "authority is not a tenant (§2.1)"
            ),
        }
    )

    result = CeremonyResult(
        witnesses=witnesses,
        threshold=threshold,
        authority=authority,
        publisher=publisher,
        delegation_anchor_dig=anchor_dig,
        trust_material=trust_material,
        key_state=key_state,
        root_material_digest=root_material_digest,
        steps=steps,
    )

    if include_rotation:
        rotated = rotate_identity(publisher)
        rotation_anchor = anchor_rotation(
            authority, delegate_aid=rotated.aid, rotation_dig=rotated.kel.latest.digest
        )
        rotated_state = resolve_publisher_key_state(
            authority_kel=authority.kel,
            signing_kel=rotated.kel,
            witness_keys=witness_material,
        )
        result.publisher = rotated
        result.rotated_key_state = rotated_state
        result.rotated_root_material_digest = rotated_state.root_material_digest()
        steps.append(
            {
                "step": 6,
                "action": "rotate publisher signing key and anchor the rotation",
                "spec": "§4.4, §4.6, §6.3.1",
                "rotation_anchor_dig": rotation_anchor,
                "root_material_digest": result.rotated_root_material_digest,
                "note": (
                    "root_material_digest changes at every published rotation, which "
                    "is why §6.3.1 binds a verifier's policy to the authority AID "
                    "rather than to a key-state digest"
                ),
            }
        )

    if include_succession:
        successor, successor_anchor = incept_delegated_signer(
            authority, label=_SUCCESSOR_LABEL
        )
        result.successor = successor
        result.trust_material = build_authority_trust_material(
            authority_kel=authority.kel,
            signing_material=authority.current,
            legal_entity_binding_statement=_legal_entity_statement(),
            pinned_witnesses=_pinned_witnesses(witnesses, authority.kel),
            pinned_witness_threshold=threshold,
            anchored_signers=(
                AnchoredSigner(
                    signing_aid=result.publisher.aid,
                    delegation_anchor_dig=anchor_dig,
                    purpose="ADAMAS release build manifest signing",
                    status=SIGNER_SUPERSEDED,
                ),
                AnchoredSigner(
                    signing_aid=successor.aid,
                    delegation_anchor_dig=successor_anchor,
                    purpose="ADAMAS release build manifest signing (successor)",
                    status=SIGNER_ACTIVE,
                ),
            ),
            issued_at=STAGING_ISSUED_AT,
            expires_at=STAGING_EXPIRES_AT,
        )
        steps.append(
            {
                "step": 7,
                "action": "succeed the publisher AID with a replacement delegated signer",
                "spec": "§4.6, §6.3.1",
                "successor_aid": successor.aid,
                "delegation_anchor_dig": successor_anchor,
            }
        )

    return result


# -- artifacts -------------------------------------------------------------


def _require_signature_hex(value: str, what: str) -> None:
    # Canonical form only: bytes.fromhex would also accept uppercase digits
    # and whitespace, so a noncanonical artifact would load as if canonical.
    if len(value) != 128 or any(ch not in "0123456789abcdef" for ch in value):
        raise ArtifactError(f"{what} must be 128 lowercase hex digits")


def _event_to_dict(event: keri.KelEvent) -> Dict[str, Any]:
    # ``content()`` is exactly the digested surface. The controller signature
    # is an attachment over that digest and the timestamp is not serialized,
    # so neither enters any SAID.
    if event.controller_signature is None:
        raise ArtifactError("refusing to serialize an unsigned KEL event")
    return {
        **event.content(),
        "controller_signature": event.controller_signature.hex(),
    }


def _event_from_dict(data: Any) -> keri.KelEvent:
    if not isinstance(data, Mapping):
        raise ArtifactError("KEL event must be a JSON object")
    expected = {
        "ilk",
        "sn",
        "keys",
        "next_key_digest",
        "prior_dig",
        "witnesses",
        "threshold",
        "delegator_aid",
        "seal",
        "controller_signature",
    }
    if set(data) != expected:
        raise ArtifactError("KEL event has noncanonical members")
    if not isinstance(data["keys"], list) or not isinstance(data["witnesses"], list):
        raise ArtifactError("KEL event keys and witnesses must be JSON lists")
    if not isinstance(data["controller_signature"], str):
        raise ArtifactError("KEL event controller signature must be a hex string")
    _require_signature_hex(data["controller_signature"], "KEL event controller signature")
    return keri.KelEvent(
        ilk=data["ilk"],
        sn=data["sn"],
        keys=list(data["keys"]),
        next_key_digest=data["next_key_digest"],
        prior_dig=data["prior_dig"],
        witnesses=list(data["witnesses"]),
        threshold=data["threshold"],
        delegator_aid=data["delegator_aid"],
        seal=data["seal"],
        controller_signature=bytes.fromhex(data["controller_signature"]),
        timestamp=STAGING_EVENT_TIMESTAMP,
    )


def kel_to_dict(kel: keri.Kel) -> Dict[str, Any]:
    """Serialize a KEL and its witness receipts as a marked staging artifact."""
    receipts = []
    for event_dig in sorted(kel.receipts):
        for receipt in kel.receipts[event_dig]:
            receipts.append(
                {
                    "event_dig": event_dig,
                    "witness_aid": receipt.witness_aid,
                    "receipt": receipt.signature.hex(),
                }
            )
    return stamp_not_production(
        {
            "kind": KEL_ARTIFACT_KIND,
            "aid": kel.aid,
            "events": [_event_to_dict(event) for event in kel.events],
            "receipts": receipts,
        }
    )


def kel_from_dict(data: Any) -> keri.Kel:
    """Load a KEL artifact, refusing anything not marked non-production."""
    enforce_not_production(data, what="KEL artifact")
    expected = {
        "kind",
        "aid",
        "events",
        "receipts",
        *staging_markers(),
    }
    if set(data) != expected:
        raise ArtifactError("KEL artifact has noncanonical members")
    if data.get("kind") != KEL_ARTIFACT_KIND:
        raise ArtifactError(f"KEL artifact kind must be {KEL_ARTIFACT_KIND!r}")
    if not isinstance(data["aid"], str):
        raise ArtifactError("KEL artifact aid must be a string")
    if not isinstance(data["events"], list) or not isinstance(data["receipts"], list):
        raise ArtifactError("KEL artifact events and receipts must be JSON lists")
    try:
        events = [_event_from_dict(item) for item in data["events"]]
        kel = keri.Kel(aid=data["aid"], events=events)
        for entry in data["receipts"]:
            if not isinstance(entry, Mapping) or set(entry) != {
                "event_dig",
                "witness_aid",
                "receipt",
            }:
                raise ArtifactError("witness receipt has noncanonical members")
            if not all(isinstance(entry[name], str) for name in entry):
                raise ArtifactError("witness receipt members must be strings")
            _require_signature_hex(entry["receipt"], "witness receipt")
            kel.add_receipt(
                keri.WitnessReceipt(
                    witness_aid=entry["witness_aid"],
                    event_dig=entry["event_dig"],
                    signature=bytes.fromhex(entry["receipt"]),
                )
            )
    except ArtifactError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ArtifactError(f"malformed KEL artifact: {exc}") from exc
    return kel


def _key_state_artifact(
    key_state: AfpPublisherKeyState, root_material_digest: str
) -> Dict[str, Any]:
    return stamp_not_production(
        {
            "kind": KEY_STATE_ARTIFACT_KIND,
            "record": key_state.to_dict(),
            "root_material_digest": root_material_digest,
            "note": (
                "The record is the RFC 8785 JCS preimage §6.3.1 fixes for "
                "root_material_digest. It is never transmitted as an AFP message; "
                "a verifier recomputes it from resolved KEL state."
            ),
        }
    )


def _witness_directory(result: CeremonyResult) -> Dict[str, Any]:
    return stamp_not_production(
        {
            "kind": WITNESS_DIRECTORY_KIND,
            "threshold": result.threshold,
            "witnesses": [
                {
                    "witness_aid": witness.aid,
                    "witness_endpoint": staging_endpoint(witness.aid.lower()),
                    "witness_verification_material": witness.keypair.public_qb64,
                }
                for witness in result.witnesses
            ],
        }
    )


def _transcript(result: CeremonyResult) -> Dict[str, Any]:
    return stamp_not_production(
        {
            "kind": TRANSCRIPT_KIND,
            "authority_aid": result.authority.aid,
            "authority_label": STAGING_AUTHORITY_LABEL,
            "publisher_aid": result.publisher.aid,
            "published_signing_aid": result.published_signer.aid,
            "delegation_anchor_dig": result.delegation_anchor_dig,
            "initial_root_material_digest": result.root_material_digest,
            "rotated_root_material_digest": result.rotated_root_material_digest,
            "published_root_material_digest": (
                result.published_key_state.root_material_digest()
            ),
            "successor_aid": result.successor.aid if result.successor else None,
            "steps": result.steps,
            "honest_disclosure": [
                "This is a NON-PRODUCTION staging dry run. Pyramidal Inc.'s "
                "organizational root AID has not been incepted and is not created here.",
                "Signatures are real RFC 8032 Ed25519, but every private seed derives "
                "from a derivation phrase published in this repository, so all key "
                "material here is public and carries no trust.",
                "Identifiers use AFP's readable <code>_<hex> reference encoding, not "
                "CESR/qb64: a staging AID is not a valid KERI AID.",
                "The reference KERI subset is single-signing-key, so kt/nt M-of-N "
                "signing custody is NOT exercised here; it is an obligation on the "
                "production ceremony recorded in the custody policy.",
                "kt/nt are not carried on KEL events in the reference subset, so two "
                "of the nine §6.3.1 key-state fields (signing_threshold, "
                "next_threshold) are the implicit §4.4.2 constant \"1\" rather than values "
                "resolved from published KEL state. Seven of nine resolve from the "
                "KELs; these two do not.",
                "The organizational root key is NOT rotated by this run — only the "
                "delegated publisher key is rotated and re-anchored. The separate "
                "production root-rotation procedure is unrehearsed.",
                "KEL events carry real Ed25519 controller signatures over their "
                "event digests in AFP's reference attachment, not KERI/CESR "
                "indexed signatures.",
                "There is no guardian/recovery event, no duplicity detection, and "
                "witness KELs are not walked (§4.5.3 step 5).",
                "After succession, the superseded publisher KEL is NOT emitted in "
                "the staging artifact tree, so artifact-only verification cannot "
                "re-check that historical KEL; the in-memory conformance report does.",
                "An AFP production implementation must preserve §4.4.2 encoding; "
                "KERI/CESR interoperability remains an AFP §10 open item.",
            ],
        }
    )


def write_ceremony_artifacts(result: CeremonyResult, out_dir: Path) -> Dict[str, Path]:
    """Write every staging artifact into ``out_dir`` and return the paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    published_signer = result.published_signer
    published_state = result.published_key_state
    documents: Dict[str, Any] = {
        "authority_kel": kel_to_dict(result.authority.kel),
        "publisher_kel": kel_to_dict(published_signer.kel),
        "trust_material": result.trust_material.to_dict(),
        "key_state": _key_state_artifact(
            published_state, published_state.root_material_digest()
        ),
        "witness_directory": _witness_directory(result),
        "transcript": _transcript(result),
    }
    written: Dict[str, Path] = {}
    for name, document in documents.items():
        path = out_dir / ARTIFACT_FILENAMES[name]
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written[name] = path
    return written


def load_ceremony_artifacts(out_dir: Path) -> Dict[str, Any]:
    """Load and marker-check every artifact in ``out_dir``."""
    out_dir = Path(out_dir)
    loaded: Dict[str, Any] = {}
    for name, filename in ARTIFACT_FILENAMES.items():
        path = out_dir / filename
        if not path.is_file():
            raise ArtifactError(f"missing ceremony artifact {filename}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ArtifactError(
                f"ceremony artifact {filename} is not valid JSON"
            ) from exc
        enforce_not_production(document, what=filename)
        loaded[name] = document
    return loaded


def verify_ceremony_artifacts(out_dir: Path, *, now: str = STAGING_NOW) -> Dict[str, Any]:
    """Re-verify a published staging tree from its artifacts alone.

    This is the verifier's-eye view: nothing in-memory from the ceremony run is
    reused, and **nothing is read out of the artifact under test and fed back
    into the recomputation**. It re-derives the publisher key state out of the
    two loaded KELs alone and checks that both the record and its
    ``root_material_digest`` recompute to the published values — exactly the
    out-of-circuit recomputation §6.3.1 makes mandatory, and the property whose
    absence §6.3.1 says "forfeits" the attest-own-builds-only guarantee.

    Any disagreement raises :class:`ArtifactError`. It is deliberately not a
    field a caller may read and ignore: §6.3.1's consequence for a key state
    that does not recompute is rejection with
    ``instance_attestation_untrusted_authority``.
    """
    try:
        documents = load_ceremony_artifacts(out_dir)
        authority_kel = kel_from_dict(documents["authority_kel"])
        publisher_kel = kel_from_dict(documents["publisher_kel"])
        trust_material = AfpAuthorityTrustMaterial.from_dict(
            documents["trust_material"]
        )

        verify_authority_trust_material(
            trust_material,
            authority_kel=authority_kel,
            anchored_kels={publisher_kel.aid: publisher_kel},
            now=now,
        )

        key_state_artifact = documents["key_state"]
        if key_state_artifact.get("kind") != KEY_STATE_ARTIFACT_KIND:
            raise ArtifactError("publisher key-state artifact has the wrong kind")
        published = AfpPublisherKeyState.from_dict(key_state_artifact["record"])
        recomputed = resolve_publisher_key_state(
            authority_kel=authority_kel,
            signing_kel=publisher_kel,
            witness_keys=trust_material.pinned_witness_material,
        )
        if recomputed.to_dict() != published.to_dict():
            # Field-level disagreement is caught before the digest comparison so
            # the message names the offending field: a record asserting, say, a
            # 3-of-N signing threshold that no KEL event supports is reported by
            # name rather than as an opaque digest mismatch.
            differing = sorted(
                name
                for name, value in recomputed.to_dict().items()
                if published.to_dict().get(name) != value
            )
            raise ArtifactError(
                "the published afp:publisher-key-state:v1 record disagrees with the "
                f"key state resolved from the published KELs (fields: {differing}); "
                "§6.3.1 requires rejection with "
                "instance_attestation_untrusted_authority"
            )
        if (
            recomputed.root_material_digest()
            != key_state_artifact["root_material_digest"]
        ):
            raise ArtifactError(
                "root_material_digest does not recompute from the published KEL "
                "state (instance_attestation_untrusted_authority, §6.3.1)"
            )
        accept_publisher_key_state(
            recomputed, material=trust_material, signing_kel=publisher_kel
        )
    except CeremonyError:
        raise
    except keri.KeriError as exc:
        raise ArtifactError(f"published KEL verification failed: {exc}") from exc
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"malformed ceremony artifact: {exc}") from exc
    return {
        "authority_aid": authority_kel.aid,
        "publisher_aid": publisher_kel.aid,
        "root_material_digest": recomputed.root_material_digest(),
        "markers": staging_markers(),
        # This compatibility field is True whenever this function returns;
        # mismatches raise above.
        "key_state_matches_published_record": True,
    }
