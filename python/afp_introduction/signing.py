"""§14.4 — the two ``afp:provisional-agreement:v1`` signatures.

Both parties sign the same bytes: the ASCII ``D_`` content hash of the
agreement content (:meth:`ProvisionalAgreement.content_hash`), the form the
§12.2.1 stable session content and the §15.3 quote content use. The content
binds both ``signed_by`` AIDs, so the parties fix them before the first
signature. Each signature is a §12.6.1 ``AfpCommitSignature`` made with the
signer's KEL-current Ed25519 key. ``signed_at`` is observational metadata
outside the signed bytes.

The agreement names neither its introduction session nor its parties, so the
verifier supplies the two parties of that session as :class:`RemoteParty`
material. A signature verifies only in its own role, by the tenant root AID or
the delegated entity AID of that role's party, at that signer's current key
state, under the strict Ed25519 profile (§4.4.1).
"""

from __future__ import annotations

from dataclasses import replace
import re
from typing import Optional

from afp_session import RemoteParty, ed25519, keri
from afp_session.atoms import (
    AfpCommitSignature,
    validate_signed_at,
    validate_signed_at_number,
)

from .atoms import IntroductionWireError, ProvisionalAgreement

__all__ = [
    "AGREEMENT_SIGNATURE_ROLES",
    "AgreementSignatureError",
    "agreement_signing_input",
    "sign_provisional_agreement",
    "verify_provisional_agreement",
]

#: The two signature members of the agreement, by role.
AGREEMENT_SIGNATURE_ROLES = ("initiator", "responder")

_AID_RE = re.compile(r"E_[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"D_[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")


class AgreementSignatureError(ValueError):
    """An agreement signature that cannot be made or does not verify (§14.4)."""


def agreement_signing_input(
    agreement: ProvisionalAgreement,
    initiator_signed_by: Optional[str] = None,
    responder_signed_by: Optional[str] = None,
) -> bytes:
    """The §14.4 signed bytes: the ASCII content hash, exactly 66 octets.

    The ``signed_by`` AIDs come from the signatures present; a draft names
    the planned AIDs for the missing ones.
    """
    if not isinstance(agreement, ProvisionalAgreement):
        raise AgreementSignatureError("agreement must be a ProvisionalAgreement")
    try:
        return agreement.content_hash(initiator_signed_by, responder_signed_by).encode(
            "ascii"
        )
    except IntroductionWireError as exc:
        raise AgreementSignatureError(f"agreement cannot be signed: {exc}") from exc


def _role(role: object) -> str:
    if role not in AGREEMENT_SIGNATURE_ROLES:
        raise AgreementSignatureError(
            "agreement signature role must be 'initiator' or 'responder'"
        )
    return role  # type: ignore[return-value]


def sign_provisional_agreement(
    agreement: ProvisionalAgreement,
    identity: keri.Identity,
    *,
    role: str,
    initiator_signed_by: str,
    responder_signed_by: str,
    signed_at: int | float,
) -> ProvisionalAgreement:
    """Return a copy of ``agreement`` with ``identity``'s signature in ``role``.

    ``identity`` is the party's tenant root or delegated entity identity, and
    its AID must be the planned ``signed_by`` of ``role``. Both planned AIDs
    are part of the signed content, so both parties fix them first; a
    signature already present must carry its planned AID.
    ``signed_at`` is the observational §1.6.1 JSON number; it is not signed.
    """
    role = _role(role)
    if not isinstance(identity, keri.Identity):
        raise AgreementSignatureError("identity must be a keri.Identity")
    planned = {"initiator": initiator_signed_by, "responder": responder_signed_by}
    if identity.aid != planned[role]:
        raise AgreementSignatureError(
            f"the signing identity is not the planned {role} signed_by"
        )
    if initiator_signed_by == responder_signed_by:
        raise AgreementSignatureError("the two planned signers must differ")
    # The signature this call replaces does not constrain the planned AIDs.
    signing_input = agreement_signing_input(
        replace(agreement, **{f"{role}_signature": None}),
        initiator_signed_by,
        responder_signed_by,
    )
    try:
        observed = validate_signed_at_number(signed_at)
    except ValueError as exc:
        raise AgreementSignatureError(f"signed_at: {exc}") from exc
    signature = AfpCommitSignature(
        signed_by=identity.aid,
        kel_event_dig=keri.current_key_event_digest(identity.kel),
        signature=identity.sign(signing_input).hex(),
        signed_at=observed,
    )
    return replace(agreement, **{f"{role}_signature": signature})


def _party_aids(party: RemoteParty) -> tuple[str, str]:
    return party.tenant_kel.aid, party.entity_kel.aid


def _check_shape(signature: object, *, role: str, party: RemoteParty, other: RemoteParty) -> str:
    """Check one signature's members and role; return its signing KEL's kind."""
    name = f"{role}_signature"
    if type(signature) is not AfpCommitSignature:
        raise AgreementSignatureError(f"{name} is required (§14.4)")
    if type(signature.signed_by) is not str or not _AID_RE.fullmatch(signature.signed_by):
        raise AgreementSignatureError(f"{name}.signed_by is not a canonical AID")
    if type(signature.kel_event_dig) is not str or not _DIGEST_RE.fullmatch(
        signature.kel_event_dig
    ):
        raise AgreementSignatureError(f"{name}.kel_event_dig is not a canonical digest")
    if type(signature.signature) is not str or not _SIGNATURE_RE.fullmatch(
        signature.signature
    ):
        raise AgreementSignatureError(
            f"{name}.signature is not 128 lowercase hexadecimal characters"
        )
    try:
        # Shape only: signed_at is outside the signed bytes and decides nothing.
        validate_signed_at(signature.signed_at)
    except ValueError as exc:
        raise AgreementSignatureError(f"{name}.signed_at: {exc}") from exc
    if signature.signed_by in _party_aids(other):
        raise AgreementSignatureError(
            f"{name} is signed by the other party; a signature verifies only in its own role"
        )
    tenant_aid, entity_aid = _party_aids(party)
    if signature.signed_by == entity_aid:
        return "entity"
    if signature.signed_by == tenant_aid:
        return "tenant"
    raise AgreementSignatureError(f"{name}.signed_by names neither AID of the {role} party")


def _verify_one(
    signing_input: bytes,
    signature: AfpCommitSignature,
    signer: str,
    *,
    role: str,
    party: RemoteParty,
    kel_state: Optional[keri.KelStateStore],
) -> None:
    name = f"{role}_signature"
    first_seen = (getattr(party, "kel_state", None), kel_state)
    try:
        if signer == "entity":
            kel = party.entity_kel
            keri.verify_kel(
                kel,
                tenant_kel=party.tenant_kel,
                witness_keys=party.witness_keys,
                first_seen=first_seen,
            )
        else:
            kel = party.tenant_kel
            keri.verify_kel(kel, witness_keys=party.witness_keys, first_seen=first_seen)
        keri.assert_keystate_current(kel, signature.kel_event_dig)
        public_key = keri.resolve_current_key(kel)
        ed25519.validate_public_key(public_key)
        valid = ed25519.verify_strict(
            signing_input, bytes.fromhex(signature.signature), public_key
        )
    except (keri.KeriError, AttributeError, TypeError, ValueError) as exc:
        raise AgreementSignatureError(f"{name} is not KEL-current or valid: {exc}") from exc
    if not valid:
        raise AgreementSignatureError(f"{name} does not verify over the content hash")


def verify_provisional_agreement(
    agreement: ProvisionalAgreement,
    *,
    initiator: RemoteParty,
    responder: RemoteParty,
    kel_state: Optional[keri.KelStateStore] = None,
) -> str:
    """Verify both §14.4 agreement signatures and return the content hash.

    ``initiator`` and ``responder`` are the two authenticated parties of the
    introduction session in which the agreement was formed. Each signature
    must name its own role's tenant root or delegated entity AID; the content
    hash binds both of those AIDs. Raises :class:`AgreementSignatureError`
    unless both signatures verify.
    """
    if not isinstance(agreement, ProvisionalAgreement):
        raise AgreementSignatureError("agreement must be a ProvisionalAgreement")
    for role, party in (("initiator", initiator), ("responder", responder)):
        if not isinstance(party, RemoteParty):
            raise AgreementSignatureError(f"{role} must be a RemoteParty")
        if not isinstance(party.witness_keys, dict):
            raise AgreementSignatureError(
                f"{role} witness key material must be explicitly supplied"
            )
    if initiator.tenant_kel.aid == responder.tenant_kel.aid:
        raise AgreementSignatureError(
            "the initiator and responder must be different tenants"
        )
    roles = (
        ("initiator", agreement.initiator_signature, initiator, responder),
        ("responder", agreement.responder_signature, responder, initiator),
    )
    signers = [
        _check_shape(signature, role=role, party=party, other=other)
        for role, signature, party, other in roles
    ]
    signing_input = agreement_signing_input(agreement)
    for (role, signature, party, _other), signer in zip(roles, signers):
        _verify_one(
            signing_input, signature, signer, role=role, party=party, kel_state=kel_state
        )
    return signing_input.decode("ascii")
