"""Bilateral commitment + optional anchor primitive (§12.6).

Both profiles end an interaction with a bilaterally-signed commitment to an
agreed outcome, chained for replay-resistance, with an optional DLT anchor. This
module owns the *core* construction (a profile specializes the atom but reuses
this machinery, §12.6.1):

  * build a :class:`~afp_session.atoms.AfpCommitmentAtom` over an ``outcome_root``;
  * collect BOTH parties' KEL-anchored Ed25519 signatures (one is not a
    commitment, §12.6.1);
  * verify the commitment: both signatures valid, key state current (§12.3),
    sequence monotonic per AID-pair (§12.6.1 chaining);
  * optionally an arbiter co-signature (§12.5) — which still cannot *replace* a
    party signature;
  * optionally anchor to a DLT (Ethereum L2 via APL baseline, §12.6.2) — the
    submission itself is an APL seam.

Seam: ``outcome_root`` is spec'd as a *Poseidon2* commitment (§12.6.1). Poseidon2
is a ZKA/ZKC in-circuit hash; the AFP reference uses SHA-256 via
``canonical.digest`` for the outcome root so the core is self-contained. A
deployment binding to real ZK proofs substitutes the Poseidon2 root; the
bilateral-signature / chaining / opacity semantics this module enforces are
hash-agnostic.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from . import ed25519, keri
from .atoms import (
    AfpAnchorAtom,
    AfpCommitmentAtom,
    AfpCommitSignature,
)
from .canonical import digest, qb64

__all__ = [
    "CommitmentError",
    "SequenceError",
    "outcome_root_for",
    "build_commitment",
    "sign_commitment",
    "verify_commitment",
    "anchor_commitment",
]


class CommitmentError(Exception):
    """A commitment failed verification (§12.6)."""


class SequenceError(CommitmentError):
    """A non-monotonic / gapped sequence number per AID-pair (§12.6.1)."""


def outcome_root_for(outcome: object) -> str:
    """Compute the ``outcome_root`` commitment for a profile-defined outcome.

    Reference uses SHA-256 over the canonical outcome (the documented Poseidon2
    seam, see module docstring). The outcome stays opaque in the atom — only the
    root is committed (§12.6.1 outcome opacity / Safeguard 2).
    """
    return qb64("R", digest({"outcome": outcome}))


def build_commitment(
    *,
    commitment_id: str,
    session_ref: str,
    outcome_root: str,
    profile: str,
    sequence_number: int,
    previous_commitment_ref: Optional[str] = None,
) -> AfpCommitmentAtom:
    """Construct an unsigned commitment atom (§12.6.1)."""
    return AfpCommitmentAtom(
        id=commitment_id,
        session_ref=session_ref,
        outcome_root=outcome_root,
        profile=profile,
        sequence_number=sequence_number,
        previous_commitment_ref=previous_commitment_ref,
    )


def sign_commitment(
    commitment: AfpCommitmentAtom,
    identity: keri.Identity,
    role: str,
) -> AfpCommitSignature:
    """Produce a KEL-anchored Ed25519 signature for ``role`` and attach it.

    ``role`` is ``initiator`` | ``responder`` | ``arbiter`` (§12.6.1 / §12.5).
    The signature covers the commitment content hash and pins the digest of
    the signer's latest establishment event (§12.6.1).
    """
    if role not in ("initiator", "responder", "arbiter"):
        raise CommitmentError(f"unknown commitment role {role!r}")
    content_hash = commitment.content_hash
    sig = identity.sign(content_hash.encode("utf-8"))
    commit_sig = AfpCommitSignature(
        signed_by=identity.aid,
        kel_event_dig=keri.current_key_event_digest(identity.kel),
        signature=sig.hex(),
        signed_at=time.time(),
    )
    if role == "initiator":
        commitment.initiator_signature = commit_sig
    elif role == "responder":
        commitment.responder_signature = commit_sig
    else:
        commitment.arbiter_signature = commit_sig
    return commit_sig


def _verify_one(
    commitment: AfpCommitmentAtom,
    sig: AfpCommitSignature,
    kel: keri.Kel,
    tenant_kel: Optional[keri.Kel] = None,
    witness_keys: Optional[Dict[str, bytes]] = None,
    historical: bool = False,
    kel_state: Optional[keri.KelStateStore] = None,
) -> None:
    """Verify a single commitment signature against the key state it pins (§12.3).

    With ``tenant_kel`` the signer must be an entity delegated by that tenant
    and is verified up to its root (§12.3); without it only a tenant-root
    signer verifies. ``witness_keys`` must be explicitly supplied so KEL
    verification cannot silently skip a witness policy; ``{}`` is the
    explicit value for a threshold-zero KEL. ``historical`` selects the
    durable-record rule; otherwise the pin must be the current key state.
    """
    if type(witness_keys) is not dict:
        raise CommitmentError(
            "commitment signer witness key material must be explicitly supplied"
        )
    if type(sig.signed_by) is not str or sig.signed_by != kel.aid:
        raise CommitmentError("commitment signature names a different signer AID")
    if historical:
        public_key = keri.resolve_key_at(
            kel,
            sig.kel_event_dig,
            tenant_kel=tenant_kel,
            witness_keys=witness_keys,
            first_seen=kel_state,
        )
    else:
        keri.verify_kel(
            kel, tenant_kel=tenant_kel, witness_keys=witness_keys, first_seen=kel_state
        )
        keri.assert_keystate_current(kel, sig.kel_event_dig)  # not a superseded key
        public_key = keri.resolve_current_key(kel)
    ok = ed25519.verify_strict(
        commitment.content_hash.encode("utf-8"),
        bytes.fromhex(sig.signature),
        public_key,
    )
    if not ok:
        raise CommitmentError(f"invalid commitment signature by {sig.signed_by}")


def verify_commitment(
    commitment: AfpCommitmentAtom,
    *,
    initiator_kel: keri.Kel,
    responder_kel: keri.Kel,
    initiator_tenant_kel: Optional[keri.Kel],
    responder_tenant_kel: Optional[keri.Kel],
    initiator_witness_keys: Optional[Dict[str, bytes]] = None,
    responder_witness_keys: Optional[Dict[str, bytes]] = None,
    arbiter_kel: Optional[keri.Kel] = None,
    arbiter_tenant_kel: Optional[keri.Kel] = None,
    arbiter_witness_keys: Optional[Dict[str, bytes]] = None,
    previous: Optional[AfpCommitmentAtom] = None,
    historical: bool = False,
    kel_state: Optional[keri.KelStateStore] = None,
) -> None:
    """Verify a commitment is valid per §12.6.1.

    Checks:
      * BOTH party signatures present and valid (one signature is not a
        commitment); no operator/arbiter signature substitutes (§12.5);
      * each signature verifies under the key state its ``kel_event_dig``
        pins. By default that pin must be the signer's current key state, the
        live-acceptance rule; with ``historical=True`` (durable-record
        verification, §12.3) a pin to an earlier establishment event of the
        verified KEL is accepted, so a later rotation or revocation does not
        void the record;
      * each signer's KEL satisfies its declared witness threshold using an
        explicitly supplied verifier-owned key map (``{}`` for threshold zero);
      * chaining: ``sequence_number`` is monotonic and references ``previous``
        when given (a gap / non-monotonic sequence is a detectable error,
        §12.6.1);
      * an arbiter co-signature, if present, also verifies — but is additive
        (§12.5).

    The party tenant KELs have no default: the parties are session principals,
    entities delegated by their tenants (§12.3), so each must be supplied.
    Passing ``None`` explicitly accepts a tenant-root signer for that role.

    Raises :class:`CommitmentError` (or :class:`SequenceError`) on failure.
    """
    if not commitment.is_fully_signed:
        raise CommitmentError(
            "commitment requires BOTH party signatures (§12.6.1); "
            "one signature is not a commitment"
        )
    _verify_one(
        commitment,
        commitment.initiator_signature,
        initiator_kel,
        tenant_kel=initiator_tenant_kel,
        witness_keys=initiator_witness_keys,
        historical=historical,
        kel_state=kel_state,
    )
    _verify_one(
        commitment,
        commitment.responder_signature,
        responder_kel,
        tenant_kel=responder_tenant_kel,
        witness_keys=responder_witness_keys,
        historical=historical,
        kel_state=kel_state,
    )
    if commitment.arbiter_signature is not None:
        if arbiter_kel is None:
            raise CommitmentError("arbiter signature present but no arbiter KEL supplied")
        _verify_one(
            commitment,
            commitment.arbiter_signature,
            arbiter_kel,
            tenant_kel=arbiter_tenant_kel,
            witness_keys=arbiter_witness_keys,
            historical=historical,
            kel_state=kel_state,
        )

    # Chaining (§12.6.1).
    if previous is not None:
        if commitment.previous_commitment_ref != previous.id:
            raise SequenceError("previous_commitment_ref does not match prior commitment")
        if commitment.sequence_number != previous.sequence_number + 1:
            raise SequenceError(
                f"sequence_number {commitment.sequence_number} is not "
                f"{previous.sequence_number + 1} (gap / non-monotonic)"
            )
    else:
        if commitment.sequence_number < 0:
            raise SequenceError("sequence_number must be non-negative")
        if commitment.previous_commitment_ref is not None and commitment.sequence_number == 0:
            raise SequenceError("sequence 0 must not reference a previous commitment")


def _hash_parties(aids: List[str]) -> List[str]:
    """Hash party AIDs for the anchor (§12.6.2 — parties hashed for privacy)."""
    return [qb64("H", digest({"aid": aid})) for aid in aids]


def anchor_commitment(
    commitment: AfpCommitmentAtom,
    *,
    anchor_id: str,
    chain: str,
    transaction_id: str,
    block_number: int,
    block_timestamp: str,
    inclusion_proof: str,
    parties: List[str],
) -> AfpAnchorAtom:
    """Build an :class:`AfpAnchorAtom` for a committed outcome (§12.6.2).

    Anchoring is OPTIONAL (no-anchor is conformant, the default for low-stakes
    state). Only hashes are anchored — commitment hash, outcome root, hashed
    party AIDs, sequence number — never atom content. Ethereum L2 via APL is the
    mandatory baseline target *when anchoring*; the on-chain submission is an APL
    seam — this records the verifier-facing anchor atom and links it back.

    ``block_timestamp`` is the §1.6.1 UTC datetime string
    (``YYYY-MM-DDTHH:MM:SSZ``); a number or any other spelling raises
    ``ValueError``.
    """
    if not commitment.is_fully_signed:
        raise CommitmentError("cannot anchor an incompletely-signed commitment (§12.6.1)")
    anchor = AfpAnchorAtom(
        id=anchor_id,
        commitment_ref=commitment.id,
        chain=chain,
        transaction_id=transaction_id,
        block_number=block_number,
        block_timestamp=block_timestamp,
        commitment_hash=commitment.content_hash,
        outcome_root=commitment.outcome_root,
        parties=_hash_parties(parties),
        sequence_number=commitment.sequence_number,
        inclusion_proof=inclusion_proof,
    )
    commitment.anchor_ref = anchor.id
    return anchor
