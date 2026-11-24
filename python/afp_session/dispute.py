"""Bilateral dispute + optional pre-agreed arbiter model (§12.5).

A dispute within a bilateral session is resolved **bilaterally**, or not
in-protocol at all. There is **no operator-mediated dispute**: no operator can
adjudicate, freeze, reverse, or force any outcome (Safeguard 3, §12.8). When the
two parties cannot agree, the session aborts/escalates with a **signed
divergence record** as the durable artifact, and the parties resolve off-protocol.

Optionally, a federation agreement (§5.5) MAY name, *in advance*, a single
arbiter — a specific pre-agreed AID. The arbiter receives the evidence and issues
a signed decision, but **cannot force a commitment**: an arbiter's decision still
requires BOTH parties' counter-signatures on the resulting CommitmentAtom
(enforced by :func:`afp_session.commitment.verify_commitment`). This module
provides:

  * :class:`DivergenceRecord` — the signed durable artifact when parties diverge;
  * :class:`Arbiter` — a pre-agreed arbiter that can issue a signed decision and
    co-sign a commitment, but never substitute for a party signature.

No global arbiter registry, no min_tvf_level, no capability query, no
random-from-pool selection — those are retired marketplace mechanisms (§12.5).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import ed25519, keri
from .atoms import AfpCommitmentAtom, AfpCommitSignature
from .canonical import digest, qb64
from .commitment import sign_commitment

__all__ = [
    "DisputeError",
    "ArbiterError",
    "DivergenceRecord",
    "ArbiterDecision",
    "Arbiter",
]


class DisputeError(Exception):
    """A dispute-handling failure (§12.5)."""


class ArbiterError(DisputeError):
    """An arbiter was used where it was not pre-agreed, or overreached (§12.5)."""


def _pinned_key(
    kel: keri.Kel,
    kel_event_dig: str,
    tenant_kel: Optional[keri.Kel],
    witness_keys: Optional[Dict[str, bytes]],
    historical: bool,
    kel_state: Optional[keri.KelStateStore] = None,
) -> Optional[bytes]:
    """The signer key a record's pin selects, or ``None`` when it does not verify.

    Live verification requires the pin to be the current key state; durable
    verification accepts any establishment event of the verified KEL (§12.3).
    """
    if type(witness_keys) is not dict:
        return None
    try:
        if historical:
            return keri.resolve_key_at(
                kel,
                kel_event_dig,
                tenant_kel=tenant_kel,
                witness_keys=witness_keys,
                first_seen=kel_state,
            )
        keri.verify_kel(
            kel, tenant_kel=tenant_kel, witness_keys=witness_keys, first_seen=kel_state
        )
        keri.assert_keystate_current(kel, kel_event_dig)
        return keri.resolve_current_key(kel)
    except keri.KeriError:
        return None


@dataclass
class DivergenceRecord:
    """A signed record that two principals could not agree in-protocol (§12.5).

    Left as the durable artifact when a session aborts/escalates on dispute. It
    is *not* an outcome and forces nothing; it records the divergence so the
    parties can resolve off-protocol. Signed by the party that raises it (a
    profile may have both parties counter-sign).
    """

    id: str
    session_ref: str
    raised_by: str  # entity AID
    kel_event_dig: str
    reason: str
    evidence_refs: List[str] = field(default_factory=list)
    signature: Optional[str] = None  # hex Ed25519 over content
    raised_at: float = field(default_factory=time.time)

    def content_to_sign(self) -> dict:
        return {
            "kind": "afp:divergence:v1",
            "id": self.id,
            "session_ref": self.session_ref,
            "raised_by": self.raised_by,
            "kel_event_dig": self.kel_event_dig,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "raised_at": self.raised_at,
        }

    @property
    def content_hash(self) -> str:
        return qb64("D", digest(self.content_to_sign()))

    def sign(self, identity: keri.Identity) -> "DivergenceRecord":
        self.raised_by = identity.aid
        self.kel_event_dig = keri.current_key_event_digest(identity.kel)
        self.signature = identity.sign(self.content_hash.encode("utf-8")).hex()
        return self

    def verify(
        self,
        kel: keri.Kel,
        tenant_kel: Optional[keri.Kel],
        witness_keys: Optional[Dict[str, bytes]] = None,
        *,
        historical: bool = False,
        kel_state: Optional[keri.KelStateStore] = None,
    ) -> bool:
        """Verify the record against KEL state and its declared witnesses.

        ``tenant_kel`` has no default: a record is raised by a session
        principal, an entity of that tenant (§12.3); ``None`` explicitly
        accepts a tenant-root signer. The verifier-owned witness map is
        mandatory; ``{}`` explicitly denotes a threshold-zero KEL. Missing or
        malformed material fails closed. ``historical`` selects the §12.3
        durable-record rule.
        """
        if self.signature is None or self.raised_by != kel.aid:
            return False
        public_key = _pinned_key(
            kel, self.kel_event_dig, tenant_kel, witness_keys, historical, kel_state
        )
        if public_key is None:
            return False
        return ed25519.verify_strict(
            self.content_hash.encode("utf-8"),
            bytes.fromhex(self.signature),
            public_key,
        )


@dataclass
class ArbiterDecision:
    """A pre-agreed arbiter's signed decision (§12.5) — advisory, never binding."""

    id: str
    session_ref: str
    arbiter_aid: str
    kel_event_dig: str
    decision: str  # the arbiter's ruling (profile-defined content)
    decided_at: float
    signature: Optional[str] = None

    def content_to_sign(self) -> dict:
        return {
            "kind": "afp:arbiter-decision:v1",
            "id": self.id,
            "session_ref": self.session_ref,
            "arbiter_aid": self.arbiter_aid,
            "kel_event_dig": self.kel_event_dig,
            "decision": self.decision,
            "decided_at": self.decided_at,
        }

    @property
    def content_hash(self) -> str:
        return qb64("D", digest(self.content_to_sign()))

    def verify(
        self,
        kel: keri.Kel,
        tenant_kel: Optional[keri.Kel] = None,
        witness_keys: Optional[Dict[str, bytes]] = None,
        *,
        historical: bool = False,
        kel_state: Optional[keri.KelStateStore] = None,
    ) -> bool:
        """Verify the decision against KEL state and declared witnesses.

        The verifier-owned witness map is mandatory; ``{}`` explicitly denotes
        a threshold-zero KEL. Missing or malformed material fails closed.
        ``historical`` selects the §12.3 durable-record rule.
        """
        if self.signature is None or self.arbiter_aid != kel.aid:
            return False
        public_key = _pinned_key(
            kel, self.kel_event_dig, tenant_kel, witness_keys, historical, kel_state
        )
        if public_key is None:
            return False
        return ed25519.verify_strict(
            self.content_hash.encode("utf-8"),
            bytes.fromhex(self.signature),
            public_key,
        )


class Arbiter:
    """A pre-agreed third-party arbiter (§12.5).

    Constructed from a verified ADAMAS-instance identity and bound to the
    agreement that pre-named it. It can:
      * issue a signed :class:`ArbiterDecision` (advisory);
      * co-sign a commitment (:meth:`co_sign_commitment`) — which is *additive*:
        the commitment is still invalid without BOTH party signatures.

    It MUST NOT be selected at dispute time. The ``agreement_arbiter_aid`` guard
    enforces that this arbiter is the one the agreement pre-agreed.
    """

    def __init__(self, identity: keri.Identity, agreement_arbiter_aid: str):
        if identity.aid != agreement_arbiter_aid:
            raise ArbiterError(
                "arbiter identity does not match the agreement's pre-agreed arbiter AID "
                "(§12.5 — never selected at dispute time)"
            )
        self.identity = identity
        self.aid = identity.aid

    def decide(self, *, decision_id: str, session_ref: str, decision: str) -> ArbiterDecision:
        d = ArbiterDecision(
            id=decision_id,
            session_ref=session_ref,
            arbiter_aid=self.aid,
            kel_event_dig=keri.current_key_event_digest(self.identity.kel),
            decision=decision,
            decided_at=time.time(),
        )
        d.signature = self.identity.sign(d.content_hash.encode("utf-8")).hex()
        return d

    def co_sign_commitment(self, commitment: AfpCommitmentAtom) -> AfpCommitSignature:
        """Add the arbiter co-signature to a commitment (§12.5).

        This is the one capability that can touch a tie-break, and it is bounded:
        it never replaces a party signature. ``verify_commitment`` still requires
        both party signatures regardless of this co-signature.
        """
        return sign_commitment(commitment, self.identity, role="arbiter")
