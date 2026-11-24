"""Minimal verifiable KERI subset for AFP §4 identity and §12.3 session binding.

AFP v0.3.x adopts KERI-aligned self-certifying identity (§4). A full KERI stack
(keripy) is heavy and its on-the-wire CESR encoding is more than the §12
bilateral-session core needs to be *verifiable*. This module implements the
minimal subset the spec's normative requirements actually depend on:

  * **Self-certifying AID** (§4.1, §4.2): the identifier is derived from the
    inception event, so it can be verified from the identifier + its KEL alone,
    with no registry lookup and no operator (§4.1).
  * **Key Event Log** (§4.4): append-only inception / delegated-inception /
    rotation / interaction events, each pointing to its predecessor by digest.
  * **Controller authorization** (§4.4): every event carries an Ed25519
    controller signature. An inception is signed by its own key, a rotation
    by the pre-rotated key it reveals, and an interaction by the current key;
    an interaction cannot change establishment state.
  * **Pre-rotation, REQUIRED** (§4.4): every event commits to the digest of the
    next key set; a rotation must reveal a key set matching the commitment of
    the latest establishment event, else the KEL is rejected.
  * **Two-level delegation** (§4.2): a tenant root AID, and entity *delegated*
    AIDs whose inception (``dip``) and every rotation are anchored by seals in
    the tenant KEL, and which the tenant revokes by a revocation seal there.
  * **Witnesses** (§4.5): events carry receipts; a verifier checks them against
    the witness policy of the latest establishment event, and a rotation also
    against the policy it replaces. (Receipts here are real Ed25519 signatures
    by witness AIDs.)
  * **KEL verification to a tenant root** (§12.3): given an entity's KEL and its
    tenant root's KEL, verify the entity AID up to the tenant root AID against
    the §4.5 witness policies, and resolve the *current* signing key so a
    signature can be checked and a stale-keystate signature rejected
    (``kel_keystate_stale``, §12.3).

What is a documented seam vs. full KERI:
  * Encoding: AFP's own §4.4.2 KEL encoding (``<code>_<hex>`` qualified values,
    RFC 8785 JSON, SHA-256), not CESR; KERI/CESR interop is an AFP §10 open item.
  * Tenant-root recovery after loss of the pre-rotated keys is an AFP §10 open
    item with no event to implement; an entity is recovered by revocation and
    re-delegation (``Identity.revoke_delegation``). The rotation-presentation
    artifact (§4.6.1) is out of the §12 *session-core* scope; the rotation
    event + pre-rotation enforcement that the session layer needs IS here.
  * Witness KEL cross-verification (§4.5.3 step 5) is modeled by verifying each
    receipt signature against a supplied witness public key; the witnesses' own
    KELs are not walked (a deeper KERI seam).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import ed25519
from .canonical import jcs_digest, qb64, qb64_payload

__all__ = [
    "KeriError",
    "EventAuthorizationError",
    "PreRotationError",
    "DelegationError",
    "InvalidPublicKeyError",
    "WitnessThresholdError",
    "StaleKeyStateError",
    "DuplicityError",
    "KelStateStore",
    "KeyPair",
    "Witness",
    "KelEvent",
    "Kel",
    "Identity",
    "delegation_seal",
    "rotation_anchor_seal",
    "revocation_seal",
    "kel_event_signing_input",
    "receipt_signing_input",
    "sign_event",
    "verify_kel",
    "current_key_event_digest",
    "resolve_current_key",
    "resolve_key_at",
]


class KeriError(Exception):
    """Base class for KERI verification failures (§4 / §12.3)."""


class EventAuthorizationError(KeriError):
    """A KEL event lacks a valid signature by the key set that authorizes it (§4.4)."""


class PreRotationError(KeriError):
    """A rotation did not honor the prior pre-rotation commitment (§4.4)."""


class DelegationError(KeriError):
    """An entity delegated AID is not anchored in its tenant KEL (§4.2)."""


class InvalidPublicKeyError(KeriError):
    """A KEL or witness map contains invalid Ed25519 public-key material."""


class WitnessThresholdError(KeriError):
    """An event lacks valid receipts meeting a witness policy it must meet (§4.5)."""


class StaleKeyStateError(KeriError):
    """A signature is bound to a superseded KEL event (§12.3 kel_keystate_stale)."""


class DuplicityError(KeriError):
    """A presented KEL forks from KEL state the verifier already accepted (§4.5)."""


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair. The seed is secret; only the public key crosses the wire."""

    seed: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        seed = ed25519.generate_seed()
        return cls(seed=seed, public_key=ed25519.public_key_from_seed(seed))

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        return cls(seed=seed, public_key=ed25519.public_key_from_seed(seed))

    @property
    def public_qb64(self) -> str:
        return qb64("K", self.public_key)

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(message, self.seed)


# Witness keys also sign mixnet-directory digests in the same ``D_<hex>``
# form, so a KEL receipt is domain-separated from them (§4.4.2).
_RECEIPT_PREFIX = b"afp:kel-receipt:v1\0"


def receipt_signing_input(event_dig: str) -> bytes:
    """The exact bytes a witness receipt over ``event_dig`` covers (§4.4.2)."""
    return _RECEIPT_PREFIX + event_dig.encode("ascii")


@dataclass(frozen=True)
class Witness:
    """A KERI witness (§4.5): receipts KEL events, never sees work content."""

    aid: str
    keypair: KeyPair

    def receipt(self, event_dig: str) -> "WitnessReceipt":
        sig = self.keypair.sign(receipt_signing_input(event_dig))
        return WitnessReceipt(witness_aid=self.aid, event_dig=event_dig, signature=sig)

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key


@dataclass(frozen=True, slots=True)
class WitnessReceipt:
    witness_aid: str
    event_dig: str
    signature: bytes


def _next_key_digest(public_key: bytes) -> str:
    """Pre-rotation commitment: digest of the *next* key set (§4.4)."""
    return qb64("D", jcs_digest({"next_keys": [public_key.hex()]}))


# Slotted so an instance cannot shadow ``content``/``digest`` with values that
# disagree with the fields the verifier reads.
@dataclass(slots=True)
class KelEvent:
    """One KEL event (§4.4). ``ilk`` is icp | dip | rot | ixn."""

    ilk: str
    sn: int  # sequence number
    keys: List[str]  # current signing public keys (qb64), threshold 1 in this subset
    next_key_digest: str  # pre-rotation commitment to the next key set
    prior_dig: Optional[str]  # digest of the preceding event (None for icp/dip)
    witnesses: List[str] = field(default_factory=list)  # witness AIDs
    threshold: int = 0  # witness receipt threshold
    delegator_aid: Optional[str] = None  # tenant root AID for a dip event
    seal: Optional[str] = None  # for ixn: digest of the data being anchored
    # Attachment, not content: signs the digest, so it cannot be part of it.
    controller_signature: Optional[bytes] = None
    timestamp: float = field(default_factory=lambda: time.time())

    def content(self) -> dict:
        """The signed/digested content of the event (deterministic, no receipts)."""
        return {
            "ilk": self.ilk,
            "sn": self.sn,
            "keys": list(self.keys),
            "next_key_digest": self.next_key_digest,
            "prior_dig": self.prior_dig,
            "witnesses": list(self.witnesses),
            "threshold": self.threshold,
            "delegator_aid": self.delegator_aid,
            "seal": self.seal,
        }

    @property
    def digest(self) -> str:
        return qb64("D", jcs_digest(self.content()))


ESTABLISHMENT_ILKS = ("icp", "dip", "rot")
INCEPTION_ILKS = ("icp", "dip")

# Entity keys also sign bare ``D_<hex>`` content digests (session atoms,
# envelopes, commitments, quotes), so the controller signature is
# domain-separated from every one of them (§4.4).
_CONTROLLER_SIGNATURE_PREFIX = b"afp:kel-event:v1\0"


def delegation_seal(delegate_aid: str, inception_dig: str) -> str:
    """Seal of the tenant ``ixn`` that anchors a delegated inception (§4.2)."""
    return qb64("D", jcs_digest({"delegate": delegate_aid, "icp": inception_dig}))


def rotation_anchor_seal(delegate_aid: str, rotation_dig: str) -> str:
    """Seal of the tenant ``ixn`` that approves a delegated rotation (§4.2).

    Each seal kind has its own member name, so an anchor of one kind can never
    be read as, or replayed for, another.
    """
    return qb64("D", jcs_digest({"delegate": delegate_aid, "rot": rotation_dig}))


def revocation_seal(delegate_aid: str, inception_dig: str) -> str:
    """Seal of the tenant ``ixn`` that revokes a delegation (§4.2)."""
    return qb64("D", jcs_digest({"delegate": delegate_aid, "revoke": inception_dig}))


def kel_event_signing_input(event: KelEvent) -> bytes:
    """The exact bytes a KEL controller signature covers (§4.4)."""
    return _CONTROLLER_SIGNATURE_PREFIX + event.digest.encode("ascii")


def sign_event(event: KelEvent, keypair: KeyPair) -> KelEvent:
    """Attach ``keypair``'s controller signature to ``event`` and return it.

    The caller chooses the authorizing key set (§4.4): the inception key for
    ``icp``/``dip``, the newly revealed key for ``rot``, the current key for
    ``ixn``. Signing does not change the event digest.
    """
    event.controller_signature = keypair.sign(kel_event_signing_input(event))
    return event


@dataclass(slots=True)
class Kel:
    """A Key Event Log and the AID it certifies (§4.4)."""

    aid: str
    events: List[KelEvent]
    # event_dig -> ordered receipts gathered for that event
    receipts: Dict[str, List[WitnessReceipt]] = field(default_factory=dict)

    @property
    def latest(self) -> KelEvent:
        return self.events[-1]

    @property
    def latest_dig(self) -> str:
        return self.latest.digest

    def add_receipt(self, receipt: WitnessReceipt) -> None:
        self.receipts.setdefault(receipt.event_dig, []).append(receipt)


_KelSnapshot = Tuple[str, Tuple[Tuple[str, str], ...]]


def _snapshot(kel: Kel) -> _KelSnapshot:
    return kel.aid, tuple((event.digest, event.ilk) for event in kel.events)


class KelStateStore:
    """The KEL state a verifier has verified for each AID (§4.5).

    A valid prefix of a KEL is itself a valid KEL, so a holder of a superseded
    key can present the genuine, fully witnessed history that ends before the
    rotation away from that key, or a tenant KEL that ends before a revocation.
    A verifier therefore retains the longest KEL it has verified per AID and
    rejects a later-presented KEL that is a strict prefix of it
    (``kel_keystate_stale``) or forks from it (duplicity). The one permitted
    divergence is KERI's superseding recovery: a ``rot``, which only the
    pre-rotated keys can sign, replacing an ``ixn`` at the same position.

    A store is shared state held by reference, so copying returns it unchanged.
    """

    def __init__(self) -> None:
        self._accepted: Dict[str, Tuple[Tuple[str, str], ...]] = {}
        self._lock = threading.Lock()

    def __copy__(self) -> "KelStateStore":
        return self

    def __deepcopy__(self, memo: dict) -> "KelStateStore":
        return self

    def accept(self, *kels: Kel, allow_prefix: bool = False) -> None:
        """Check every KEL against retained state, then record them together."""
        self._accept_snapshots([_snapshot(kel) for kel in kels], allow_prefix)

    def assert_current(self, *kels: Kel) -> None:
        """Check already-authenticated KELs against retained state without recording.

        This checks currency, not signatures or witness policy. Callers must
        authenticate the supplied snapshots separately. Unseen state is never
        promoted to authenticated state by this check.
        """
        self._accept_snapshots([_snapshot(kel) for kel in kels], False, record=False)

    def _accept_snapshots(
        self, snapshots: Sequence[_KelSnapshot], allow_prefix: bool, *, record: bool = True
    ) -> None:
        """Check every snapshot against retained state, then record them together.

        With ``allow_prefix`` a strict prefix is accepted without shrinking the
        retained state; durable-record verification needs history, not
        currency. A fork is rejected either way.
        """
        with self._lock:
            updates: Dict[str, Tuple[Tuple[str, str], ...]] = {}
            for aid, presented in snapshots:
                known = updates.get(aid, self._accepted.get(aid, ()))
                diverged = next(
                    (
                        index
                        for index, (a, b) in enumerate(zip(known, presented))
                        if a[0] != b[0]
                    ),
                    None,
                )
                if diverged is not None:
                    if known[diverged][1] == "ixn" and presented[diverged][1] == "rot":
                        updates[aid] = presented
                        continue
                    raise DuplicityError(
                        f"KEL for {aid} forks at sn={diverged} from KEL state "
                        "previously verified for that AID"
                    )
                if len(presented) < len(known):
                    if allow_prefix:
                        continue
                    raise StaleKeyStateError(
                        f"KEL for {aid} ends before KEL state previously "
                        "verified for that AID (kel_keystate_stale)"
                    )
                updates[aid] = presented
            if record:
                self._accepted.update(updates)

    def accepted_length(self, aid: str) -> int:
        """Number of events of ``aid``'s KEL this store has accepted."""
        with self._lock:
            return len(self._accepted.get(aid, ()))


class Identity:
    """A KERI AID with its KEL — a tenant root or an entity delegated AID.

    The AID is self-certifying: it is derived from the inception event's content
    (so it cannot be claimed by anyone who did not author that event). Rotation
    walks the pre-rotation chain. Delegated identities anchor their inception in
    a parent (tenant) KEL via a ``dip`` event carrying ``delegator_aid``, and
    each later rotation through ``delegator``, which approves it in its own KEL.
    """

    def __init__(
        self,
        kel: Kel,
        current: KeyPair,
        next_keypair: KeyPair,
        witnesses: Optional[Sequence["Witness"]] = None,
        delegator: Optional["Identity"] = None,
    ):
        self.kel = kel
        self._current = current
        self._next = next_keypair
        # Retained so subsequent events (delegation anchor, rotation) can
        # re-gather receipts under the same witness set (§4.5).
        self._witnesses: List["Witness"] = list(witnesses or [])
        self._delegator = delegator

    # -- construction -----------------------------------------------------

    @staticmethod
    def _require_witness_policy(names: Sequence[str], threshold: int) -> None:
        """Refuse a policy no verifier accepts, before any state changes (§4.5)."""
        if any(not _is_qualified_value(name, "E") for name in names):
            raise ValueError("witness identifiers must be canonical E_ AIDs")
        if len(set(names)) != len(names):
            raise ValueError("a witness set cannot list a witness twice")
        if type(threshold) is not int or not 0 <= threshold <= len(names):
            raise ValueError("witness threshold must be between 0 and the set size")

    @classmethod
    def incept_tenant(
        cls,
        witnesses: Optional[Sequence[Witness]] = None,
        threshold: Optional[int] = None,
    ) -> "Identity":
        """Incept a tenant root AID (§4.2). Optionally witnessed (§4.5)."""
        witnesses = list(witnesses or [])
        thr = threshold if threshold is not None else len(witnesses)
        cls._require_witness_policy([w.aid for w in witnesses], thr)
        current = KeyPair.generate()
        nxt = KeyPair.generate()
        event = KelEvent(
            ilk="icp",
            sn=0,
            keys=[current.public_qb64],
            next_key_digest=_next_key_digest(nxt.public_key),
            prior_dig=None,
            witnesses=[w.aid for w in witnesses],
            threshold=thr,
        )
        sign_event(event, current)
        aid = qb64("E", jcs_digest(event.content()))
        kel = Kel(aid=aid, events=[event])
        cls._gather_receipts(kel, event, witnesses)
        return cls(kel=kel, current=current, next_keypair=nxt, witnesses=witnesses)

    @classmethod
    def incept_entity(
        cls,
        tenant: "Identity",
        witnesses: Optional[Sequence[Witness]] = None,
        threshold: Optional[int] = None,
    ) -> "Identity":
        """Incept an entity *delegated* AID anchored in ``tenant``'s KEL (§4.2).

        Produces a ``dip`` event naming the tenant as delegator and an ``ixn``
        anchoring seal in the tenant KEL, so the delegation is bilaterally
        verifiable: the entity points to the tenant, and the tenant's log
        confirms it authorized the delegation.
        """
        witnesses = list(witnesses or [])
        thr = threshold if threshold is not None else len(witnesses)
        cls._require_witness_policy([w.aid for w in witnesses], thr)
        current = KeyPair.generate()
        nxt = KeyPair.generate()
        event = KelEvent(
            ilk="dip",
            sn=0,
            keys=[current.public_qb64],
            next_key_digest=_next_key_digest(nxt.public_key),
            prior_dig=None,
            witnesses=[w.aid for w in witnesses],
            threshold=thr,
            delegator_aid=tenant.aid,
        )
        sign_event(event, current)
        aid = qb64("E", jcs_digest(event.content()))
        kel = Kel(aid=aid, events=[event])
        cls._gather_receipts(kel, event, witnesses)
        # Anchor the delegation in the tenant's KEL (interaction event), which the
        # tenant's own witnesses receipt under the tenant's threshold (§4.5).
        tenant._anchor_delegation(aid, event.digest)
        return cls(
            kel=kel,
            current=current,
            next_keypair=nxt,
            witnesses=witnesses,
            delegator=tenant,
        )

    def rotate(
        self,
        witnesses: Optional[Sequence[Witness]] = None,
        threshold: Optional[int] = None,
    ) -> KelEvent:
        """Rotate signing keys (§4.6), revealing the pre-committed next key set.

        The rotation is signed by the revealed key (§4.4). It keeps the current
        witness set and threshold unless ``witnesses`` is passed (an empty list
        removes every witness); the threshold then defaults to the new set's
        size. A witness change is receipted by the outgoing and the incoming
        witnesses, because a verifier checks it under both policies (§4.5).
        A delegated identity's rotation is approved by its delegator, which
        anchors it in the delegator's own KEL (§4.2).
        """
        inception = self.kel.events[0]
        delegated = inception.ilk == "dip"
        if delegated:
            if self._delegator is None:
                raise ValueError("a delegated rotation needs its delegator to anchor it")
            if self._delegator.aid != inception.delegator_aid:
                raise ValueError("delegator is not the AID this identity's dip names")
            revoked = revocation_seal(self.aid, inception.digest)
            if any(e.ilk == "ixn" and e.seal == revoked for e in self._delegator.kel.events):
                raise ValueError("the delegator has revoked this identity")
        revealed = self._next  # the key the prior establishment pre-committed to
        new_next = KeyPair.generate()
        prior = self.kel.latest
        establishment = _current_key_event(self.kel)
        outgoing = self._witnesses
        if witnesses is not None:
            incoming = list(witnesses)
            names = [w.aid for w in incoming]
            thr = threshold if threshold is not None else len(incoming)
        else:
            incoming = outgoing
            names = list(establishment.witnesses)
            thr = threshold if threshold is not None else establishment.threshold
        self._require_witness_policy(names, thr)
        event = KelEvent(
            ilk="rot",
            sn=prior.sn + 1,
            keys=[revealed.public_qb64],
            next_key_digest=_next_key_digest(new_next.public_key),
            prior_dig=prior.digest,
            witnesses=names,
            threshold=thr,
        )
        sign_event(event, revealed)
        # The delegator approves first, so a failed approval leaves this KEL
        # without an unanchored rotation.
        if delegated:
            self._delegator._anchor(rotation_anchor_seal(self.aid, event.digest))
        self.kel.events.append(event)
        outgoing_aids = {w.aid for w in outgoing}
        receipting = list(outgoing) + [w for w in incoming if w.aid not in outgoing_aids]
        self._gather_receipts(self.kel, event, receipting)
        self._witnesses = incoming
        self._current = revealed
        self._next = new_next
        return event

    def revoke_delegation(self, delegate_aid: str, delegate_icp_dig: str) -> KelEvent:
        """Revoke a delegated AID by a revocation seal in this KEL (§4.2).

        Revocation is permanent: a verifier rejects the delegate from then on,
        and the tenant replaces it by delegating a new AID. An AID is the
        digest of its ``dip``, so a mismatched pair is refused rather than
        written as a seal that revokes nothing.
        """
        if (
            type(delegate_aid) is not str
            or type(delegate_icp_dig) is not str
            or not delegate_aid.startswith("E_")
            or not delegate_icp_dig.startswith("D_")
            or delegate_aid[2:] != delegate_icp_dig[2:]
        ):
            raise ValueError("delegate AID and inception digest do not match")
        return self._anchor(revocation_seal(delegate_aid, delegate_icp_dig))

    def _anchor_delegation(self, delegate_aid: str, delegate_icp_dig: str) -> KelEvent:
        return self._anchor(delegation_seal(delegate_aid, delegate_icp_dig))

    def _anchor(self, seal: str) -> KelEvent:
        prior = self.kel.latest
        establishment = _current_key_event(self.kel)
        event = KelEvent(
            ilk="ixn",
            sn=prior.sn + 1,
            keys=list(establishment.keys),
            next_key_digest=establishment.next_key_digest,  # ixn does not rotate
            prior_dig=prior.digest,
            witnesses=list(establishment.witnesses),
            threshold=establishment.threshold,
            seal=seal,
        )
        sign_event(event, self._current)
        self.kel.events.append(event)
        self._gather_receipts(self.kel, event, self._witnesses)
        return event

    @staticmethod
    def _gather_receipts(kel: Kel, event: KelEvent, witnesses: Sequence[Witness]) -> None:
        for w in witnesses:
            kel.add_receipt(w.receipt(event.digest))

    # -- accessors --------------------------------------------------------

    @property
    def aid(self) -> str:
        return self.kel.aid

    @property
    def signing_key(self) -> KeyPair:
        return self._current

    def sign(self, message: bytes) -> bytes:
        return self._current.sign(message)

    def current_public_key(self) -> bytes:
        return self._current.public_key


def _verify_public_keys(events: Sequence[KelEvent]) -> None:
    """Validate every event's threshold-one signing key at KEL ingestion."""
    for event in events:
        if not isinstance(event.keys, list) or len(event.keys) != 1:
            raise InvalidPublicKeyError(
                f"KEL event sn={event.sn} must contain exactly one signing key"
            )
        _pub_from_qb64(event.keys[0])


_NONE = type(None)
_EVENT_FIELD_TYPES = (
    ("ilk", (str,)),
    ("sn", (int,)),
    ("keys", (list,)),
    ("next_key_digest", (str,)),
    ("prior_dig", (str, _NONE)),
    ("witnesses", (list,)),
    ("threshold", (int,)),
    ("delegator_aid", (str, _NONE)),
    ("seal", (str, _NONE)),
)


def _verify_plain_types(kel: Kel) -> None:
    """Reject subclassed or mistyped KEL values before any comparison reads them.

    A ``str`` subclass can override equality, so an AID, digest or seal that
    is not a plain value could satisfy self-certification, chaining or anchor
    checks it does not actually meet.
    """
    if type(kel) is not Kel or type(kel.aid) is not str:
        raise KeriError("KEL and its AID must be plain values")
    if type(kel.events) is not list or type(kel.receipts) is not dict:
        raise KeriError("KEL events and receipts must be a plain list and dict")
    for index, event in enumerate(kel.events):
        if type(event) is not KelEvent:
            raise KeriError(f"KEL entry at index {index} is not a KEL event")
        for name, allowed in _EVENT_FIELD_TYPES:
            if type(getattr(event, name)) not in allowed:
                raise KeriError(
                    f"KEL event at index {index} has a non-plain {name} value"
                )


def _is_qualified_value(value: object, code: str) -> bool:
    if type(value) is not str or not value.startswith(code + "_"):
        return False
    try:
        return len(qb64_payload(value)) == 32
    except ValueError:
        return False


def _is_digest_qb64(value: object) -> bool:
    return _is_qualified_value(value, "D")


def _verify_event_shapes(events: Sequence[KelEvent]) -> None:
    """Reject event states outside the reference subset before reading them (§4.4)."""
    if not events:
        raise KeriError("empty KEL")
    _verify_public_keys(events)
    for index, event in enumerate(events):
        if type(event.sn) is not int or not 0 <= event.sn <= 2**53 - 1:
            raise KeriError(f"KEL event at index {index} has an invalid sn")
        if not _is_digest_qb64(event.next_key_digest):
            raise KeriError(
                f"KEL event sn={event.sn} has an invalid next-key commitment"
            )
        if type(event.witnesses) is not list or any(
            not _is_qualified_value(witness, "E") for witness in event.witnesses
        ):
            raise KeriError(f"KEL event sn={event.sn} has an invalid witness set")
        if len(set(event.witnesses)) != len(event.witnesses):
            raise KeriError(f"KEL event sn={event.sn} lists a witness twice")
        if (
            type(event.threshold) is not int
            or not 0 <= event.threshold <= len(event.witnesses)
        ):
            raise KeriError(
                f"KEL event sn={event.sn} has an invalid witness threshold"
            )

        if index == 0:
            if event.ilk not in INCEPTION_ILKS:
                raise KeriError(f"first event must be icp/dip, got {event.ilk!r}")
            if event.sn != 0 or event.prior_dig is not None:
                raise KeriError("inception event must have sn=0 and no prior event")
            if event.seal is not None:
                raise KeriError("inception event cannot carry an interaction seal")
            if event.ilk == "icp" and event.delegator_aid is not None:
                raise KeriError("non-delegated inception cannot name a delegator")
            if event.ilk == "dip" and (
                type(event.delegator_aid) is not str or not event.delegator_aid
            ):
                raise KeriError("delegated inception must name its delegator")
        elif event.ilk == "rot":
            if event.delegator_aid is not None or event.seal is not None:
                raise KeriError(
                    f"rotation sn={event.sn} cannot carry a delegator or a seal"
                )
        elif event.ilk == "ixn":
            if event.delegator_aid is not None:
                raise KeriError(
                    f"interaction event sn={event.sn} cannot name a delegator"
                )
            if event.seal is not None and not _is_digest_qb64(event.seal):
                raise KeriError(f"interaction event sn={event.sn} has an invalid seal")
        else:
            raise KeriError(
                f"post-inception event sn={event.sn} must be rot or ixn, "
                f"got {event.ilk!r}"
            )


def _verify_chain(events: Sequence[KelEvent], aid: str) -> None:
    """Verify the AID is self-certifying and the prior-digest chain is intact."""
    derived = qb64("E", jcs_digest(events[0].content()))
    if derived != aid:
        raise KeriError("AID is not self-certifying (does not match inception event)")
    for i in range(1, len(events)):
        if events[i].prior_dig != events[i - 1].digest:
            raise KeriError(f"broken KEL chain at sn={events[i].sn}")
        if events[i].sn != events[i - 1].sn + 1:
            raise KeriError(f"non-monotonic sn at index {i}")


def _require_controller_signature(
    event: KelEvent, authorizing_key: str, description: str
) -> None:
    if not ed25519.verify_strict(
        kel_event_signing_input(event),
        event.controller_signature,
        _pub_from_qb64(authorizing_key),
    ):
        raise EventAuthorizationError(
            f"{description} is not signed by the key set that authorizes it"
        )


def _verify_authorization(events: Sequence[KelEvent]) -> None:
    """Verify every event against the key state it extends (§4.4).

    An inception is signed by its own key. A rotation must reveal the key the
    latest establishment event committed to and be signed by that revealed key,
    which proves possession of the pre-rotated private key. An interaction is
    signed by the current key and repeats the establishment state unchanged:
    only an establishment event can change keys, the next-key commitment, the
    witness set or the witness threshold.
    """
    establishment = events[0]
    _require_controller_signature(
        establishment, establishment.keys[0], "inception event"
    )
    for event in events[1:]:
        if event.ilk == "rot":
            revealed = _next_key_digest(_pub_from_qb64(event.keys[0]))
            if revealed != establishment.next_key_digest:
                raise PreRotationError(
                    f"rotation at sn={event.sn} does not honor pre-rotation commitment"
                )
            _require_controller_signature(
                event, event.keys[0], f"rotation sn={event.sn}"
            )
            establishment = event
            continue
        if (
            event.keys != establishment.keys
            or event.next_key_digest != establishment.next_key_digest
            or event.witnesses != establishment.witnesses
            or event.threshold != establishment.threshold
        ):
            raise EventAuthorizationError(
                f"interaction event sn={event.sn} changes establishment state"
            )
        _require_controller_signature(
            event, establishment.keys[0], f"interaction event sn={event.sn}"
        )


def _verify_kel_events(kel: Kel) -> None:
    _verify_plain_types(kel)
    _verify_event_shapes(kel.events)
    _verify_chain(kel.events, kel.aid)
    _verify_authorization(kel.events)


def _witness_policies(events: Sequence[KelEvent]):
    """Yield each event with the witness policies its receipts must meet (§4.5).

    The policy in force is the latest establishment event's. A rotation must
    also satisfy the policy it replaces, so the witnesses that held the prior
    key state can stop a forked rotation.
    """
    establishment: Optional[KelEvent] = None
    for event in events:
        if event.ilk in INCEPTION_ILKS:
            policies = [("", event)]
            establishment = event
        elif event.ilk == "rot":
            policies = [("prior ", establishment), ("", event)]
            establishment = event
        else:
            policies = [("", establishment)]
        yield event, policies


def _verify_witnesses(
    kel: Kel,
    witness_keys: Dict[str, bytes],
) -> None:
    """Each event meets the witness policies in force for it (§4.5)."""
    pinned_keys = set()
    for witness_aid, public_key in witness_keys.items():
        if not _is_qualified_value(witness_aid, "E"):
            raise InvalidPublicKeyError(
                "witness public-key identifiers must be canonical E_ AIDs"
            )
        try:
            ed25519.validate_public_key(public_key)
        except ValueError as exc:
            raise InvalidPublicKeyError(
                f"witness {witness_aid!r} has invalid Ed25519 public-key material"
            ) from exc
        # A threshold counts distinct witnesses, so one key pinned under two
        # identifiers would let a single signer count twice.
        if public_key in pinned_keys:
            raise InvalidPublicKeyError(
                "witness key map pins one public key under two witness identifiers"
            )
        pinned_keys.add(public_key)

    for event, policies in _witness_policies(kel.events):
        required = [(label, p) for label, p in policies if p.threshold > 0]
        if not required:
            continue
        eligible = {aid for _, p in required for aid in p.witnesses}
        valid = set()
        receipts = kel.receipts.get(event.digest, [])
        if type(receipts) is not list:
            raise KeriError(f"receipts for event sn={event.sn} must be a plain list")
        for r in receipts:
            if type(r) is not WitnessReceipt:
                raise KeriError(f"event sn={event.sn} has a malformed receipt")
            if type(r.witness_aid) is not str:
                raise InvalidPublicKeyError(
                    "witness receipt identifiers must be plain strings"
                )
            if r.witness_aid in valid or r.witness_aid not in eligible:
                continue
            if type(r.event_dig) is not str or r.event_dig != event.digest:
                continue
            pub = witness_keys.get(r.witness_aid)
            if pub is None:
                continue
            if ed25519.verify_strict(receipt_signing_input(event.digest), r.signature, pub):
                valid.add(r.witness_aid)
        for label, policy in required:
            count = len(valid.intersection(policy.witnesses))
            if count < policy.threshold:
                raise WitnessThresholdError(
                    f"event sn={event.sn} has {count} valid receipts from the "
                    f"{label}witness set, needs threshold {policy.threshold}"
                )


def _pub_from_qb64(value: str) -> bytes:
    try:
        if type(value) is not str or value.partition("_")[0] != "K":
            raise ValueError("public key must use the K derivation code")
        public_key = qb64_payload(value)
        ed25519.validate_public_key(public_key)
        return public_key
    except ValueError as exc:
        raise InvalidPublicKeyError(
            "KEL signing key must be canonical K_<64 lowercase hex> "
            "prime-order Ed25519 material"
        ) from exc


def verify_kel(
    kel: Kel,
    *,
    tenant_kel: Optional[Kel] = None,
    witness_keys: Optional[Dict[str, bytes]] = None,
    first_seen: Union[KelStateStore, Iterable[Optional[KelStateStore]], None] = None,
) -> KelEvent:
    """Verify a KEL end to end and return its latest verified event.

    This is the §12.3 / §4.5.3 verification entry point. It checks:

      1. every event is well formed: one canonical, prime-order Ed25519
         signing key, an inception first and only rotations or interactions
         after it;
      2. the AID is self-certifying (derived from its inception event), the
         prior-digest chain is intact and sn is monotonic;
      3. every event is signed by the key set that authorizes it, rotations
         honor the pre-rotation commitment of the latest establishment event,
         and interactions leave establishment state unchanged (§4.4);
      4. with ``tenant_kel``, ``kel`` is an entity: it opens with a ``dip``
         naming that tenant, and the tenant KEL opens with an ``icp``, passes
         the same checks, anchors the delegation and every entity rotation by
         matching interaction seals, and has not revoked the delegation
         (§4.2);
      5. each event meets the witness policy in force for it, and a rotation
         also the policy it replaces (§4.5), when ``witness_keys`` is supplied.
         Without ``witness_keys`` no receipt is checked, so a fork of a
         witnessed KEL is not detected; every §12 consumer supplies the map.

    Without ``tenant_kel`` only a tenant-root (``icp``) KEL verifies. A §12.3
    session principal is always an entity, so every session-layer consumer
    passes the claimed tenant's KEL and thereby requires a delegated AID.

    With ``first_seen`` (a store, or several), both KELs must also extend the
    state each store has verified for their AIDs, and become its new state
    (§4.5). The tenant KEL is recorded as soon as it verifies, so a revocation
    it carries is retained even when it rejects the entity.

    Raises a :class:`KeriError` subclass on any failure; the AFP session layer
    maps that to "decline session establishment" (§4.5.3 — failure has exactly
    one protocol consequence and never mutates tenant state).
    """
    return _verify_recording(
        kel, tenant_kel, witness_keys, first_seen, revocation_voids=True
    )


def _stores(first_seen: Any) -> Tuple[KelStateStore, ...]:
    if first_seen is None:
        return ()
    if isinstance(first_seen, KelStateStore):
        return (first_seen,)
    return tuple(dict.fromkeys(s for s in first_seen if s is not None))


def _checked_snapshot(kel: Kel, verify: Any) -> Tuple[Any, _KelSnapshot]:
    """Run ``verify`` and return its result with the KEL state it verified.

    The snapshot is taken before verification and compared after it, so the
    recorded state is exactly the state that was checked.
    """
    try:
        before: Optional[_KelSnapshot] = _snapshot(kel)
    except (AttributeError, TypeError):
        before = None
    result = verify()
    if before is None or _snapshot(kel) != before:
        raise KeriError("KEL changed while it was being verified")
    return result, before


def _verify_recording(
    kel: Kel,
    tenant_kel: Optional[Kel],
    witness_keys: Optional[Dict[str, bytes]],
    first_seen: Any,
    *,
    revocation_voids: bool,
    allow_prefix: bool = False,
) -> KelEvent:
    """Verify ``kel`` and record each verified KEL in every retained store.

    The tenant KEL is verified and recorded on its own first, so retained
    state keeps a revocation it carries even when that revocation is what
    rejects the entity (§4.5).
    """
    stores = _stores(first_seen)
    if not stores:
        return _verify(kel, tenant_kel, witness_keys, revocation_voids=revocation_voids)
    tenant_verified = False
    if tenant_kel is not None:
        _, tenant_state = _checked_snapshot(
            tenant_kel,
            lambda: _verify(tenant_kel, None, witness_keys, revocation_voids=True),
        )
        for store in stores:
            store._accept_snapshots([tenant_state], allow_prefix)
        tenant_verified = True
    latest, state = _checked_snapshot(
        kel,
        lambda: _verify(
            kel,
            tenant_kel,
            witness_keys,
            revocation_voids=revocation_voids,
            tenant_verified=tenant_verified,
        ),
    )
    for store in stores:
        store._accept_snapshots([state], allow_prefix)
    return latest


def _verify(
    kel: Kel,
    tenant_kel: Optional[Kel],
    witness_keys: Optional[Dict[str, bytes]],
    *,
    revocation_voids: bool,
    tenant_verified: bool = False,
) -> KelEvent:
    _verify_kel_events(kel)

    icp = kel.events[0]
    if tenant_kel is None and icp.ilk == "dip":
        raise DelegationError("delegated AID requires its tenant KEL to verify")
    if tenant_kel is not None:
        if icp.ilk != "dip":
            raise DelegationError(
                "an AID verified against a tenant KEL must be a delegated AID "
                "whose KEL opens with dip (§4.2)"
            )
        if not tenant_verified:
            _verify_kel_events(tenant_kel)
        if tenant_kel.events[0].ilk != "icp":
            raise DelegationError("a tenant root KEL must open with icp (§4.2)")
        if icp.delegator_aid != tenant_kel.aid:
            raise DelegationError("delegated AID names a different delegator")
        # Every tenant ixn is authenticated by now, so its seal is the
        # tenant's own statement about this delegation.
        seal_at: Dict[str, int] = {}
        for index, event in enumerate(tenant_kel.events):
            if event.ilk == "ixn" and event.seal is not None:
                seal_at.setdefault(event.seal, index)
        if delegation_seal(kel.aid, icp.digest) not in seal_at:
            raise DelegationError("delegation not anchored in tenant KEL")
        revoked_at = seal_at.get(revocation_seal(kel.aid, icp.digest))
        if revocation_voids and revoked_at is not None:
            raise DelegationError("delegation has been revoked by the tenant")
        for event in kel.events[1:]:
            if event.ilk != "rot":
                continue
            anchored_at = seal_at.get(rotation_anchor_seal(kel.aid, event.digest))
            if anchored_at is None:
                raise DelegationError(
                    f"delegated rotation sn={event.sn} is not anchored in the "
                    "tenant KEL"
                )
            # Revocation is permanent: no approval after it counts (§4.2).
            if revoked_at is not None and anchored_at > revoked_at:
                raise DelegationError(
                    f"delegated rotation sn={event.sn} was approved after the "
                    "delegation was revoked"
                )
        if witness_keys is not None and not tenant_verified:
            _verify_witnesses(tenant_kel, witness_keys)

    if witness_keys is not None:
        _verify_witnesses(kel, witness_keys)

    return kel.latest


def _current_key_event(kel: Kel) -> KelEvent:
    """Return the latest key-establishing event, ignoring interactions."""
    for event in reversed(kel.events):
        if event.ilk in ESTABLISHMENT_ILKS:
            return event
    raise KeriError("KEL has no key-establishing event")


def current_key_event_digest(kel: Kel) -> str:
    """Return the digest that canonically pins the current KERI signing key."""
    return _current_key_event(kel).digest


def resolve_current_key(kel: Kel) -> bytes:
    """Return the current signing key, walking back over interaction events."""
    return _pub_from_qb64(_current_key_event(kel).keys[0])


def resolve_key_at(
    kel: Kel,
    kel_event_dig: str,
    *,
    tenant_kel: Optional[Kel] = None,
    witness_keys: Optional[Dict[str, bytes]] = None,
    first_seen: Union[KelStateStore, Iterable[Optional[KelStateStore]], None] = None,
) -> bytes:
    """Verify ``kel`` and return the key its pinned establishment event set (§12.3).

    This is durable-record verification: a record signed under a key state
    the KEL establishes keeps verifying after a later rotation, and after the
    tenant revokes the delegation, because neither changes which key signed
    it. Everything else ``verify_kel`` checks still applies, including the
    tenant's anchor for the pinned event. The pin must name an establishment
    event of this KEL; an interaction or unknown digest raises
    :class:`StaleKeyStateError`. With ``first_seen`` a KEL that forks from
    retained state is rejected, while a prefix of it is enough history.
    """
    _verify_recording(
        kel,
        tenant_kel,
        witness_keys,
        first_seen,
        revocation_voids=False,
        allow_prefix=True,
    )
    if type(kel_event_dig) is not str:
        raise StaleKeyStateError("record key-state pin must be a plain string")
    for event in kel.events:
        if event.ilk in ESTABLISHMENT_ILKS and event.digest == kel_event_dig:
            return _pub_from_qb64(event.keys[0])
    raise StaleKeyStateError(
        "record is pinned to no establishment event of the signer's KEL"
    )


def assert_keystate_current(kel: Kel, kel_event_dig: str) -> None:
    """Reject a signature pinned to a superseded KEL event (§12.3).

    A signer pins the ``kel_event_dig`` of the key state it signed under. If that
    event is not the *current* key-establishing event, the signature is stale.
    """
    if kel_event_dig != current_key_event_digest(kel):
        raise StaleKeyStateError(
            "signature is bound to a superseded KEL event (kel_keystate_stale)"
        )
