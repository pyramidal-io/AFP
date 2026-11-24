"""Bilateral session lifecycle, FSM, and envelope exchange (§12.2 / §12.7).

This module is the heart of the §12 Bilateral Session Core. It provides:

  * :class:`SessionFSM` — the core lifecycle state machine
    (PROPOSED→OPEN→ACTIVE→CLOSING→CLOSED, with ABORTED/EXPIRED), enforcing the
    legal transitions of §12.2.2 and the timeout of §12.2.3;
  * :class:`Instance` — one ADAMAS instance (a tenant+entity identity over a
    transport) that can propose/accept sessions, send/receive signature-verified
    ``afp:envelope:v1`` envelopes (§12.7), and close sessions, all over the
    §12.4 NATS namespace.

Two ``Instance``s sharing one :class:`~afp_session.transport.InMemoryTransport`
demonstrate the acceptance criterion: open/close a real bilateral session and
exchange a signed, signature-verified envelope.

Identity binding (§12.3) is real: every session atom and envelope carries an
``AfpPartyRef`` with a KEL-anchored Ed25519 signature, verified up to the tenant
root AID (``afp_session.keri``). A signature bound to a superseded KEL event is
rejected (``kel_keystate_stale``).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
from threading import Lock, RLock
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import ed25519, keri
from .atoms import (
    AfpEnvelope,
    AfpPartyRef,
    AfpSessionAtom,
    AfpSessionStatus,
    compute_session_context,
    unix_to_session_datetime,
)
from .bundle import (
    BUNDLE_VERSION,
    BundleError,
    BundleVerificationResult,
    BundleVerifier,
    ZkaBundle,
    verify_bundle,
)
from .canonical import canonical_bytes
from .credential import (
    CREDENTIAL_ENVELOPE_KIND,
    _ACCEPTED_MINT_TOKEN,
    _record_json,
    AcceptedCredentialEnvelope,
    AprSignerBindingResolver,
    AfpCredentialEnvelope,
    CredentialEnvelopeError,
    NativeCredentialVerification,
    NativeCredentialVerificationRequest,
    NativeCredentialVerifier,
    NativeAprSignerBinding,
    NativeAprSignerBindingRequest,
)
from .canonical import jcs_bytes
from .presentation import (
    AfpTrustFlow,
    RequiredPredicatePolicy,
    ZkcPresentationEvidence,
    ZkcVerifiedPublicStatement,
    as_trust_flow,
    verify_presentation_binding,
)
from .coord import (
    COORD_COMPLETION_MESSAGE_CLASS,
    CoordAcceptancePolicy,
    CoordCompletion,
    CoordCompletionVerificationContext,
    CoordEvidenceReference,
    CoordFailureCode,
    CoordFinalProof,
    CoordVerificationError,
    CoordVerifierRequest,
    derive_coord_context,
)
from .channel import (
    ChannelError,
    ChannelRole,
    SealedChannelAttestation,
    SessionChannel,
)
from .namespace import subject
from .profiles import ProfileRegistry, default_registry
from .transport import Transport

__all__ = [
    "SessionError",
    "TransitionError",
    "SessionExpired",
    "IdentityBindingError",
    "EnvelopeError",
    "SessionFSM",
    "Instance",
    "RemoteParty",
    "verify_party_ref",
    "VerifiedLiveSession",
    "DEFAULT_MAX_CLOCK_SKEW_SECONDS",
]

# Legal core transitions (§12.2.2). EXPIRED is reachable from any non-terminal
# state (handled in code, not the table). ABORTED is reachable from any
# non-terminal state (either-party exit / error, Safeguard 5).
_LEGAL: Dict[AfpSessionStatus, frozenset] = {
    AfpSessionStatus.PROPOSED: frozenset(
        {AfpSessionStatus.OPEN, AfpSessionStatus.ABORTED, AfpSessionStatus.EXPIRED}
    ),
    AfpSessionStatus.OPEN: frozenset(
        {AfpSessionStatus.ACTIVE, AfpSessionStatus.ABORTED, AfpSessionStatus.EXPIRED}
    ),
    AfpSessionStatus.ACTIVE: frozenset(
        {AfpSessionStatus.CLOSING, AfpSessionStatus.ABORTED, AfpSessionStatus.EXPIRED}
    ),
    AfpSessionStatus.CLOSING: frozenset(
        {AfpSessionStatus.CLOSED, AfpSessionStatus.ABORTED, AfpSessionStatus.EXPIRED}
    ),
    AfpSessionStatus.CLOSED: frozenset(),
    AfpSessionStatus.EXPIRED: frozenset(),
    AfpSessionStatus.ABORTED: frozenset(),
}

# How far a proposal's opened_at may run ahead of the responder's clock
# (§12.2.1). Together with the expiry check it bounds replay-record retention.
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300

_TERMINAL = frozenset(
    {AfpSessionStatus.CLOSED, AfpSessionStatus.EXPIRED, AfpSessionStatus.ABORTED}
)

_ENVELOPE_WIRE_KEYS = frozenset(
    {
        "kind",
        "session_ref",
        "session_context",
        "profile",
        "bundle",
        "bundle_version",
        "message_class",
        "generated_at",
        "expires_at",
        "sender",
    }
)
_PARTY_REF_WIRE_KEYS = frozenset(
    {"tenant_aid", "entity_aid", "kel_event_dig", "signature"}
)


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value!r}")


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


class SessionError(Exception):
    """Base class for session-layer failures (§12)."""


class TransitionError(SessionError):
    """An illegal lifecycle transition was attempted (§12.2.2)."""


class SessionExpired(SessionError):
    """A session operation was attempted past ``expires_at`` (§12.2.3)."""


class IdentityBindingError(SessionError):
    """An ``AfpPartyRef`` failed §12.3 identity-binding verification."""


class EnvelopeError(SessionError):
    """An ``afp:envelope:v1`` failed §12.7 envelope verification."""


class SessionFSM:
    """The core bilateral-session lifecycle FSM (§12.2.2 / §12.2.3).

    Wraps an :class:`AfpSessionAtom` and gates status changes through the legal
    transition map. Timeout is observe-and-resolve (§12.2.3): :meth:`check_timeout`
    moves any non-terminal session past ``expires_at`` to EXPIRED — it never
    freezes or rolls back tenant state.
    """

    def __init__(self, atom: AfpSessionAtom, clock: Callable[[], float] = time.time):
        self.atom = atom
        self._clock = clock
        # An Instance binds this to its completion lock before publishing the
        # FSM. Standalone FSMs retain the same synchronized public lifecycle API.
        self._state_lock = RLock()

    @property
    def status(self) -> AfpSessionStatus:
        with self._state_lock:
            return self.atom.status

    @property
    def is_terminal(self) -> bool:
        with self._state_lock:
            return self.atom.status in _TERMINAL

    def check_timeout(self) -> bool:
        """Expire the session if past ``expires_at`` (§12.2.3). Returns True if expired now."""
        with self._state_lock:
            if self.atom.status in _TERMINAL:
                return False
            observed = self._clock()
            if observed >= self.atom.expires_at_seconds:
                self.atom.status = AfpSessionStatus.EXPIRED
                self.atom.closed_at = self._observed_datetime(observed)
                return True
            return False

    @staticmethod
    def _observed_datetime(observed: float) -> str:
        """Record a local clock reading as the unsigned ``closed_at`` value."""
        return unix_to_session_datetime(math.floor(observed))

    def transition(self, target: AfpSessionStatus) -> None:
        """Move to ``target``, enforcing legality and timeout (§12.2.2/§12.2.3)."""
        with self._state_lock:
            self._transition_locked(target)

    def _transition_locked(self, target: AfpSessionStatus) -> None:
        # Expiry pre-empts any other transition.
        if target not in (AfpSessionStatus.EXPIRED, AfpSessionStatus.ABORTED):
            if self.check_timeout():
                raise SessionExpired(
                    f"session {self.atom.id} expired before transition to {target.value}"
                )
        current = self.atom.status
        if target not in _LEGAL.get(current, frozenset()):
            raise TransitionError(
                f"illegal transition {current.value} -> {target.value} (§12.2.2)"
            )
        initiator_signature = getattr(self.atom.initiator, "signature", None)
        responder_signature = getattr(self.atom.responder, "signature", None)
        if target in {
            AfpSessionStatus.OPEN,
            AfpSessionStatus.ACTIVE,
            AfpSessionStatus.CLOSING,
            AfpSessionStatus.CLOSED,
        } and (
            not isinstance(initiator_signature, str)
            or not initiator_signature
            or not isinstance(responder_signature, str)
            or not responder_signature
        ):
            raise TransitionError(
                f"cannot transition to {target.value} without both party signatures"
            )
        self.atom.status = target
        if target in _TERMINAL:
            self.atom.closed_at = self._observed_datetime(self._clock())

    def abort(self, reason: str = "") -> None:
        """Either-party exit / error → ABORTED (§12.2.2, Safeguard 5). Always legal."""
        with self._state_lock:
            if self.atom.status in _TERMINAL:
                return
            self.atom.status = AfpSessionStatus.ABORTED
            self.atom.closed_at = self._observed_datetime(self._clock())


_LIVE_SESSION_MINT_TOKEN = object()


@dataclass(frozen=True, init=False, eq=False)
class VerifiedLiveSession:
    """Immutable capability minted only after an owned normal ACTIVE transition.

    The wire snapshot is detached from the mutable FSM, while the capability
    remains bound to its owning ``Instance`` and exact FSM. Every access checks
    current provenance and the owner's clock. It is intentionally non-serializable:
    a restarted manager rehydrates durable FSM state and mints a new handle.
    """

    _atom_wire: bytes
    _owner: "Instance"
    _fsm: SessionFSM

    def __init__(
        self,
        atom_wire: bytes,
        owner: "Instance",
        fsm: SessionFSM,
        *,
        _mint_token: object = None,
    ) -> None:
        if _mint_token is not _LIVE_SESSION_MINT_TOKEN:
            raise SessionError(
                "VerifiedLiveSession can only be minted by an owning Instance"
            )
        object.__setattr__(self, "_atom_wire", bytes(atom_wire))
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_fsm", fsm)

    @classmethod
    def _mint(
        cls, owner: "Instance", fsm: SessionFSM
    ) -> "VerifiedLiveSession":
        """Internal mint path that independently rechecks lifecycle provenance."""
        owner._require_owned_fsm(fsm)
        if (
            fsm.status is not AfpSessionStatus.ACTIVE
            or id(fsm) not in owner._normally_opened_fsms
            or id(fsm) not in owner._normally_activated_fsms
            or not fsm.atom.responder.signature
        ):
            raise SessionError(
                "cannot mint live-session capability without normal ACTIVE provenance"
            )
        return cls(
            canonical_bytes(fsm.atom.to_dict()),
            owner,
            fsm,
            _mint_token=_LIVE_SESSION_MINT_TOKEN,
        )

    def to_atom(self) -> AfpSessionAtom:
        """Return a detached session-atom snapshot for boundary re-verification."""
        self._owner._revalidate_live_session_handle(self)
        try:
            return AfpSessionAtom.from_json(self._atom_wire)
        except (KeyError, TypeError, ValueError) as exc:
            raise SessionError("verified live-session snapshot is malformed") from exc

    @property
    def detached_atom(self) -> AfpSessionAtom:
        """Alias that performs the same owner-side liveness revalidation."""
        return self.to_atom()

    @property
    def kel_state(self) -> keri.KelStateStore:
        """The owning instance's retained first-seen KEL state (§4.5)."""
        return self._owner.kel_state

    def __reduce__(self) -> object:
        raise TypeError("VerifiedLiveSession is a live capability and cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("VerifiedLiveSession is a live capability and cannot be serialized")


class RemoteParty:
    """A counterparty's verifier-facing identity material (§12.3).

    What one instance needs to verify the *other*: the counterparty's entity KEL,
    its tenant KEL, and the witness public keys needed to check the declared
    threshold. Verification requires an explicit mapping; ``{}`` is valid for a
    threshold-zero KEL. In a live deployment the KELs come from the
    counterparty's witnesses or the verifier's watchers (§4.5); here they are
    supplied directly. ``kel_state`` is a retained first-seen KEL state. An
    :class:`Instance` always consults its own as well, and attaches it to a
    RemoteParty that carries none, so later uses of the same RemoteParty, such
    as sealed-channel establishment, consult it too.
    """

    def __init__(
        self,
        entity_kel: keri.Kel,
        tenant_kel: keri.Kel,
        witness_keys: Optional[Dict[str, bytes]] = None,
        kel_state: Optional[keri.KelStateStore] = None,
    ):
        self.entity_kel = entity_kel
        self.tenant_kel = tenant_kel
        self.witness_keys = witness_keys
        self.kel_state = kel_state


def _first_seen(
    remote: Any, fallback: Optional[keri.KelStateStore]
) -> Tuple[Optional[keri.KelStateStore], ...]:
    """Every retained store a check must consult: the remote's and the verifier's."""
    return (getattr(remote, "kel_state", None), fallback)


def _make_party_ref(
    identity_entity: keri.Identity,
    identity_tenant: keri.Identity,
    content_hash: str,
) -> AfpPartyRef:
    """Build a signed :class:`AfpPartyRef` over ``content_hash`` (§12.2.1/§12.3)."""
    signature = identity_entity.sign(content_hash.encode("utf-8")).hex()
    return AfpPartyRef(
        tenant_aid=identity_tenant.aid,
        entity_aid=identity_entity.aid,
        kel_event_dig=keri.current_key_event_digest(identity_entity.kel),
        signature=signature,
    )


def verify_party_ref(
    ref: AfpPartyRef,
    content_hash: str,
    remote: RemoteParty,
    *,
    kel_state: Optional[keri.KelStateStore] = None,
) -> None:
    """Verify a counterparty's :class:`AfpPartyRef` per §12.3.

    Checks: the entity AID verifies up to its tenant root AID against the witness
    threshold (§4.5 / §12.3); both KELs extend the verifier's retained KEL state
    (``remote.kel_state``, else ``kel_state``) when one is supplied (§4.5); the
    pinned ``kel_event_dig`` is the current key
    state (rejecting a stale-keystate signature, §12.3); and the Ed25519
    signature over the content hash is valid for that key.
    """
    try:
        if remote.witness_keys is None:
            raise IdentityBindingError(
                "party ref witness key material must be explicitly supplied"
            )
        if not isinstance(remote.witness_keys, dict):
            raise IdentityBindingError("party ref witness key material is malformed")
        if ref.entity_aid != remote.entity_kel.aid:
            raise IdentityBindingError(
                "party ref entity AID does not match the remote KEL"
            )
        if ref.tenant_aid != remote.tenant_kel.aid:
            raise IdentityBindingError(
                "party ref tenant AID does not match the remote tenant KEL"
            )
        keri.verify_kel(
            remote.entity_kel,
            tenant_kel=remote.tenant_kel,
            witness_keys=remote.witness_keys,
            first_seen=_first_seen(remote, kel_state),
        )
        keri.assert_keystate_current(remote.entity_kel, ref.kel_event_dig)
        public_key = keri.resolve_current_key(remote.entity_kel)
        ok = ed25519.verify_strict(
            content_hash.encode("utf-8"),
            bytes.fromhex(ref.signature),
            public_key,
        )
    except IdentityBindingError:
        raise
    except (keri.KeriError, AttributeError, TypeError, ValueError) as exc:
        raise IdentityBindingError(str(exc)) from exc
    if not ok:
        raise IdentityBindingError("party ref signature does not verify (§12.3)")


_verify_party_ref = verify_party_ref


class Instance:
    """One ADAMAS instance: a tenant root + acting entity over a transport.

    Drives the bilateral-session lifecycle from one side. The two sides of a
    session are two :class:`Instance` objects (typically sharing an
    :class:`InMemoryTransport` in tests); each verifies the other's identity
    binding (§12.3) and the envelopes it receives (§12.7).
    """

    def __init__(
        self,
        *,
        tenant: keri.Identity,
        entity: keri.Identity,
        transport: Transport,
        clock: Callable[[], float] = time.time,
        coord_completion_context: Optional[CoordCompletionVerificationContext] = None,
        max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        profile_registry: Optional[ProfileRegistry] = None,
        apr_signer_binding_resolver: Optional[AprSignerBindingResolver] = None,
    ):
        if (
            isinstance(max_clock_skew_seconds, bool)
            or not isinstance(max_clock_skew_seconds, int)
            or max_clock_skew_seconds < 0
        ):
            raise SessionError("max_clock_skew_seconds must be a non-negative integer")
        if coord_completion_context is not None and not isinstance(
            coord_completion_context, CoordCompletionVerificationContext
        ):
            raise SessionError(
                "coord completion context must be deployment-configured"
            )
        if profile_registry is not None and not isinstance(
            profile_registry, ProfileRegistry
        ):
            raise SessionError("profile_registry must be a ProfileRegistry")
        if apr_signer_binding_resolver is not None and not callable(apr_signer_binding_resolver):
            raise SessionError("APR signer binding resolver must be deployment-configured")
        # The profiles this instance runs sessions under: the published set
        # plus any recognized bilaterally (§12.4 rule 2, §13.2).
        self.profiles = (
            profile_registry if profile_registry is not None else default_registry()
        )
        self.tenant = tenant
        self.entity = entity
        self.transport = transport
        self._clock = clock
        self._max_clock_skew_seconds = max_clock_skew_seconds
        self._coord_completion_context = coord_completion_context
        self._apr_signer_binding_resolver = apr_signer_binding_resolver
        self._inbox_lock = Lock()
        self._coord_state_lock = RLock()
        # Every session this Instance proposed or accepted, terminal ones
        # included. It doubles as the §12.2.1 replay record: an id present
        # here is never reused, so each id names exactly one signed session.
        self.sessions: Dict[str, SessionFSM] = {}
        # session_id -> ordered list of received, verified envelopes
        self.inbox: Dict[str, List[AfpEnvelope]] = {}
        self.credential_inbox: Dict[str, List[AcceptedCredentialEnvelope]] = {}
        self._credential_seen: set[tuple[str, str]] = set()
        self._credential_pending: set[tuple[str, str]] = set()
        self._native_results: dict[int, tuple[AcceptedCredentialEnvelope, bytes, bytes, RemoteParty]] = {}
        self._remotes: Dict[str, RemoteParty] = {}
        # First-seen KEL state for every counterparty AID this instance has
        # accepted, used whenever a RemoteParty carries none of its own (§4.5).
        self.kel_state = keri.KelStateStore()
        self._normally_opened_fsms: set[int] = set()
        self._normally_activated_fsms: set[int] = set()
        self._subs = []

    @property
    def tenant_aid(self) -> str:
        return self.tenant.aid

    @property
    def entity_aid(self) -> str:
        return self.entity.aid

    # -- proposing / accepting -------------------------------------------

    def propose(
        self,
        *,
        responder_tenant_aid: str,
        responder_entity_aid: str,
        agreement_ref: str,
        agreement_version: str,
        profile: str,
        profile_policy_hash: str,
        responder_remote: RemoteParty,
        ttl_seconds: int = 3600,
        session_id: Optional[str] = None,
    ) -> SessionFSM:
        """Propose a session (→ PROPOSED) with authenticated party bindings (§12.2.2).

        ``expires_at`` is ``opened_at + ttl_seconds`` rendered as the §12.2.1
        whole-second UTC string, so ``ttl_seconds`` must be a whole number of
        seconds greater than zero.
        """
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds != int(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise SessionError("session ttl_seconds must be a positive whole number")
        self._require_registered_profile(profile)
        try:
            if responder_remote.witness_keys is None:
                raise IdentityBindingError(
                    "proposal responder witness key material must be explicitly supplied"
                )
            if not isinstance(responder_remote.witness_keys, dict):
                raise IdentityBindingError(
                    "proposal responder witness key material is malformed"
                )
            if responder_tenant_aid != responder_remote.tenant_kel.aid:
                raise IdentityBindingError(
                    "proposal responder tenant AID does not match the remote KEL"
                )
            if responder_entity_aid != responder_remote.entity_kel.aid:
                raise IdentityBindingError(
                    "proposal responder entity AID does not match the remote KEL"
                )
            keri.verify_kel(
                responder_remote.entity_kel,
                tenant_kel=responder_remote.tenant_kel,
                witness_keys=responder_remote.witness_keys,
                first_seen=_first_seen(responder_remote, self.kel_state),
            )
            responder_kel_event_dig = keri.current_key_event_digest(
                responder_remote.entity_kel
            )
            keri.assert_keystate_current(
                responder_remote.entity_kel, responder_kel_event_dig
            )
        except IdentityBindingError:
            raise
        except (keri.KeriError, AttributeError, TypeError, ValueError) as exc:
            raise IdentityBindingError(str(exc)) from exc
        now = int(self._clock())
        sid = session_id or f"sess_{uuid.uuid4().hex}"
        ctx = compute_session_context(
            self.entity_aid, responder_entity_aid, sid, now
        )
        try:
            expires_at = unix_to_session_datetime(now + int(ttl_seconds))
        except ValueError as exc:
            raise SessionError("session expires_at is outside the datetime range") from exc
        atom = AfpSessionAtom(
            id=sid,
            initiator=AfpPartyRef(
                tenant_aid=self.tenant_aid,
                entity_aid=self.entity_aid,
                kel_event_dig=keri.current_key_event_digest(self.entity.kel),
                signature="",
            ),
            responder=AfpPartyRef(
                tenant_aid=responder_tenant_aid,
                entity_aid=responder_entity_aid,
                kel_event_dig=responder_kel_event_dig,
                signature="",
            ),
            agreement_ref=agreement_ref,
            agreement_version=agreement_version,
            profile=profile,
            profile_policy_hash=profile_policy_hash,
            status=AfpSessionStatus.PROPOSED,
            opened_at=now,
            expires_at=expires_at,
            session_context=ctx,
        )
        # Sign the initiator party ref over the stable session content (§12.2.1).
        atom.initiator.signature = self.entity.sign(
            atom.content_hash.encode("utf-8")
        ).hex()
        fsm = SessionFSM(atom, clock=self._clock)
        fsm._state_lock = self._coord_state_lock
        with self._coord_state_lock:
            if sid in self.sessions:
                raise SessionError(
                    "session id is already in use at this Instance (§12.2.1)"
                )
            self.sessions[sid] = fsm
        return fsm

    def accept(
        self,
        proposal: AfpSessionAtom,
        *,
        initiator_remote: RemoteParty,
    ) -> SessionFSM:
        """Accept a proposed session (→ OPEN), verifying the initiator ref (§12.2.2).

        Completes mutual authentication: the responder verifies the initiator's
        identity binding (§12.3) before opening, then signs its own responder ref.
        A rejection is modeled by the caller invoking :meth:`reject` instead.
        """
        # Work on the responder's OWN copy of the session atom — never alias the
        # initiator's object (the two instances hold separate copies; in a live
        # deployment this copy arrives over the wire).
        try:
            atom = AfpSessionAtom.from_dict(proposal.to_dict())
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise SessionError("proposal session atom is malformed") from exc
        if atom.status is not AfpSessionStatus.PROPOSED:
            raise SessionError("can only accept a PROPOSED session")
        self._require_registered_profile(atom.profile)
        if atom.closed_at is not None:
            raise SessionError("proposed session unexpectedly carries closed_at")
        if atom.responder.signature != "":
            raise SessionError(
                "proposed session responder signature must be exactly empty"
            )
        # Verify the initiator's party ref over the proposed session content.
        _verify_party_ref(
            atom.initiator, atom.content_hash, initiator_remote, kel_state=self.kel_state
        )
        if (
            atom.responder.tenant_aid != self.tenant_aid
            or atom.responder.entity_aid != self.entity_aid
            or atom.responder.kel_event_dig
            != keri.current_key_event_digest(self.entity.kel)
        ):
            raise SessionError("proposal responder binding does not match this instance")
        try:
            expected_context = compute_session_context(
                atom.initiator.entity_aid,
                atom.responder.entity_aid,
                atom.id,
                atom.opened_at,
            )
        except ValueError as exc:
            raise SessionError("proposal session_context timestamp is invalid") from exc
        if atom.session_context != expected_context:
            raise SessionError("proposal session_context does not recompute (§5.2)")
        with self._coord_state_lock:
            # §12.2.1 uniqueness: an id this Instance already holds, live or
            # terminal, is a replay or a collision and must not displace it.
            if atom.id in self.sessions:
                raise SessionError(
                    "proposal session id is already in use at this Instance (§12.2.1)"
                )
            now = self._clock()
            if now >= atom.expires_at_seconds:
                raise SessionExpired(f"proposed session {atom.id} has already expired")
            if atom.opened_at > now + self._max_clock_skew_seconds:
                raise SessionError(
                    "proposal opened_at is beyond the accepted clock skew (§12.2.1)"
                )
            # Complete the responder binding committed by the initiator-signed
            # context, and open a detached FSM before publishing any state.
            atom.responder.signature = self.entity.sign(
                atom.content_hash.encode("utf-8")
            ).hex()
            fsm = SessionFSM(atom, clock=self._clock)
            fsm._state_lock = self._coord_state_lock
            fsm.transition(AfpSessionStatus.OPEN)
            self.sessions[atom.id] = fsm
            self._remotes[atom.id] = initiator_remote
            self._attach_retained_state(initiator_remote)
            self._normally_opened_fsms.add(id(fsm))
        return fsm

    def reject(self, fsm: SessionFSM) -> None:
        """Reject a proposed session (→ ABORTED, §12.2.2)."""
        with self._coord_state_lock:
            fsm.abort(reason="rejected")

    def confirm_open(
        self,
        fsm: SessionFSM,
        accepted: AfpSessionAtom,
        *,
        responder_remote: RemoteParty,
    ) -> None:
        """Initiator side: verify the responder ref and move PROPOSED→OPEN (§12.2.2).

        ``accepted`` is the responder-signed atom returned from the responder's
        :meth:`accept` (over the wire, the responder's copy). The responder ref
        is verified (§12.3) and copied onto the initiator's own session atom.
        """
        self._require_owned_fsm(fsm)
        if fsm.status is not AfpSessionStatus.PROPOSED:
            raise SessionError("can only confirm a PROPOSED session")
        try:
            accepted = AfpSessionAtom.from_dict(accepted.to_dict())
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise SessionError("accepted session atom is malformed") from exc
        if accepted.status is not AfpSessionStatus.OPEN:
            raise SessionError("accepted atom is not OPEN")
        if accepted.closed_at is not None:
            raise SessionError("accepted OPEN atom unexpectedly carries closed_at")
        if accepted.id != fsm.atom.id:
            raise SessionError("accepted atom is for a different session")
        if accepted.content_hash != fsm.atom.content_hash:
            raise SessionError("accepted atom changed the signed session bindings")
        if accepted.initiator.to_dict() != fsm.atom.initiator.to_dict():
            raise SessionError("accepted atom changed the initiator party reference")
        if accepted.responder.unsigned() != fsm.atom.responder.unsigned():
            raise SessionError("accepted responder binding differs from the proposal")
        if (
            not isinstance(accepted.responder.signature, str)
            or not accepted.responder.signature
        ):
            raise SessionError("accepted atom has no responder signature")
        # The responder must have signed the SAME session content the initiator
        # proposed; verify against the initiator's own content hash.
        _verify_party_ref(
            accepted.responder,
            fsm.atom.content_hash,
            responder_remote,
            kel_state=self.kel_state,
        )
        fsm.atom.responder.signature = accepted.responder.signature
        self._remotes[fsm.atom.id] = responder_remote
        self._attach_retained_state(responder_remote)
        fsm.transition(AfpSessionStatus.OPEN)
        self._normally_opened_fsms.add(id(fsm))

    # -- activation / exchange -------------------------------------------

    def activate(self, fsm: SessionFSM) -> None:
        """Move OPEN→ACTIVE on first profile exchange (§12.2.2)."""
        with self._coord_state_lock:
            self._require_owned_fsm(fsm)
            if id(fsm) not in self._normally_opened_fsms:
                raise SessionError(
                    "session was not opened through normal accept/confirm lifecycle"
                )
            fsm.transition(AfpSessionStatus.ACTIVE)
            self._normally_activated_fsms.add(id(fsm))

    def verified_live_session(self, fsm: SessionFSM) -> VerifiedLiveSession:
        """Mint an immutable handle for an owned, normally activated session."""
        self._require_owned_fsm(fsm)
        if fsm.check_timeout():
            self._normally_activated_fsms.discard(id(fsm))
            raise SessionExpired(f"session {fsm.atom.id} expired")
        if (
            fsm.status is not AfpSessionStatus.ACTIVE
            or id(fsm) not in self._normally_activated_fsms
        ):
            raise SessionError(
                "live-session capability requires a normal owned ACTIVE transition"
            )
        if not fsm.atom.responder.signature:
            raise SessionError("ACTIVE session has no responder party signature")
        return VerifiedLiveSession._mint(self, fsm)

    def _require_credential_session(self, fsm: SessionFSM) -> None:
        self._require_owned_fsm(fsm)
        self._require_registered_profile(fsm.atom.profile)
        fsm.check_timeout()
        if (
            fsm.status not in (AfpSessionStatus.OPEN, AfpSessionStatus.ACTIVE)
            or id(fsm) not in self._normally_opened_fsms
        ):
            raise CredentialEnvelopeError("native credentials require a normally opened live session")

    def _native_identity_snapshot(self, remote: RemoteParty) -> bytes:
        return jcs_bytes(_record_json({
            "local_entity": self.entity.kel,
            "local_tenant": self.tenant.kel,
            "peer_entity": remote.entity_kel,
            "peer_tenant": remote.tenant_kel,
            "peer_witness_keys": remote.witness_keys,
        }), floats=True)

    def _require_native_identity_currency(self, remote: RemoteParty) -> None:
        """Recheck unchanged authenticated identities against both live stores.

        A callback can learn a newer KEL without changing the supplied KEL
        bytes. Snapshot equality alone therefore cannot establish currency.
        This check does not authenticate or record previously unseen KELs.
        """
        try:
            for store in dict.fromkeys(_first_seen(remote, self.kel_state)):
                if store is not None:
                    store.assert_current(
                        self.entity.kel, self.tenant.kel,
                        remote.entity_kel, remote.tenant_kel,
                    )
        except (keri.KeriError, AttributeError, TypeError, ValueError):
            raise CredentialEnvelopeError("native credential identity key state is no longer current") from None

    def build_credential_envelope(
        self,
        fsm: SessionFSM,
        *,
        presentation: dict,
        apr: dict,
        message_class: str,
        ttl_seconds: int = 600,
    ) -> AfpCredentialEnvelope:
        """Sign native proof/APR carriage without activating or publishing it."""
        with self._coord_state_lock:
            self._require_credential_session(fsm)
            self._subject(fsm.atom.profile, *message_class.split("."))
            if type(ttl_seconds) is not int or ttl_seconds <= 0:
                raise CredentialEnvelopeError("credential TTL must be positive exact seconds")
            observed = self._clock()
            if type(observed) not in (int, float) or not math.isfinite(observed):
                raise CredentialEnvelopeError("credential clock is invalid")
            now = math.floor(observed)
            envelope = AfpCredentialEnvelope(
                session_ref=fsm.atom.id,
                session_context=fsm.atom.session_context,
                profile=fsm.atom.profile,
                message_class=message_class,
                generated_at=now,
                expires_at=min(now + ttl_seconds, fsm.atom.expires_at_seconds),
                presentation=presentation,
                apr=apr,
                sender=AfpPartyRef(
                    tenant_aid=self.tenant_aid,
                    entity_aid=self.entity_aid,
                    kel_event_dig=keri.current_key_event_digest(self.entity.kel),
                    signature="",
                ),
            )
            envelope.sender.signature = self.entity.sign(envelope.content_hash.encode("utf-8")).hex()
            return envelope

    def seal_credential_envelope(
        self, fsm: SessionFSM, envelope: AfpCredentialEnvelope, *, channel: SessionChannel
    ) -> bytes:
        """Seal the native carrier; no plaintext transport acceptance exists."""
        self._require_session_channel(fsm, channel)
        self._require_credential_session(fsm)
        if type(envelope) is not AfpCredentialEnvelope:
            raise CredentialEnvelopeError("native credential envelope type is invalid")
        # Reconstruct to validate mutable objects before signing/channel effects.
        envelope = AfpCredentialEnvelope.from_json(envelope.to_json())
        if (
            envelope.session_ref != fsm.atom.id
            or envelope.session_context != fsm.atom.session_context
            or envelope.profile != fsm.atom.profile
            or envelope.sender.entity_aid != self.entity_aid
            or envelope.sender.tenant_aid != self.tenant_aid
        ):
            raise CredentialEnvelopeError("native credential envelope is not bound to this session")
        self._subject(fsm.atom.profile, *envelope.message_class.split("."))
        return channel.seal(envelope.to_json(), message_class=envelope.message_class)

    def send_credential_envelope(
        self, fsm: SessionFSM, *, presentation: dict, apr: dict,
        message_class: str, channel: SessionChannel, ttl_seconds: int = 600,
    ) -> AfpCredentialEnvelope:
        """Build, sign, seal and publish native credentials on the profile tree."""
        self._require_session_channel(fsm, channel)
        envelope = self.build_credential_envelope(
            fsm, presentation=presentation, apr=apr, message_class=message_class,
            ttl_seconds=ttl_seconds,
        )
        sealed = self.seal_credential_envelope(fsm, envelope, channel=channel)
        self.transport.publish(self._subject(fsm.atom.profile, *message_class.split(".")), sealed)
        return envelope

    def receive_credential_envelope(
        self, fsm: SessionFSM, sealed_envelope: bytes, *, message_class: str,
        channel: SessionChannel, sender_remote: RemoteParty,
        expected_flow: AfpTrustFlow, required_predicates: RequiredPredicatePolicy,
        credential_verifier: NativeCredentialVerifier,
    ) -> AcceptedCredentialEnvelope:
        """Accept the exact native proof/APR only after channel and AFP binding.

        The deployment adapter must authenticate both native objects, derive the
        actual subject/context/predicates, and return structured evidence. All
        callback exceptions fail closed without publishing sensitive details.
        Replays of the same signed content remain replays in fresh sealed frames.
        """
        with self._coord_state_lock:
            self._require_session_channel(fsm, channel)
            self._require_credential_session(fsm)
            self._subject(fsm.atom.profile, *message_class.split("."))
            expected_flow = as_trust_flow(expected_flow)
            if type(required_predicates) is not RequiredPredicatePolicy:
                raise CredentialEnvelopeError("native credentials require an explicit predicate policy")
            required_predicates = replace(required_predicates)
            envelope = AfpCredentialEnvelope.from_json(channel.open(
                sealed_envelope, message_class=message_class,
            ))
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now):
                raise CredentialEnvelopeError("credential clock is invalid")
            if (
                envelope.session_ref != fsm.atom.id
                or envelope.session_context != fsm.atom.session_context
                or envelope.profile != fsm.atom.profile
                or envelope.message_class != message_class
            ):
                raise CredentialEnvelopeError("native credential session/profile/message binding failed")
            if not envelope.generated_at <= now < envelope.expires_at:
                raise CredentialEnvelopeError("native credential timestamp is not live")
            if envelope.expires_at > fsm.atom.expires_at_seconds:
                raise CredentialEnvelopeError("native credential expiry exceeds session expiry")
            peer = (fsm.atom.responder if self.entity_aid == fsm.atom.initiator.entity_aid
                    else fsm.atom.initiator)
            if (envelope.sender.tenant_aid, envelope.sender.entity_aid) != (peer.tenant_aid, peer.entity_aid):
                raise CredentialEnvelopeError("native credential signer is not the session peer")
            if not envelope.sender.signature:
                raise CredentialEnvelopeError("native credential envelope is unsigned")
            verify_party_ref(envelope.sender, envelope.content_hash, sender_remote, kel_state=self.kel_state)
            if type(envelope.apr.get("request")) is not dict or type(envelope.apr.get("signature")) is not dict or not envelope.apr["signature"]:
                raise CredentialEnvelopeError("native credential APR is unsigned or malformed")
            if not callable(credential_verifier):
                raise CredentialEnvelopeError("a native credential verifier is required")
            wire = envelope.to_json()
            content_hash = envelope.content_hash
            replay_key = (fsm.atom.id, content_hash)
            if replay_key in self._credential_seen or replay_key in self._credential_pending:
                raise CredentialEnvelopeError("native credential content replay")
            session_snapshot = canonical_bytes(fsm.atom.to_dict())
            session_content_hash = fsm.atom.content_hash
            identity_snapshot = self._native_identity_snapshot(sender_remote)
            self._require_native_identity_currency(sender_remote)
            expected_presenter_aid = peer.entity_aid
            expected_verifier_aid = self.entity_aid
            expected_apr_key = keri.resolve_current_key(self.entity.kel)
            expected_policy_hash = fsm.atom.profile_policy_hash
            self._credential_pending.add(replay_key)
            try:
                if self._apr_signer_binding_resolver is not None:
                    expected_kel_event_dig = keri.current_key_event_digest(self.entity.kel)
                    binding_request = NativeAprSignerBindingRequest(
                        expected_verifier_aid=expected_verifier_aid,
                        expected_kel_event_dig=expected_kel_event_dig,
                        expected_keri_public_key=expected_apr_key,
                        expected_session_ref=fsm.atom.id,
                        expected_session_context=envelope.session_context,
                        expected_session_policy_hash=expected_policy_hash,
                        expected_flow=expected_flow,
                    )
                    binding_snapshot = jcs_bytes(_record_json(binding_request))
                    try:
                        binding = self._apr_signer_binding_resolver(binding_request)
                        if jcs_bytes(_record_json(binding_request)) != binding_snapshot:
                            raise ValueError
                        if type(binding) is not NativeAprSignerBinding:
                            raise ValueError
                        # The resolver may retain its frozen record and mutate
                        # it via object.__setattr__. Validate a detached output,
                        # so the accepted key cannot change between checks/use.
                        binding = replace(binding)
                        if (
                            type(binding.verifier_aid) is not str
                            or binding.verifier_aid != expected_verifier_aid
                            or type(binding.kel_event_dig) is not str
                            or binding.kel_event_dig != expected_kel_event_dig
                            or type(binding.public_key) is not bytes
                            or not (len(binding.public_key) == 32 or (
                                len(binding.public_key) == 33 and binding.public_key[0] in (2, 3)
                            ))
                        ):
                            raise ValueError
                        expected_apr_key = bytes(binding.public_key)
                    except Exception:
                        raise CredentialEnvelopeError("APR signer binding could not be authenticated") from None
                    self._require_session_channel(fsm, channel)
                    self._require_credential_session(fsm)
                    if channel.closed:
                        raise CredentialEnvelopeError("native credential channel closed during APR signer resolution")
                    if (
                        canonical_bytes(fsm.atom.to_dict()) != session_snapshot
                        or keri.current_key_event_digest(self.entity.kel) != expected_kel_event_dig
                        or self._native_identity_snapshot(sender_remote) != identity_snapshot
                    ):
                        raise CredentialEnvelopeError("session or verifier key changed during APR signer resolution")
                self._require_native_identity_currency(sender_remote)
                presentation_binding = envelope.presentation.get("presentationBinding")
                if (
                    type(presentation_binding) is dict
                    and presentation_binding.get("profile") == "zkc:presentation:scoped:v1"
                    and not (len(expected_apr_key) == 33 and expected_apr_key[0] in (2, 3))
                ):
                    raise CredentialEnvelopeError("scoped credentials require an authenticated SEC1 APR signer binding")
                request = NativeCredentialVerificationRequest(
                    envelope_wire=wire, expected_flow=expected_flow,
                    expected_presenter_aid=expected_presenter_aid,
                    expected_verifier_aid=expected_verifier_aid,
                    expected_apr_signer_public_key=expected_apr_key,
                    expected_session_context=fsm.atom.session_context,
                    expected_session_policy_hash=expected_policy_hash,
                    required_predicates=replace(required_predicates),
                )
                request_snapshot = jcs_bytes(_record_json(request))
            except BaseException:
                self._credential_pending.discard(replay_key)
                raise
        try:
            try:
                result = credential_verifier(request)
                if jcs_bytes(_record_json(request)) != request_snapshot:
                    raise CredentialEnvelopeError("native verifier changed its authenticated request")
                if type(result) is not NativeCredentialVerification or type(result.envelope_content_hash) is not str or result.envelope_content_hash != content_hash:
                    raise CredentialEnvelopeError("native verifier returned no matching structured result")
                if type(result.evidence) is not ZkcPresentationEvidence or type(result.statement) is not ZkcVerifiedPublicStatement:
                    raise CredentialEnvelopeError("native verifier returned malformed evidence")
                evidence = replace(result.evidence)
                statement = replace(result.statement)
                if (
                    evidence.carrier_kind != CREDENTIAL_ENVELOPE_KIND
                    or evidence.zka_bundle_kind is not None
                    or evidence.zkc_envelope_version != envelope.presentation["version"]
                ):
                    raise CredentialEnvelopeError("native verifier substituted the carrier or presentation version")
                verified = verify_presentation_binding(
                    evidence,
                    expected_flow=expected_flow,
                    expected_responder_aid=expected_presenter_aid,
                    expected_verifier_aid=expected_verifier_aid,
                    expected_apr_signer_public_key=expected_apr_key,
                    expected_session_context=envelope.session_context,
                    expected_session_policy_hash=expected_policy_hash,
                    required_predicates=required_predicates,
                    zkc_verifier=lambda _evidence: statement,
                )
            except Exception:
                raise CredentialEnvelopeError("native credential proof/APR verification failed") from None
            with self._coord_state_lock:
                self._require_session_channel(fsm, channel)
                self._require_credential_session(fsm)
                if channel.closed:
                    raise CredentialEnvelopeError("native credential channel closed during proof verification")
                if canonical_bytes(fsm.atom.to_dict()) != session_snapshot:
                    raise CredentialEnvelopeError("session changed during native credential verification")
                if self._native_identity_snapshot(sender_remote) != identity_snapshot:
                    raise CredentialEnvelopeError("identity state changed during native credential verification")
                self._require_native_identity_currency(sender_remote)
                if not envelope.generated_at <= self._clock() < envelope.expires_at:
                    raise CredentialEnvelopeError("native credential expired during verification")
                accepted = AcceptedCredentialEnvelope(
                    self, wire, verified, evidence, statement, session_content_hash,
                    _mint_token=_ACCEPTED_MINT_TOKEN,
                )
                acceptance_snapshot = accepted._snapshot()
                if fsm.status is AfpSessionStatus.OPEN:
                    self.activate(fsm)
                self._credential_seen.add(replay_key)
                self._native_results[id(accepted)] = (accepted, acceptance_snapshot, identity_snapshot, sender_remote)
                self.credential_inbox.setdefault(fsm.atom.id, []).append(accepted)
                return accepted
        finally:
            with self._coord_state_lock:
                self._credential_pending.discard(replay_key)

    def _revalidate_native_credential(self, result: AcceptedCredentialEnvelope) -> None:
        with self._coord_state_lock:
            retained = self._native_results.get(id(result))
            if retained is None or retained[0] is not result:
                raise CredentialEnvelopeError("native credential result was not issued by this Instance")
            try:
                if result._snapshot() != retained[1]:
                    raise ValueError
                if self._native_identity_snapshot(retained[3]) != retained[2]:
                    raise ValueError
                self._require_native_identity_currency(retained[3])
                envelope = AfpCredentialEnvelope.from_json(result._envelope_wire)
                fsm = self.sessions[envelope.session_ref]
                self._require_credential_session(fsm)
                if fsm.status is not AfpSessionStatus.ACTIVE or fsm.atom.content_hash != result._session_content_hash:
                    raise ValueError
                if not envelope.generated_at <= self._clock() < envelope.expires_at:
                    raise ValueError
            except Exception:
                raise CredentialEnvelopeError("native credential result or live session changed") from None

    def build_envelope(
        self,
        fsm: SessionFSM,
        *,
        bundle: ZkaBundle,
        message_class: str,
        ttl_seconds: float = 600.0,
    ) -> AfpEnvelope:
        """Build and sign an ``afp:envelope:v1`` WITHOUT publishing it (§12.7).

        Same construction as :meth:`send_envelope` minus channel sealing and the
        transport publish. An alternative carrier — notably the §8 metadata-private
        mixnet (``afp_mixnet``) — must pass the result through
        :meth:`seal_envelope` before transport while the §12.7 verification on the
        far side stays identical. Auto-activates an OPEN session (first exchange →
        ACTIVE, §12.2.2).
        """
        self._subject(fsm.atom.profile, *message_class.split("."))
        if fsm.check_timeout():
            raise SessionExpired(f"session {fsm.atom.id} expired")
        if fsm.status == AfpSessionStatus.OPEN:
            self.activate(fsm)
        if fsm.status != AfpSessionStatus.ACTIVE:
            raise SessionError(
                f"cannot send envelope in status {fsm.status.value} (need ACTIVE)"
            )
        now = self._clock()
        envelope = AfpEnvelope(
            session_ref=fsm.atom.id,
            session_context=fsm.atom.session_context,
            profile=fsm.atom.profile,
            bundle=bundle,
            message_class=message_class,
            generated_at=now,
            expires_at=now + ttl_seconds,
            sender=AfpPartyRef(
                tenant_aid=self.tenant_aid,
                entity_aid=self.entity_aid,
                kel_event_dig=keri.current_key_event_digest(self.entity.kel),
                signature="",
            ),
        )
        # Sign over the envelope content hash (which includes the unsigned sender ref).
        envelope.sender.signature = self.entity.sign(
            envelope.content_hash.encode("utf-8")
        ).hex()
        return envelope

    def seal_envelope(
        self,
        fsm: SessionFSM,
        envelope: AfpEnvelope,
        *,
        channel: SessionChannel,
    ) -> bytes:
        """Seal an already-built §12.7 envelope for an alternative carrier."""
        self._require_session_channel(fsm, channel)
        if not isinstance(envelope, AfpEnvelope):
            raise EnvelopeError("envelope must be an AfpEnvelope")
        if (
            envelope.session_ref != fsm.atom.id
            or envelope.session_context != fsm.atom.session_context
            or envelope.profile != fsm.atom.profile
        ):
            raise EnvelopeError("envelope is not bound to the exact AFP session")
        if envelope.sender is None or envelope.sender.entity_aid != self.entity_aid:
            raise EnvelopeError("envelope sender does not match this Instance")
        return channel.seal(
            canonical_bytes(envelope.to_dict()),
            message_class=envelope.message_class,
        )

    def send_envelope(
        self,
        fsm: SessionFSM,
        *,
        bundle: ZkaBundle,
        message_class: str,
        channel: SessionChannel,
        ttl_seconds: float = 600.0,
    ) -> AfpEnvelope:
        """Build, sign, seal, and publish an envelope on the session (§5.2/§12.7).

        The envelope binds its canonical ``X_`` session context to the ZKA
        bundle's canonical BN254 projection (§12.3/§12.7), carries that bundle
        verbatim, and is signed by this instance's entity (KEL-anchored). It is
        sealed *after* signing by the mandatory entity-to-entity channel and then
        published on the session's profile subtree (§12.4). Auto-activates an
        OPEN session (first exchange message → ACTIVE, §12.2.2).
        """
        self._require_session_channel(fsm, channel)
        subj = self._subject(fsm.atom.profile, *message_class.split("."))
        envelope = self.build_envelope(
            fsm, bundle=bundle, message_class=message_class, ttl_seconds=ttl_seconds
        )
        sealed = self.seal_envelope(fsm, envelope, channel=channel)
        self.transport.publish(subj, sealed)
        return envelope

    def receive_envelope(
        self,
        fsm: SessionFSM,
        sealed_envelope: bytes,
        *,
        message_class: str,
        channel: SessionChannel,
        sender_remote: RemoteParty,
        bundle_verifier: BundleVerifier,
    ) -> AfpEnvelope:
        """Open, verify, and accept a sealed envelope per §5.2 and §12.7.

        The transport-facing boundary accepts only an authenticated
        ``afp:sealed:v1`` frame. It opens the channel frame before parsing the
        canonical ``afp:envelope:v1`` payload, then runs the unchanged §12.7
        envelope and bundle verification path. There is deliberately no
        plaintext or legacy-envelope fallback.
        """
        self._require_session_channel(fsm, channel)
        # Validate the transport-supplied class before it is used as channel AD.
        self._subject(fsm.atom.profile, *message_class.split("."))
        raw_envelope = channel.open(
            sealed_envelope, message_class=message_class
        )
        return self._accept_opened_envelope(
            fsm,
            raw_envelope,
            message_class=message_class,
            sender_remote=sender_remote,
            bundle_verifier=bundle_verifier,
        )

    def receive_envelope_with_attestation(
        self,
        fsm: SessionFSM,
        sealed_envelope: bytes,
        *,
        message_class: str,
        channel: SessionChannel,
        sender_remote: RemoteParty,
        bundle_verifier: BundleVerifier,
    ) -> tuple[AfpEnvelope, SealedChannelAttestation]:
        """Accept an envelope and return evidence of its authenticated transit.

        The evidence is returned only after both the channel boundary and the
        unchanged §12.7 envelope verification succeed.
        """
        self._require_session_channel(fsm, channel)
        # Validate the transport-supplied class before it is used as channel AD.
        self._subject(fsm.atom.profile, *message_class.split("."))
        raw_envelope, attestation = channel.open_with_attestation(
            sealed_envelope, message_class=message_class
        )
        received = self._accept_opened_envelope(
            fsm,
            raw_envelope,
            message_class=message_class,
            sender_remote=sender_remote,
            bundle_verifier=bundle_verifier,
        )
        return received, attestation

    def _accept_opened_envelope(
        self,
        fsm: SessionFSM,
        raw_envelope: bytes,
        *,
        message_class: str,
        sender_remote: RemoteParty,
        bundle_verifier: BundleVerifier,
    ) -> AfpEnvelope:
        """Decode and run unchanged §12.7 checks after channel authentication."""
        envelope = self._decode_envelope(raw_envelope)
        if envelope.message_class != message_class:
            raise EnvelopeError(
                "envelope message_class does not match the authenticated transport class"
            )
        return self._verify_received_envelope(
            fsm,
            envelope,
            sender_remote=sender_remote,
            bundle_verifier=bundle_verifier,
        )

    @staticmethod
    def _decode_envelope(raw_envelope: bytes) -> AfpEnvelope:
        """Decode one opened envelope payload without a plaintext fallback."""
        try:
            data = json.loads(
                raw_envelope.decode("utf-8"),
                parse_constant=_reject_non_json_number,
                object_pairs_hook=_reject_duplicate_json_members,
            )
            if not isinstance(data, dict) or set(data) != _ENVELOPE_WIRE_KEYS:
                raise TypeError("envelope payload must decode to an object")
            sender = data["sender"]
            if not isinstance(sender, dict) or set(sender) != _PARTY_REF_WIRE_KEYS:
                raise TypeError("envelope sender must have the exact wire shape")
            return AfpEnvelope.from_dict(data)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise EnvelopeError(
                "opened channel payload is not a valid AFP envelope"
            ) from exc

    def _verify_received_envelope(
        self,
        fsm: SessionFSM,
        envelope: AfpEnvelope,
        *,
        sender_remote: RemoteParty,
        bundle_verifier: BundleVerifier,
        allow_coord_completion: bool = False,
        record_inbox: bool = True,
    ) -> AfpEnvelope:
        """Verify a received envelope per §12.7 (two-layer) and accept it.

        AFP verifies the *envelope*: session_context matches the live session,
        not expired, profile/message_class valid for the session, and the sender
        party ref's KEL-anchored signature verifies (§12.3). ZKA verifies the
        *bundle*: here the AFP-side structural bundle checks run, and the required
        ``bundle_verifier`` seam sees the field-projected bundle and runs a real
        ZKA verifier (§12.7).

        An OPEN session auto-activates on its first received exchange, but only
        once the envelope has verified: session state advances on a verified
        envelope, never on the arrival of one.
        """
        self._require_owned_fsm(fsm)
        self._subject(fsm.atom.profile, *envelope.message_class.split("."))
        if fsm.check_timeout():
            raise SessionExpired(f"session {fsm.atom.id} expired")
        if fsm.status not in (AfpSessionStatus.OPEN, AfpSessionStatus.ACTIVE):
            raise EnvelopeError(
                f"cannot receive envelope in status {fsm.status.value} (need OPEN or ACTIVE)"
            )
        # Envelope-layer checks (AFP owns these).
        if envelope.kind != "afp:envelope:v1":
            raise EnvelopeError(f"unexpected envelope kind {envelope.kind!r}")
        if envelope.bundle_version != BUNDLE_VERSION:
            raise EnvelopeError("envelope bundle_version is not zka:bundle:v1")
        if envelope.session_ref != fsm.atom.id:
            raise EnvelopeError("envelope session_ref does not match the live session")
        if envelope.session_context != fsm.atom.session_context:
            raise EnvelopeError(
                "envelope session_context does not match the live session (§12.7)"
            )
        if envelope.profile != fsm.atom.profile:
            raise EnvelopeError("envelope profile does not match the session profile")
        now = self._clock()
        if now >= envelope.expires_at:
            raise EnvelopeError("envelope has expired (§12.7)")
        if envelope.sender is None:
            raise EnvelopeError("envelope is unsigned")
        if self.entity_aid == fsm.atom.initiator.entity_aid:
            expected_sender = fsm.atom.responder
        elif self.entity_aid == fsm.atom.responder.entity_aid:
            expected_sender = fsm.atom.initiator
        else:
            raise SessionError("owned session does not contain this instance identity")
        if (
            envelope.sender.tenant_aid != expected_sender.tenant_aid
            or envelope.sender.entity_aid != expected_sender.entity_aid
        ):
            raise IdentityBindingError("envelope sender is not the session counterparty")
        # Sender identity binding + signature (§12.3).
        _verify_party_ref(
            envelope.sender, envelope.content_hash, sender_remote, kel_state=self.kel_state
        )
        if (
            envelope.profile in {"prp", "vxp"}
            and "coord_proof" in envelope.bundle.present_proofs
            and not allow_coord_completion
        ):
            raise EnvelopeError(
                "PRP/VXP Coord proof requires the completion acceptance path"
            )
        # Snapshot the complete signed object before invoking the external proof
        # verifier.  The verifier receives the nested mutable bundle and may also
        # have captured the envelope through its closure; neither capability may
        # change the state that AFP accepts.
        verified_envelope_wire = canonical_bytes(envelope.to_dict())
        # Bundle-layer checks (ZKA owns; AFP runs the boundary checks, §12.7).
        verify_bundle(
            envelope.bundle,
            expected_session_context=fsm.atom.session_context,
            bundle_verifier=bundle_verifier,
            now=now,
        )

        if canonical_bytes(envelope.to_dict()) != verified_envelope_wire:
            raise EnvelopeError(
                "ZKA bundle verifier mutated the signed envelope during verification"
            )
        self._require_registered_profile(fsm.atom.profile)
        accepted_envelope = self._decode_envelope(verified_envelope_wire)
        if fsm.status == AfpSessionStatus.OPEN:
            self.activate(fsm)
        if record_inbox:
            self.inbox.setdefault(fsm.atom.id, []).append(accepted_envelope)
        return accepted_envelope

    def receive_coord_completion(
        self,
        live_session: VerifiedLiveSession,
        sealed_envelope: bytes,
        *,
        channel: SessionChannel,
        sender_remote: RemoteParty,
        policy: CoordAcceptancePolicy,
        evidence_references: tuple[CoordEvidenceReference, ...] = (),
    ) -> CoordCompletion:
        """Accept one canonical Coord v2 completion for an ACTIVE PRP/VXP session.

        The ``Instance``-bound context supplies the independently configured ZKA
        verifier and durable completion store. AFP first authenticates and opens
        the mandatory sealed session channel, then checks the signed bilateral
        session and exact committed acceptance policy. The store records replay
        identity and the authoritative inbox effect in one transaction.
        """
        try:
            self._revalidate_live_session_handle(live_session)
            fsm = live_session._fsm
            self._require_session_channel(fsm, channel)
            self._subject(fsm.atom.profile, *COORD_COMPLETION_MESSAGE_CLASS.split("."))
            raw_envelope, _attestation = channel.open_with_attestation(
                sealed_envelope,
                message_class=COORD_COMPLETION_MESSAGE_CLASS,
            )
            envelope = self._decode_envelope(raw_envelope)
            context = self._coord_completion_context
            if not isinstance(context, CoordCompletionVerificationContext):
                raise CoordVerificationError(CoordFailureCode.VERIFIER_FAILURE)
            if not isinstance(policy, CoordAcceptancePolicy):
                raise CoordVerificationError(CoordFailureCode.PROFILE_POLICY)
            if (
                fsm.atom.profile != policy.afp_profile
                or fsm.atom.profile_policy_hash != policy.policy_hash
            ):
                raise CoordVerificationError(CoordFailureCode.PROFILE_POLICY)
            derived_context = derive_coord_context(fsm.atom.session_context)
            if (
                envelope.message_class != COORD_COMPLETION_MESSAGE_CLASS
                or not envelope.bundle.is_pure_coord_payload
                or envelope.bundle.present_proofs != ["coord_proof"]
            ):
                raise CoordVerificationError(CoordFailureCode.MALFORMED)
            request = CoordVerifierRequest(
                session_ref=fsm.atom.id,
                original_context=fsm.atom.session_context,
                derived_context=derived_context,
                party_a_aid=fsm.atom.initiator.entity_aid,
                party_b_aid=fsm.atom.responder.entity_aid,
                sender_aid=(
                    fsm.atom.responder.entity_aid
                    if self.entity_aid == fsm.atom.initiator.entity_aid
                    else fsm.atom.initiator.entity_aid
                ),
                recipient_aid=self.entity_aid,
                verification_time=int(self._clock()),
                policy=policy,
                evidence_references=evidence_references,
            )
            envelope_wire = canonical_bytes(envelope.to_dict())
            proofs: list[CoordFinalProof] = []

            def verify_final_bundle(bundle: ZkaBundle) -> BundleVerificationResult:
                proofs.append(context._validate_bundle_bindings(bundle, request))
                return BundleVerificationResult.accepted(bundle)

            envelope = self._verify_received_envelope(
                fsm,
                envelope,
                sender_remote=sender_remote,
                bundle_verifier=verify_final_bundle,
                allow_coord_completion=True,
                record_inbox=False,
            )
            if len(proofs) != 1:
                raise CoordVerificationError(CoordFailureCode.VERIFIER_FAILURE)
            # Only authenticated, structurally valid, locally bound completions
            # may query durable replay state. Exact retransmissions still avoid
            # any dependency on the configured external verifier.
            prior = context._lookup_completion(policy.workflow_instance_id)
            if prior is not None:
                completion = context._recover_retransmission(
                    prior,
                    proofs[0],
                    request,
                    envelope_wire,
                )
            else:
                verification = context._verify_bundle(envelope.bundle, request)

                def record_active_completion(record):
                    with self._coord_state_lock:
                        self._revalidate_live_session_handle(live_session)
                        stored = context._record_completion(record)
                        inbox = self.inbox.setdefault(fsm.atom.id, [])
                        if all(
                            canonical_bytes(item.to_dict()) != stored.record.envelope_wire
                            for item in inbox
                        ):
                            inbox.append(envelope)
                        return stored

                completion = context._verify_and_record(
                    proofs[0],
                    request,
                    verification,
                    envelope.bundle,
                    envelope_wire,
                    record_completion=record_active_completion,
                )
            if prior is not None:
                stored_wire = completion.record.envelope_wire
                with self._coord_state_lock:
                    self._revalidate_live_session_handle(live_session)
                    inbox = self.inbox.setdefault(fsm.atom.id, [])
                    if all(
                        canonical_bytes(item.to_dict()) != stored_wire for item in inbox
                    ):
                        inbox.append(envelope)
            return completion
        except CoordVerificationError:
            raise
        except IdentityBindingError:
            raise CoordVerificationError(CoordFailureCode.IDENTITY) from None
        except (BundleError, ChannelError, EnvelopeError, SessionError, SessionExpired):
            raise CoordVerificationError(CoordFailureCode.SESSION_CONTEXT) from None

    # -- closing ---------------------------------------------------------

    def begin_close(self, fsm: SessionFSM) -> None:
        """Move ACTIVE→CLOSING when the profile reports its exchange complete (§12.2.2)."""
        with self._coord_state_lock:
            self._require_owned_fsm(fsm)
            fsm.transition(AfpSessionStatus.CLOSING)
            self._normally_opened_fsms.discard(id(fsm))
            self._normally_activated_fsms.discard(id(fsm))

    def complete_close(self, fsm: SessionFSM) -> None:
        """Move CLOSING→CLOSED (§12.2.2)."""
        with self._coord_state_lock:
            self._require_owned_fsm(fsm)
            fsm.transition(AfpSessionStatus.CLOSED)
            self._normally_opened_fsms.discard(id(fsm))
            self._normally_activated_fsms.discard(id(fsm))

    def close(self, fsm: SessionFSM) -> None:
        """Convenience: ACTIVE→CLOSING→CLOSED in one call (graceful teardown)."""
        if fsm.status == AfpSessionStatus.ACTIVE:
            self.begin_close(fsm)
        self.complete_close(fsm)

    # -- helpers ---------------------------------------------------------

    def _require_owned_fsm(self, fsm: SessionFSM) -> None:
        if not isinstance(fsm, SessionFSM) or self.sessions.get(fsm.atom.id) is not fsm:
            raise SessionError("session FSM is not owned by this Instance")

    def _require_session_channel(
        self, fsm: SessionFSM, channel: SessionChannel
    ) -> None:
        """Require a channel bound to this exact owned session and local party."""
        self._require_owned_fsm(fsm)
        self._require_registered_profile(fsm.atom.profile)
        if not isinstance(channel, SessionChannel):
            raise ChannelError("channel must be an established SessionChannel")

        binding = channel.binding
        atom = fsm.atom
        expected_binding = (
            atom.id,
            atom.content_hash,
            atom.session_context,
            atom.profile,
            atom.initiator.tenant_aid,
            atom.initiator.entity_aid,
            atom.initiator.kel_event_dig,
            atom.responder.tenant_aid,
            atom.responder.entity_aid,
            atom.responder.kel_event_dig,
        )
        actual_binding = (
            binding.session_id,
            binding.session_content_hash,
            binding.context,
            binding.profile,
            binding.initiator_tenant_aid,
            binding.initiator_entity_aid,
            binding.initiator_kel_event_dig,
            binding.responder_tenant_aid,
            binding.responder_entity_aid,
            binding.responder_kel_event_dig,
        )
        if actual_binding != expected_binding:
            raise ChannelError("channel is not bound to the exact AFP session")

        if channel.role is ChannelRole.INITIATOR:
            local_party = (
                binding.initiator_tenant_aid,
                binding.initiator_entity_aid,
            )
        elif channel.role is ChannelRole.RESPONDER:
            local_party = (
                binding.responder_tenant_aid,
                binding.responder_entity_aid,
            )
        else:  # Defensive even though established channels fix the enum role.
            raise ChannelError("channel has an invalid local role")
        if local_party != (self.tenant_aid, self.entity_aid):
            raise ChannelError("channel local party does not match this Instance")

    def _revalidate_live_session_handle(
        self, handle: VerifiedLiveSession
    ) -> None:
        """Revalidate one non-portable capability against current owned state."""
        if handle._owner is not self:
            raise SessionError("live-session capability belongs to another Instance")
        fsm = handle._fsm
        self._require_owned_fsm(fsm)
        self._require_registered_profile(fsm.atom.profile)
        if fsm.check_timeout():
            self._normally_opened_fsms.discard(id(fsm))
            self._normally_activated_fsms.discard(id(fsm))
            raise SessionExpired(f"session {fsm.atom.id} expired")
        if (
            fsm.status is not AfpSessionStatus.ACTIVE
            or id(fsm) not in self._normally_opened_fsms
            or id(fsm) not in self._normally_activated_fsms
        ):
            raise SessionError("live-session capability is no longer ACTIVE")
        if canonical_bytes(fsm.atom.to_dict()) != handle._atom_wire:
            raise SessionError("live-session state changed after capability mint")

    def _attach_retained_state(self, remote: RemoteParty) -> None:
        if getattr(remote, "kel_state", None) is None:
            remote.kel_state = self.kel_state

    def _runs_profile(self, profile: str) -> bool:
        return (
            type(profile) is str
            and profile not in ("session", "telemetry")
            and profile in self.profiles.names()
        )

    def _require_registered_profile(self, profile: str) -> None:
        if not self._runs_profile(profile):
            raise SessionError(
                f"profile {profile!r} is not registered with this instance (§12.4)"
            )

    def _subject(self, profile: str, *leaves: str) -> str:
        """This instance's §12.4 subject: its own tenant subtree, registered profile."""
        self._require_registered_profile(profile)
        return subject(
            self._tenant_label(), profile, *leaves, registered=self._runs_profile(profile)
        )

    def _tenant_label(self) -> str:
        """A NATS-safe tenant label for the §12.4 subject (the tenant AID)."""
        return self.tenant_aid.replace("_", "-", 1)
