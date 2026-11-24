"""§14.3 — the introduction handshake state machine.

Drives one §12 bilateral session (``profile: 'afp.introduction'``) from zero trust
to a signed provisional agreement. The machine encodes the §14 safeguard rules
structurally: a failed credential can only DECLINE (never freeze tenant state,
Safeguard 3 / §5.4), abort/terminate are unconditional (Safeguard 5), and a
trustless-ZKA-direct envelope skips BONDING (no credit, no exposure).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .atoms import CredentialPresentation, IntroductionRequest, content_digest
from .credentialing import CredentialingDecision, CredentialingError

__all__ = ["State", "TransitionError", "IntroductionFSM"]


class State(str, Enum):
    PROPOSED = "proposed"
    CREDENTIALING = "credentialing"
    NEGOTIATING = "negotiating"
    BONDING = "bonding"
    ACTIVE = "active"
    DECLINED = "declined"
    ABORTED = "aborted"
    DOWNGRADED = "downgraded"
    TERMINATED = "terminated"
    GRADUATED = "graduated"


class TransitionError(RuntimeError):
    """An attempt to take a transition illegal from the current state."""


# States from which an unconditional abort (Safeguard 5) is still meaningful.
_PRE_TERMINAL = {State.PROPOSED, State.CREDENTIALING, State.NEGOTIATING, State.BONDING}


@dataclass
class IntroductionFSM:
    initiator: str
    responder: str
    state: State = State.PROPOSED
    _credentialing_request_digest: str | None = None
    _credentialing_session_context: str | None = None
    _credentialing_initiator: str | None = None
    _credentialing_responder: str | None = None

    @classmethod
    def propose(cls, initiator: str, responder: str) -> "IntroductionFSM":
        return cls(initiator=initiator, responder=responder, state=State.PROPOSED)

    def open_credentialing(
        self, *, request: IntroductionRequest, session_context: str
    ) -> None:
        """PROPOSED -> CREDENTIALING: the request is accepted and both sides now
        exchange their `afp:credential-presentation:v1` bundles (§14.3)."""
        self._require(State.PROPOSED)
        if type(request) is not IntroductionRequest:
            raise TransitionError("credentialing requires an IntroductionRequest record")
        if not all(
            type(value) is str and value
            for value in (
                self.initiator,
                self.responder,
                request.initiator_tenant_aid,
                request.responder_tenant_aid,
                session_context,
            )
        ):
            raise TransitionError(
                "credentialing parties and session context must be non-empty exact strings"
            )
        if (
            request.initiator_tenant_aid != self.initiator
            or request.responder_tenant_aid != self.responder
        ):
            raise TransitionError(
                "credentialing request parties do not match this introduction FSM"
            )
        self._credentialing_request_digest = content_digest(request)
        self._credentialing_session_context = session_context
        self._credentialing_initiator = request.initiator_tenant_aid
        self._credentialing_responder = request.responder_tenant_aid
        self.state = State.CREDENTIALING

    def present_credentials(
        self,
        *,
        decision: CredentialingDecision,
        request: IntroductionRequest,
        presentation: CredentialPresentation,
    ) -> None:
        """CREDENTIALING: a matched presentation advances to NEGOTIATING; an
        unmatched one DECLINES — the only permitted consequence (§5.4,
        Safeguard 3).

        The decision comes from
        :func:`afp_introduction.credentialing.evaluate_credentialing`, which
        compared the presented credentials against what ``request`` required
        (§14.3/§14.4). Its seal is re-checked here against the request, session,
        and exact opaque presentation bundle captured for this FSM, so a decision
        reached for another flow cannot advance this one.
        """
        self._require(State.CREDENTIALING)
        if type(decision) is not CredentialingDecision:
            raise TransitionError(
                "CREDENTIALING advances only on a decision issued by "
                "evaluate_credentialing"
            )
        if type(request) is not IntroductionRequest:
            raise TransitionError("credentialing requires an IntroductionRequest record")
        if type(presentation) is not CredentialPresentation:
            raise TransitionError(
                "credentialing requires the exact CredentialPresentation record"
            )
        if (
            self._credentialing_request_digest is None
            or self._credentialing_session_context is None
            or self._credentialing_initiator is None
            or self._credentialing_responder is None
        ):
            raise TransitionError("credentialing was not opened with a bound request")
        if not all(
            type(value) is str and value
            for value in (
                request.initiator_tenant_aid,
                request.responder_tenant_aid,
                presentation.session_context,
            )
        ):
            raise TransitionError(
                "credentialing request parties and presentation session must be exact strings"
            )
        if (
            request.initiator_tenant_aid != self.initiator
            or request.responder_tenant_aid != self.responder
            or request.initiator_tenant_aid != self._credentialing_initiator
            or request.responder_tenant_aid != self._credentialing_responder
        ):
            raise TransitionError(
                "credentialing request parties do not match this introduction FSM"
            )
        if content_digest(request) != self._credentialing_request_digest:
            raise CredentialingError(
                "credentialing request does not match the request opened by this FSM"
            )
        if presentation.session_context != self._credentialing_session_context:
            raise CredentialingError(
                "credential presentation session does not match the session opened by this FSM"
            )
        self.state = (
            State.NEGOTIATING
            if decision.verify_for(
                request,
                expected_session_context=self._credentialing_session_context,
                expected_bundle=presentation.bundle,
            )
            else State.DECLINED
        )

    def present_native_credentials(
        self, *, decision, request, credential, expected_session_profile: str
    ) -> None:
        """Consume a native receive-issued credential and its policy decision."""
        from afp_session.credential import require_verified_native_credential
        from afp_session.presentation import AfpTrustFlow

        self._require(State.CREDENTIALING)
        require_verified_native_credential(credential)
        if type(decision) is not CredentialingDecision:
            raise TransitionError("native credentialing requires an issued decision")
        if type(request) is not IntroductionRequest:
            raise TransitionError("native credentialing requires an IntroductionRequest")
        envelope = credential.envelope
        if (
            credential.verified_presentation.flow is not AfpTrustFlow.INTRODUCTION
            or type(expected_session_profile) is not str
            or not expected_session_profile
            or envelope.profile != expected_session_profile
            or envelope.sender is None
            or envelope.sender.tenant_aid != self.responder
            or request.initiator_tenant_aid != self.initiator
            or request.responder_tenant_aid != self.responder
            or request.initiator_tenant_aid != self._credentialing_initiator
            or request.responder_tenant_aid != self._credentialing_responder
            or content_digest(request) != self._credentialing_request_digest
            or envelope.session_context != self._credentialing_session_context
        ):
            raise CredentialingError("native credential does not match this introduction")
        accepted = decision.verify_for(
            request,
            expected_session_context=self._credentialing_session_context,
            expected_bundle=credential,
        )
        require_verified_native_credential(credential)
        self.state = State.NEGOTIATING if accepted else State.DECLINED

    def agree_envelope(self, *, requires_bond: bool) -> None:
        """NEGOTIATING -> BONDING if the envelope extends credit, else straight to
        ACTIVE (trustless ZKA-direct: atomic, no exposure; §14.5)."""
        self._require(State.NEGOTIATING)
        self.state = State.BONDING if requires_bond else State.ACTIVE

    def post_bond(self) -> None:
        self._require(State.BONDING)
        self.state = State.ACTIVE

    def abort(self) -> None:
        if self.state not in _PRE_TERMINAL:
            raise TransitionError(f"cannot abort from {self.state}")
        self.state = State.ABORTED  # unconditional exit (Safeguard 5)

    def downgrade(self) -> None:
        self._require(State.ACTIVE)
        self.state = State.DOWNGRADED

    def reactivate(self) -> None:
        self._require(State.DOWNGRADED)  # downgrade returns to ACTIVE under new terms
        self.state = State.ACTIVE

    def terminate(self) -> None:
        if self.state not in (State.ACTIVE, State.DOWNGRADED):
            raise TransitionError(f"cannot terminate from {self.state}")
        self.state = State.TERMINATED  # unconditional (Safeguard 5)

    def graduate(self) -> None:
        self._require(State.ACTIVE)
        self.state = State.GRADUATED

    def _require(self, expected: State) -> None:
        if self.state != expected:
            raise TransitionError(f"expected {expected}, in {self.state}")
