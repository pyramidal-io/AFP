"""§14.3 CREDENTIALING — required-vs-presented credential matching.

The handshake's CREDENTIALING step is where an introduction decides whether the
counterparty proved what the request asked for. That decision is a *comparison*,
not a report: §5.9 is explicit that "a boolean envelope label that merely says
'verified' is insufficient", and §14.4 that a verifier "MUST accept only a proof
whose public ``root_class`` and ``root_authority_identifier`` exactly match one
signed pair" and "MUST NOT silently authorize an attestation predicate".

:func:`evaluate_credentialing` performs that comparison over real artifacts — the
``afp:introduction-request:v1`` that states the requirement, the
``afp:credential-presentation:v1`` that answers it, and the
``afp:introduction-policy:v1`` that signs the accepted roots — and issues a
sealed :class:`CredentialingDecision`. :meth:`IntroductionFSM.present_credentials`
revalidates that decision against the exact request and presentation, so a caller
cannot replay or assert its way past the step.

A failure declines and nothing more (§5.4, Safeguard 3): the decision carries its
reasons, and the FSM moves to ``DECLINED``. No tenant state is gated, frozen, or
downgraded by a credential outcome.

Two obligations are honestly out of reach here and are reported as seams rather
than claimed. Resolving a root authority's KEL, delegation chain, and
revocation state (§6.3.1) needs authority trust material this seam is not given —
supply ``root_authority_resolver`` to discharge it. And the cryptographic
verification of the opaque presentation bundle is ZKA/ZKC's, through the
required ``presentation_verifier`` callback.
"""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from afp_session.atoms import session_datetime_to_unix
from afp_session.canonical import canonical_json
from afp_session.presentation import (
    INSTANCE_ATTESTATION_PREDICATE_V2,
    PresentationBindingError,
    ProvenPredicate,
    RequiredPredicatePolicy,
    root_pair_of,
)

from .atoms import (
    AcceptedCredential,
    AttestationWindow,
    CREDENTIAL_PRESENTATION_KIND,
    CredentialPresentation,
    OFFER_KIND,
    IntroductionOffer,
    IntroductionPolicy,
    IntroductionRequest,
    InstanceAttestationRoot,
    REQUEST_KIND,
    content_digest,
)

__all__ = [
    "CredentialingDecision",
    "CredentialingError",
    "CredentialPresentationVerifier",
    "RootAuthorityResolver",
    "VerifiedCredentialPresentation",
    "evaluate_credentialing",
    "evaluate_native_credentialing",
    "required_predicate_policy",
]


class CredentialingError(ValueError):
    """A credentialing input is malformed, not merely unsatisfied."""


def _exact_string(value: object) -> bool:
    """Whether ``value`` is a non-empty wire string, not a lookalike."""
    return type(value) is str and bool(value)


def _exact_string_list(label: str, value: object) -> Tuple[str, ...]:
    """Snapshot a decoded JSON string array before comparison or callbacks."""
    if type(value) is not list or any(not _exact_string(item) for item in value):
        raise CredentialingError(f"{label} must be a list of non-empty exact strings")
    return tuple(value)


def _exact_proven_predicate(predicate: object) -> ProvenPredicate:
    """Rebuild one verifier fact after rejecting mutable/equality-spoofed fields.

    ``ProvenPredicate`` is frozen for ordinary callers, but a caller with the
    original object can still use ``object.__setattr__``.  Rebuilding an exact
    primitive snapshot is therefore part of the credentialing boundary rather
    than merely relying on the constructor's earlier validation.
    """
    if type(predicate) is not ProvenPredicate:
        raise CredentialingError(
            "proven_predicates must contain ProvenPredicate records"
        )
    if not _exact_string(predicate.predicate_id) or not _exact_string(
        predicate.predicate_version
    ):
        raise CredentialingError(
            "proven predicate identifier and version must be non-empty exact strings"
        )
    if predicate.root_class is not None and not _exact_string(predicate.root_class):
        raise CredentialingError("proven predicate root class must be an exact string")
    if predicate.root_authority_identifier is not None and not _exact_string(
        predicate.root_authority_identifier
    ):
        raise CredentialingError(
            "proven predicate root authority identifier must be an exact string"
        )
    if predicate.subject_aid is not None and not _exact_string(predicate.subject_aid):
        raise CredentialingError("proven predicate subject AID must be an exact string")
    if predicate.attestation_window is not None:
        if (
            type(predicate.attestation_window) is not tuple
            or len(predicate.attestation_window) != 2
            or any(not _exact_string(value) for value in predicate.attestation_window)
        ):
            raise CredentialingError(
                "proven predicate attestation window must be an exact string pair"
            )
    try:
        return ProvenPredicate(
            predicate_id=predicate.predicate_id,
            predicate_version=predicate.predicate_version,
            root_class=predicate.root_class,
            root_authority_identifier=predicate.root_authority_identifier,
            attestation_window=predicate.attestation_window,
            subject_aid=predicate.subject_aid,
        )
    except PresentationBindingError as exc:
        raise CredentialingError("proven predicate violates the AFP profile") from exc


#: Resolves a §6.3.1 ``(root_class, root_authority_identifier)`` pair to a
#: verdict on that authority's current key state, delegation chain, and
#: revocation status. Returns True where the authority is accepted and live.
#: AFP does not implement this: the resolution reads published KEL events under
#: authority trust material the deployment holds.
RootAuthorityResolver = Callable[[str, str], bool]


@dataclass(frozen=True)
class VerifiedCredentialPresentation:
    """Structured facts issued by a verifier for one exact presentation.

    The callback that returns this record is the cryptographic trust boundary:
    it MUST verify the *exact* ``CredentialPresentation`` object it receives,
    including its opaque bundle, and derive these facts from the verified public
    statement rather than from holder-controlled labels. AFP subsequently
    compares the facts against the presentation, request, and signed policy.
    """

    presenter_aid: str
    session_context: str
    bundle: object
    proven_predicates: Tuple[ProvenPredicate, ...]

    def __post_init__(self) -> None:
        if type(self.presenter_aid) is not str or not self.presenter_aid:
            raise CredentialingError("verified presenter AID must be a non-empty string")
        if type(self.session_context) is not str or not self.session_context:
            raise CredentialingError(
                "verified session context must be a non-empty string"
            )
        if type(self.proven_predicates) is not tuple or any(
            type(predicate) is not ProvenPredicate
            for predicate in self.proven_predicates
        ):
            raise CredentialingError(
                "verified proven_predicates must be an exact tuple of "
                "ProvenPredicate records"
            )


# The ZKA/ZKC seam receives the exact opaque presentation and returns the exact
# bundle object it verified, not a pre-digested boolean. ``None`` means the
# verifier rejected it; callers cannot turn a raw ``True`` into credentialing
# success or transplant facts from another bundle.
CredentialPresentationVerifier = Callable[
    [CredentialPresentation], Optional[VerifiedCredentialPresentation]
]


def required_predicate_policy(
    policy: IntroductionPolicy,
    *,
    required_predicate_ids: Sequence[str] = (),
) -> RequiredPredicatePolicy:
    """Derive the §5.9 required-predicate policy from a signed §14.4 policy block.

    The accepted set is the agreement's ``accepted_credentials`` classes and the
    accepted roots are its signed ``accepted_instance_attestation_roots`` pairs,
    so what a presentation may prove is exactly what the two tenants signed.
    "A pair that a party's implementation ships as a default entry has no
    different status here: it is signed into the agreement by that party or it
    does not apply" (§14.4).
    """
    if type(policy) is not IntroductionPolicy:
        raise CredentialingError("policy must be an IntroductionPolicy record")
    if type(policy.accepted_credentials) is not list:
        raise CredentialingError("accepted_credentials must be a list")
    accepted = []
    for entry in policy.accepted_credentials:
        if (
            type(entry) is not AcceptedCredential
            or not _exact_string(entry.credential_class)
        ):
            raise CredentialingError(
                "accepted credential entries must be {class, valid_until} "
                "records with exact predicate strings"
            )
        accepted.append(entry.credential_class)
    if type(policy.accepted_instance_attestation_roots) is not list:
        raise CredentialingError("accepted_instance_attestation_roots must be a list")
    roots = []
    for root in policy.accepted_instance_attestation_roots:
        if (
            type(root) is not InstanceAttestationRoot
            or not _exact_string(root.root_class)
            or not _exact_string(root.root_authority_identifier)
        ):
            raise CredentialingError(
                "accepted attestation roots must contain exact class and authority strings"
            )
        roots.append((root.root_class, root.root_authority_identifier))
    required = tuple(required_predicate_ids)
    if any(not _exact_string(predicate_id) for predicate_id in required):
        raise CredentialingError(
            "required predicate identifiers must be non-empty exact strings"
        )
    return RequiredPredicatePolicy(
        accepted_predicate_ids=frozenset(accepted),
        required_predicate_ids=frozenset(required),
        accepted_instance_attestation_roots=frozenset(roots),
    )


def _define_credentialing_capability():
    authority = object()
    seal_key = secrets.token_bytes(32)
    # The opaque ZKA bundle has no canonical AFP representation. Keep its
    # object-identity capability in this issuing closure, keyed by the decision
    # seal, rather than accepting a caller-supplied surrogate for the verified
    # proof object.
    bundle_capabilities = {}

    @dataclass(frozen=True, init=False)
    class CredentialingDecision:
        """The outcome of a §14.3 CREDENTIALING comparison over real artifacts.

        Issued only by :func:`evaluate_credentialing`. The seal is what stops
        the step from degrading back into a caller-asserted boolean: a decision
        assembled by hand does not verify, one produced for a different request
        cannot be replayed onto this one, and a field edited after issuance no
        longer matches the sealed wire.

        This is process-local integrity, not unforgeability against code running
        in the same interpreter: anything that can reach the closure can mint a
        decision. It raises the floor from "any caller may assert verified" to
        "the assertion must come from the comparison", which is the §5.9
        obligation at issue.
        """

        accepted: bool
        request_digest: str
        presenter_aid: str
        session_context: str
        proven_predicate_ids: Tuple[str, ...]
        reasons: Tuple[str, ...]
        seams: Tuple[str, ...]
        _bundle_capability: str
        _canonical_wire: str
        _decision_seal: bytes

        def __new__(cls, supplied_authority: object = None):
            if supplied_authority is not authority:
                raise TypeError(
                    "CredentialingDecision is issued only by evaluate_credentialing"
                )
            return super().__new__(cls)

        def verify_for(
            self,
            request: IntroductionRequest,
            *,
            expected_session_context: Optional[str] = None,
            expected_bundle: object = None,
        ) -> bool:
            """Return the decision after checking its sealed artifact bindings.

            Request-only verification supports conformance evidence inspection.
            A state-transition consumer MUST also provide both the authenticated
            session context and exact presentation bundle capability.
            """
            if type(request) is not IntroductionRequest:
                raise CredentialingError(
                    "credentialing decision requires an IntroductionRequest record"
                )
            if (
                type(self.accepted) is not bool
                or not _exact_string(self.request_digest)
                or not _exact_string(self.presenter_aid)
                or not _exact_string(self.session_context)
                or type(self.proven_predicate_ids) is not tuple
                or any(not _exact_string(value) for value in self.proven_predicate_ids)
                or type(self.reasons) is not tuple
                or any(not _exact_string(value) for value in self.reasons)
                or type(self.seams) is not tuple
                or any(not _exact_string(value) for value in self.seams)
                or not _exact_string(self._bundle_capability)
                or type(self._canonical_wire) is not str
                or type(self._decision_seal) is not bytes
            ):
                raise CredentialingError("credentialing decision is malformed")
            expected_seal = hmac.digest(
                seal_key, self._canonical_wire.encode("utf-8"), "sha256"
            )
            if not hmac.compare_digest(self._decision_seal, expected_seal):
                raise CredentialingError("credentialing decision seal is invalid")
            try:
                wire = json.loads(self._canonical_wire)
            except json.JSONDecodeError as exc:
                raise CredentialingError(
                    "credentialing decision snapshot is malformed"
                ) from exc
            if (
                type(wire) is not dict
                or type(wire.get("accepted")) is not bool
                or type(wire.get("request_digest")) is not str
                or type(wire.get("presenter_aid")) is not str
                or type(wire.get("session_context")) is not str
                or type(wire.get("bundle_capability")) is not str
                or type(wire.get("proven_predicate_ids")) is not list
                or any(type(value) is not str for value in wire["proven_predicate_ids"])
                or type(wire.get("reasons")) is not list
                or any(type(value) is not str for value in wire["reasons"])
                or type(wire.get("seams")) is not list
                or any(type(value) is not str for value in wire["seams"])
                or wire.get("accepted") is not self.accepted
                or wire.get("request_digest") != self.request_digest
                or wire.get("presenter_aid") != self.presenter_aid
                or wire.get("session_context") != self.session_context
                or wire.get("bundle_capability") != self._bundle_capability
                or wire.get("proven_predicate_ids") != sorted(self.proven_predicate_ids)
                or tuple(wire.get("reasons", ())) != self.reasons
                or tuple(wire.get("seams", ())) != self.seams
            ):
                raise CredentialingError(
                    "credentialing decision fields do not match sealed wire"
                )
            if self.request_digest != content_digest(request):
                raise CredentialingError(
                    "credentialing decision was issued for a different introduction "
                    "request"
                )
            if (expected_session_context is None) != (expected_bundle is None):
                raise CredentialingError(
                    "credentialing decision consumption requires both session context "
                    "and the exact presentation bundle"
                )
            if expected_session_context is not None:
                if not _exact_string(expected_session_context):
                    raise CredentialingError(
                        "expected session context must be a non-empty exact string"
                    )
                capability = bundle_capabilities.get(self._decision_seal)
                if (
                    capability is None
                    or capability[0] != self._bundle_capability
                    or capability[1] != self.session_context
                    or self.session_context != expected_session_context
                    or capability[2] is not expected_bundle
                ):
                    raise CredentialingError(
                        "credentialing decision is not bound to this session and exact "
                        "presentation bundle"
                    )
            # Return the authenticated primitive rather than a mutable public
            # field.  This keeps a sealed decline a decline even if a hostile
            # caller tampers with the frozen record through ``object.__setattr__``.
            return wire["accepted"]

        def __reduce__(self):
            raise TypeError("CredentialingDecision is process-local authority")

        def __reduce_ex__(self, _protocol):
            raise TypeError("CredentialingDecision is process-local authority")

    CredentialingDecision.__name__ = "CredentialingDecision"
    CredentialingDecision.__qualname__ = "CredentialingDecision"

    def issue(
        *,
        accepted: bool,
        request_digest: str,
        presenter_aid: str,
        session_context: str,
        bundle: object,
        proven_predicate_ids: Tuple[str, ...],
        reasons: Tuple[str, ...],
        seams: Tuple[str, ...],
    ) -> CredentialingDecision:
        if (
            type(accepted) is not bool
            or not _exact_string(request_digest)
            or not _exact_string(presenter_aid)
            or not _exact_string(session_context)
            or bundle is None
            or type(proven_predicate_ids) is not tuple
            or any(not _exact_string(value) for value in proven_predicate_ids)
            or type(reasons) is not tuple
            or any(not _exact_string(value) for value in reasons)
            or type(seams) is not tuple
            or any(not _exact_string(value) for value in seams)
        ):
            raise CredentialingError("credentialing decision issuance is malformed")
        bundle_capability = secrets.token_hex(32)
        canonical_wire = canonical_json(
            {
                "kind": "afp:credentialing-decision:v1",
                "accepted": accepted,
                "request_digest": request_digest,
                "presenter_aid": presenter_aid,
                "session_context": session_context,
                "bundle_capability": bundle_capability,
                "proven_predicate_ids": sorted(proven_predicate_ids),
                "reasons": list(reasons),
                "seams": list(seams),
            }
        )
        decision = CredentialingDecision(authority)
        object.__setattr__(decision, "accepted", accepted)
        object.__setattr__(decision, "request_digest", request_digest)
        object.__setattr__(decision, "presenter_aid", presenter_aid)
        object.__setattr__(decision, "session_context", session_context)
        object.__setattr__(
            decision, "proven_predicate_ids", tuple(sorted(proven_predicate_ids))
        )
        object.__setattr__(decision, "reasons", tuple(reasons))
        object.__setattr__(decision, "seams", tuple(seams))
        object.__setattr__(decision, "_bundle_capability", bundle_capability)
        object.__setattr__(decision, "_canonical_wire", canonical_wire)
        object.__setattr__(
            decision,
            "_decision_seal",
            hmac.digest(seal_key, canonical_wire.encode("utf-8"), "sha256"),
        )
        bundle_capabilities[decision._decision_seal] = (
            bundle_capability,
            session_context,
            bundle,
        )
        return decision

    return CredentialingDecision, issue


CredentialingDecision, _issue_decision = _define_credentialing_capability()


def evaluate_credentialing(
    *,
    request: IntroductionRequest,
    presentation: CredentialPresentation,
    policy: IntroductionPolicy,
    offer: IntroductionOffer,
    expected_session_context: str,
    presentation_verifier: Optional[CredentialPresentationVerifier],
    root_authority_resolver: Optional[RootAuthorityResolver] = None,
) -> CredentialingDecision:
    """Compare what §14.3 required against what the presentation proved.

    ``presentation_verifier`` receives the exact opaque presentation and returns
    structured facts only after ZKA/ZKC verifies its bundle and proof statement.
    ``None`` (or a callback returning ``None``) declines; a callback that returns
    anything other than :class:`VerifiedCredentialPresentation` is malformed.

    ``offer`` and ``expected_session_context`` are required rather than optional:
    a comparand a caller can forget is a check a deployment silently loses.
    """
    if type(request) is not IntroductionRequest:
        raise CredentialingError("request must be an IntroductionRequest record")
    if type(presentation) is not CredentialPresentation:
        raise CredentialingError(
            "presentation must be a CredentialPresentation record"
        )
    if type(policy) is not IntroductionPolicy:
        raise CredentialingError("policy must be an IntroductionPolicy record")
    if type(offer) is not IntroductionOffer:
        raise CredentialingError("offer must be an IntroductionOffer record")
    if type(request.kind) is not str or request.kind != REQUEST_KIND:
        raise CredentialingError(
            f"introduction request kind must be {REQUEST_KIND!r}"
        )
    if type(presentation.kind) is not str or presentation.kind != CREDENTIAL_PRESENTATION_KIND:
        raise CredentialingError(
            f"credential presentation kind must be {CREDENTIAL_PRESENTATION_KIND!r}"
        )
    if presentation.bundle is None:
        raise CredentialingError("credential presentation bundle must be non-null")
    if type(offer.kind) is not str or offer.kind != OFFER_KIND:
        raise CredentialingError(f"introduction offer kind must be {OFFER_KIND!r}")

    if not _exact_string(request.initiator_tenant_aid) or not _exact_string(
        request.responder_tenant_aid
    ):
        raise CredentialingError(
            "request tenant AIDs must be non-empty exact strings"
        )
    _exact_string_list(
        "request offered_credential_classes", request.offered_credential_classes
    )
    request_required_classes = _exact_string_list(
        "request required_credential_classes", request.required_credential_classes
    )
    if type(request.attestation_window) is not AttestationWindow or not (
        _exact_string(request.attestation_window.starts_at)
        and _exact_string(request.attestation_window.ends_at)
    ):
        raise CredentialingError(
            "request attestation window must contain non-empty exact strings"
        )
    # §1.6.1 / §14.3 (AFP-0029): both endpoints are UTC datetime strings in
    # the session range (the window lies within a session, whose opened_at is
    # nonnegative), and starts_at precedes ends_at. Containment in the actual
    # session lifetime needs the session, which this evaluator does not hold.
    try:
        window_starts = session_datetime_to_unix(
            request.attestation_window.starts_at, "attestation_window.starts_at"
        )
        window_ends = session_datetime_to_unix(
            request.attestation_window.ends_at, "attestation_window.ends_at"
        )
    except ValueError as exc:
        raise CredentialingError(
            f"request attestation window is not canonical: {exc}"
        ) from exc
    if window_starts >= window_ends:
        raise CredentialingError(
            "request attestation window starts_at must precede ends_at"
        )
    if type(presentation.predicate_classes) is not list:
        raise CredentialingError(
            "credential presentation predicate_classes must be a string list"
        )
    declared = _exact_string_list(
        "credential presentation predicate_classes", presentation.predicate_classes
    )
    if not _exact_string(presentation.presenter_aid) or not _exact_string(
        presentation.session_context
    ):
        raise CredentialingError(
            "credential presentation identity fields must be non-empty exact strings"
        )
    if not _exact_string(offer.tenant_aid) or not _exact_string(offer.route_handle):
        raise CredentialingError(
            "offer tenant AID and route handle must be non-empty exact strings"
        )
    offer_accepted_classes = frozenset(
        _exact_string_list(
            "offer accepted_credential_classes", offer.accepted_credential_classes
        )
    )

    presentation_snapshot = (
        presentation.presenter_aid,
        presentation.session_context,
        presentation.bundle,
        declared,
        presentation.kind,
    )
    presenter_aid, presentation_session_context, _, declared, presentation_kind = (
        presentation_snapshot
    )
    # These atoms are mutable dataclasses because they model decoded wire
    # records.  Capture every comparand before any adapter runs: a decision must
    # not compare one request/policy/offer and then seal another one after a
    # callback (or concurrent owner) edits the live record.
    request_responder_aid = request.responder_tenant_aid
    request_window = (
        request.attestation_window.starts_at,
        request.attestation_window.ends_at,
    )
    request_digest = content_digest(request)
    offer_tenant_aid = offer.tenant_aid
    if type(expected_session_context) is not str or not expected_session_context:
        raise CredentialingError(
            "expected_session_context must be a non-empty exact string"
        )
    try:
        if type(policy.accepted_credentials) is not list:
            raise CredentialingError("accepted_credentials must be a list")
        accepted_predicate_ids = []
        for entry in policy.accepted_credentials:
            if type(entry) is not AcceptedCredential:
                raise CredentialingError(
                    "accepted credential entries must be {class, valid_until} records"
                )
            predicate_id = entry.credential_class
            if not _exact_string(predicate_id):
                raise CredentialingError(
                    "accepted credential entries must contain exact predicate strings"
                )
            accepted_predicate_ids.append(predicate_id)
        if type(policy.accepted_instance_attestation_roots) is not list:
            raise CredentialingError(
                "accepted_instance_attestation_roots must be a list"
            )
        accepted_roots = []
        for root in policy.accepted_instance_attestation_roots:
            root_class = root.root_class
            root_authority_identifier = root.root_authority_identifier
            if (
                type(root) is not InstanceAttestationRoot
                or not _exact_string(root_class)
                or not _exact_string(root_authority_identifier)
            ):
                raise CredentialingError(
                    "accepted attestation roots must contain exact class and "
                    "authority strings"
                )
            accepted_roots.append((root_class, root_authority_identifier))
        accepted_policy = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset(accepted_predicate_ids),
            accepted_instance_attestation_roots=frozenset(accepted_roots),
        )
    except (
        CredentialingError,
        PresentationBindingError,
        IndexError,
        KeyError,
        TypeError,
        AttributeError,
    ) as exc:
        return _issue_decision(
            accepted=False,
            request_digest=request_digest,
            presenter_aid=presenter_aid,
            session_context=presentation_session_context,
            bundle=presentation_snapshot[2],
            proven_predicate_ids=(),
            reasons=(
                f"the introduction policy block is not a valid accepted-credential "
                f"policy: {exc}",
            ),
            seams=(),
        )
    if presenter_aid != request_responder_aid:
        raise CredentialingError(
            "credential presentation does not come from the request's responder"
        )
    if offer_tenant_aid != presenter_aid:
        raise CredentialingError(
            "the willingness offer belongs to a different tenant than the presenter"
        )

    reasons: List[str] = []
    seams: List[str] = []
    if presentation_verifier is None:
        return _issue_decision(
            accepted=False,
            request_digest=request_digest,
            presenter_aid=presenter_aid,
            session_context=presentation_session_context,
            bundle=presentation_snapshot[2],
            proven_predicate_ids=(),
            reasons=(
                "no credential presentation verifier supplied; the opaque ZKA/ZKC "
                "bundle cannot be accepted without cryptographic verification",
            ),
            seams=(),
        )
    if not callable(presentation_verifier):
        raise CredentialingError("credential presentation verifier must be callable")

    verified = presentation_verifier(presentation)
    if verified is None:
        return _issue_decision(
            accepted=False,
            request_digest=request_digest,
            presenter_aid=presentation_snapshot[0],
            session_context=presentation_snapshot[1],
            bundle=presentation_snapshot[2],
            proven_predicate_ids=(),
            reasons=("the credential presentation verifier rejected the opaque bundle",),
            seams=(),
        )
    if type(verified) is not VerifiedCredentialPresentation:
        raise CredentialingError(
            "credential presentation verifier returned a malformed result"
        )
    if (
        type(presentation.presenter_aid) is not str
        or presentation.presenter_aid != presentation_snapshot[0]
        or type(presentation.session_context) is not str
        or presentation.session_context != presentation_snapshot[1]
        or presentation.bundle is not presentation_snapshot[2]
        or type(presentation.predicate_classes) is not list
        or any(
            not _exact_string(predicate_class)
            for predicate_class in presentation.predicate_classes
        )
        or tuple(presentation.predicate_classes) != presentation_snapshot[3]
        or type(presentation.kind) is not str
        or presentation.kind != presentation_kind
    ):
        raise CredentialingError("credential presentation verifier mutated its input")
    if (
        type(verified.presenter_aid) is not str
        or not verified.presenter_aid
        or type(verified.session_context) is not str
        or not verified.session_context
    ):
        raise CredentialingError(
            "credential presentation verifier returned malformed identity facts"
        )
    if type(verified.proven_predicates) is not tuple:
        raise CredentialingError(
            "credential presentation verifier returned malformed predicate facts"
        )
    # Rebuild the facts from exact primitive fields.  The verifier's frozen
    # record is still an object supplied across a callback boundary; it must not
    # retain custom equality/hash behaviour that can turn a different root,
    # window, subject, or required class into a set-membership match.
    proven = tuple(
        _exact_proven_predicate(predicate)
        for predicate in verified.proven_predicates
    )
    proven_ids = frozenset(item.predicate_id for item in proven)

    if verified.presenter_aid != presenter_aid:
        reasons.append(
            "credential presentation verifier reported a different presenter"
        )
    if verified.session_context != presentation_session_context:
        reasons.append(
            "credential presentation verifier reported a different session context"
        )
    if verified.bundle is not presentation_snapshot[2]:
        reasons.append(
            "credential presentation verifier reported facts for a different bundle"
        )

    # §12.7: the presentation is bound to the introduction session that asked for
    # it, so a bundle answered for one session cannot be replayed into another.
    if presentation_session_context != expected_session_context:
        reasons.append(
            "the credential presentation is bound to a different session context"
        )

    # §5.9: a presentation that proves nothing is the boolean label the
    # specification rejects.
    if not proven:
        reasons.append("the presentation proves no predicate")

    # Safeguard 2 (§14.3): the bundle wraps atomic proofs, one predicate each,
    # and the presentation's declared classes are what those proofs answer.
    if not declared:
        reasons.append("the credential presentation declares no predicate classes")
    if frozenset(declared) != proven_ids:
        reasons.append(
            f"declared predicate classes {sorted(set(declared))!r} do not match the "
            f"proven predicates {sorted(proven_ids)!r}"
        )
    if len(declared) != len(set(declared)):
        reasons.append(
            "the credential presentation repeats a predicate class; §14.3 proofs are "
            "atomic, one predicate each (Safeguard 2)"
        )

    # §14.3: everything the request required must be proven, and nothing outside
    # what the offer accepts may be admitted. ``request.offered_credential_classes``
    # is deliberately not compared here: it states what the *initiator* brings, and
    # §14.3 resolves it during NEGOTIATING rather than fixing a rule this step
    # could apply to the responder's presentation.
    missing = sorted(frozenset(request_required_classes) - proven_ids)
    if missing:
        reasons.append(f"required credential class(es) {missing!r} were not proven")
    unoffered = sorted(proven_ids - offer_accepted_classes)
    if unoffered:
        reasons.append(
            f"credential class(es) {unoffered!r} are outside the classes this "
            f"offer accepts"
        )

    # §14.4 over the signed policy snapshot, via the same comparison the §5.9
    # seam applies, so the two tiers cannot disagree about what a root pair
    # means.  The snapshot was validated before the presentation callback.
    unaccepted = sorted(proven_ids - accepted_policy.accepted_predicate_ids)
    if unaccepted:
        reasons.append(
            f"predicate(s) {unaccepted!r} are not among the agreement's accepted "
            f"credentials (§14.4)"
        )
    for predicate in proven:
        pair = root_pair_of(predicate)
        if predicate.predicate_id != INSTANCE_ATTESTATION_PREDICATE_V2:
            if pair is not None:
                reasons.append(
                    f"predicate {predicate.predicate_id!r} MUST NOT carry a root "
                    f"class (§6.3.1)"
                )
            continue
        if pair is None:
            reasons.append(
                f"{INSTANCE_ATTESTATION_PREDICATE_V2} must name a root class and root "
                f"authority identifier (§6.3.1)"
            )
            continue
        if pair not in accepted_policy.accepted_instance_attestation_roots:
            reasons.append(
                f"instance-attestation root {pair!r} does not exactly match a signed "
                f"accepted pair (§14.4)"
            )
            continue
        if root_authority_resolver is None:
            # §6.3.1: "A verifier that cannot resolve the chain to the named
            # authority root MUST reject the proof with
            # instance_attestation_untrusted_authority." Not resolving is not a
            # softer form of resolving.
            reasons.append(
                f"root authority {pair[1]!r} was not resolved: §6.3.1 key state, "
                f"delegation, and revocation need a root_authority_resolver "
                f"(instance_attestation_untrusted_authority)"
            )
        else:
            try:
                resolved = root_authority_resolver(*pair)
            except Exception:
                reasons.append(
                    f"root authority {pair[1]!r} could not be resolved "
                    f"(§6.3.1 instance_attestation_untrusted_authority)"
                )
            else:
                if resolved is not True:
                    reasons.append(
                        f"root authority {pair[1]!r} is not accepted, or its key state is "
                        f"stale or revoked (§6.3.1 instance_attestation_untrusted_authority)"
                    )

    # §6.3.1 / §14.3: a v2 attestation MUST copy the request's explicit window.
    expected_window = request_window
    for predicate in proven:
        if predicate.predicate_id != INSTANCE_ATTESTATION_PREDICATE_V2:
            continue
        if predicate.attestation_window != expected_window:
            reasons.append(
                f"instance attestation window {predicate.attestation_window!r} does "
                f"not equal the introduction request's window {expected_window!r}"
            )
        if predicate.subject_aid != presenter_aid:
            reasons.append(
                "the attested machine subject is not the presenting tenant"
            )

    return _issue_decision(
        accepted=not reasons,
        request_digest=request_digest,
        presenter_aid=presenter_aid,
        session_context=presentation_session_context,
        bundle=presentation_snapshot[2],
        proven_predicate_ids=tuple(proven_ids),
        reasons=tuple(reasons),
        seams=tuple(seams),
    )


def _governance_snapshot(request, policy, offer) -> Tuple[str, ...]:
    """Digest the three governance inputs, refusing a policy that is not §14.4."""
    try:
        return tuple(content_digest(atom) for atom in (request, policy, offer))
    except ValueError as exc:
        # A policy edited after construction into a shape the published
        # types exclude is refused, never digested.
        raise CredentialingError(
            "native credentialing policy is not a §14.4 policy"
        ) from exc


def evaluate_native_credentialing(
    *,
    request: IntroductionRequest,
    credential,
    policy: IntroductionPolicy,
    offer: IntroductionOffer,
    expected_session_context: str,
    expected_session_profile: str,
    root_authority_resolver: Optional[RootAuthorityResolver] = None,
) -> CredentialingDecision:
    """Evaluate a receive-issued native carrier without a ZKA bundle.

    Native receive has already checked the entity subject, exact APR, flow and
    cryptographic statement. The introduction parties are tenant roots, so this
    adapter uses the sender's verified KERI delegation to identify the tenant;
    it never substitutes a tenant label for the credential's verified entity
    subject. The temporary comparison record is private to this function and
    is never serialized or sent as a historical credential-presentation atom.
    """
    from afp_session.credential import require_verified_native_credential
    from afp_session.presentation import AfpTrustFlow

    require_verified_native_credential(credential)
    if type(request) is not IntroductionRequest:
        raise CredentialingError("native credentialing requires an IntroductionRequest")
    if not _exact_string(expected_session_profile):
        raise CredentialingError("expected native session profile must be exact text")
    envelope = credential.envelope
    bound = credential.verified_presentation
    if (
        bound.flow is not AfpTrustFlow.INTRODUCTION
        or envelope.profile != expected_session_profile
        or envelope.session_context != expected_session_context
        or envelope.sender is None
        or envelope.sender.tenant_aid != request.responder_tenant_aid
    ):
        raise CredentialingError("native credential is not bound to this introduction")
    governance_snapshot = _governance_snapshot(request, policy, offer)
    try:
        expected_policy = required_predicate_policy(
            policy, required_predicate_ids=request.required_credential_classes
        )
    except (PresentationBindingError, CredentialingError) as exc:
        raise CredentialingError("native credentialing predicate policy is invalid") from exc
    if bound.required_predicates_digest != expected_policy.digest:
        raise CredentialingError("native credential was verified under another predicate policy")
    tenant = envelope.sender.tenant_aid
    comparison = CredentialPresentation(
        presenter_aid=tenant,
        session_context=envelope.session_context,
        bundle=credential,  # process-local capability, never a ZKA wire object
        predicate_classes=[item.predicate_id for item in credential.proven_predicates],
    )

    def verified_native_facts(exact_comparison):
        require_verified_native_credential(credential)
        if exact_comparison is not comparison:
            raise CredentialingError("native comparison record was replaced")
        return VerifiedCredentialPresentation(
            presenter_aid=tenant,
            session_context=envelope.session_context,
            bundle=credential,
            proven_predicates=credential.proven_predicates,
        )

    decision = evaluate_credentialing(
        request=request,
        presentation=comparison,
        policy=policy,
        offer=offer,
        expected_session_context=expected_session_context,
        presentation_verifier=verified_native_facts,
        root_authority_resolver=root_authority_resolver,
    )
    if _governance_snapshot(request, policy, offer) != governance_snapshot:
        raise CredentialingError("native credentialing callback mutated governance inputs")
    require_verified_native_credential(credential)
    return decision
