"""§14.3 handshake FSM — decline-not-freeze, trustless skip-bonding, unconditional abort."""

import _path  # noqa: F401

import unittest

from afp_introduction import handshake
from afp_introduction.atoms import (
    AcceptedCredential,
    AttestationWindow,
    CredentialPresentation,
    Envelope,
    InstanceAttestationRoot,
    IntroductionOffer,
    IntroductionPolicy,
    IntroductionRequest,
)
from afp_introduction.credentialing import (
    CredentialingDecision,
    CredentialingError,
    VerifiedCredentialPresentation,
    evaluate_credentialing,
)
from afp_introduction.handshake import State, TransitionError
from afp_session.presentation import INSTANCE_ATTESTATION_PREDICATE_V2, ProvenPredicate

INITIATOR_AID = "EtenantA"
RESPONDER_AID = "EtenantB"
ROOT_CLASS = "root:build-provenance"
ROOT_AUTHORITY = "Eroot-authority"
OTHER_ROOT_AUTHORITY = "Eother-root-authority"
WINDOW_STARTS = "2026-01-01T00:00:00Z"
WINDOW_ENDS = "2026-01-01T01:00:00Z"
OTHER_WINDOW = ("2026-02-01T00:00:00Z", "2026-02-01T01:00:00Z")
OFFCATALOG_CLASS = "acme.unaccepted_credential.v1"
SESSION_CONTEXT = "X_" + "ab" * 32
DEFAULT_BUNDLE = object()


def accept_root_authority(_root_class, _authority):
    """Test seam for a resolved, live §6.3.1 root authority."""
    return True


def envelope(**overrides):
    values = {
        "assets": ["USD"],
        "max_per_interaction": "100.00",
        "max_cumulative": "1000.00",
        "collateral_required": False,
    }
    values.update(overrides)
    return Envelope(**values)


def attestation_window(**overrides):
    values = {"starts_at": WINDOW_STARTS, "ends_at": WINDOW_ENDS}
    values.update(overrides)
    return AttestationWindow(**values)


def introduction_request(**overrides):
    values = {
        "initiator_tenant_aid": INITIATOR_AID,
        "responder_tenant_aid": RESPONDER_AID,
        "offered_credential_classes": [INSTANCE_ATTESTATION_PREDICATE_V2],
        "required_credential_classes": [INSTANCE_ATTESTATION_PREDICATE_V2],
        "proposed_envelope": envelope(),
        "attestation_window": attestation_window(),
    }
    values.update(overrides)
    return IntroductionRequest(**values)


def introduction_offer(**overrides):
    values = {
        "tenant_aid": RESPONDER_AID,
        "accepted_credential_classes": [INSTANCE_ATTESTATION_PREDICATE_V2],
        "entertained_envelope": envelope(),
        "route_handle": "rendezvous-handle",
        "directory_epoch": 1,
    }
    values.update(overrides)
    return IntroductionOffer(**values)


def credential_presentation(**overrides):
    values = {
        "presenter_aid": RESPONDER_AID,
        "session_context": SESSION_CONTEXT,
        "bundle": DEFAULT_BUNDLE,  # opaque zka:bundle:v1 (§12.7 ZKA seam)
        "predicate_classes": [INSTANCE_ATTESTATION_PREDICATE_V2],
    }
    values.update(overrides)
    return CredentialPresentation(**values)


def introduction_policy(**overrides):
    values = {
        "permitted_entities": [INITIATOR_AID, RESPONDER_AID],
        "permitted_assets": ["USD"],
        "max_per_interaction": "100.00",
        "max_cumulative_outstanding": "1000.00",
        "bond_ref": None,
        "accepted_credentials": [
            AcceptedCredential(INSTANCE_ATTESTATION_PREDICATE_V2, "2027-01-15T08:00:00Z")
        ],
        "accepted_instance_attestation_roots": [
            InstanceAttestationRoot(
                root_class=ROOT_CLASS, root_authority_identifier=ROOT_AUTHORITY
            )
        ],
        "rotation_policy": "manual",
        "growth_curve": {"step": "0", "cap": "0", "decay": "0"},
        "agreement_expires_at": "2027-01-15T08:00:00Z",
    }
    values.update(overrides)
    return IntroductionPolicy(**values)


def proven_predicate(**overrides):
    values = {
        "predicate_id": INSTANCE_ATTESTATION_PREDICATE_V2,
        "predicate_version": "2",
        "root_class": ROOT_CLASS,
        "root_authority_identifier": ROOT_AUTHORITY,
        "attestation_window": (WINDOW_STARTS, WINDOW_ENDS),
        "subject_aid": RESPONDER_AID,
    }
    values.update(overrides)
    return ProvenPredicate(**values)


def credentialing_decision(**overrides):
    verified_predicates = overrides.pop("verified_predicates", (proven_predicate(),))
    values = {
        "request": introduction_request(),
        "presentation": credential_presentation(),
        "policy": introduction_policy(),
        "offer": introduction_offer(),
        "expected_session_context": SESSION_CONTEXT,
        "root_authority_resolver": accept_root_authority,
    }
    values.update(overrides)
    if "presentation_verifier" not in values:
        presentation = values["presentation"]
        verified = VerifiedCredentialPresentation(
            presenter_aid=presentation.presenter_aid,
            session_context=presentation.session_context,
            bundle=presentation.bundle,
            proven_predicates=verified_predicates,
        )

        def presentation_verifier(observed):
            if observed is not presentation:
                raise AssertionError("credentialing must pass the exact presentation")
            return verified

        values["presentation_verifier"] = presentation_verifier
    return evaluate_credentialing(**values)


def present_matching(fsm, *, request=None):
    """Advance a CREDENTIALING fsm with a fully matching decision (§14.3/§14.4)."""
    request = request or introduction_request()
    presentation = credential_presentation()
    fsm.present_credentials(
        decision=credentialing_decision(request=request, presentation=presentation),
        request=request,
        presentation=presentation,
    )


def present_declining(fsm, *, request=None):
    """Advance a CREDENTIALING fsm with a decision the comparison rejects."""
    request = request or introduction_request()
    presentation = credential_presentation()
    fsm.present_credentials(
        decision=credentialing_decision(
            request=request,
            presentation=presentation,
            presentation_verifier=None,
        ),
        request=request,
        presentation=presentation,
    )


def open_credentialing(fsm, *, request=None, session_context=SESSION_CONTEXT):
    """Open one FSM against the authenticated introduction request/session."""
    request = request or introduction_request()
    fsm.open_credentialing(request=request, session_context=session_context)
    return request


class TestHandshakeFSM(unittest.TestCase):
    def test_happy_path_to_active(self):
        fsm = handshake.IntroductionFSM.propose(initiator="EtenantA", responder="EtenantB")
        self.assertEqual(fsm.state, State.PROPOSED)
        open_credentialing(fsm)
        self.assertEqual(fsm.state, State.CREDENTIALING)  # the state is reachable + observable
        present_matching(fsm)
        self.assertEqual(fsm.state, State.NEGOTIATING)
        fsm.agree_envelope(requires_bond=True)
        self.assertEqual(fsm.state, State.BONDING)
        fsm.post_bond()
        self.assertEqual(fsm.state, State.ACTIVE)

    def test_failed_credential_declines_not_freezes(self):
        fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
        open_credentialing(fsm)
        present_declining(fsm)
        self.assertEqual(fsm.state, State.DECLINED)  # decline is the ONLY consequence (§5.4)

    def test_present_credentials_requires_credentialing_state(self):
        fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
        with self.assertRaises(handshake.TransitionError):
            present_matching(fsm)  # cannot present straight from PROPOSED

    def test_trustless_envelope_skips_bonding(self):
        fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
        open_credentialing(fsm)
        present_matching(fsm)
        fsm.agree_envelope(requires_bond=False)  # ZKA-direct only -> straight to ACTIVE
        self.assertEqual(fsm.state, State.ACTIVE)

    def test_abort_is_unconditional_from_any_pre_terminal(self):
        def to_negotiating(f):
            open_credentialing(f); present_matching(f)

        def to_bonding(f):
            to_negotiating(f); f.agree_envelope(requires_bond=True)

        for advance in (
            lambda f: None,                       # PROPOSED
            lambda f: open_credentialing(f),      # CREDENTIALING
            to_negotiating,                       # NEGOTIATING
            to_bonding,                           # BONDING
        ):
            fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
            advance(fsm)
            fsm.abort()  # Safeguard 5
            self.assertEqual(fsm.state, State.ABORTED)

    def test_downgrade_returns_to_active_then_can_graduate(self):
        fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
        open_credentialing(fsm)
        present_matching(fsm)
        fsm.agree_envelope(requires_bond=False)
        fsm.downgrade()
        self.assertEqual(fsm.state, State.DOWNGRADED)
        fsm.reactivate()
        self.assertEqual(fsm.state, State.ACTIVE)
        fsm.graduate()
        self.assertEqual(fsm.state, State.GRADUATED)

    def _active(self):
        fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
        open_credentialing(fsm)
        present_matching(fsm)
        fsm.agree_envelope(requires_bond=False)
        return fsm

    def test_terminate_from_active(self):
        fsm = self._active()
        fsm.terminate()  # unconditional exit (Safeguard 5)
        self.assertEqual(fsm.state, State.TERMINATED)

    def test_terminate_from_downgraded(self):
        fsm = self._active()
        fsm.downgrade()
        fsm.terminate()
        self.assertEqual(fsm.state, State.TERMINATED)

    def test_terminate_from_invalid_state_raises(self):
        for advance in (
            lambda f: None,                       # PROPOSED
            lambda f: open_credentialing(f),      # CREDENTIALING
        ):
            fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
            advance(fsm)
            with self.assertRaises(handshake.TransitionError):
                fsm.terminate()

    def test_illegal_transition_raises(self):
        fsm = handshake.IntroductionFSM.propose("EtenantA", "EtenantB")
        with self.assertRaises(handshake.TransitionError):
            fsm.post_bond()  # can't bond from PROPOSED


class TestCredentialingIsAComparison(unittest.TestCase):
    """§14.3/§14.4: CREDENTIALING compares real artifacts; it is not a report."""

    def _credentialed(self, decision, request, presentation=None):
        presentation = presentation or credential_presentation()
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        open_credentialing(
            fsm, request=request, session_context=presentation.session_context
        )
        fsm.present_credentials(
            decision=decision, request=request, presentation=presentation
        )
        return fsm

    def test_honest_control_fully_matching_presentation_advances(self):
        request = introduction_request()
        presentation = credential_presentation()
        decision = credentialing_decision(request=request, presentation=presentation)
        fsm = self._credentialed(decision, request, presentation)
        self.assertEqual(fsm.state, State.NEGOTIATING)

    def test_accepted_decision_cannot_advance_an_attacker_fsm(self):
        request = introduction_request()
        presentation = credential_presentation(bundle=object())
        decision = credentialing_decision(request=request, presentation=presentation)
        attacker_request = introduction_request(initiator_tenant_aid="Eattacker")
        attacker_fsm = handshake.IntroductionFSM.propose("Eattacker", RESPONDER_AID)
        open_credentialing(attacker_fsm, request=attacker_request)

        with self.assertRaisesRegex(TransitionError, "parties do not match"):
            attacker_fsm.present_credentials(
                decision=decision,
                request=request,
                presentation=presentation,
            )
        self.assertIs(attacker_fsm.state, State.CREDENTIALING)

    def test_accepted_decision_cannot_cross_to_another_session(self):
        request = introduction_request()
        presentation = credential_presentation(bundle=object())
        decision = credentialing_decision(request=request, presentation=presentation)
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        other_session = "X_" + "cd" * 32
        open_credentialing(fsm, request=request, session_context=other_session)

        with self.assertRaisesRegex(CredentialingError, "session does not match"):
            fsm.present_credentials(
                decision=decision,
                request=request,
                presentation=presentation,
            )
        self.assertIs(fsm.state, State.CREDENTIALING)

    def test_accepted_decision_cannot_cross_to_another_bundle(self):
        request = introduction_request()
        presentation = credential_presentation(bundle=object())
        decision = credentialing_decision(request=request, presentation=presentation)
        other_bundle_presentation = credential_presentation(bundle=object())
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        open_credentialing(fsm, request=request)

        with self.assertRaisesRegex(CredentialingError, "exact presentation bundle"):
            fsm.present_credentials(
                decision=decision,
                request=request,
                presentation=other_bundle_presentation,
            )
        self.assertIs(fsm.state, State.CREDENTIALING)

    def test_missing_required_credential_class_declines(self):
        request = introduction_request(
            required_credential_classes=[
                INSTANCE_ATTESTATION_PREDICATE_V2,
                OFFCATALOG_CLASS,
            ]
        )
        # Only the v2 attestation is proven; OFFCATALOG_CLASS is required but absent.
        decision = credentialing_decision(
            request=request,
            policy=introduction_policy(
                accepted_credentials=[
                    AcceptedCredential(
                        INSTANCE_ATTESTATION_PREDICATE_V2, "2027-01-15T08:00:00Z"
                    ),
                    AcceptedCredential(OFFCATALOG_CLASS, "2027-01-15T08:00:00Z"),
                ]
            ),
        )
        fsm = self._credentialed(decision, request)
        self.assertEqual(fsm.state, State.DECLINED)

    def test_predicate_outside_accepted_credentials_declines(self):
        # Proven and required agree, but the policy never signed this class in.
        request = introduction_request(required_credential_classes=[OFFCATALOG_CLASS])
        decision = credentialing_decision(
            request=request,
            presentation=credential_presentation(predicate_classes=[OFFCATALOG_CLASS]),
            verified_predicates=(
                ProvenPredicate(predicate_id=OFFCATALOG_CLASS, predicate_version="1"),
            ),
            policy=introduction_policy(
                accepted_credentials=[
                    AcceptedCredential(
                        INSTANCE_ATTESTATION_PREDICATE_V2, "2027-01-15T08:00:00Z"
                    )
                ]
            ),
        )
        fsm = self._credentialed(decision, request)
        self.assertEqual(fsm.state, State.DECLINED)

    def test_v2_root_pair_mismatch_declines(self):
        # Signed policy pins ROOT_AUTHORITY; the proof names a different one.
        decision = credentialing_decision(
            verified_predicates=(
                proven_predicate(root_authority_identifier=OTHER_ROOT_AUTHORITY),
            )
        )
        request = introduction_request()
        fsm = self._credentialed(decision, request)
        self.assertEqual(fsm.state, State.DECLINED)

    def test_v2_attestation_window_mismatch_declines(self):
        # The proof's window is valid on its own but does not equal the request's.
        decision = credentialing_decision(
            verified_predicates=(proven_predicate(attestation_window=OTHER_WINDOW),)
        )
        request = introduction_request()
        fsm = self._credentialed(decision, request)
        self.assertEqual(fsm.state, State.DECLINED)

    def test_request_attestation_window_must_be_canonical_and_ordered(self):
        # §1.6.1 and §14.3 (AFP-0029): UTC datetime strings in the session range,
        # starts_at first, checked before the request can be digested.
        for window in (
            {"starts_at": "2026-01-01T00:00:00.0Z"},
            {"ends_at": "2026-01-01T01:00:00+00:00"},
            {"starts_at": "2026-02-30T00:00:00Z"},
            {"starts_at": "1969-12-31T23:59:59Z"},
            {"starts_at": WINDOW_ENDS, "ends_at": WINDOW_STARTS},
            {"starts_at": WINDOW_STARTS, "ends_at": WINDOW_STARTS},
            {"ends_at": 1_767_229_200.0},
        ):
            with self.subTest(window=window), self.assertRaises(ValueError):
                attestation_window(**window)

    def test_request_attestation_window_accepts_the_epoch_boundary(self):
        window = attestation_window(
            starts_at="1970-01-01T00:00:00Z", ends_at="1970-01-01T00:00:01Z"
        )
        self.assertEqual(window.starts_at, "1970-01-01T00:00:00Z")

    def test_empty_proven_predicates_declines(self):
        decision = credentialing_decision(
            presentation=credential_presentation(predicate_classes=[]),
            verified_predicates=(),
        )
        request = introduction_request()
        fsm = self._credentialed(decision, request)
        self.assertEqual(fsm.state, State.DECLINED)

    def test_presentation_verifier_rejection_declines(self):
        decision = credentialing_decision(presentation_verifier=lambda _presentation: None)
        request = introduction_request()
        fsm = self._credentialed(decision, request)
        self.assertEqual(fsm.state, State.DECLINED)

    def test_missing_presentation_verifier_declines(self):
        decision = credentialing_decision(presentation_verifier=None)
        self.assertFalse(decision.accepted)
        self.assertIn("no credential presentation verifier supplied", decision.reasons[0])

    def test_missing_opaque_bundle_is_malformed(self):
        with self.assertRaisesRegex(
            CredentialingError, "bundle must be non-null"
        ):
            credentialing_decision(
                presentation=credential_presentation(bundle=None),
                presentation_verifier=None,
            )

    def test_false_or_malformed_presentation_verifier_result_is_an_error(self):
        for result in (False, object()):
            with self.subTest(result=result):
                with self.assertRaisesRegex(CredentialingError, "malformed result"):
                    credentialing_decision(
                        presentation_verifier=lambda _presentation, value=result: value
                    )

    def test_verified_predicates_must_be_an_exact_tuple(self):
        with self.assertRaisesRegex(CredentialingError, "exact tuple"):
            VerifiedCredentialPresentation(
                presenter_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                bundle=object(),
                proven_predicates=[proven_predicate()],
            )

    def test_verifier_observes_the_exact_bundle_and_matching_facts_advance(self):
        presentation = credential_presentation()
        observed = []

        def verifier(exact_presentation):
            observed.append(exact_presentation)
            self.assertIs(exact_presentation.bundle, presentation.bundle)
            return VerifiedCredentialPresentation(
                presenter_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                bundle=exact_presentation.bundle,
                proven_predicates=(proven_predicate(),),
            )

        request = introduction_request()
        decision = credentialing_decision(
            request=request,
            presentation=presentation,
            presentation_verifier=verifier,
        )
        self.assertEqual(observed, [presentation])
        self.assertEqual(
            self._credentialed(decision, request, presentation).state,
            State.NEGOTIATING,
        )

    def test_a_time_varying_presentation_lookalike_is_rejected_before_reads(self):
        class ChangingPresentation:
            @property
            def presenter_aid(self):
                raise AssertionError("a lookalike presentation must not be read")

        with self.assertRaisesRegex(
            CredentialingError, "CredentialPresentation record"
        ):
            credentialing_decision(
                presentation=ChangingPresentation(), presentation_verifier=None
            )

    def test_exact_atom_kind_discriminators_are_required(self):
        for label, overrides in (
            ("request", {"request": introduction_request(kind="wrong")}),
            (
                "presentation",
                {"presentation": credential_presentation(kind="wrong")},
            ),
            ("offer", {"offer": introduction_offer(kind="wrong")}),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(CredentialingError, "kind must be"):
                    credentialing_decision(**overrides)

    def test_adversarial_string_subclasses_are_rejected_before_comparison(self):
        class EqualEverything(str):
            def __eq__(self, _other):
                return True

            def __hash__(self):
                return hash(str(self))

        for presentation in (
            credential_presentation(presenter_aid=EqualEverything("E-attacker")),
            credential_presentation(
                session_context=EqualEverything("X_" + "ef" * 32)
            ),
            credential_presentation(
                predicate_classes=[EqualEverything(INSTANCE_ATTESTATION_PREDICATE_V2)]
            ),
        ):
            with self.subTest(presentation=presentation):
                with self.assertRaisesRegex(CredentialingError, "exact string"):
                    credentialing_decision(
                        presentation=presentation, presentation_verifier=None
                    )

    def test_adversarial_required_class_cannot_alias_a_real_predicate(self):
        class Alias(str):
            def __eq__(self, _other):
                return True

            def __ne__(self, _other):
                return False

            def __hash__(self):
                return hash(INSTANCE_ATTESTATION_PREDICATE_V2)

        request = introduction_request(
            required_credential_classes=[Alias("attacker:predicate:v9")]
        )
        with self.assertRaisesRegex(CredentialingError, "required_credential_classes"):
            credentialing_decision(request=request, presentation_verifier=None)

    def test_adversarial_predicate_fields_cannot_alias_signed_facts(self):
        class Alias(str):
            def __new__(cls, value, expected_hash_value):
                instance = super().__new__(cls, value)
                instance.expected_hash_value = expected_hash_value
                return instance

            def __eq__(self, _other):
                return True

            def __ne__(self, _other):
                return False

            def __hash__(self):
                return hash(self.expected_hash_value)

        hostile_predicate = proven_predicate()
        object.__setattr__(
            hostile_predicate, "root_class", Alias("root:attacker", ROOT_CLASS)
        )
        object.__setattr__(
            hostile_predicate,
            "root_authority_identifier",
            Alias("Eattacker", ROOT_AUTHORITY),
        )
        object.__setattr__(
            hostile_predicate,
            "attestation_window",
            (
                Alias("2027-01-01T00:00:00Z", WINDOW_STARTS),
                Alias("2027-01-01T01:00:00Z", WINDOW_ENDS),
            ),
        )
        object.__setattr__(
            hostile_predicate,
            "subject_aid",
            Alias("Eattacker-subject", RESPONDER_AID),
        )
        with self.assertRaisesRegex(CredentialingError, "root class"):
            credentialing_decision(verified_predicates=(hostile_predicate,))

    def test_verifier_facts_must_match_the_presentation(self):
        decision = credentialing_decision(
            presentation_verifier=lambda _presentation: VerifiedCredentialPresentation(
                presenter_aid=RESPONDER_AID,
                session_context="X_" + "cd" * 32,
                bundle=_presentation.bundle,
                proven_predicates=(proven_predicate(),),
            )
        )
        self.assertFalse(decision.accepted)
        self.assertIn("different session context", decision.reasons[0])

    def test_verifier_facts_for_another_bundle_decline(self):
        decision = credentialing_decision(
            presentation_verifier=lambda _presentation: VerifiedCredentialPresentation(
                presenter_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                bundle=object(),
                proven_predicates=(proven_predicate(),),
            )
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("different bundle" in reason for reason in decision.reasons),
            decision.reasons,
        )

    def test_verifier_cannot_mutate_the_presentation_kind(self):
        presentation = credential_presentation()

        def verifier(observed):
            observed.kind = "afp:other:v1"
            return VerifiedCredentialPresentation(
                presenter_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                bundle=observed.bundle,
                proven_predicates=(proven_predicate(),),
            )

        with self.assertRaisesRegex(CredentialingError, "mutated its input"):
            credentialing_decision(
                presentation=presentation,
                presentation_verifier=verifier,
            )

    def test_raw_boolean_and_predicate_arguments_are_rejected(self):
        with self.assertRaises(TypeError):
            evaluate_credentialing(
                request=introduction_request(),
                presentation=credential_presentation(),
                policy=introduction_policy(),
                offer=introduction_offer(),
                expected_session_context=SESSION_CONTEXT,
                proven_predicates=(proven_predicate(),),
                bundle_verified=True,
            )

    def test_decision_cannot_advance_a_different_request(self):
        request_a = introduction_request()
        request_b = introduction_request(required_credential_classes=[OFFCATALOG_CLASS])
        decision = credentialing_decision(request=request_a)
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        open_credentialing(fsm, request=request_b)
        with self.assertRaises(CredentialingError):
            fsm.present_credentials(
                decision=decision,
                request=request_b,
                presentation=credential_presentation(),
            )

    def test_declared_predicate_classes_must_match_what_was_proven(self):
        decision = credentialing_decision(
            presentation=credential_presentation(predicate_classes=[OFFCATALOG_CLASS])
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("do not match the proven predicates" in r for r in decision.reasons),
            decision.reasons,
        )

    def test_no_declared_predicate_classes_declines(self):
        decision = credentialing_decision(
            presentation=credential_presentation(predicate_classes=[])
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("no predicate classes" in r for r in decision.reasons), decision.reasons
        )

    def test_a_repeated_predicate_class_declines(self):
        # §14.3 proofs are atomic, one predicate each (Safeguard 2).
        decision = credentialing_decision(
            presentation=credential_presentation(
                predicate_classes=[
                    INSTANCE_ATTESTATION_PREDICATE_V2,
                    INSTANCE_ATTESTATION_PREDICATE_V2,
                ]
            )
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("repeats a predicate class" in r for r in decision.reasons),
            decision.reasons,
        )

    def test_an_attestation_of_another_machine_subject_declines(self):
        decision = credentialing_decision(
            verified_predicates=(proven_predicate(subject_aid="Esomeone-else"),)
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("attested machine subject" in r for r in decision.reasons),
            decision.reasons,
        )

    def test_a_presentation_from_another_tenant_is_malformed_not_declined(self):
        # A presentation that is not the responder's is not an unsatisfied
        # comparison; it is the wrong artifact for this request.
        with self.assertRaises(CredentialingError):
            credentialing_decision(
                presentation=credential_presentation(presenter_aid="Esomeone-else")
            )

    def test_a_presentation_bound_to_another_session_declines(self):
        decision = credentialing_decision(
            presentation=credential_presentation(session_context="X_" + "ee" * 32)
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("session context" in reason for reason in decision.reasons),
            decision.reasons,
        )

    def test_a_class_outside_the_offer_declines(self):
        decision = credentialing_decision(
            offer=introduction_offer(accepted_credential_classes=[OFFCATALOG_CLASS])
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("outside the classes this offer accepts" in r for r in decision.reasons),
            decision.reasons,
        )

    def test_an_unresolved_root_authority_declines(self):
        # §6.3.1: a verifier that cannot resolve the chain to the named authority
        # root MUST reject. Not resolving is not a softer form of resolving.
        decision = credentialing_decision(root_authority_resolver=None)
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("was not resolved" in reason for reason in decision.reasons),
            decision.reasons,
        )

    def test_a_revoked_root_authority_declines(self):
        decision = credentialing_decision(
            root_authority_resolver=lambda _class, _authority: False
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("stale or revoked" in reason for reason in decision.reasons),
            decision.reasons,
        )

    def test_malformed_root_authority_verdict_declines(self):
        decision = credentialing_decision(
            root_authority_resolver=lambda _class, _authority: "revoked"
        )
        self.assertFalse(decision.accepted)

    def test_root_authority_resolver_exception_declines(self):
        def unavailable(_class, _authority):
            raise RuntimeError("KEL transport unavailable")

        decision = credentialing_decision(root_authority_resolver=unavailable)
        self.assertFalse(decision.accepted)
        self.assertTrue(
            any("could not be resolved" in reason for reason in decision.reasons),
            decision.reasons,
        )

    def test_callback_cannot_transplant_a_later_request_into_the_sealed_decision(self):
        request = introduction_request()

        def resolver(_class, _authority):
            # The resolver returns a truthful verdict, but a concurrent owner
            # mutates the live request after the credential comparison. The
            # decision must stay sealed to the entry snapshot and cannot advance
            # the changed request.
            request.required_credential_classes.append(OFFCATALOG_CLASS)
            return True

        decision = credentialing_decision(
            request=request, root_authority_resolver=resolver
        )
        self.assertTrue(decision.accepted)
        self.assertEqual(
            decision.proven_predicate_ids, (INSTANCE_ATTESTATION_PREDICATE_V2,)
        )
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        open_credentialing(fsm, request=request)
        with self.assertRaisesRegex(CredentialingError, "different introduction request"):
            fsm.present_credentials(
                decision=decision,
                request=request,
                presentation=credential_presentation(),
            )

    def test_a_malformed_policy_block_declines_rather_than_raising(self):
        # Declining is the only permitted consequence (§5.4, Safeguard 3), so a
        # malformed counterparty policy must not strand the handshake.
        decision = credentialing_decision(
            policy=introduction_policy(accepted_instance_attestation_roots=[])
        )
        self.assertFalse(decision.accepted)
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        request = introduction_request()
        open_credentialing(fsm, request=request)
        fsm.present_credentials(
            decision=decision,
            request=request,
            presentation=credential_presentation(),
        )
        self.assertIs(fsm.state, State.DECLINED)

    def test_malformed_accepted_credential_tuple_declines_with_policy_reason(self):
        # The construction check rejects a tuple entry (§14.4, AFP-0508); a
        # live policy edited afterwards is still declined, never read.
        with self.assertRaises(ValueError):
            introduction_policy(
                accepted_credentials=[(INSTANCE_ATTESTATION_PREDICATE_V2, 0.0)]
            )
        policy = introduction_policy()
        policy.accepted_credentials = [(INSTANCE_ATTESTATION_PREDICATE_V2, 0.0)]
        decision = credentialing_decision(policy=policy)
        self.assertFalse(decision.accepted)
        self.assertEqual(
            decision.reasons,
            (
                "the introduction policy block is not a valid accepted-credential "
                "policy: accepted credential entries must be {class, valid_until} "
                "records",
            ),
        )

    def test_malformed_attestation_root_declines_with_policy_reason(self):
        # The construction check refuses a malformed root; a live policy
        # edited afterwards is still declined, never read.
        with self.assertRaises(ValueError):
            introduction_policy(accepted_instance_attestation_roots=[object()])
        policy = introduction_policy()
        policy.accepted_instance_attestation_roots = [object()]
        decision = credentialing_decision(policy=policy)
        self.assertFalse(decision.accepted)
        self.assertEqual(
            decision.reasons,
            (
                "the introduction policy block is not a valid accepted-credential "
                "policy: 'object' object has no attribute 'root_class'",
            ),
        )

    def test_a_tampered_decision_field_fails_the_seal(self):
        decision = credentialing_decision()
        object.__setattr__(decision, "reasons", ())
        object.__setattr__(decision, "proven_predicate_ids", ("anything-i-like",))
        with self.assertRaises(CredentialingError):
            decision.verify_for(introduction_request())

    def test_a_tampered_decline_cannot_become_a_truthy_acceptance(self):
        class TruthyEqualitySpoof(str):
            def __eq__(self, _other):
                return True

            def __ne__(self, _other):
                return False

            def __bool__(self):
                return True

        request = introduction_request()
        decision = credentialing_decision(
            request=request, presentation_verifier=lambda _presentation: None
        )
        self.assertFalse(decision.accepted)
        object.__setattr__(decision, "accepted", TruthyEqualitySpoof("accepted"))
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        open_credentialing(fsm, request=request)
        with self.assertRaisesRegex(CredentialingError, "decision is malformed"):
            fsm.present_credentials(
                decision=decision,
                request=request,
                presentation=credential_presentation(),
            )
        self.assertIs(fsm.state, State.CREDENTIALING)

    def test_a_lookalike_predicate_is_malformed_input(self):
        # The §6.3.1 v2 invariants live in ProvenPredicate.__post_init__, so an
        # object that never ran them could present a v2 identifier with no root
        # class and skip the §14.4 gate entirely.
        class Forged:
            predicate_id = INSTANCE_ATTESTATION_PREDICATE_V2
            predicate_version = "2"
            root_class = None
            root_authority_identifier = "Eattacker-controlled-authority"
            attestation_window = None
            subject_aid = RESPONDER_AID

        with self.assertRaises(CredentialingError):
            credentialing_decision(verified_predicates=(Forged(),))

    def test_a_lookalike_decision_cannot_advance_the_handshake(self):
        class FakeDecision:
            accepted = True

            def verify_for(self, _request):
                return True

        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        request = introduction_request()
        open_credentialing(fsm, request=request)
        with self.assertRaises(handshake.TransitionError):
            fsm.present_credentials(
                decision=FakeDecision(),
                request=request,
                presentation=credential_presentation(),
            )
        self.assertIs(fsm.state, State.CREDENTIALING)

    def test_a_forged_decision_subclass_cannot_advance_the_handshake(self):
        class ForgedDecision(CredentialingDecision):
            def verify_for(self, _request):
                return True

        forged = object.__new__(ForgedDecision)
        fsm = handshake.IntroductionFSM.propose(INITIATOR_AID, RESPONDER_AID)
        request = introduction_request()
        open_credentialing(fsm, request=request)
        with self.assertRaises(handshake.TransitionError):
            fsm.present_credentials(
                decision=forged,
                request=request,
                presentation=credential_presentation(),
            )
        self.assertIs(fsm.state, State.CREDENTIALING)

    def test_credentialing_decision_cannot_be_constructed_directly(self):
        with self.assertRaises(TypeError):
            CredentialingDecision()


if __name__ == "__main__":
    unittest.main()
