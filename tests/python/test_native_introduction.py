"""Native carrier to introduction policy; the lower ZKC adapter is synthetic."""

import _path  # noqa: F401

from dataclasses import replace
import unittest
from unittest.mock import patch

import afp_introduction as intro
import afp_session as afp
from afp_session.atoms import unix_to_utc_datetime
import test_native_credentials as native


class NativeIntroductionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native.NativeCredentialTest()
        self.fixture.session_profile = "native_intro_fixture"
        self.fixture.session_descriptor = afp.AfpProfileDescriptor(
            name="native_intro_fixture", version="fixture", spec_ref="synthetic policy test",
            atom_kinds=[], policy_schema_ref="test-only", status="experimental",
        )
        self.fixture.trust_flow = afp.AfpTrustFlow.INTRODUCTION
        self.fixture.setUp()
        f = self.fixture
        self.request = intro.IntroductionRequest(
            initiator_tenant_aid=f.b.tenant_aid,
            responder_tenant_aid=f.a.tenant_aid,
            offered_credential_classes=[native.KYC_V2.predicate_id],
            required_credential_classes=[native.KYC_V2.predicate_id],
            proposed_envelope=intro.Envelope(["asset"], "1", "1", False),
            attestation_window=intro.atoms.AttestationWindow(
                "2023-11-14T22:13:20Z", "2023-11-14T22:23:20Z"
            ),
        )
        self.offer = intro.IntroductionOffer(
            f.a.tenant_aid, [native.KYC_V2.predicate_id],
            self.request.proposed_envelope, "private-route", 1,
        )
        self.policy = intro.IntroductionPolicy(
            permitted_entities=[f.a.entity_aid, f.b.entity_aid],
            permitted_assets=["asset"], max_per_interaction="1",
            max_cumulative_outstanding="1", bond_ref=None,
            accepted_credentials=[intro.AcceptedCredential(
                native.KYC_V2.predicate_id, unix_to_utc_datetime(native.NOW + 600)
            )],
            accepted_instance_attestation_roots=[], rotation_policy="manual",
            growth_curve={"step": "0", "cap": "0", "decay": "0"},
            agreement_expires_at=unix_to_utc_datetime(native.NOW + 600),
        )
        self.fsm = intro.IntroductionFSM.propose(f.b.tenant_aid, f.a.tenant_aid)
        self.fsm.open_credentialing(
            request=self.request, session_context=f.fa.atom.session_context
        )

    def evaluate(self, credential, **changes):
        args = dict(
            request=self.request, credential=credential, policy=self.policy,
            offer=self.offer,
            expected_session_context=self.fixture.fa.atom.session_context,
            expected_session_profile="native_intro_fixture",
        )
        args.update(changes)
        return intro.evaluate_native_credentialing(**args)

    def consume(self, credential, decision):
        self.fsm.present_native_credentials(
            request=self.request, credential=credential, decision=decision,
            expected_session_profile="native_intro_fixture",
        )

    def test_native_credentialing_never_constructs_or_verifies_a_zka_bundle(self):
        with patch.object(afp.ZkaBundle, "__init__", side_effect=AssertionError("ZKA bundle")), \
             patch("afp_session.session.verify_bundle", side_effect=AssertionError("ZKA verifier")):
            credential = self.fixture.receive(self.fixture.build())
            decision = self.evaluate(credential)
            self.assertTrue(decision.accepted)
            self.consume(credential, decision)
        self.assertEqual(self.fsm.state, intro.State.NEGOTIATING)
        self.assertIsNone(credential.evidence.zka_bundle_kind)
        self.assertEqual(credential.envelope.sender.tenant_aid, self.request.responder_tenant_aid)
        self.assertNotEqual(credential.envelope.sender.entity_aid, self.request.responder_tenant_aid)

    def test_offer_policy_and_native_required_predicate_policy_cannot_be_substituted(self):
        credential = self.fixture.receive(self.fixture.build())
        with self.assertRaises(intro.CredentialingError):
            self.evaluate(credential, policy=replace(self.policy, accepted_credentials=[]))
        edited = replace(self.policy)
        edited.accepted_credentials = [(native.KYC_V2.predicate_id, native.NOW + 600)]
        with self.assertRaises(intro.CredentialingError):
            self.evaluate(credential, policy=edited)
        declined = self.evaluate(credential, offer=replace(self.offer, accepted_credential_classes=[]))
        self.assertFalse(declined.accepted)
        self.consume(credential, declined)
        self.assertEqual(self.fsm.state, intro.State.DECLINED)

    def test_other_tenant_or_live_session_cannot_consume_native_credentials(self):
        credential = self.fixture.receive(self.fixture.build())
        with self.assertRaises(intro.CredentialingError):
            self.evaluate(credential, request=replace(self.request, responder_tenant_aid="other"))
        decision = self.evaluate(credential)
        self.fixture.fb.abort()
        with self.assertRaises(afp.CredentialEnvelopeError):
            self.consume(credential, decision)
        self.assertEqual(self.fsm.state, intro.State.CREDENTIALING)

    def test_governance_mutation_during_policy_evaluation_is_rejected(self):
        credential = self.fixture.receive(self.fixture.build())
        original = intro.credentialing.evaluate_credentialing

        def mutate_after_evaluation(**kwargs):
            decision = original(**kwargs)
            self.policy.max_per_interaction = "999"
            return decision

        with patch("afp_introduction.credentialing.evaluate_credentialing", mutate_after_evaluation):
            with self.assertRaisesRegex(intro.CredentialingError, "mutated governance"):
                self.evaluate(credential)
        self.assertEqual(self.fsm.state, intro.State.CREDENTIALING)

        # A policy edited into a shape §14.4 excludes during evaluation is
        # refused with the same error type, never a plain ValueError.
        policy = replace(self.policy, max_per_interaction="1")

        def unshape_after_evaluation(**kwargs):
            decision = original(**kwargs)
            policy.agreement_expires_at = native.NOW + 600
            return decision

        with patch("afp_introduction.credentialing.evaluate_credentialing", unshape_after_evaluation):
            with self.assertRaisesRegex(intro.CredentialingError, "not a §14.4 policy"):
                self.evaluate(credential, policy=policy)
        self.assertEqual(self.fsm.state, intro.State.CREDENTIALING)

    def test_a_boolean_or_nominal_native_result_cannot_advance_credentialing(self):
        with self.assertRaises(afp.CredentialEnvelopeError):
            self.evaluate(True)
        credential = self.fixture.receive(self.fixture.build())
        with self.assertRaises(intro.TransitionError):
            self.consume(credential, True)
        self.assertEqual(self.fsm.state, intro.State.CREDENTIALING)


if __name__ == "__main__":
    unittest.main()
