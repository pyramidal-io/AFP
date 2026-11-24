"""The §5.9 conformance vectors distinguish a bound verifier from a blind one."""

import _path  # noqa: F401

import unittest
from typing import get_args, get_type_hints

from afp_session.presentation import (
    ANONYMOUS_PROFILE,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    PresentationBindingError,
    afp_scope_policy,
    derive_scope_id,
    flow_policy,
    presentation_proof_context,
    verify_presentation_binding,
    ZkcVerifiedPublicStatement,
)
from afp_session.bundle import (
    BundleError,
    BundleVerificationResult,
    ZkaBundle,
    session_context_field,
    verify_bundle,
)
from afp_session.presentation_conformance import (
    BUNDLE_REJECTION_VECTORS,
    BundleVector,
    ConformanceVector,
    PRESENTATION_REJECTION_VECTORS,
    VectorStatus,
    baseline_case,
    linkable_baseline_case,
    run_bundle_conformance,
    run_presentation_conformance,
)


def meaning_blind_verify(
    evidence,
    *,
    expected_flow,
    expected_responder_aid,
    expected_verifier_aid,
    expected_apr_signer_public_key,
    expected_session_context,
    expected_session_policy_hash,
    required_predicates,
    zkc_verifier,
):
    """A verifier that binds identity correctly and never binds meaning.

    This is the implementation the §5.9 negative cases cannot distinguish from a
    conforming one: every identity obligation the specification enumerates is
    discharged — including flow agreement — and what the presentation proves is
    never consulted. Selecting the policy from ``evidence.flow`` is the defect
    the meaning-flow-relabel vector names: with agreement enforced the two flows
    are equal, so only a case the caller's flow would forbid can distinguish them.
    """
    if evidence.flow != expected_flow:
        raise PresentationBindingError("presentation declares another flow")
    if evidence.presenter_aid != expected_responder_aid:
        raise PresentationBindingError("presenter AID does not match the AFP responder")
    if evidence.credential_subject_aid != expected_responder_aid:
        raise PresentationBindingError("ZKC credential subject does not match")
    if evidence.session_context != expected_session_context:
        raise PresentationBindingError("presentation session context mismatch")
    if evidence.apr_verifier_aid != expected_verifier_aid:
        raise PresentationBindingError("APR verifier AID mismatch")
    if evidence.apr_signer_public_key != expected_apr_signer_public_key:
        raise PresentationBindingError("APR signer key mismatch")

    expected_scope_policy = (
        afp_scope_policy(expected_session_policy_hash)
        if evidence.profile == SCOPED_PROFILE
        else None
    )
    if evidence.proof_context != presentation_proof_context(
        flow=expected_flow,
        responder_aid=expected_responder_aid,
        session_context=expected_session_context,
        apr_verifier_aid=expected_verifier_aid,
        profile=evidence.profile,
        scope_policy=expected_scope_policy,
    ):
        raise PresentationBindingError("ZKC proof context does not match")

    policy = flow_policy(evidence.flow)
    if evidence.profile not in policy.accepted_profiles:
        raise PresentationBindingError("profile is not accepted for this flow")
    if evidence.profile == SCOPED_PROFILE:
        if evidence.scope_id != derive_scope_id(
            expected_apr_signer_public_key, expected_scope_policy, evidence.rotation_epoch
        ):
            raise PresentationBindingError("scope identifier does not match")
    elif evidence.profile == ANONYMOUS_PROFILE:
        if evidence.scope_id != 0 or evidence.presentation_pseudonym != 0:
            raise PresentationBindingError("anonymous presentation must use sentinels")
    elif evidence.profile == LINKABLE_PROFILE:
        if not evidence.linkable_consent:
            raise PresentationBindingError("linkable presentation requires consent")

    verified = zkc_verifier(evidence)
    if type(verified) is not ZkcVerifiedPublicStatement:
        raise PresentationBindingError("ZKC verifier rejected the proof or APR")
    if (
        verified.proof_context != evidence.proof_context
        or verified.credential_subject_aid != expected_responder_aid
        or verified.credential_subject_aid != evidence.credential_subject_aid
        or verified.proven_predicates != evidence.proven_predicates
    ):
        raise PresentationBindingError("ZKC verifier result does not match the presentation")
    return verified


class ReferenceConformanceTest(unittest.TestCase):
    def test_linkable_reference_baseline_uses_the_frozen_v1_kyc_predicate(self):
        evidence, arguments = linkable_baseline_case()

        self.assertEqual(evidence.zkc_envelope_version, "zkc:proof:v1")
        self.assertEqual(
            evidence.proven_predicates[0].predicate_id, "zkc:proof:kyc:v1"
        )
        self.assertEqual(
            arguments["required_predicates"].required_predicate_ids,
            frozenset({"zkc:proof:kyc:v1"}),
        )

    def test_bundle_vector_annotations_resolve_at_runtime(self):
        annotations = get_type_hints(BundleVector)
        return_type = get_args(annotations["build"])[1]
        self.assertIs(get_args(return_type)[0], ZkaBundle)

    def test_the_reference_verifier_passes_exercised_vectors_with_a_coverage_gap(self):
        report = run_presentation_conformance(verify_presentation_binding)
        self.assertFalse(report.conforms, report.summary())
        self.assertEqual(report.failures(), [])
        self.assertEqual(
            [result.vector.vector_id for result in report.not_exercised()],
            ["meaning-unknown-root-class"],
        )
        self.assertIn("meaning-unknown-root-class", report.summary())
        self.assertIn(": not_exercised", report.summary())
        self.assertIn("conforms=False (0 failed, 1 not exercised)", report.summary())

    def test_an_accept_everything_verifier_passes_no_must_reject_vector(self):
        calls = []

        def accept_everything(evidence, **arguments):
            calls.append(evidence)

        report = run_presentation_conformance(accept_everything)
        self.assertFalse(report.conforms)
        self.assertEqual(len(calls), len(report.results) - 1)
        for result in report.results:
            if result.vector.must_reject:
                with self.subTest(vector=result.vector.vector_id):
                    self.assertFalse(result.ok, result.evidence)
                    self.assertIs(
                        result.status,
                        VectorStatus.NOT_EXERCISED
                        if result.vector.vector_id == "meaning-unknown-root-class"
                        else VectorStatus.FAILED,
                    )

    def test_construction_rejections_never_exercise_the_verifier(self):
        def refuse_construction():
            raise PresentationBindingError("synthetic construction refusal")

        def unexpected_verify(*args, **kwargs):
            self.fail("a construction refusal reached the verifier")

        for must_reject in (True, False):
            with self.subTest(must_reject=must_reject):
                vector = ConformanceVector(
                    "construction-refusal", "unbuildable fixture", "§5.9",
                    must_reject, refuse_construction,
                )
                report = run_presentation_conformance(
                    unexpected_verify, vectors=(vector,)
                )
                result = report.result(vector.vector_id)
                self.assertIs(result.status, VectorStatus.NOT_EXERCISED)
                self.assertFalse(result.ok)
                self.assertFalse(report.conforms)
                self.assertEqual(report.failures(), [])
                self.assertEqual(report.not_exercised(), [result])
                self.assertIn("verifier not called", result.evidence)
                self.assertIn("synthetic construction refusal", result.evidence)

    def test_a_fully_exercised_passing_suite_conforms(self):
        report = run_presentation_conformance(
            verify_presentation_binding,
            vectors=tuple(
                vector for vector in PRESENTATION_REJECTION_VECTORS
                if vector.vector_id != "meaning-unknown-root-class"
            ),
        )
        self.assertTrue(report.conforms, report.summary())
        self.assertEqual(report.not_exercised(), [])

    def test_unexpected_errors_propagate_from_construction_and_verification(self):
        def crash(*args, **kwargs):
            raise RuntimeError("unexpected error")

        for build, verify in ((crash, verify_presentation_binding), (baseline_case, crash)):
            with self.subTest(build=build, verify=verify):
                vector = ConformanceVector(
                    "crashing-case", "crashing fixture", "§5.9", True, build
                )
                with self.assertRaisesRegex(RuntimeError, "unexpected error"):
                    run_presentation_conformance(verify, vectors=(vector,))

    def test_the_suite_covers_both_identity_and_meaning(self):
        ids = {vector.vector_id for vector in PRESENTATION_REJECTION_VECTORS}
        for required in (
            "identity-presenter-aid",
            "identity-credential-subject",
            "identity-verified-credential-subject",
            "identity-scope",
            "identity-apr-signer",
            "identity-apr-verifier-aid",
            "identity-session-context",
            "identity-proof-context",
            "identity-flow-context",
            "identity-flow-relabel-both-fields",
            "identity-profile-downgrade",
            "identity-flow-relabel",
            "meaning-unaccepted-predicate",
            "meaning-verified-predicate-disagreement",
            "meaning-required-not-proven",
            "meaning-empty-proof-set",
            "meaning-telemetry-off-catalog",
            "meaning-unmatched-attestation-root",
            "meaning-unmatched-attestation-class",
            "meaning-unknown-root-class",
            "meaning-repeated-predicate",
            "meaning-unchecked-rebind-claim",
        ):
            self.assertIn(required, ids)

    def test_every_vector_states_a_spec_reference(self):
        for vector in PRESENTATION_REJECTION_VECTORS:
            with self.subTest(vector=vector.vector_id):
                self.assertTrue(vector.spec_reference.strip())
                self.assertTrue(vector.name.strip())


class MeaningBlindVerifierTest(unittest.TestCase):
    """The property an identity-only negative-case suite cannot deliver."""

    def setUp(self):
        self.report = run_presentation_conformance(meaning_blind_verify)

    def test_a_meaning_blind_verifier_fails_conformance(self):
        self.assertFalse(
            self.report.conforms,
            "a verifier that never checks which predicate was proven passed the "
            "conformance suite; the suite cannot detect the defect it exists for",
        )

    def test_it_still_passes_every_identity_vector(self):
        # The point of the demonstration: the specification's own enumerated
        # negative cases are all satisfied by an implementation with the defect.
        for result in self.report.results:
            if result.vector.vector_id.startswith("identity-"):
                with self.subTest(vector=result.vector.vector_id):
                    self.assertTrue(result.ok, result.evidence)

    def test_it_fails_exactly_the_meaning_vectors(self):
        failed = {result.vector.vector_id for result in self.report.failures()}
        self.assertTrue(failed, "the meaning vectors have no teeth")
        self.assertTrue(
            all(vector_id.startswith("meaning-") for vector_id in failed),
            f"a meaning-blind verifier failed a non-meaning vector: {sorted(failed)!r}",
        )
        # The vectors a verifier can only pass by reading proven_predicates.
        # meaning-unknown-root-class cannot exercise the verifier because the
        # reference types refuse it at construction. It earns no pass credit.
        self.assertIs(
            self.report.result("meaning-unknown-root-class").status,
            VectorStatus.NOT_EXERCISED,
        )
        self.assertLessEqual(
            {
                "meaning-unaccepted-predicate",
                "meaning-required-not-proven",
                "meaning-empty-proof-set",
                "meaning-telemetry-off-catalog",
                "meaning-unmatched-attestation-root",
                "meaning-unmatched-attestation-class",
                "meaning-repeated-predicate",
                "meaning-unchecked-rebind-claim",
            },
            failed,
        )


class BundleConformanceTest(unittest.TestCase):
    """§12.7 is two-layer: a structural pass without the proof layer is not one."""

    def test_the_reference_bundle_verifier_conforms(self):
        report = run_bundle_conformance(verify_bundle)
        self.assertTrue(report.conforms, report.summary())

    def test_a_verifier_that_skips_the_proof_layer_fails_conformance(self):
        def optional_proof_layer(
            bundle, *, expected_session_context, bundle_verifier
        ):
            if bundle.kind != "zka:bundle:v1":
                raise BundleError("bundle kind")
            if bundle.context != session_context_field(expected_session_context):
                raise BundleError("bundle context does not equal projected session_context")
            if not bundle.present_proofs:
                raise BundleError("bundle carries no proofs")
            if bundle_verifier is not None:
                result = bundle_verifier(bundle)
                if (
                    type(result) is not BundleVerificationResult
                    or result.verified is not True
                ):
                    raise BundleError("ZKA bundle verifier rejected the bundle proofs")

        report = run_bundle_conformance(optional_proof_layer)
        self.assertFalse(report.conforms)
        self.assertEqual(
            {result.vector.vector_id for result in report.failures()},
            {"bundle-default-deny"},
        )

    def test_the_suite_names_the_default_deny_obligation(self):
        ids = {vector.vector_id for vector in BUNDLE_REJECTION_VECTORS}
        self.assertIn("bundle-default-deny", ids)


if __name__ == "__main__":
    unittest.main()
