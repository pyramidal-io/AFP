"""AFP's ZKC v0.4 presentation-profile boundary."""

import _path  # noqa: F401

import hashlib
import unittest
from dataclasses import replace
from unittest import mock

import afp_session
from afp_session.canonical import canonical_bytes
from afp_session.presentation import (
    AFP_ZKC_PRESENTATION_CONTEXT_V2,
    ANONYMOUS_PROFILE,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    AfpTrustFlow,
    PresentationBindingError,
    ProvenPredicate,
    RequiredPredicatePolicy,
    VerifiedPresentation,
    ZkcVerifiedPublicStatement,
    ZkcPresentationEvidence,
    afp_scope_policy,
    derive_scope_id,
    flow_policy,
    presentation_proof_context,
    verify_presentation_binding,
)


APR_KEY = bytes.fromhex("02" + "11" * 32)
OTHER_APR_KEY = bytes.fromhex("03" + "22" * 32)
RESPONDER_AID = "E-responder"
VERIFIER_AID = "E-verifier"
SESSION_CONTEXT = "X_" + "ab" * 32
POLICY_HASH = "0x" + "cd" * 32
SCOPE_POLICY = afp_scope_policy(POLICY_HASH)
SCOPE_ID = derive_scope_id(APR_KEY, SCOPE_POLICY, 7)

KYC = ProvenPredicate(predicate_id="zkc:proof:kyc:v2", predicate_version="2")
LINKABLE_KYC = ProvenPredicate(
    predicate_id="zkc:proof:kyc:v1", predicate_version="1"
)
QUOTA = ProvenPredicate(
    predicate_id="afp.telemetry.compute_quota.v1", predicate_version="1"
)
# What a counterparty-facing flow requires is the verifier's own choice
# (Safeguard 1), so every call states it.
BASE_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset({"zkc:proof:kyc:v2", "zkc:proof:jurisdiction:v2"}),
    required_predicate_ids=frozenset({"zkc:proof:kyc:v2"}),
)
LINKABLE_BASE_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset({"zkc:proof:kyc:v1"}),
    required_predicate_ids=frozenset({"zkc:proof:kyc:v1"}),
)
TELEMETRY_POLICY = RequiredPredicatePolicy(
    accepted_predicate_ids=frozenset({"afp.telemetry.compute_quota.v1"}),
    required_predicate_ids=frozenset({"afp.telemetry.compute_quota.v1"}),
)


def evidence(**overrides):
    values = {
        "flow": AfpTrustFlow.OPEN_FEDERATION,
        "profile": SCOPED_PROFILE,
        "requested_profile": SCOPED_PROFILE,
        "presenter_aid": RESPONDER_AID,
        "credential_subject_aid": RESPONDER_AID,
        "proven_predicates": (KYC,),
        "session_context": SESSION_CONTEXT,
        "proof_context": None,
        "apr_verifier_aid": VERIFIER_AID,
        "apr_signer_public_key": APR_KEY,
        "scope_policy": SCOPE_POLICY,
        "rotation_epoch": 7,
        "scope_id": SCOPE_ID,
        "presentation_pseudonym": 123456,
        "holder_commitment": None,
        "zkc_envelope_version": "zkc:proof:v2",
        "zka_bundle_kind": "zka:bundle:v1",
        "linkable_consent": False,
        "receipt_response": {
            "contextValue": SESSION_CONTEXT,
            "presentationPseudonym": 123456,
            "scopeId": SCOPE_ID,
        },
        "rotation_binding": {
            "presentationPseudonym": 123456,
            "scopeId": SCOPE_ID,
        },
    }
    values.update(overrides)
    if "proof_context" not in overrides:
        try:
            values["proof_context"] = presentation_proof_context(
                flow=values["flow"],
                responder_aid=values["credential_subject_aid"],
                session_context=values["session_context"],
                apr_verifier_aid=values["apr_verifier_aid"],
                profile=values["profile"],
                scope_policy=values["scope_policy"],
            )
        except (PresentationBindingError, ValueError):
            # Keep invalid-input tests focused on the evidence constructor rather
            # than letting this test builder preempt its validation boundary.
            values["proof_context"] = "0x" + "00" * 32
    return ZkcPresentationEvidence(**values)


def _context_digest(*, kind, purpose):
    statement = {
        "kind": kind,
        "credential_subject_aid": RESPONDER_AID,
        "session_context": SESSION_CONTEXT,
        "apr_verifier_aid": VERIFIER_AID,
        "presentation_profile": SCOPED_PROFILE,
        "scope_policy": SCOPE_POLICY,
    }
    if purpose is not None:
        statement["purpose"] = purpose
    digest = hashlib.sha256(canonical_bytes(statement)).digest()
    if kind != AFP_ZKC_PRESENTATION_CONTEXT_V2:
        return "0x" + digest.hex()
    value = int.from_bytes(digest, "big") % (
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    return f"0x{value:064x}"


def accept_test_zkc_boundary(_evidence):
    """Synthetic success with a fixed, independently authenticated subject."""
    return ZkcVerifiedPublicStatement(
        proof_context=_evidence.proof_context,
        credential_subject_aid=RESPONDER_AID,
        proven_predicates=_evidence.proven_predicates,
    )


class FlowPolicyTest(unittest.TestCase):
    def test_scope_derivation_matches_zkc_v04_golden_vector(self):
        # Independent KAT from ZKC v0.4.0 §5.9.1 for this fixed key/policy/epoch.
        self.assertEqual(
            derive_scope_id(bytes.fromhex("02" + "11" * 32), "verifier", 0),
            0x2632AAF1E51423D6EAB07AA448F245C91490F34A5B3E6744E47F584FAB96C4D5,
        )

    def test_each_flow_declares_profiles_and_downgrade_rule(self):
        telemetry = flow_policy(AfpTrustFlow.TELEMETRY)
        bilateral = flow_policy(AfpTrustFlow.BILATERAL)
        introduction = flow_policy(AfpTrustFlow.INTRODUCTION)
        open_federation = flow_policy(AfpTrustFlow.OPEN_FEDERATION)

        self.assertEqual(telemetry.default_profile, ANONYMOUS_PROFILE)
        self.assertEqual(bilateral.default_profile, ANONYMOUS_PROFILE)
        self.assertTrue(telemetry.allows_downgrade(SCOPED_PROFILE, ANONYMOUS_PROFILE))
        self.assertTrue(bilateral.allows_downgrade(SCOPED_PROFILE, ANONYMOUS_PROFILE))
        self.assertEqual(introduction.default_profile, SCOPED_PROFILE)
        self.assertEqual(open_federation.default_profile, SCOPED_PROFILE)
        self.assertFalse(introduction.allows_downgrade(SCOPED_PROFILE, ANONYMOUS_PROFILE))
        self.assertFalse(open_federation.allows_downgrade(SCOPED_PROFILE, ANONYMOUS_PROFILE))

    def test_context_v2_uses_an_exact_namespaced_flow_purpose(self):
        contexts = {
            flow: presentation_proof_context(
                flow=flow,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=SCOPED_PROFILE,
                scope_policy=SCOPE_POLICY,
            )
            for flow in AfpTrustFlow
        }
        self.assertEqual(AFP_ZKC_PRESENTATION_CONTEXT_V2, "afp:zkc-presentation-context:v2")
        self.assertEqual(
            contexts[AfpTrustFlow.OPEN_FEDERATION],
            _context_digest(
                kind=AFP_ZKC_PRESENTATION_CONTEXT_V2,
                purpose="afp:trust-flow:open-federation",
            ),
        )
        self.assertEqual(
            contexts[AfpTrustFlow.OPEN_FEDERATION],
            "0x2bf30c89b647f318b49ed7f019ac69a2d71b427a124ef61e19e7a09363190fa7",
        )
        self.assertEqual(
            contexts,
            {
                AfpTrustFlow.TELEMETRY:
                    "0x1305df636b8c930b6fb1a3e75c8b929bb3b609016822ed26a4b9915ac6511a4d",
                AfpTrustFlow.BILATERAL:
                    "0x1bba2a7ac78a76b4724daddc677227da47c73752f0d555ffc0645573763f829f",
                AfpTrustFlow.INTRODUCTION:
                    "0x0a97daaf6e5acd942877a023723ff101505a9697e82aede00e41f640a2332ad9",
                AfpTrustFlow.OPEN_FEDERATION:
                    "0x2bf30c89b647f318b49ed7f019ac69a2d71b427a124ef61e19e7a09363190fa7",
            },
        )
        self.assertEqual(len(contexts), len(set(contexts.values())))
        self.assertTrue(
            all(
                0 < int(context, 16)
                < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                for context in contexts.values()
            )
        )
        self.assertEqual(
            contexts[AfpTrustFlow.OPEN_FEDERATION],
            presentation_proof_context(
                flow="open-federation",
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=SCOPED_PROFILE,
                scope_policy=SCOPE_POLICY,
            ),
        )

    def test_context_v2_reduces_digest_above_the_field_modulus(self):
        statement = {
            "kind": AFP_ZKC_PRESENTATION_CONTEXT_V2,
            "purpose": "afp:trust-flow:telemetry",
            "credential_subject_aid": RESPONDER_AID,
            "session_context": SESSION_CONTEXT,
            "apr_verifier_aid": VERIFIER_AID,
            "presentation_profile": SCOPED_PROFILE,
            "scope_policy": SCOPE_POLICY,
        }
        raw = int.from_bytes(hashlib.sha256(canonical_bytes(statement)).digest(), "big")
        modulus = (
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        )
        self.assertGreater(raw, modulus)
        self.assertEqual(
            presentation_proof_context(
                flow=AfpTrustFlow.TELEMETRY,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=SCOPED_PROFILE,
                scope_policy=SCOPE_POLICY,
            ),
            f"0x{raw % modulus:064x}",
        )

    def test_context_v2_rejects_the_zero_field_sentinel_without_retry(self):
        digest = mock.Mock()
        digest.digest.return_value = b"\x00" * 32
        with mock.patch(
            "afp_session.presentation.hashlib.sha256", return_value=digest
        ), self.assertRaisesRegex(PresentationBindingError, "zero sentinel"):
            presentation_proof_context(
                flow=AfpTrustFlow.TELEMETRY,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=SCOPED_PROFILE,
                scope_policy=SCOPE_POLICY,
            )

    def test_context_v2_rejects_a_noncanonical_or_zero_projecting_session_first(self):
        modulus = (
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        )
        invalid_session_contexts = (
            "0x" + "11" * 32,
            "D_" + "11" * 32,
            "X_" + "AA" * 32,
            "X_" + "11" * 31,
            "X_" + "00" * 32,
            f"X_{modulus:064x}",
        )
        with mock.patch("afp_session.presentation.hashlib.sha256") as sha256:
            for session_context in invalid_session_contexts:
                with self.subTest(session_context=session_context), self.assertRaisesRegex(
                    PresentationBindingError, "nonzero-projecting AFP session digest"
                ):
                    presentation_proof_context(
                        flow=AfpTrustFlow.TELEMETRY,
                        responder_aid=RESPONDER_AID,
                        session_context=session_context,
                        apr_verifier_aid=VERIFIER_AID,
                        profile=SCOPED_PROFILE,
                        scope_policy=SCOPE_POLICY,
                    )
            sha256.assert_not_called()

    def test_context_rejects_an_unknown_or_noncanonical_flow(self):
        for flow in ("not-an-afp-flow", 1):
            with self.subTest(flow=flow), self.assertRaises(PresentationBindingError):
                presentation_proof_context(
                    flow=flow,
                    responder_aid=RESPONDER_AID,
                    session_context=SESSION_CONTEXT,
                    apr_verifier_aid=VERIFIER_AID,
                    profile=SCOPED_PROFILE,
                    scope_policy=SCOPE_POLICY,
                )

    def test_anonymous_remains_valid_where_continuity_is_unnecessary(self):
        item = evidence(
            flow=AfpTrustFlow.TELEMETRY,
            profile=ANONYMOUS_PROFILE,
            requested_profile=ANONYMOUS_PROFILE,
            proven_predicates=(QUOTA,),
            scope_policy=None,
            rotation_epoch=0,
            scope_id=0,
            presentation_pseudonym=0,
            proof_context=presentation_proof_context(
                flow=AfpTrustFlow.TELEMETRY,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=ANONYMOUS_PROFILE,
                scope_policy=None,
            ),
            receipt_response={"contextValue": SESSION_CONTEXT},
            rotation_binding={},
        )
        self._verify(item)

    def test_bilateral_may_downgrade_scoped_request_to_anonymous(self):
        item = evidence(
            flow=AfpTrustFlow.BILATERAL,
            profile=ANONYMOUS_PROFILE,
            requested_profile=SCOPED_PROFILE,
            scope_policy=None,
            rotation_epoch=0,
            scope_id=0,
            presentation_pseudonym=0,
            proof_context=presentation_proof_context(
                flow=AfpTrustFlow.BILATERAL,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=ANONYMOUS_PROFILE,
                scope_policy=None,
            ),
            receipt_response={"contextValue": SESSION_CONTEXT},
            rotation_binding={},
        )
        self._verify(item)

    def test_open_federation_rejects_anonymous_downgrade(self):
        item = evidence(
            profile=ANONYMOUS_PROFILE,
            scope_policy=None,
            rotation_epoch=0,
            scope_id=0,
            presentation_pseudonym=0,
            proof_context=presentation_proof_context(
                flow=AfpTrustFlow.OPEN_FEDERATION,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=ANONYMOUS_PROFILE,
                scope_policy=None,
            ),
            receipt_response={"contextValue": SESSION_CONTEXT},
            rotation_binding={},
        )
        with self.assertRaisesRegex(PresentationBindingError, "downgrade"):
            self._verify(item)

    def test_linkable_profile_requires_explicit_consent(self):
        item = evidence(
            profile=LINKABLE_PROFILE,
            requested_profile=LINKABLE_PROFILE,
            proven_predicates=(LINKABLE_KYC,),
            scope_policy=None,
            rotation_epoch=0,
            scope_id=None,
            presentation_pseudonym=None,
            holder_commitment=987654,
            zkc_envelope_version="zkc:proof:v1",
            proof_context=presentation_proof_context(
                flow=AfpTrustFlow.OPEN_FEDERATION,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=LINKABLE_PROFILE,
                scope_policy=None,
            ),
            receipt_response={
                "contextValue": SESSION_CONTEXT,
                "holderCommitment": 987654,
            },
            rotation_binding={"holderCommitment": 987654},
        )
        with self.assertRaisesRegex(PresentationBindingError, "consent"):
            self._verify(item, policy=LINKABLE_BASE_POLICY)
        self._verify(
            replace(item, linkable_consent=True), policy=LINKABLE_BASE_POLICY
        )

    def _verify(self, item, *, policy=None, flow=None, **overrides):
        """Verify ``item`` for the flow it declares, unless told otherwise."""
        arguments = dict(
            expected_flow=flow or item.flow,
            expected_responder_aid=RESPONDER_AID,
            expected_verifier_aid=VERIFIER_AID,
            expected_apr_signer_public_key=APR_KEY,
            expected_session_context=SESSION_CONTEXT,
            expected_session_policy_hash=POLICY_HASH,
            required_predicates=policy
            or (
                TELEMETRY_POLICY
                if (flow or item.flow) is AfpTrustFlow.TELEMETRY
                else BASE_POLICY
            ),
            zkc_verifier=accept_test_zkc_boundary,
        )
        arguments.update(overrides)
        return verify_presentation_binding(item, **arguments)


class BindingAttackTest(unittest.TestCase):
    def test_open_federation_profile_subclass_is_rejected_at_construction(self):
        class Profile(str):
            def __eq__(self, other):
                return True

            def __hash__(self):
                return hash(SCOPED_PROFILE)

        with self.assertRaisesRegex(PresentationBindingError, "profile.*exact string"):
            evidence(profile=Profile("attacker-profile"))

    def test_requested_profile_subclass_is_rejected_at_construction(self):
        class Profile(str):
            pass

        with self.assertRaisesRegex(PresentationBindingError, "requested_profile"):
            evidence(requested_profile=Profile(SCOPED_PROFILE))

    def test_behavior_selecting_scalar_subclasses_are_rejected(self):
        class Epoch(int):
            pass

        for field, value in (
            ("rotation_epoch", Epoch(7)),
            ("scope_id", Epoch(SCOPE_ID)),
            ("presentation_pseudonym", Epoch(123456)),
            ("linkable_consent", 1),
        ):
            with self.subTest(field=field), self.assertRaises(PresentationBindingError):
                evidence(**{field: value})

    def test_valid_scoped_open_federation_binding(self):
        self._verify(evidence())

    def test_rejects_swapped_presenter_aid(self):
        with self.assertRaisesRegex(PresentationBindingError, "presenter AID"):
            self._verify(evidence(presenter_aid="E-attacker"))

    def test_rejects_swapped_credential_holder(self):
        with self.assertRaisesRegex(PresentationBindingError, "credential subject"):
            self._verify(evidence(credential_subject_aid="E-unrelated-holder"))

    def test_rejects_swapped_scope(self):
        with self.assertRaisesRegex(PresentationBindingError, "scope"):
            self._verify(evidence(scope_id=SCOPE_ID + 1))

    def test_rejects_swapped_apr_signer(self):
        with self.assertRaisesRegex(PresentationBindingError, "APR signer"):
            self._verify(evidence(apr_signer_public_key=OTHER_APR_KEY))

    def test_rejects_swapped_context(self):
        with self.assertRaisesRegex(PresentationBindingError, "session context"):
            self._verify(evidence(session_context="X_" + "ef" * 32))

    def test_rejects_legacy_and_prepurpose_contexts_without_fallback(self):
        for kind, purpose in (
            ("afp:zkc-presentation-context:v1", None),
            (AFP_ZKC_PRESENTATION_CONTEXT_V2, None),
        ):
            with self.subTest(kind=kind, purpose=purpose):
                with self.assertRaisesRegex(PresentationBindingError, "proof context"):
                    self._verify(
                        evidence(proof_context=_context_digest(kind=kind, purpose=purpose))
                    )

    def test_rejects_swapped_profile(self):
        with self.assertRaisesRegex(PresentationBindingError, "proof context"):
            self._verify(evidence(profile=ANONYMOUS_PROFILE))

    def test_requires_successful_zkc_cryptographic_verification(self):
        with self.assertRaisesRegex(PresentationBindingError, "ZKC verifier"):
            self._verify(evidence(), zkc_verifier=lambda _item: None)

    def test_requires_zka_bundle_v1_contract(self):
        with self.assertRaisesRegex(PresentationBindingError, "zka:bundle:v1"):
            self._verify(evidence(zka_bundle_kind="zka:bundle:v2"))

    def test_receipt_exposes_no_handle_beyond_scoped_profile(self):
        leaked = dict(evidence().receipt_response)
        leaked["holderCommitment"] = 987654
        with self.assertRaisesRegex(PresentationBindingError, "receipt"):
            self._verify(evidence(receipt_response=leaked))

    def test_rotation_exposes_no_handle_beyond_scoped_profile(self):
        with self.assertRaisesRegex(PresentationBindingError, "rotation"):
            self._verify(
                evidence(
                    rotation_binding={
                        "presentationPseudonym": 123456,
                        "scopeId": SCOPE_ID,
                        "holderCommitment": 987654,
                    }
                )
            )

    def _verify(self, item, *, policy=None, flow=None, **overrides):
        """Verify ``item`` for the flow it declares, unless told otherwise."""
        arguments = dict(
            expected_flow=flow or item.flow,
            expected_responder_aid=RESPONDER_AID,
            expected_verifier_aid=VERIFIER_AID,
            expected_apr_signer_public_key=APR_KEY,
            expected_session_context=SESSION_CONTEXT,
            expected_session_policy_hash=POLICY_HASH,
            required_predicates=policy
            or (
                TELEMETRY_POLICY
                if (flow or item.flow) is AfpTrustFlow.TELEMETRY
                else BASE_POLICY
            ),
            zkc_verifier=accept_test_zkc_boundary,
        )
        arguments.update(overrides)
        return verify_presentation_binding(item, **arguments)


class PredicateMeaningTest(unittest.TestCase):
    """§6.3/§6.3.1/§14.4: what was proven must be what this flow requires."""

    def test_valid_meaning_binding(self):
        result = self._verify(evidence())
        self.assertIsInstance(result, VerifiedPresentation)
        self.assertEqual(result.proven_predicate_ids, frozenset({KYC.predicate_id}))
        self.assertEqual(result.flow, AfpTrustFlow.OPEN_FEDERATION)

    def test_rejects_a_predicate_the_flow_does_not_accept(self):
        other = ProvenPredicate(
            predicate_id="zkc:proof:accreditation:v2", predicate_version="2"
        )
        with self.assertRaisesRegex(PresentationBindingError, "does not accept"):
            self._verify(evidence(proven_predicates=(other,)))

    def test_rejects_a_presentation_missing_the_required_predicate(self):
        other = ProvenPredicate(
            predicate_id="zkc:proof:jurisdiction:v2", predicate_version="2"
        )
        with self.assertRaisesRegex(PresentationBindingError, "does not prove required"):
            self._verify(evidence(proven_predicates=(other,)))

    def test_rejects_a_presentation_that_proves_nothing(self):
        with self.assertRaisesRegex(PresentationBindingError, "proves no predicate"):
            self._verify(evidence(proven_predicates=()))

    def test_telemetry_rejects_a_predicate_outside_the_closed_catalog(self):
        # §6.3: the telemetry catalog is closed, so an off-catalog predicate is
        # not AFP-conforming however permissive the verifier's own policy is.
        permissive = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset(
                {"zkc:proof:kyc:v2", "afp.telemetry.compute_quota.v1"}
            )
        )
        item = evidence(flow=AfpTrustFlow.TELEMETRY)
        with self.assertRaisesRegex(PresentationBindingError, "closed §6.3"):
            self._verify(item, policy=permissive)

    def test_telemetry_accepts_a_catalog_predicate(self):
        item = evidence(flow=AfpTrustFlow.TELEMETRY, proven_predicates=(QUOTA,))
        self._verify(item)

    def test_a_relabelled_flow_is_rejected(self):
        with self.assertRaisesRegex(PresentationBindingError, "declares flow"):
            self._verify(
                evidence(flow=AfpTrustFlow.TELEMETRY),
                flow=AfpTrustFlow.OPEN_FEDERATION,
            )

    def test_a_telemetry_labelled_anonymous_presentation_is_not_open_federation(self):
        # Telemetry accepts every profile; open federation forbids the anonymous
        # downgrade. This is the case a verifier selecting policy from
        # evidence.flow would accept. Note the agreement check above already
        # rejects it, and with agreement enforced flow_policy(evidence.flow) and
        # flow_policy(expected_flow) are provably identical -- so the caller-flow
        # policy selection is defence in depth, not the load-bearing check.
        item = evidence(
            flow=AfpTrustFlow.TELEMETRY,
            profile=ANONYMOUS_PROFILE,
            scope_policy=None,
            rotation_epoch=0,
            scope_id=0,
            presentation_pseudonym=0,
            proof_context=presentation_proof_context(
                flow=AfpTrustFlow.TELEMETRY,
                responder_aid=RESPONDER_AID,
                session_context=SESSION_CONTEXT,
                apr_verifier_aid=VERIFIER_AID,
                profile=ANONYMOUS_PROFILE,
                scope_policy=None,
            ),
            receipt_response={},
            rotation_binding={},
        )
        with self.assertRaises(PresentationBindingError):
            self._verify(item, flow=AfpTrustFlow.OPEN_FEDERATION)

    def test_a_bare_string_flow_reaches_the_same_policy(self):
        # AfpTrustFlow subclasses str, so an equality test against a bare string
        # succeeds where an identity test does not; the closed catalog must not
        # depend on which form the caller passed.
        item = evidence(flow="telemetry")
        permissive = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({"zkc:proof:kyc:v2"})
        )
        with self.assertRaisesRegex(PresentationBindingError, "closed §6.3"):
            self._verify(item, flow="telemetry", policy=permissive)

    def test_an_unknown_flow_is_rejected(self):
        with self.assertRaisesRegex(PresentationBindingError, "unknown AFP trust flow"):
            self._verify(evidence(), flow="not-a-flow")

    def test_generator_predicates_are_snapshotted(self):
        # A one-shot iterable would be exhausted by the first check and read as
        # empty by every later one, vacating the meaning comparison entirely.
        other = ProvenPredicate(
            predicate_id="zkc:proof:accreditation:v2", predicate_version="2"
        )
        item = evidence(proven_predicates=(p for p in (other,)))
        self.assertEqual(item.proven_predicates, (other,))
        with self.assertRaisesRegex(PresentationBindingError, "does not accept"):
            self._verify(item)

    def test_callback_mutation_cannot_rewrite_the_checked_statement(self):
        # The ZKC callback is third-party adapter code and receives the live
        # record; frozen=True does not stop object.__setattr__. AFP snapshots
        # the comparands before calling it and rejects a different result.
        def tampering(item):
            object.__setattr__(item, "credential_subject_aid", "E-attacker")
            object.__setattr__(
                item,
                "proven_predicates",
                (
                    ProvenPredicate(
                        predicate_id="zkc:proof:sanctions:v2", predicate_version="2"
                    ),
                ),
            )
            return ZkcVerifiedPublicStatement(
                proof_context=item.proof_context,
                credential_subject_aid=item.credential_subject_aid,
                proven_predicates=item.proven_predicates,
            )

        with self.assertRaisesRegex(PresentationBindingError, "result does not match"):
            self._verify(evidence(), zkc_verifier=tampering)

    def test_callback_cannot_mutate_returned_presentation_fields(self):
        # A verifier receives the live evidence object.  Its return value cannot
        # authorize a post-verification rewrite of the profile, session, or
        # proof context AFP uses for the accepted presentation.
        def tampering(item):
            verified = ZkcVerifiedPublicStatement(
                proof_context=item.proof_context,
                credential_subject_aid=item.credential_subject_aid,
                proven_predicates=item.proven_predicates,
            )
            object.__setattr__(item, "profile", ANONYMOUS_PROFILE)
            object.__setattr__(item, "session_context", "X_" + "ef" * 32)
            object.__setattr__(item, "proof_context", "0x" + "ef" * 32)
            return verified

        with self.assertRaisesRegex(PresentationBindingError, "mutated presentation"):
            self._verify(evidence(), zkc_verifier=tampering)

    def test_a_lookalike_evidence_record_is_rejected(self):
        # The construction invariants run in __post_init__; an object that never
        # passed through them can answer the meaning comparison for itself.
        class Lookalike:
            def __init__(self, real):
                self._real = real

            def __getattr__(self, name):
                return getattr(self._real, name)

            @property
            def proven_predicates(self):
                return (
                    ProvenPredicate(
                        predicate_id="zkc:proof:sanctions:v2", predicate_version="2"
                    ),
                )

        with self.assertRaisesRegex(PresentationBindingError, "ZkcPresentationEvidence"):
            self._verify(Lookalike(evidence()))

    def test_a_predicate_subclass_cannot_answer_the_root_gate(self):
        # The §14.4 comparison reads the fields; admitting a subclass would let
        # the object being constrained supply the value it is checked against.
        class Sneaky(ProvenPredicate):
            pass

        with self.assertRaisesRegex(PresentationBindingError, "ProvenPredicate"):
            evidence(
                proven_predicates=(
                    Sneaky(predicate_id="zkc:proof:kyc:v2", predicate_version="2"),
                )
            )

    def test_a_string_subclass_predicate_id_is_rejected(self):
        class FakeId(str):
            def __eq__(self, other):
                return True

            def __hash__(self):
                return hash("zkc:proof:kyc:v2")

        with self.assertRaisesRegex(PresentationBindingError, "non-empty string"):
            ProvenPredicate(
                predicate_id=FakeId("zkc:proof:sanctions:v2"), predicate_version="2"
            )

    def test_a_post_construction_predicate_alias_is_rejected(self):
        class FakeId(str):
            def __eq__(self, _other):
                return True

            def __hash__(self):
                return hash(KYC.predicate_id)

        item = evidence()
        object.__setattr__(
            item.proven_predicates[0],
            "predicate_id",
            FakeId("zkc:proof:sanctions:v2"),
        )
        with self.assertRaisesRegex(PresentationBindingError, "snapshot is malformed"):
            self._verify(item)

    def test_a_post_construction_policy_alias_is_rejected(self):
        class FakeId(str):
            def __hash__(self):
                return hash(KYC.predicate_id)

        policy = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({KYC.predicate_id})
        )
        object.__setattr__(
            policy,
            "accepted_predicate_ids",
            frozenset({FakeId("zkc:proof:sanctions:v2")}),
        )
        with self.assertRaisesRegex(PresentationBindingError, "scalar aliases"):
            self._verify(evidence(), policy=policy)

    def test_a_repeated_predicate_is_rejected(self):
        with self.assertRaisesRegex(PresentationBindingError, "atomic"):
            self._verify(evidence(proven_predicates=(KYC, KYC)))

    def test_handle_artifacts_are_snapshotted(self):
        receipt = {"presentationPseudonym": 123456, "scopeId": SCOPE_ID}
        item = evidence(receipt_response=receipt)
        receipt["holderCommitment"] = 1
        self.assertNotIn("holderCommitment", item.receipt_response)

    def test_rejects_a_non_predicate_member(self):
        with self.assertRaisesRegex(PresentationBindingError, "ProvenPredicate"):
            evidence(proven_predicates=("zkc:proof:kyc:v2",))

    def _verify(self, item, *, policy=None, flow=None, **overrides):
        arguments = dict(
            expected_flow=flow or item.flow,
            expected_responder_aid=RESPONDER_AID,
            expected_verifier_aid=VERIFIER_AID,
            expected_apr_signer_public_key=APR_KEY,
            expected_session_context=SESSION_CONTEXT,
            expected_session_policy_hash=POLICY_HASH,
            required_predicates=policy
            or (
                TELEMETRY_POLICY
                if (flow or item.flow) is AfpTrustFlow.TELEMETRY
                else BASE_POLICY
            ),
            zkc_verifier=accept_test_zkc_boundary,
        )
        arguments.update(overrides)
        return verify_presentation_binding(item, **arguments)


class InstanceAttestationRootTest(unittest.TestCase):
    """§14.4: accept only a proof matching one signed root pair."""

    WINDOW = ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    ROOT = ("root:publisher-manifest", "E-accountable-authority")

    def _attestation(self, **overrides):
        values = dict(
            predicate_id="afp.telemetry.instance_attestation.v2",
            predicate_version="2",
            root_class=self.ROOT[0],
            root_authority_identifier=self.ROOT[1],
            attestation_window=self.WINDOW,
            subject_aid=RESPONDER_AID,
        )
        values.update(overrides)
        return ProvenPredicate(**values)

    def _policy(self, roots=None):
        return RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset(
                {"afp.telemetry.instance_attestation.v2"}
            ),
            required_predicate_ids=frozenset(
                {"afp.telemetry.instance_attestation.v2"}
            ),
            accepted_instance_attestation_roots=frozenset(
                {self.ROOT} if roots is None else roots
            ),
        )

    def _verify(self, predicate, policy):
        item = evidence(flow=AfpTrustFlow.INTRODUCTION, proven_predicates=(predicate,))
        return verify_presentation_binding(
            item,
            expected_flow=AfpTrustFlow.INTRODUCTION,
            expected_responder_aid=RESPONDER_AID,
            expected_verifier_aid=VERIFIER_AID,
            expected_apr_signer_public_key=APR_KEY,
            expected_session_context=SESSION_CONTEXT,
            expected_session_policy_hash=POLICY_HASH,
            required_predicates=policy,
            zkc_verifier=accept_test_zkc_boundary,
        )

    def test_a_signed_pair_is_accepted(self):
        self._verify(self._attestation(), self._policy())

    def test_rejects_an_unsigned_authority(self):
        predicate = self._attestation(root_authority_identifier="E-unsigned")
        with self.assertRaisesRegex(PresentationBindingError, "signed"):
            self._verify(predicate, self._policy())

    def test_rejects_a_branch_proof_for_another_class(self):
        predicate = self._attestation(root_class="root:tee-attestation")
        with self.assertRaisesRegex(PresentationBindingError, "signed"):
            self._verify(predicate, self._policy())

    def test_a_v2_attestation_without_a_root_is_rejected(self):
        # The §14.4 gate keys on the predicate's identity, not on whether it
        # happens to carry a root: absence must reject, never skip, or the
        # attestation predicate is silently authorized.
        import copy

        predicate = copy.copy(self._attestation())
        object.__setattr__(predicate, "root_class", None)
        with self.assertRaisesRegex(PresentationBindingError, "must name a root class"):
            self._verify(predicate, self._policy())

    def test_a_non_attestation_predicate_carrying_a_root_is_rejected(self):
        import copy

        predicate = copy.copy(
            ProvenPredicate(predicate_id="zkc:proof:kyc:v2", predicate_version="2")
        )
        object.__setattr__(predicate, "root_class", "root:publisher-manifest")
        policy = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({"zkc:proof:kyc:v2"})
        )
        with self.assertRaisesRegex(PresentationBindingError, "MUST NOT carry a root"):
            self._verify(predicate, policy)

    def test_rejects_an_unknown_root_class(self):
        with self.assertRaisesRegex(PresentationBindingError, "unknown"):
            self._attestation(root_class="root:vibes")

    def test_rejects_scalar_aliases_in_attestation_fields(self):
        class Alias(str):
            def __eq__(self, other):
                return True

            def __hash__(self):
                return hash("root:publisher-manifest")

        cases = (
            {"predicate_id": Alias("zkc:proof:kyc:v2")},
            {"root_class": Alias("root:publisher-manifest")},
            {"root_authority_identifier": Alias("E-accountable-authority")},
            {"subject_aid": Alias(RESPONDER_AID)},
            {
                "attestation_window": (
                    Alias("2026-01-01T00:00:00Z"),
                    "2026-01-02T00:00:00Z",
                )
            },
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(PresentationBindingError):
                self._attestation(**overrides)

    def test_rejects_scalar_aliases_in_policy_roots(self):
        class Alias(str):
            pass

        with self.assertRaisesRegex(PresentationBindingError, "exact string pairs"):
            self._policy(roots={(Alias(self.ROOT[0]), self.ROOT[1])})

    def test_a_v1_attestation_may_not_carry_a_root_class(self):
        # §6.3.1 freezes v1 semantically: a v1 proof MUST NOT be reinterpreted
        # as carrying a generic root class.
        with self.assertRaisesRegex(PresentationBindingError, "MUST NOT carry a root"):
            ProvenPredicate(
                predicate_id="afp.telemetry.instance_attestation.v1",
                predicate_version="1",
                root_class="root:publisher-manifest",
            )

    def test_a_predicate_version_must_match_its_identifier(self):
        with self.assertRaisesRegex(PresentationBindingError, "contradicts"):
            ProvenPredicate(predicate_id="zkc:proof:kyc:v2", predicate_version="1")

    def test_an_attestation_window_must_be_canonical(self):
        with self.assertRaisesRegex(PresentationBindingError, "whole-second UTC"):
            self._attestation(attestation_window=("2026-01-01", "2026-01-02"))

    def test_an_attestation_window_must_be_ordered(self):
        with self.assertRaisesRegex(PresentationBindingError, "precede"):
            self._attestation(
                attestation_window=("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")
            )

    def test_a_v2_attestation_window_starts_no_earlier_than_1970(self):
        # §1.6.1 / AFP-0220: v2 endpoints are also unsigned 64-bit Unix seconds.
        with self.assertRaisesRegex(PresentationBindingError, "1970"):
            self._attestation(
                attestation_window=("1969-12-31T23:59:59Z", "1970-01-01T00:00:01Z")
            )
        accepted = self._attestation(
            attestation_window=("1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z")
        )
        self.assertEqual(accepted.attestation_window[0], "1970-01-01T00:00:00Z")

    def test_accepting_v2_requires_at_least_one_signed_pair(self):
        with self.assertRaisesRegex(PresentationBindingError, "requires at least one"):
            self._policy(roots=frozenset())

    def test_pinned_pairs_require_v2_to_be_accepted(self):
        with self.assertRaisesRegex(PresentationBindingError, "MUST be empty"):
            RequiredPredicatePolicy(
                accepted_predicate_ids=frozenset({"zkc:proof:kyc:v2"}),
                accepted_instance_attestation_roots=frozenset({self.ROOT}),
            )


class RequiredPredicatePolicyTest(unittest.TestCase):
    def test_an_empty_allow_list_is_rejected(self):
        with self.assertRaisesRegex(PresentationBindingError, "at least one predicate"):
            RequiredPredicatePolicy(accepted_predicate_ids=frozenset())

    def test_an_unsatisfiable_policy_is_rejected(self):
        with self.assertRaisesRegex(PresentationBindingError, "never be satisfied"):
            RequiredPredicatePolicy(
                accepted_predicate_ids=frozenset({"zkc:proof:kyc:v2"}),
                required_predicate_ids=frozenset({"zkc:proof:sanctions:v2"}),
            )

    def test_the_digest_is_stable_and_order_independent(self):
        first = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({"a:v1", "b:v2"}),
            required_predicate_ids=frozenset({"a:v1"}),
        )
        second = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({"b:v2", "a:v1"}),
            required_predicate_ids=frozenset({"a:v1"}),
        )
        self.assertEqual(first.digest, second.digest)

    def test_a_different_policy_has_a_different_digest(self):
        first = RequiredPredicatePolicy(accepted_predicate_ids=frozenset({"a:v1"}))
        second = RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({"a:v1", "b:v2"})
        )
        self.assertNotEqual(first.digest, second.digest)


class UnsupportedRebindTest(unittest.TestCase):
    def test_dead_rotation_verifier_is_not_public(self):
        self.assertFalse(hasattr(afp_session, "verify_rotation_rebind_contract"))
        self.assertFalse(hasattr(afp_session, "RotationRebind"))

    def test_rebind_declarations_are_rejected(self):
        for field in (
            "rebindProofKind",
            "rebindProof",
            "oldPresentationPseudonym",
            "newPresentationPseudonym",
            "oldHolderCommitment",
            "newHolderCommitment",
            "zkcCredentialRebind",
            "zkc_credential_rebind",
        ):
            with self.subTest(field=field):
                item = evidence(
                    rotation_binding={
                        "presentationPseudonym": 123456,
                        "scopeId": SCOPE_ID,
                        field: "opaque-rebind-data",
                    }
                )
                with self.assertRaisesRegex(PresentationBindingError, "unsupported"):
                    verify_presentation_binding(
                        item,
                        expected_flow=item.flow,
                        expected_responder_aid=RESPONDER_AID,
                        expected_verifier_aid=VERIFIER_AID,
                        expected_apr_signer_public_key=APR_KEY,
                        expected_session_context=SESSION_CONTEXT,
                        expected_session_policy_hash=POLICY_HASH,
                        required_predicates=BASE_POLICY,
                        zkc_verifier=accept_test_zkc_boundary,
                    )


if __name__ == "__main__":
    unittest.main()
