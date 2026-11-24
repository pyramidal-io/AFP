"""The presentation seam's public-input classification is complete and earned."""

import _path  # noqa: F401

import dataclasses
import json
import unittest
from pathlib import Path

from afp_session.presentation import (
    AFP_TELEMETRY_PREDICATE_CATALOG,
    INSTANCE_ATTESTATION_ROOT_CLASSES,
    PresentationBindingError,
    ProvenPredicate,
    ZkcVerifiedPublicStatement,
    ZkcPresentationEvidence,
    verify_presentation_binding,
)
from afp_session.presentation import AfpTrustFlow
from afp_session.presentation_conformance import PROFILE_BASELINES, baseline_case

_REPO = Path(__file__).resolve().parents[2]
TABLE = json.loads(
    (_REPO / "docs" / "afp_presentation_public_input_classification_v1.json").read_text(
        encoding="utf-8"
    )
)
SURFACE = json.loads(
    (_REPO / "protocol-family" / "afp-interface-surface-v1.json").read_text(
        encoding="utf-8"
    )
)

CLASSES = frozenset({"bound", "derived", "free"})

# One mutation per evidence field, per active profile. A field classified bound
# or derived must reject its mutation on that profile; the rejection is what
# earns the classification, and a field the table calls free is one no mutation
# needs to disturb.
EVIDENCE_MUTATIONS = {
    "flow": AfpTrustFlow.INTRODUCTION,
    "profile": "zkc:presentation:anonymous:v1",
    "requested_profile": "zkc:presentation:linkable:v1",
    "presenter_aid": "E-attacker",
    "credential_subject_aid": "E-attacker",
    "proven_predicates": (
        ProvenPredicate(predicate_id="zkc:proof:sanctions:v2", predicate_version="2"),
    ),
    "session_context": "X_" + "ee" * 32,
    "proof_context": "0x" + "ff" * 32,
    "apr_verifier_aid": "E-other-verifier",
    "apr_signer_public_key": bytes.fromhex("03" + "22" * 32),
    "scope_policy": "protocol:afp:0x" + "99" * 32,
    "rotation_epoch": 9,
    "scope_id": 12345,
    "presentation_pseudonym": 999,
    "holder_commitment": 4242,
    "zkc_envelope_version": "zkc:proof:v1",
    "zka_bundle_kind": "zka:bundle:v2",
    "carrier_kind": "afp:credential-envelope:v1",
    "linkable_consent": True,
    "receipt_response": {"holderCommitment": 4242},
    "rotation_binding": {"holderCommitment": 4242},
}

# A handful of fields need a different mutation on a profile whose baseline
# already holds the value above.
PROFILE_MUTATION_OVERRIDES = {
    "anonymous": {
        "profile": "zkc:presentation:scoped:v1",
        "requested_profile": "zkc:presentation:scoped:v1",
        "zkc_envelope_version": "zkc:proof:v1",
        "scope_id": 1,
        "presentation_pseudonym": 1,
        "flow": AfpTrustFlow.INTRODUCTION,
    },
    "linkable": {
        "profile": "zkc:presentation:scoped:v1",
        "requested_profile": "zkc:presentation:scoped:v1",
        "zkc_envelope_version": "zkc:proof:v2",
        "holder_commitment": 0,
        "linkable_consent": False,
        "scope_id": 1,
        "presentation_pseudonym": 1,
        "receipt_response": {"scopeId": 1, "presentationPseudonym": 1},
        "rotation_binding": {"scopeId": 1, "presentationPseudonym": 1},
    },
}


def _classification(row, profile):
    """The class this row claims for one active profile."""
    return row.get("by_profile", {}).get(profile, row["classification"])


def _mutation(field, profile):
    return PROFILE_MUTATION_OVERRIDES.get(profile, {}).get(
        field, EVIDENCE_MUTATIONS[field]
    )


def _rows(key):
    return {row["field"]: row for row in TABLE[key]}


class ClassificationCompletenessTest(unittest.TestCase):
    """No public input reaches the seam without a stated classification."""

    def test_every_evidence_field_is_classified(self):
        declared = set(_rows("evidence_fields"))
        actual = {f.name for f in dataclasses.fields(ZkcPresentationEvidence)}
        self.assertEqual(
            declared,
            actual,
            "the classification table and ZkcPresentationEvidence disagree; "
            "an unclassified public input is an unstated trust assumption",
        )

    def test_every_predicate_field_is_classified(self):
        declared = set(_rows("predicate_fields"))
        actual = {f.name for f in dataclasses.fields(ProvenPredicate)}
        self.assertEqual(declared, actual)

    def test_every_verified_statement_field_is_classified(self):
        declared = set(_rows("verified_statement_fields"))
        actual = {f.name for f in dataclasses.fields(ZkcVerifiedPublicStatement)}
        self.assertEqual(declared, actual)

    def test_every_row_declares_a_known_class(self):
        for key in (
            "evidence_fields",
            "predicate_fields",
            "verified_statement_fields",
        ):
            for field, row in _rows(key).items():
                with self.subTest(field=field):
                    self.assertIn(row["classification"], CLASSES)
                    self.assertTrue(row["rationale"].strip())
                    self.assertTrue(row["spec_reference"].strip())
                    for profile_class in row.get("by_profile", {}).values():
                        self.assertIn(profile_class, CLASSES)

    def test_a_free_field_names_no_comparand(self):
        # The distinction the table exists to make: a free field is one the
        # presenter chooses, so claiming a comparand for it would be a false
        # statement about what the verifier checks.
        for key in (
            "evidence_fields",
            "predicate_fields",
            "verified_statement_fields",
        ):
            for field, row in _rows(key).items():
                if row["classification"] == "free":
                    with self.subTest(field=field):
                        self.assertIsNone(row["comparand"])

    def test_a_bound_or_derived_field_names_its_comparand(self):
        for key in (
            "evidence_fields",
            "predicate_fields",
            "verified_statement_fields",
        ):
            for field, row in _rows(key).items():
                if row["classification"] in ("bound", "derived"):
                    with self.subTest(field=field):
                        self.assertTrue((row["comparand"] or "").strip())


class ClassificationIsEarnedTest(unittest.TestCase):
    """A bound or derived claim is demonstrated by mutation, not asserted."""

    def _verify(self, evidence, arguments):
        verify_presentation_binding(evidence, **arguments)

    def test_every_mutation_is_defined(self):
        self.assertEqual(set(EVIDENCE_MUTATIONS), set(_rows("evidence_fields")))

    def test_each_profile_baseline_is_accepted(self):
        for profile, build in PROFILE_BASELINES.items():
            with self.subTest(profile=profile):
                evidence, arguments = build()
                self._verify(evidence, arguments)

    def test_bound_and_derived_fields_reject_a_mutation(self):
        for profile, build in PROFILE_BASELINES.items():
            for field, row in _rows("evidence_fields").items():
                claimed = _classification(row, profile)
                if claimed not in ("bound", "derived"):
                    continue
                with self.subTest(profile=profile, field=field):
                    evidence, arguments = build()
                    with self.assertRaises(
                        PresentationBindingError,
                        msg=f"on the {profile} profile {field} is classified "
                        f"{claimed} but its mutation was accepted",
                    ):
                        # Construction is part of admission: a rejected
                        # discriminator/shape pair must not be built merely
                        # to exercise a later verification check.
                        mutated = dataclasses.replace(
                            evidence, **{field: _mutation(field, profile)}
                        )
                        self._verify(mutated, arguments)

    def test_carrier_and_bundle_discriminators_are_bound_together_on_every_profile(self):
        for profile, build in PROFILE_BASELINES.items():
            evidence, arguments = build()
            # Both supported shapes remain admissible at this presentation
            # seam with its existing synthetic structured verifier. Actual
            # signed/encrypted carriage is independently checked by receive.
            native = dataclasses.replace(
                evidence, carrier_kind="afp:credential-envelope:v1", zka_bundle_kind=None
            )
            with self.subTest(profile=profile, carrier="native"):
                self._verify(native, arguments)
            for carrier, bundle in (
                ("afp:credential-envelope:v1", "zka:bundle:v1"),
                ("zka:bundle:v1", None),
                ("afp:credential-envelope:v2", None),
            ):
                with self.subTest(profile=profile, carrier=carrier, bundle=bundle):
                    with self.assertRaises(PresentationBindingError):
                        mutated = dataclasses.replace(
                            evidence, carrier_kind=carrier, zka_bundle_kind=bundle
                        )
                        self._verify(mutated, arguments)

    def test_predicate_meaning_fields_reject_a_mutation(self):
        # root_class and root_authority_identifier are enforced against the
        # signed pairs; predicate_id and predicate_version against the policy
        # and the identifier's own version token.
        from afp_session.presentation_conformance import (
            PRESENTATION_REJECTION_VECTORS,
            run_presentation_conformance,
        )

        report = run_presentation_conformance(verify_presentation_binding)
        self.assertEqual(report.failures(), [], report.summary())
        covered = {vector.vector_id for vector in PRESENTATION_REJECTION_VECTORS}
        for required in (
            "meaning-unaccepted-predicate",
            "meaning-unmatched-attestation-root",
            "meaning-unmatched-attestation-class",
        ):
            self.assertIn(required, covered)
            self.assertTrue(report.result(required).ok, report.summary())

    def test_verified_statement_fields_have_negative_vectors(self):
        from afp_session.presentation_conformance import PRESENTATION_REJECTION_VECTORS

        covered = {vector.vector_id for vector in PRESENTATION_REJECTION_VECTORS}
        for required in (
            "identity-proof-context",
            "identity-flow-relabel-both-fields",
            "identity-verified-credential-subject",
            "meaning-verified-predicate-disagreement",
        ):
            self.assertIn(required, covered)


class CatalogDoesNotDriftTest(unittest.TestCase):
    """The closed catalog and root classes match their published sources."""

    def test_telemetry_catalog_matches_the_interface_surface(self):
        published = {entry["id"] for entry in SURFACE["telemetry_predicates"]}
        self.assertEqual(
            AFP_TELEMETRY_PREDICATE_CATALOG,
            frozenset(published),
            "the closed §6.3 catalog in afp_session.presentation has drifted from "
            "the published interface surface",
        )

    def test_root_classes_match_the_specification(self):
        spec = (_REPO / "docs" / "afp_specification.md").read_text(encoding="utf-8")
        for root_class in INSTANCE_ATTESTATION_ROOT_CLASSES:
            with self.subTest(root_class=root_class):
                self.assertIn(f"'{root_class}'", spec)

    def test_the_table_records_the_closed_catalog_flow(self):
        policy = TABLE["flow_policy"]
        self.assertTrue(policy["telemetry_predicate_catalog_is_closed"])
        self.assertEqual(policy["catalog_constrained_flows"], ["telemetry"])
        self.assertEqual(policy["selected_from"], "expected_flow")


if __name__ == "__main__":
    unittest.main()
