"""Regression checks for AFP §6.3 instance-attestation versioning."""

import json
from pathlib import Path
import unittest

import _path  # noqa: F401
from scripts.check_afp_interface_surface import specification_text


# The assembled normative set (ADR-0013): the core with every member in place.
SPEC = specification_text()
ROOT = Path(__file__).resolve().parents[2]

# Derive expectations from the machine-readable interface surface so they track
# the wire surface without coupling to the independent document-revision axis.
SURFACE = json.loads(
    (ROOT / "protocol-family" / "afp-interface-surface-v1.json").read_text(
        encoding="utf-8"
    )
)
INTERFACE_VERSION = SURFACE["interface_version"]
INTERFACE_NUMBER = INTERFACE_VERSION.split("-")[0]
SUPERSEDED_NUMBERS = [
    version.split("-")[0] for version in SURFACE["superseded_interface_versions"]
]


FROZEN_V1_ROW = (
    "| `afp.telemetry.instance_attestation.v1` | \"I am a verified ADAMAS "
    "instance, build hash X\" | Third-party-issued: the ADAMAS publisher signs "
    "a build manifest; the tenant proves possession. | Tenant AID, entity AID "
    "or instance AID, build manifest digest, publisher AID, predicate version, "
    "telemetry window, operator AID. | Publisher-issued ZKC credential, holder "
    "binding key, instance signing key. | At bootstrap, after build change, and "
    "at least once per operator policy window. | "
    "`instance_attestation_missing` or `instance_attestation_invalid`. |"
)


# The v2 public-input and accepted-root shapes are frozen: the organizational
# root AID is the value of `root_authority_identifier`, not a separate field.
# These byte pins reject field additions, renames, and reordering.
FROZEN_V2_PUBLIC_INPUTS = (
    "interface AfpInstanceAttestationPublicInputsV2 {\n"
    "  kind: 'afp:instance-attestation-public-inputs:v2';\n"
    "  tenant_aid: string;\n"
    "  subject_aid: string;                       // entity AID or instance AID\n"
    "  attested_manifest_digest: string;          // canonical digest, defined below\n"
    "  root_class: 'root:build-provenance' | 'root:tee-attestation' | "
    "'root:publisher-manifest';\n"
    "  root_authority_identifier: string;\n"
    "  root_material_digest: string;\n"
    "  attestation_evidence_digest: string;\n"
    "  verification_policy_digest: string;\n"
    "  public_sample_binding_digest: string;      // canonical digest or exact zero "
    "sentinel\n"
    "  predicate_id: 'afp.telemetry.instance_attestation.v2';\n"
    "  predicate_version: '2';\n"
    "  attestation_window: { starts_at: datetime; ends_at: datetime };\n"
    "  verifier_aid: string;\n"
    "  presentation_profile: string;              // active §5.9 profile\n"
    "}"
)


FROZEN_ACCEPTED_ROOTS = (
    "  accepted_instance_attestation_roots: {\n"
    "    root_class: 'root:build-provenance' | 'root:tee-attestation' | "
    "'root:publisher-manifest';\n"
    "    root_authority_identifier: string;\n"
    "  }[];                                      // signed v2 verifier policy; empty "
    "only when v2 is not required"
)


class InstanceAttestationSpecTest(unittest.TestCase):
    def test_v1_catalog_row_remains_byte_identical(self):
        self.assertIn(FROZEN_V1_ROW, SPEC)

    def test_v2_public_inputs_remain_byte_identical(self):
        self.assertEqual(1, SPEC.count(FROZEN_V2_PUBLIC_INPUTS))

    def test_accepted_instance_attestation_roots_remain_byte_identical(self):
        self.assertEqual(1, SPEC.count(FROZEN_ACCEPTED_ROOTS))

    def test_publisher_manifest_binds_witnessed_signing_state_to_root_digest(self):
        branch_start = SPEC.index("- **`root:publisher-manifest`.**")
        branch_end = SPEC.index(
            "\nThe operator-facing predicate catalog remains closed.", branch_start
        )
        branch = SPEC[branch_start:branch_end]

        self.assertIn("`afp:publisher-key-state:v1` JCS bytes", branch)
        self.assertNotIn("are **not** in the private witness", branch)
        self.assertNotIn("does **not** open `root_material_digest`", branch)
        self.assertIn("`signing_public_keys`", branch)
        self.assertIn("`signing_threshold`", branch)
        self.assertIn("equal `root_material_digest`", branch)

    def test_v2_catalog_contract_is_fixed_and_not_draft(self):
        v2_start = SPEC.index("| `afp.telemetry.instance_attestation.v2` |")
        v2_end = SPEC.index("\n| `afp.telemetry.build_currency.v1` |", v2_start)
        v2_row = SPEC[v2_start:v2_end]

        for required in (
            "root class",
            "root-authority identifier",
            "attested manifest digest",
            "attestation-evidence digest",
            "verification-policy digest",
            "public-sample-binding digest",
        ):
            self.assertIn(required, v2_row)
        self.assertEqual(7, len(v2_row.strip().split("|")) - 2)
        self.assertTrue(all(column.strip() for column in v2_row.strip().split("|")[1:-1]))
        self.assertNotIn("DRAFT", v2_row.upper())

    def test_v2_defines_all_root_class_verifier_obligations(self):
        section_start = SPEC.index("### 6.3.1 Instance-attestation root classes")
        section_end = SPEC.index("### 6.4 Public-sample consistency", section_start)
        section = SPEC[section_start:section_end]

        for root_class in (
            "`root:build-provenance`",
            "`root:tee-attestation`",
            "`root:publisher-manifest`",
        ):
            self.assertIn(root_class, section)
        self.assertIn(
            "root_class: 'root:build-provenance' | 'root:tee-attestation' | "
            "'root:publisher-manifest';",
            section,
        )
        self.assertIn("MUST reject an unknown class", section)
        for obligation in (
            "transparency-log inclusion",
            "measurement-to-manifest binding",
            "hardware-vendor root",
            "public-sample binding",
            "SELF-ATTESTED",
            "honest disclosure",
        ):
            self.assertIn(obligation, section)
        self.assertIn("AfpInstanceAttestationPublicInputsV2", section)
        self.assertIn("verifier_aid", section)
        self.assertIn("attestation_window", section)
        self.assertIn("sha256:" + "0" * 64, section)
        self.assertIn("telemetry operator AID", section)
        self.assertIn("counterparty tenant AID", section)
        self.assertIn("circuit proves leaf inclusion", section)
        self.assertIn("RFC 8785", section)
        self.assertIn("exact scheme-native signed bytes", section)
        self.assertIn("apr_verifier_aid", section)
        self.assertIn("scheme-specific log entry", section)

        sample_start = SPEC.index("### 6.4 Public-sample consistency")
        sample_end = SPEC.index("### 6.5 Push model and cadence", sample_start)
        sample_section = SPEC[sample_start:sample_end]
        self.assertIn("For v2 sample bindings", sample_section)
        self.assertIn("verifier_aid", sample_section)
        self.assertIn("attestation_window", sample_section)
        self.assertIn("declines the introduction interaction", sample_section)

    def test_external_digest_source_is_independent_of_the_bound_verifier(self):
        section_start = SPEC.index("### 6.4 Public-sample consistency")
        section_end = SPEC.index("### 6.5 Push model and cadence", section_start)
        section = SPEC[section_start:section_end]

        for required in (
            '"Non-operator" means operationally independent of the verifier for that binding',
            "the operator bound by `sample_context_hash`",
            "under the v2 counterparty mapping, it is `verifier_aid`",
            "MAY operate an AFP transport for another deployment",
            "operated by, controlled by, or under common control with that verifier",
            "A distinct AID does not by itself establish independence",
        ):
            self.assertIn(required, section)

    def test_introduction_profile_consumes_v2(self):
        section_start = SPEC.index("### 14.2 The `afp.introduction.v1` profile")
        section_end = SPEC.index("### 14.3 The handshake", section_start)
        section = SPEC[section_start:section_end]

        self.assertIn("`afp.telemetry.instance_attestation.v2`", section)
        self.assertNotIn("`afp.telemetry.instance_attestation.v1`", section)

        disclosure_start = SPEC.index("### 14.9 Open seams and honest disclosure")
        disclosure_end = SPEC.index("\n---", disclosure_start)
        disclosure = SPEC[disclosure_start:disclosure_end]
        self.assertIn("selected §6.3.1 v2 root path", disclosure)

    def test_current_version_surfaces_advertise_the_interface_version(self):
        # Summary surfaces describe only the current interface, so naming a
        # superseded number here means the surface went stale.
        for relative_path in (
            "website/spec.md",
            "website/llms.txt",
            "website/index.html",
            "website/schema/index.html",
            "docs/afp_concept_brief_v0_1.md",
            "docs/Agent_Federation_Protocol_AFP.md",
            "docs/AFP_AGENT_IDENTITY_ADDENDUM.md",
            "protocol-family/interface-manifest-v1.json",
        ):
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn(INTERFACE_NUMBER, text, relative_path)
            for superseded in SUPERSEDED_NUMBERS:
                self.assertNotIn(superseded, text, relative_path)

    def test_specification_renderings_advertise_the_interface_version(self):
        # These are verbatim renderings of the current-only normative
        # specification generated by website/build.py. They must advertise the
        # current interface without republishing the private evolution record.
        for relative_path in (
            "website/llms-full.txt",
            "website/spec/index.html",
        ):
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn(INTERFACE_NUMBER, text, relative_path)
            self.assertNotIn("Document History", text, relative_path)

    def test_normative_spec_header_advertises_the_interface_version(self):
        # Deliberately not positional: the front matter now carries a second
        # axis, so pinning `splitlines()[2]` would make every additive front
        # matter change look like a version regression. The line must still be
        # present verbatim -- the vendored family manifest asserts that exact
        # string by `text_contains`.
        front_matter = SPEC.split("\n---\n", 1)[0].splitlines()
        self.assertEqual(
            [line for line in front_matter if line.startswith("**Version:**")],
            [f"**Version:** {INTERFACE_VERSION}"],
        )
        self.assertIn(f"**Interface version:** {INTERFACE_VERSION}", front_matter)

    def test_document_revision_is_a_separate_unpinned_axis(self):
        """A prose revision must be able to move without a family action."""

        front_matter = SPEC.split("\n---\n", 1)[0].splitlines()
        revisions = [
            line for line in front_matter if line.startswith("**Document revision:**")
        ]
        self.assertEqual(len(revisions), 1, front_matter)
        self.assertTrue(
            revisions[0].startswith(
                f"**Document revision:** {SURFACE['document_revision']} "
            ),
            revisions[0],
        )
        # The two axes are distinct values, not the same string twice.
        self.assertNotIn(INTERFACE_VERSION, revisions[0])

        # And nothing in the vendored family manifest may reference the prose
        # axis: if it did, an editorial edit would again force a family epoch.
        manifest = json.loads(
            (ROOT / "protocol-family" / "interface-manifest-v1.json").read_text(
                encoding="utf-8"
            )
        )
        for assertion in manifest["projections"]["afp"]["assertions"]:
            expected = assertion.get("expected")
            if isinstance(expected, str):
                self.assertNotIn("Document revision", expected, assertion["id"])
            self.assertNotIn("document_revision", str(assertion.get("pointer", "")))


if __name__ == "__main__":
    unittest.main()
