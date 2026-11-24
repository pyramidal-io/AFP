"""AFP interface-surface gates: the wire surface, not the prose label.

`protocol-family/afp-interface-surface-v1.json` exists so that AFP's interface
version and its document revision can move independently. These tests run the
AFP-local checker in-process and pin the two properties that make the split real
rather than nominal: prose is excluded from `interface_set_id` by construction,
and nothing pins the surface *file*.
"""

import copy
import json
import re
import unittest

from _path import REPO_ROOT
from scripts.check_afp_interface_surface import (
    PROSE_KEYS,
    SECTIONS,
    Failure,
    interface_set_id,
    load_sources,
    parse_version,
    run_checks,
    self_test,
    specification_text,
    ADR_0013_RANGES,
    _add_set_table_rows,
    assemble_set,
    split_adr_0013,
)


SURFACE_RELATIVE = "protocol-family/afp-interface-surface-v1.json"
SPEC_RELATIVE = "docs/afp_specification.md"
SURFACE_PATH = REPO_ROOT / SURFACE_RELATIVE
MANIFEST_PATH = REPO_ROOT / "protocol-family" / "interface-manifest-v1.json"
# The assembled normative set (ADR-0013): FROZEN_* pins hold wherever a record lives.
SPEC = specification_text()


# `interface_set_id` projects `wire_records` to `[id]`; `FROZEN_ENVELOPE`
# independently gates AFP envelope-field changes named by
# `digest_scope.field_content_is_gated_by`.
FROZEN_CREDENTIAL_ENVELOPE = """interface AfpCredentialEnvelope {
  kind: 'afp:credential-envelope:v1';
  session_ref: string;
  session_context: string;             // exact canonical nonzero-projecting X_ digest
  profile: string;                     // the live AFP session profile
  message_class: string;               // authenticated transport class for that profile
  generated_at: number;                // positive whole-second Unix integer
  expires_at: number;                  // positive whole-second Unix integer
  presentation: object;               // unchanged native zkc:proof:v1 or zkc:proof:v2
  apr: object;                        // unchanged signed ZKC Authenticated Proof Request
  sender: AfpPartyRef;                 // current KEL-anchored sender and signature
}"""

FROZEN_ENVELOPE = (
    "interface AfpEnvelope {\n"
    "  kind: 'afp:envelope:v1';\n"
    "  session_ref: string;                 // the bilateral session (§12.2) this "
    "crosses within\n"
    "  session_context: string;             // exact §5.2 X_<64 lowercase hex> "
    "digest (§12.3)\n"
    "  profile: string;                     // profile placing the envelope (e.g. "
    "'vxp' | 'prp' | 'work')\n"
    "\n"
    "  bundle: ZkaBundle;                   // zka:bundle:v1; metadata.context is "
    "the §5.2 BN254 projection\n"
    "  bundle_version: 'zka:bundle:v1';\n"
    "\n"
    "  message_class: string;               // which AFP message class / subject "
    "this rides (§5.3, §12.4)\n"
    "  generated_at: datetime;\n"
    "  expires_at: datetime;\n"
    "}"
)


FROZEN_ZKC_PRESENTATION_CONTEXT_V1 = (
    "interface AfpZkcPresentationContextV1 {\n"
    "  kind: 'afp:zkc-presentation-context:v1';\n"
    "  credential_subject_aid: string;       // == KERI-authenticated presenter entity AID\n"
    "  session_context: string;              // exact \u00a75.2 / \u00a712.3 context\n"
    "  apr_verifier_aid: string;             // APR signer key resolves here through its KEL\n"
    "  presentation_profile: string;         // active, not merely requested, profile\n"
    "  scope_policy: string | null;           // protocol:afp:<profile_policy_hash> iff scoped\n"
    "}"
)


FROZEN_ZKC_PRESENTATION_CONTEXT_V2 = (
    "interface AfpZkcPresentationContextV2 {\n"
    "  kind: 'afp:zkc-presentation-context:v2';\n"
    "  credential_subject_aid: string;       // == KERI-authenticated presenter entity AID\n"
    "  session_context: string;              // exact \u00a75.2 / \u00a712.3 context\n"
    "  apr_verifier_aid: string;             // APR signer key resolves here through its KEL\n"
    "  presentation_profile: string;         // active, not merely requested, profile\n"
    "  scope_policy: string | null;           // protocol:afp:<profile_policy_hash> iff scoped\n"
    "  purpose: 'afp:trust-flow:telemetry' | 'afp:trust-flow:bilateral' | "
    "'afp:trust-flow:introduction' | 'afp:trust-flow:open-federation';\n"
    "}"
)

FROZEN_SESSION_ATOM = (
    "interface AfpSessionAtom {\n"
    "  kind: 'afp:session:v1';\n"
    "  id: string;                       // session id; component of the session context (§5.2 step 4)\n"
    "\n"
    "  // Principals — KERI-aligned (§4). The session is between two ENTITY delegated AIDs,\n"
    "  // each verified up to its TENANT root AID.\n"
    "  initiator: AfpPartyRef;\n"
    "  responder: AfpPartyRef;\n"
    "\n"
    "  // Governing bilateral federation agreement (§5.5) and the profile this session runs.\n"
    "  agreement_ref: string;            // AFP bilateral federation agreement id\n"
    "  agreement_version: string;        // pinned at session open\n"
    "  profile: string;                  // registered profile name (§13.2), e.g. 'prp' | 'vxp' | 'work'\n"
    "  profile_policy_hash: string;      // hash of the profile policy block exchanged at open\n"
    "\n"
    "  // Lifecycle (§12.2.2)\n"
    "  status: AfpSessionStatus;\n"
    "\n"
    "  // Timing / timeout (§12.2.3)\n"
    "  opened_at: uint64;                // §5.2: RFC 8785/JCS JSON integer token, 0..253402300799; exact Unix seconds\n"
    "  expires_at: datetime;             // hard session timeout; REQUIRED\n"
    "  closed_at?: datetime;\n"
    "\n"
    "  // Binding\n"
    "  session_context: string;          // exact SHA-256 / X_ construction in §5.2\n"
    "}"
)

FROZEN_PAYMENT_POLICY_V2 = """interface AfpPaymentPolicyV2 {
  kind: 'afp:payment-policy:v2';
  deployment: VenueDeployment;
  accepted_rate_sources: string[];
  max_quote_lifetime_seconds: number;
  max_slippage_bps: number;
  required_finality: 'safe' | 'finalized';
}"""

FROZEN_PAYMENT_QUOTE_V2 = """interface AfpPaymentQuoteV2 {
  kind: 'afp:payment-quote:v2';
  quote_id: string;
  session_ref: string;
  session_context: string;
  policy_hash: string;
  obligation: { currency: 'USD'; amount_minor: string };
  settlement: VenueSettlement;
  rate: {
    source: string;
    usd_minor: string;
    asset_atomic: string;
    reference_usd_minor: string;
    reference_asset_atomic: string;
  };
  quoted_at: string;
  expires_at: string;
  max_slippage_bps: number;
  quote_nonce: string;
  initiator_signature?: AfpCommitSignature;
  responder_signature?: AfpCommitSignature;
}"""

FROZEN_PAYMENT_RECEIPT_V2 = """interface AfpPaymentReceiptV2 {
  kind: 'afp:payment-receipt:v2';
  quote_ref: string;
  quote_hash: string;
  interaction_context: string;
  settlement: VenueSettlement;
  transaction_id: string;
  output_note_hash: string;                // canonical BN254 scalar; zero allowed
  private_event_log_position: number;      // integer in 0..2^53-1
  observed_at: string;
  finality: 'pending' | 'safe' | 'finalized';
  finality_evidence: object;
}"""


class InterfaceSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.surface = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_published_surface_passes_every_checker_gate(self):
        run_checks(copy.deepcopy(self.surface), load_sources())

    def test_checker_fails_closed_on_reintroduced_drift(self):
        """The checker's own mutation suite: every gate must have teeth."""

        self_test(copy.deepcopy(self.surface), load_sources())

    def test_checker_and_self_test_hold_at_every_adr_0013_stage(self):
        """Each cumulative stage of the split, from whatever stage this checkout is at."""

        sources = load_sources()
        before = assemble_set(sources["spec"], sources["members"])
        for count in range(1, len(ADR_0013_RANGES) + 1):
            with self.subTest(stage=count):
                surface, staged = copy.deepcopy(self.surface), copy.deepcopy(sources)
                split_adr_0013(surface, staged, ranges=ADR_0013_RANGES[:count], table=False)
                self.assertEqual(before, assemble_set(staged["spec"], staged["members"]))
                _add_set_table_rows(surface, staged)
                before_id = interface_set_id(surface)
                run_checks(surface, staged)
                self_test(surface, staged)
                self.assertEqual(self.surface["interface_set_id"], before_id)

    def test_assembly_requires_each_member_exactly_once(self):
        member = "docs/afp_x.md"
        text = "# X\n\n---\n\nBody\n"
        block = f"<!-- afp-set:include {member} -->\nStub `{member}`.\n<!-- afp-set:end -->\n\n"
        self.assertEqual("Core\nBody\n", assemble_set("Core\n" + block, {member: text}))
        for core in ("Core\n", "Core\n" + block + block, "Core\n" + block.replace("<!-- afp-set:end -->\n", "")):
            with self.subTest(core=core):
                with self.assertRaises(Failure):
                    assemble_set(core, {member: text})

    def test_interface_set_id_is_declared_and_reproducible(self):
        self.assertEqual(
            interface_set_id(self.surface), self.surface["interface_set_id"]
        )

    def test_interface_set_id_excludes_prose_by_construction(self):
        """An editorial edit is not a protocol change.

        This is the property the whole file exists for. If prose could move the
        digest, the coupling being removed would reappear one layer down -- and
        would be harder to see, because it would look like a surface change.
        """

        for section, partition in SECTIONS.items():
            for field in partition["digested"]:
                self.assertNotIn(field, PROSE_KEYS, f"{section}.{field}")

        mutated = copy.deepcopy(self.surface)
        rewritten = 0
        for section in SECTIONS:
            for entry in mutated[section]:
                for key in list(entry):
                    if key in PROSE_KEYS and isinstance(entry[key], str):
                        entry[key] = "Rewritten."
                        rewritten += 1
        mutated["purpose"] = "Rewritten."
        mutated["document_axis"]["note"] = "Rewritten."
        self.assertGreater(rewritten, 20)
        self.assertEqual(interface_set_id(mutated), self.surface["interface_set_id"])

    def test_interface_set_id_moves_when_the_surface_moves(self):
        for section, key in (
            ("message_classes", "id"),
            ("telemetry_predicates", "status"),
            ("wire_records", "id"),
            ("profiles", "status"),
        ):
            mutated = copy.deepcopy(self.surface)
            mutated[section][0][key] = "moved"
            self.assertNotEqual(
                interface_set_id(mutated),
                self.surface["interface_set_id"],
                section,
            )
        for scalar in ("envelope", "nats_subject_root"):
            mutated = copy.deepcopy(self.surface)
            mutated[scalar] = "moved"
            self.assertNotEqual(
                interface_set_id(mutated), self.surface["interface_set_id"], scalar
            )
        mutated = copy.deepcopy(self.surface)
        mutated["composes_with"]["zkc"] = "0.5.0-draft"
        self.assertNotEqual(interface_set_id(mutated), self.surface["interface_set_id"])

    def test_interface_set_id_ignores_the_version_labels_it_is_not(self):
        """The digest pins the surface; the labels are pinned separately."""

        for field, value in (
            ("interface_version", "9.9.9-draft"),
            ("document_revision", 99),
            ("family_epoch", "zka:protocol-family:2099-01-01.1"),
        ):
            mutated = copy.deepcopy(self.surface)
            mutated[field] = value
            self.assertEqual(
                interface_set_id(mutated), self.surface["interface_set_id"], field
            )

    def test_nonconforming_reference_correction_rule_is_narrow_and_explicit(self):
        rules = " ".join(self.surface["version_discipline"]["rules"])

        self.assertIn("value excluded by an already-published typed record", rules)
        self.assertIn("require a fresh message", rules)
        self.assertIn("changing a previously specified signature preimage", rules)

    def test_zka_dependency_baseline_exception_is_exact_and_exhausted(self):
        rules = " ".join(self.surface["version_discipline"]["rules"])

        for exact_boundary in (
            "document revision 13",
            "zka:protocol-family:2026-09-03.3",
            "0.9.0-draft to 0.9.1-draft",
            "retaining AFP 0.3.10-draft",
            "MUST NOT be reused",
        ):
            self.assertIn(exact_boundary, rules)

    def test_envelope_record_body_remains_byte_identical(self):
        """The field-content gate interface_set_id deliberately does not provide."""

        self.assertIn(FROZEN_ENVELOPE, SPEC)

    def test_native_credential_record_has_an_independent_field_pin(self):
        self.assertIn(FROZEN_CREDENTIAL_ENVELOPE, SPEC)

    def test_session_atom_record_body_remains_byte_identical(self):
        """The session record has the same field-content gate as the envelope."""

        self.assertIn(FROZEN_SESSION_ATOM, SPEC)

    def test_the_zkc_presentation_context_records_are_pinned(self):
        """The historical and current AFP-authored contexts are byte-pinned.

        ``wire_records`` is projected to ``[id]``, so a member added to this
        struct leaves ``interface_set_id`` unchanged. AFP shares each preimage
        with every ZKC prover that binds it, so a silent field addition would be
        a wire change no gate reports.
        """
        self.assertIn(FROZEN_ZKC_PRESENTATION_CONTEXT_V1, SPEC)
        self.assertIn(FROZEN_ZKC_PRESENTATION_CONTEXT_V2, SPEC)

    def test_payment_venue_v2_wire_records_are_pinned(self):
        """Field changes remain visible beyond the identifier-granular digest."""

        self.assertIn(FROZEN_PAYMENT_POLICY_V2, SPEC)
        self.assertIn(FROZEN_PAYMENT_QUOTE_V2, SPEC)
        self.assertIn(FROZEN_PAYMENT_RECEIPT_V2, SPEC)

    def test_opened_at_fixture_is_a_published_consumer_artifact(self):
        self.assertIn(
            "docs/afp_opened_at_conformance_v1.json",
            self.surface["consumer_gate"]["artifacts"],
        )

    def test_stable_content_fixture_is_a_published_consumer_artifact(self):
        self.assertIn(
            "docs/afp_session_stable_content_v1.json",
            self.surface["consumer_gate"]["artifacts"],
        )

    def test_venue_dispatch_vectors_are_a_published_consumer_artifact(self):
        self.assertIn(
            "docs/payment_venue_v2_dispatch_conformance_v1.json",
            self.surface["consumer_gate"]["artifacts"],
        )

    def test_digest_scope_is_stated_honestly_and_names_live_gates(self):
        """The file must not claim a granularity its projection does not have."""

        scope = self.surface["digest_scope"]
        self.assertEqual(scope["granularity"], "identifier")

        # The claim: a field added to a record does not move the digest.
        mutated = copy.deepcopy(self.surface)
        for entry in mutated["wire_records"]:
            if entry["id"] == self.surface["envelope"]:
                entry["note"] = "A field was added to this record."
        self.assertEqual(
            interface_set_id(mutated), self.surface["interface_set_id"]
        )

        # And every gate the file points at instead must actually exist.
        for reference in scope["field_content_is_gated_by"]:
            module, _, symbol = reference.split(" -- ")[0].partition("::")
            path = REPO_ROOT / module
            self.assertTrue(path.is_file(), module)
            self.assertIn(symbol, path.read_text(encoding="utf-8"), reference)

    def test_no_assertion_pins_the_surface_file_digest(self):
        """Pinning the FILE would break on prose edits.

        ZKA's own suite carries this test for ZKM's statement registry
        (`test_no_assertion_pins_the_zkm_registry_file_digest`) for exactly this
        reason: a whole-file digest moves for non-protocol reasons and trains
        reviewers to re-bless it. The pin is the `/interface_set_id` field.
        """

        for unpinnable in (SURFACE_RELATIVE, SPEC_RELATIVE):
            for projection in self.manifest["projections"].values():
                for assertion in projection["assertions"]:
                    if assertion.get("path") == unpinnable:
                        self.assertNotEqual(
                            assertion["kind"], "sha256_equals", assertion["id"]
                        )
            for binding in self.manifest["artifact_bindings"]:
                self.assertNotEqual(binding.get("path"), unpinnable)

    def test_current_cross_protocol_citations_match_the_composed_tuple(self):
        """An obsolete live dependency label would mislead an implementer."""

        composes_with = self.surface["composes_with"]
        related_protocols = SPEC[
            SPEC.index("### 1.4 Related Protocols") : SPEC.index("#### 1.4.1")
        ]
        self.assertIn(f"| **ZKA** v{composes_with['zka']} |", related_protocols)
        self.assertIn(f"| **ZKC** v{composes_with['zkc']} |", related_protocols)
        self.assertNotIn("introduced in ZKA", related_protocols)

        for start, end in (
            ("### 4.6 Rotation, recovery, succession", "#### 4.6.1 Rotation presentation artifact"),
            ("### 5.9 ZKC v0.4.1-draft presentation profiles and AFP identity continuity", "## 6. Tenant ↔ Operator Telemetry"),
            ("## 9. Freedom Safeguards", "## 10. Open Items"),
        ):
            section = SPEC[SPEC.index(start) : SPEC.index(end, SPEC.index(start))]
            self.assertIn(f"ZKC v{composes_with['zkc']}", section)
            self.assertEqual(
                set(re.findall(r"ZKC v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)", section)),
                {composes_with["zkc"]},
            )

        self.assertNotIn("## Document History", SPEC)
        self.assertNotIn("**Version 0.3.7-draft Changes", SPEC)

    def test_prerelease_promotion_does_not_need_a_numeric_bump(self):
        """`0.3.11-draft` must order below `0.3.11`, not equal to it.

        Every AFP interface version published to date carries `-draft`. If
        `parse_version` flattened the qualifier away, dropping it would fail
        the "superseded is older" and "family pin does not lag" comparisons and
        force an unrelated numeric bump.
        """

        _, draft = parse_version("0.3.11-draft")
        _, final = parse_version("0.3.11")
        self.assertLess(draft, final)
        self.assertLess(final, parse_version("0.3.12-draft")[1])
        self.assertLess(parse_version("0.3.10-draft")[1], draft)

    def test_surface_is_not_part_of_the_vendored_snapshot_set(self):
        """AFP owns this file; ZKA mirrors the other four byte-for-byte."""

        self.assertFalse(self.surface["authority"]["mirrored_from_zka"])
        self.assertEqual(
            self.surface["authority"]["repository"], "pyramidal-io/AFP.dev"
        )
        self.assertEqual(self.surface["authority"]["surface_path"], SURFACE_RELATIVE)

    def test_family_pin_agrees_with_the_vendored_manifest(self):
        pin = self.surface["family_pin"]
        self.assertEqual(
            pin["declared_version"], self.manifest["protocols"]["afp"]["version"]
        )
        self.assertEqual(self.surface["family_epoch"], self.manifest["epoch"])
        self.assertEqual(
            self.surface["envelope"], self.manifest["interfaces"]["afp_envelope"]
        )

    def test_a_family_pin_lagging_a_breaking_change_fails_closed(self):
        """The inequality the family validator cannot express."""

        surface = copy.deepcopy(self.surface)
        surface["superseded_interface_versions"] = [
            "0.3.8-draft",
            "0.3.9-draft",
            "0.3.10-draft",
            "0.3.11-draft",
        ]
        surface["last_breaking_interface_version"] = "0.4.0-draft"
        surface["interface_version"] = "0.4.0-draft"
        with self.assertRaises(Failure):
            run_checks(surface, load_sources())


if __name__ == "__main__":
    unittest.main()
