"""Normative AFP-KDC v1.0.2 Poseidon2 profile and shared-vector gates."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import _path  # noqa: F401
from scripts.check_afp_interface_surface import specification_text

from afp_session.poseidon2 import (
    Poseidon2ProfileError,
    derive_kdc_keys,
    hash_fields,
    load_profile,
    permutation,
    seed_to_field,
    validate_constant_digest,
)
from scripts.validate_kdc_conformance import ConformanceError, _validate_vector_shape


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "docs" / "kdc_v1_0_2_poseidon2_parameters.json"
VECTORS_PATH = ROOT / "docs" / "kdc_v1_0_2_conformance_vectors.json"
SURFACE_PATH = ROOT / "protocol-family" / "afp-interface-surface-v1.json"

# Derive the AFP interface version from the canonical interface surface so KDC
# test expectations track the wire surface, not the document-revision axis.
_SURFACE = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
AFP_INTERFACE_VERSION = _SURFACE["interface_version"]


class Poseidon2ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile(PROFILE_PATH)
        cls.vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    def test_profile_is_normative_and_self_authenticating(self):
        self.assertEqual(self.profile["kdc_version"], "1.0.2")
        self.assertEqual(self.profile["status"], "normative")
        self.assertEqual(self.profile["permutation"]["state_width"], 4)
        self.assertEqual(self.profile["permutation"]["rate"], 3)
        self.assertEqual(self.profile["permutation"]["capacity"], 1)
        self.assertEqual(self.profile["permutation"]["s_box_exponent"], 5)
        self.assertEqual(self.profile["permutation"]["full_rounds"], 8)
        self.assertEqual(self.profile["permutation"]["partial_rounds"], 56)
        validate_constant_digest(self.profile)

    def test_raw_sponge_vectors_cover_arity_and_edge_branches(self):
        raw = self.vectors["rawSponge"]
        self.assertEqual({case["inputLength"] for case in raw}, {0, 1, 2, 3, 4, 6, 7})
        for case in raw:
            with self.subTest(case=case["name"]):
                inputs = [int(value, 16) for value in case["inputs"]]
                self.assertEqual(hash_fields(inputs, self.profile), int(case["output"], 16))

    def test_kdc_vectors_cover_boundaries_branches_and_asymmetric_seed(self):
        cases = self.vectors["kdc"]
        self.assertEqual(
            {case["name"] for case in cases},
            {"zero", "one", "r_minus_1", "r", "r_plus_1", "high_bit", "asymmetric"},
        )
        for case in cases:
            seed = bytes.fromhex(case["seed"][2:])
            with self.subTest(case=case["name"]):
                self.assertEqual(seed_to_field(seed), int(case["kdcInput"], 16))
                self.assertEqual(
                    derive_kdc_keys(seed, self.profile),
                    {
                        key: int(value, 16)
                        for key, value in case["derived"].items()
                    },
                )

    def test_vector_schema_rejects_missing_cases_and_seed_binding_drift(self):
        missing_raw_case = copy.deepcopy(self.vectors)
        missing_raw_case["rawSponge"].pop()
        with self.assertRaisesRegex(ConformanceError, "seven raw sponge"):
            _validate_vector_shape(missing_raw_case)

        wrong_kdc_input = copy.deepcopy(self.vectors)
        wrong_kdc_input["kdc"][0]["kdcInput"] = "0x" + "00" * 31 + "01"
        with self.assertRaisesRegex(ConformanceError, "seed reduction"):
            _validate_vector_shape(wrong_kdc_input)

    def test_vector_schema_binds_parameter_artifact_and_field(self):
        wrong_artifact = copy.deepcopy(self.vectors)
        wrong_artifact["parameterArtifact"] = "docs/other.json"
        with self.assertRaisesRegex(ConformanceError, "parameter artifact"):
            _validate_vector_shape(wrong_artifact)

        wrong_field = copy.deepcopy(self.vectors)
        wrong_field["fieldModulus"] = "0x" + "00" * 31 + "01"
        with self.assertRaisesRegex(ConformanceError, "field modulus"):
            _validate_vector_shape(wrong_field)

    def test_vector_schema_requires_exact_alias_semantics(self):
        wrong_aliases = []

        missing_alias = copy.deepcopy(self.vectors)
        del next(case for case in missing_alias["kdc"] if case["name"] == "r")[
            "kdcAliasOf"
        ]
        wrong_aliases.append(missing_alias)

        extra_alias = copy.deepcopy(self.vectors)
        next(case for case in extra_alias["kdc"] if case["name"] == "zero")[
            "kdcAliasOf"
        ] = "zero"
        wrong_aliases.append(extra_alias)

        wrong_type = copy.deepcopy(self.vectors)
        next(case for case in wrong_type["kdc"] if case["name"] == "r_plus_1")[
            "kdcAliasOf"
        ] = 1
        wrong_aliases.append(wrong_type)

        for vectors in wrong_aliases:
            with self.subTest(vectors=vectors):
                with self.assertRaisesRegex(ConformanceError, "alias"):
                    _validate_vector_shape(vectors)

    def test_vector_schema_requires_exact_provenance(self):
        extra_field = copy.deepcopy(self.vectors)
        extra_field["provenance"]["unreviewed"] = True
        with self.assertRaisesRegex(ConformanceError, "provenance"):
            _validate_vector_shape(extra_field)

        wrong_runtime = copy.deepcopy(self.vectors)
        wrong_runtime["provenance"]["independentRuntimes"].append("unknown runtime")
        with self.assertRaisesRegex(ConformanceError, "provenance"):
            _validate_vector_shape(wrong_runtime)

    def test_parameter_mutation_is_rejected_before_hashing(self):
        mutated = copy.deepcopy(self.profile)
        mutated["permutation"]["round_constants"][0][0] = "0x" + "00" * 31 + "01"
        with self.assertRaisesRegex(Poseidon2ProfileError, "constant digest"):
            validate_constant_digest(mutated)

    def test_cryptographic_entry_points_revalidate_profile_digest(self):
        mutated = copy.deepcopy(self.profile)
        mutated["permutation"]["round_constants"][0][0] = "0x" + "00" * 31 + "01"
        operations = {
            "permutation": lambda: permutation([0, 0, 0, 0], mutated),
            "hash_fields": lambda: hash_fields([1, 2], mutated),
            "derive_kdc_keys": lambda: derive_kdc_keys(b"\x00" * 32, mutated),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                with self.assertRaisesRegex(Poseidon2ProfileError, "constant digest"):
                    operation()

    def test_cryptographic_entry_points_reject_a_self_redigested_profile(self):
        mutated = copy.deepcopy(self.profile)
        mutated["permutation"]["round_constants"][0][0] = "0x" + "00" * 31 + "01"
        encoded = b"".join(
            int(value, 16).to_bytes(32, "big")
            for value in (
                [
                    lane
                    for row in mutated["permutation"]["round_constants"]
                    for lane in row
                ]
                + mutated["permutation"]["internal_matrix"]["diagonal_minus_one"]
            )
        )
        mutated["canonical_constant_encoding"]["sha256"] = hashlib.sha256(
            encoded
        ).hexdigest()
        operations = {
            "permutation": lambda: permutation([0, 0, 0, 0], mutated),
            "hash_fields": lambda: hash_fields([1, 2], mutated),
            "derive_kdc_keys": lambda: derive_kdc_keys(b"\x00" * 32, mutated),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                with self.assertRaisesRegex(Poseidon2ProfileError, "canonical digest"):
                    operation()

    def test_cryptographic_entry_points_revalidate_profile_identity(self):
        mutated = copy.deepcopy(self.profile)
        mutated["status"] = "draft"
        with self.assertRaisesRegex(Poseidon2ProfileError, "not normative"):
            hash_fields([1, 2], mutated)

    def test_initial_state_metadata_is_exact_and_fail_closed(self):
        self.assertEqual(
            self.profile["sponge"]["initial_state"],
            {
                "lanes_0_to_2": "0",
                "lane_3": {
                    "operation": "multiply",
                    "left_operand": "input_length",
                    "right_operand": {"base": 2, "exponent": 64},
                },
            },
        )
        mutated = copy.deepcopy(self.profile)
        mutated["sponge"]["initial_state"]["lane_3"]["right_operand"]["exponent"] = 63
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaisesRegex(Poseidon2ProfileError, "initial state"):
                load_profile(path)

    def test_parameter_shape_and_canonical_encoding_are_fail_closed(self):
        wrong_width = copy.deepcopy(self.profile)
        wrong_width["permutation"]["state_width"] = 3
        with self.assertRaisesRegex(Poseidon2ProfileError, "state_width"):
            validate_constant_digest(wrong_width)

        noncanonical = copy.deepcopy(self.profile)
        noncanonical["permutation"]["round_constants"][0][0] = "0X" + "00" * 32
        with self.assertRaisesRegex(Poseidon2ProfileError, "canonical"):
            validate_constant_digest(noncanonical)

        wrong_orientation = copy.deepcopy(self.profile)
        wrong_orientation["permutation"]["external_matrix"][0][1] = 4
        with self.assertRaisesRegex(Poseidon2ProfileError, "external_matrix"):
            validate_constant_digest(wrong_orientation)

    def test_nonobject_profile_sections_fail_with_profile_errors(self):
        for section, message in (
            ("field", "modulus"),
            ("canonical_constant_encoding", "constant encoding"),
            ("sponge", "initial state"),
        ):
            mutated = copy.deepcopy(self.profile)
            mutated[section] = []
            with self.subTest(section=section), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "profile.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.assertRaisesRegex(Poseidon2ProfileError, message):
                    load_profile(path)

    def test_profile_version_mismatch_is_rejected(self):
        wrong_version = copy.deepcopy(self.profile)
        wrong_version["kdc_version"] = "1.0.1"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(wrong_version), encoding="utf-8")
            with self.assertRaisesRegex(Poseidon2ProfileError, "v1.0.2"):
                load_profile(path)

    def test_exact_rate_does_not_apply_an_extra_trailing_permutation(self):
        state = [1, 2, 3, 3 << 64]
        after_complete_chunk = permutation(state, self.profile)
        correct = hash_fields([1, 2, 3], self.profile)
        self.assertEqual(correct, after_complete_chunk[0])
        self.assertNotEqual(correct, permutation(after_complete_chunk, self.profile)[0])

    def test_host_inputs_do_not_gain_implicit_aliases(self):
        for invalid in (True, -1, int(self.profile["field"]["modulus"])):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(Poseidon2ProfileError, "canonical fields"):
                    hash_fields([invalid], self.profile)
        for invalid_seed in (b"", b"\x00" * 31, b"\x00" * 33, bytearray(32)):
            with self.subTest(invalid_seed=invalid_seed):
                with self.assertRaisesRegex(Poseidon2ProfileError, "exactly 32 bytes"):
                    seed_to_field(invalid_seed)
        for invalid_state in (
            [1, 2, 3],
            [1, 2, 3, int(self.profile["field"]["modulus"])],
        ):
            with self.subTest(invalid_state=invalid_state):
                with self.assertRaisesRegex(Poseidon2ProfileError, "four canonical fields"):
                    permutation(invalid_state, self.profile)

    def test_spec_and_artifacts_form_one_versioned_contract(self):
        spec = specification_text()
        self.assertIn("AFP-KDC v1.0.3", spec)
        self.assertIn("**KDC Version:** 1.0.3", spec)
        self.assertIn(f"AFP {AFP_INTERFACE_VERSION} (§2.2, §4.3, §5.9)", spec)
        self.assertIn(f"|                AFP {AFP_INTERFACE_VERSION}", spec)
        self.assertIn("|  v1.0.3 -- AFP Appendix A:", spec)
        self.assertIn("The active module is **AFP-KDC v1.0.3**", spec)
        self.assertIn("reuses the v1.0.2 Poseidon2 parameter and conformance artifacts", spec)
        self.assertIn("docs/kdc_v1_0_2_poseidon2_parameters.json", spec)
        self.assertIn("docs/kdc_v1_0_2_conformance_vectors.json", spec)
        self.assertEqual(self.vectors["profile"], "afp-kdc:poseidon2:v1.0.2")
        self.assertEqual(
            self.vectors["parameterDigest"],
            self.profile["canonical_constant_encoding"]["sha256"],
        )


if __name__ == "__main__":
    unittest.main()
