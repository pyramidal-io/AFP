"""AFP-KDC v1.0.3 field-tag derivation and family registry KATs."""

import _path  # noqa: F401

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import afp_session.kdc as kdc_module
from afp_session.kdc import (
    DomainTagError,
    DomainTagRecord,
    derive_entity_subseed,
    derive_field_tag,
    derive_keys,
    encode_fixed_tag,
    load_domain_registry,
    validate_domain_registry,
)
from afp_session.poseidon2 import derive_kdc_keys, load_profile


REGISTRY_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "kdc_v1_0_3_domain_registry.json"
)
PREVIOUS_REGISTRY_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "kdc_v1_0_2_domain_registry.json"
)
HISTORICAL_REGISTRY_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "kdc_v1_0_1_domain_registry.json"
)
KDC_VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "kdc_v1_0_0_test_vectors.json"
)
PROFILE_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "kdc_v1_0_2_poseidon2_parameters.json"
)

EXPECTED_EXTERNAL_FIXED_BYTE_CLASS = {
    "authority": "ZKA",
    "class": "active_fixed_byte",
    "registry_path": "protocol-family/poseidon2-operational-domains-v1.json",
    "encoding": (
        "right-aligned UTF-8 in a 32-byte word, consumed directly as a field element"
    ),
    "included_in_kdc_tags": False,
    "uses_derive_field_tag": False,
    "publication_requirement": (
        "collision-check against the KDC field registry and the ZKA fixed-byte registry"
    ),
}


def assert_external_fixed_byte_contract(
    test: unittest.TestCase, document: dict[str, object]
) -> None:
    validator = getattr(
        kdc_module, "validate_external_operational_tag_classes", None
    )
    test.assertIsNotNone(validator, "external class validator is required")
    assert validator is not None
    validator(document)


def external_metadata_mutations(
    document: dict[str, object],
) -> list[dict[str, object]]:
    mutations = []
    for invalid_classes in (None, {}, [], [None]):
        mutated = json.loads(json.dumps(document))
        mutated["external_operational_tag_classes"] = invalid_classes
        mutations.append(mutated)
    missing_collection = json.loads(json.dumps(document))
    del missing_collection["external_operational_tag_classes"]
    mutations.append(missing_collection)
    for key in EXPECTED_EXTERNAL_FIXED_BYTE_CLASS:
        mutated = json.loads(json.dumps(document))
        del mutated["external_operational_tag_classes"][0][key]
        mutations.append(mutated)
    for key, value in (
        ("authority", "AFP"),
        ("class", "operational"),
        ("registry_path", "docs/kdc_v1_0_3_domain_registry.json"),
        ("encoding", "deriveFieldTag"),
        ("included_in_kdc_tags", True),
        ("uses_derive_field_tag", True),
        ("publication_requirement", "local-only collision check"),
    ):
        mutated = json.loads(json.dumps(document))
        mutated["external_operational_tag_classes"][0][key] = value
        mutations.append(mutated)
    for key in ("included_in_kdc_tags", "uses_derive_field_tag"):
        type_confused = json.loads(json.dumps(document))
        type_confused["external_operational_tag_classes"][0][key] = 0
        mutations.append(type_confused)
    extra_key = json.loads(json.dumps(document))
    extra_key["external_operational_tag_classes"][0]["unreviewed"] = True
    mutations.append(extra_key)
    duplicate = json.loads(json.dumps(document))
    duplicate["external_operational_tag_classes"].append(
        dict(EXPECTED_EXTERNAL_FIXED_BYTE_CLASS)
    )
    mutations.append(duplicate)
    return mutations

EXPECTED_TAGS = {
    "zka/spending",
    "zka/viewing",
    "zka/proof",
    "zka/address",
    "zkc/credential",
    "zkc/binding",
    "zka/nullifier",
    "zka/note",
    "zka/asset",
    "zka/commitment",
    "zkc/claim",
    "zkc/context",
    "zkc/purpose",
    "zkc/apr",
    "zkc/receipt",
    "zkc/presentation-scope:v1",
    "zkc/scope:v1",
    "zkc/verifier-id:v1",
    "zkm/mandate_commitment/v1",
    "zkm/mandate_nullifier/v1",
    "zkm/mandate_nullifier_key/v1",
    "zkm/mandate_root_id/v1",
    "zkm/holder_key/v1",
    "zkm/issuance_key/v1",
    "zkm/control_attestation/v1",
    "zkm/disclosure_binding/v1",
    "zkm/policy/v1",
}


class KdcDerivationTest(unittest.TestCase):
    def test_entity_subseed_reproduces_all_appendix_a5_vectors(self):
        vectors = json.loads(KDC_VECTORS_PATH.read_text(encoding="utf-8"))["vectors"][
            "entity_subseed_hkdf_sha256"
        ]
        self.assertEqual(vectors["algorithm"], "HKDF-SHA256")
        self.assertEqual(vectors["output_length_bytes"], 32)
        for case in vectors["cases"]:
            with self.subTest(case=case["id"]):
                seed = bytes.fromhex(case["tenant_master_seed_hex"][2:])
                self.assertEqual(
                    derive_entity_subseed(seed, case["entity_name"]),
                    bytes.fromhex(case["entity_subseed_hex"][2:]),
                )

    def test_entity_subseed_rejects_invalid_seed_and_entity_name(self):
        for invalid_seed in (True, bytearray(32), b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(invalid_seed=invalid_seed), self.assertRaises(
                DomainTagError
            ):
                derive_entity_subseed(invalid_seed, "entity")
        for invalid_name in (None, True, b"entity", "", "\ud800"):
            with self.subTest(invalid_name=invalid_name), self.assertRaises(
                DomainTagError
            ):
                derive_entity_subseed(b"\x00" * 32, invalid_name)

    def test_entity_subseed_does_not_normalize_unicode_names(self):
        seed = b"\x00" * 32
        self.assertNotEqual(
            derive_entity_subseed(seed, "\u00e9"),
            derive_entity_subseed(seed, "e\u0301"),
        )

    def test_derive_keys_matches_poseidon2_entry_point(self):
        profile = load_profile(PROFILE_PATH)
        seed = bytes.fromhex(
            "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"
        )
        self.assertEqual(derive_keys(seed, profile), derive_kdc_keys(seed, profile))

    def test_clean_room_blake2b512_little_endian_vectors(self):
        self.assertEqual(
            derive_field_tag("zka/spending"),
            0x14046AF3B2A955BB4C450D1B53FFC2798ACC3C2924C3519CF923146B775ACC67,
        )
        self.assertEqual(
            derive_field_tag("zkc/presentation-scope:v1"),
            0x2F7A94A38BB647D343FC7ABC74B6466FE1EB566D71C185CC9537B7E768C466AE,
        )
        self.assertEqual(
            derive_field_tag("zkm/policy/v1"),
            0x21924384B009EC6F6D4FA4058A6282081978D6E026EE2AC3D720470AB2E0BA06,
        )

    def test_fixed_byte_tag_encoding_is_separate_from_field_derivation(self):
        encoded = encode_fixed_tag("kdc/entity-subseed")
        self.assertEqual(len(encoded), 32)
        self.assertEqual(
            encoded.hex(),
            "00000000000000000000000000006b64632f656e746974792d73756273656564",
        )
        self.assertNotEqual(int.from_bytes(encoded, "big"), derive_field_tag("kdc/entity-subseed"))

    def test_fixed_byte_tag_rejects_values_longer_than_32_bytes(self):
        with self.assertRaisesRegex(DomainTagError, "32 bytes"):
            encode_fixed_tag("x" * 33)

    def test_fixed_byte_tag_rejects_leading_nul_alias(self):
        with self.assertRaisesRegex(DomainTagError, "leading NUL"):
            encode_fixed_tag("\x00a")


class FamilyRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.records = load_domain_registry(REGISTRY_PATH)

    def test_registry_pins_reconciled_kdc_patch_and_compatibility(self):
        self.assertEqual(self.document["kdc_version"], "1.0.3")
        self.assertEqual(
            self.document["compatibility"],
            "all-v1.0.0-and-deployed-operational-values-retained",
        )

    def test_v103_registry_is_a_metadata_patch(self):
        v102 = json.loads(PREVIOUS_REGISTRY_PATH.read_text(encoding="utf-8"))
        v103 = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(v103["kdc_version"], "1.0.3")
        self.assertEqual(v103["tags"], v102["tags"])
        self.assertEqual(len(v103["tags"]), 27)
        assert_external_fixed_byte_contract(self, v103)
        self.assertEqual(
            v103["external_operational_tag_classes"],
            [EXPECTED_EXTERNAL_FIXED_BYTE_CLASS],
        )

    def test_v103_registry_rederives_every_unchanged_field_tag(self):
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        records = [
            DomainTagRecord(
                tag=row["tag"],
                owner=row["owner"],
                tag_class=row["class"],
                field_value=int(row["field_hex"], 16),
            )
            for row in document["tags"]
        ]
        validate_domain_registry(records)
        self.assertEqual({record.tag for record in records}, EXPECTED_TAGS)

    def test_v103_fixed_byte_metadata_mutations_fail_closed(self):
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for mutated in external_metadata_mutations(document):
            with self.subTest(mutated=mutated), self.assertRaisesRegex(
                DomainTagError, "external operational tag classes"
            ):
                assert_external_fixed_byte_contract(self, mutated)

    def test_v103_registry_is_the_current_loader_target(self):
        records = load_domain_registry(REGISTRY_PATH)
        self.assertEqual({record.tag for record in records}, EXPECTED_TAGS)
        with self.assertRaisesRegex(DomainTagError, "AFP-KDC v1.0.3"):
            load_domain_registry(PREVIOUS_REGISTRY_PATH)
        self.assertEqual(
            self.document["field_tag_algorithm"],
            'LEInteger(Blake2b-512(UTF8("ZKA-Domain-") || UTF8(tag))) mod BN254.Fr',
        )

    def test_active_loader_rejects_external_metadata_mutations(self):
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for index, mutated in enumerate(external_metadata_mutations(document)):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "registry.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.assertRaisesRegex(
                    DomainTagError, "external operational tag classes"
                ):
                    load_domain_registry(path)

    def test_v102_registry_changes_metadata_only(self):
        historical = json.loads(HISTORICAL_REGISTRY_PATH.read_text(encoding="utf-8"))
        previous = json.loads(PREVIOUS_REGISTRY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(historical["kdc_version"], "1.0.1")
        for field in ("kdc_version", "published_on", "registry_scope"):
            historical.pop(field)
        current = dict(previous)
        for field in ("kdc_version", "published_on", "registry_scope"):
            current.pop(field)
        self.assertEqual(current, historical)

    def test_loader_rejects_historical_registry_as_current(self):
        with self.assertRaises(DomainTagError) as caught:
            load_domain_registry(HISTORICAL_REGISTRY_PATH)
        self.assertIn("AFP-KDC v1.0.3", str(caught.exception))

    def test_registry_is_complete_across_four_owners(self):
        self.assertEqual({record.tag for record in self.records}, EXPECTED_TAGS)
        by_owner = {
            owner: sum(record.owner == owner for record in self.records)
            for owner in {record.owner for record in self.records}
        }
        self.assertEqual(by_owner, {"KDC": 6, "ZKA": 4, "ZKC": 8, "ZKM": 9})

    def test_every_field_is_rederived_and_cross_protocol_collision_free(self):
        validate_domain_registry(self.records)
        self.assertEqual(len({record.field_value for record in self.records}), len(self.records))
        for record in self.records:
            self.assertEqual(record.field_value, derive_field_tag(record.tag), record.tag)

    def test_derivation_and_operational_classes_are_unambiguous(self):
        derivation = {record.tag for record in self.records if record.tag_class == "derivation"}
        self.assertEqual(
            derivation,
            {
                "zka/spending",
                "zka/viewing",
                "zka/proof",
                "zka/address",
                "zkc/credential",
                "zkc/binding",
            },
        )
        self.assertTrue(
            all(record.tag_class == "operational" for record in self.records if record.tag not in derivation)
        )

    def test_validator_rejects_a_field_constant_that_drifted(self):
        first = self.records[0]
        drifted = [replace(first, field_value=first.field_value + 1), *self.records[1:]]
        with self.assertRaisesRegex(DomainTagError, "KAT mismatch"):
            validate_domain_registry(drifted)

    def test_validator_rejects_cross_owner_collisions(self):
        first = next(record for record in self.records if record.owner != "ZKA")
        duplicate = DomainTagRecord(
            tag="zka/collision-fixture",
            owner="ZKA",
            tag_class="operational",
            field_value=first.field_value,
        )
        with self.assertRaisesRegex(DomainTagError, "collision"):
            validate_domain_registry([*self.records, duplicate], rederive=False)

    def test_complete_registry_rejects_a_truncated_family(self):
        validator = getattr(kdc_module, "validate_complete_domain_registry", None)
        self.assertIsNotNone(validator, "complete-family validator is required")
        with self.assertRaisesRegex(DomainTagError, "complete 27-tag contract"):
            validator(self.records[:-1])

    def test_complete_registry_rejects_owner_or_class_swaps(self):
        validator = getattr(kdc_module, "validate_complete_domain_registry", None)
        self.assertIsNotNone(validator, "complete-family validator is required")

        owner_target = next(
            record for record in self.records if record.tag == "zka/spending"
        )
        owner_swapped = [
            replace(record, owner="ZKA") if record.tag == owner_target.tag else record
            for record in self.records
        ]
        with self.assertRaisesRegex(DomainTagError, "owner/class mismatch"):
            validator(owner_swapped)

        class_target = next(
            record for record in self.records if record.tag == "zkc/claim"
        )
        class_swapped = [
            replace(record, tag_class="derivation")
            if record.tag == class_target.tag
            else record
            for record in self.records
        ]
        with self.assertRaisesRegex(DomainTagError, "owner/class mismatch"):
            validator(class_swapped)

    def test_loader_normalizes_non_object_registry_root(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(DomainTagError) as caught:
                load_domain_registry(path)
        self.assertRegex(str(caught.exception), "JSON object")

    def test_loader_normalizes_null_tags_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                json.dumps(
                    {
                        "kdc_version": "1.0.3",
                        "external_operational_tag_classes": [
                            EXPECTED_EXTERNAL_FIXED_BYTE_CLASS
                        ],
                        "tags": None,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(DomainTagError) as caught:
                load_domain_registry(path)
        self.assertRegex(str(caught.exception), "tags must be a list")

    def test_loader_normalizes_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(DomainTagError) as caught:
                load_domain_registry(path)
        self.assertRegex(str(caught.exception), "valid JSON")


if __name__ == "__main__":
    unittest.main()
