"""Public native-carriage wire/hash/signature fixtures; no ZKC circuit claim."""

import _path  # noqa: F401

import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import unittest

from afp_session import (
    AfpCredentialEnvelope, AfpProfileDescriptor, CredentialEnvelopeError,
    default_registry, ed25519, keri,
)

from afp_session.canonical import jcs_digest, qb64
from afp_session.profiles import ProfileError

ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def native_carriage_fixture_aids():
    """Recompute only the three public AIDs in the fixed carriage recipe."""
    keys = [keri.KeyPair.from_seed(hashlib.sha256(
        ("AFP native credential public fixture key " + str(index)).encode()
    ).digest()) for index in range(8)]

    def inception(index, delegator=None):
        event = keri.KelEvent(
            ilk="dip" if delegator else "icp", sn=0,
            keys=[keys[index].public_qb64],
            next_key_digest=keri._next_key_digest(keys[index + 1].public_key),
            prior_dig=None, witnesses=[], threshold=0, delegator_aid=delegator,
        )
        return qb64("E", jcs_digest(event.content()))

    tenant_a = inception(0)
    entity_a = inception(2, tenant_a)
    tenant_b = inception(4)
    entity_b = inception(6, tenant_b)
    return frozenset((tenant_a, entity_a, entity_b))


class NativeCredentialArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "docs/afp_native_credential_carriage_v1.json").read_text())
        cls.schema = json.loads((ROOT / "schemas/afp-credential-envelope-v1.schema.json").read_text())

    def test_public_identity_literals_match_the_fixed_reproducible_recipe(self):
        self.assertEqual(self.fixture["deterministic_fixture_basis"], {
            "key_seed": 'SHA-256(UTF-8("AFP native credential public fixture key " + decimal counter starting at 0)); public test-only material',
            "session_uuid": "00000000-0000-4000-8000-000000000014",
            "clock": 1700000000,
            "source": "tests/python/test_native_credentials.py::NativeCredentialTest",
        })
        identities = set(re.findall(r"\bE_[0-9a-f]{64}\b", json.dumps(self.fixture)))
        self.assertEqual(identities, native_carriage_fixture_aids())

    def test_published_vectors_pin_the_complete_native_signed_content(self):
        self.assertFalse(self.fixture["production_zkc_interoperability"])
        self.assertEqual(len(self.fixture["vectors"]), 3)
        for vector in self.fixture["vectors"]:
            with self.subTest(vector=vector["id"]):
                raw = json.dumps(vector["envelope"]).encode()
                envelope = AfpCredentialEnvelope.from_json(raw)
                self.assertEqual(envelope.content_hash, vector["content_hash"])
                self.assertTrue(ed25519.verify_strict(
                    envelope.content_hash.encode(), bytes.fromhex(envelope.sender.signature),
                    bytes.fromhex(vector["sender_public_key"]),
                ))
                self.assertEqual(set(envelope.to_dict()), set(self.schema["required"]))
                self.assertNotIn("bundle", envelope.to_dict())
                changed = copy.deepcopy(vector["envelope"])
                changed["apr"]["nonce"] = "0x" + "00" * 32
                self.assertNotEqual(AfpCredentialEnvelope.from_json(json.dumps(changed).encode()).content_hash,
                                    vector["content_hash"])

    def test_schema_and_decoder_reject_outer_extensions_and_non_integer_time(self):
        self.assertFalse(self.schema["additionalProperties"])
        base = self.fixture["vectors"][0]["envelope"]
        for key, value in (("bundle_version", "zka:bundle:v1"), ("generated_at", True),
                           ("generated_at", 1700000000.0), ("sender", None)):
            mutated = copy.deepcopy(base)
            mutated[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(CredentialEnvelopeError):
                AfpCredentialEnvelope.from_json(json.dumps(mutated).encode())

    def test_schema_signature_spelling_is_enforced_without_resigning(self):
        base = self.fixture["vectors"][0]["envelope"]
        for signature in (base["sender"]["signature"].upper(), " " + base["sender"]["signature"], ""):
            mutated = copy.deepcopy(base)
            mutated["sender"]["signature"] = signature
            with self.assertRaises(CredentialEnvelopeError):
                AfpCredentialEnvelope.from_json(json.dumps(mutated).encode())

    def test_a_profile_cannot_claim_the_new_core_carrier_kind(self):
        with self.assertRaises(ProfileError):
            default_registry().register(AfpProfileDescriptor(
                "fixture", "1", "test", ["afp:credential-envelope:v1"], "test-only"
            ))


if __name__ == "__main__":
    unittest.main()
