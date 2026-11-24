"""Session-context encoding tests for the §5.2 / §12.3 base contract."""

import _path  # noqa: F401

import json
from pathlib import Path
import unittest

from afp_session.atoms import (
    MAX_OPENED_AT,
    MIN_OPENED_AT,
    AfpPartyRef,
    AfpSessionAtom,
    AfpSessionStatus,
    compute_session_context,
    opened_at_to_rfc3339,
    unix_to_session_datetime,
    validate_opened_at,
)
from afp_session.bundle import BundleError, session_context_field


CONFORMANCE_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "afp_opened_at_conformance_v1.json"
)
CONFORMANCE = json.loads(CONFORMANCE_PATH.read_text(encoding="utf-8"))


def _atom(opened_at: int) -> AfpSessionAtom:
    return AfpSessionAtom(
        id="sess-1",
        initiator=AfpPartyRef("E_i", "E_i", "D_i", "sig"),
        responder=AfpPartyRef("E_r", "E_r", "D_r", ""),
        agreement_ref="agreement",
        agreement_version="1",
        profile="work",
        profile_policy_hash="policy",
        status=AfpSessionStatus.PROPOSED,
        opened_at=opened_at,
        expires_at=unix_to_session_datetime(min(opened_at + 60, MAX_OPENED_AT)),
        session_context="X_" + "01" * 32,
    )


class SessionContextEncodingTest(unittest.TestCase):
    def test_published_vectors_pin_exact_integer_tokens_and_contexts(self):
        """Changing a numeric token, UTC spelling, preimage, or digest breaks this."""
        inputs = CONFORMANCE["session_inputs"]
        for vector in CONFORMANCE["accepted"]:
            with self.subTest(vector=vector["name"]):
                opened_at = vector["opened_at"]
                self.assertIs(type(opened_at), int)
                self.assertEqual(json.dumps(opened_at), vector["canonical_json_token"])
                self.assertEqual(opened_at_to_rfc3339(opened_at), vector["rfc3339_utc"])
                self.assertEqual(validate_opened_at(opened_at), opened_at)
                if opened_at == MAX_OPENED_AT:
                    # §12.2.1: no in-range expires_at can follow the last second.
                    with self.assertRaisesRegex(ValueError, "expires_at"):
                        _atom(opened_at)
                else:
                    wire_text = json.dumps(
                        _atom(opened_at).to_dict(), sort_keys=True, separators=(",", ":")
                    )
                    self.assertEqual(
                        AfpSessionAtom.from_json(wire_text).opened_at, opened_at
                    )
                self.assertEqual(
                    compute_session_context(
                        inputs["initiator_entity_aid"],
                        inputs["responder_entity_aid"],
                        inputs["session_id"],
                        opened_at,
                    ),
                    vector["session_context"],
                )
                self.assertEqual(
                    session_context_field(vector["session_context"]),
                    vector["zka_bundle_context"],
                )

    def test_published_session_context_projects_to_the_normative_zka_field(self):
        published = next(
            vector for vector in CONFORMANCE["accepted"] if vector["name"] == "published"
        )
        self.assertEqual(
            published["session_context"],
            "X_eddb6ad038bd9a1a79c6c1d29ebd7461da0383948b7e6c13dadd6553b97e4a7f",
        )
        self.assertEqual(
            session_context_field(published["session_context"]),
            "0x2c4a3104b3f719739885aaf898b812ed3933e272a498a9cecb558f03f97e4a7b",
        )

    def test_projection_rejects_malformed_or_alternate_session_encodings(self):
        malformed = (
            "",
            "D_" + "11" * 32,
            "0x" + "11" * 32,
            "X_" + "11" * 31,
            "X_" + "AA" * 32,
            "X_" + "gg" * 32,
            " X_" + "11" * 32,
        )
        for value in malformed:
            with self.subTest(value=value), self.assertRaisesRegex(
                BundleError, "canonical X_"
            ):
                session_context_field(value)

    def test_projection_rejects_zero_without_retry_or_substitution(self):
        modulus = (
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        )
        for digest_integer in (0, modulus, 2 * modulus):
            with self.subTest(digest_integer=digest_integer), self.assertRaisesRegex(
                BundleError, "zero BN254"
            ):
                session_context_field(
                    f"X_{digest_integer:064x}"
                )

    def test_published_endpoints_match_the_reference_limits(self):
        accepted = {vector["opened_at"] for vector in CONFORMANCE["accepted"]}
        self.assertIn(MIN_OPENED_AT, accepted)
        self.assertIn(MAX_OPENED_AT, accepted)

    def test_serializer_deserializer_and_context_share_rejection_set(self):
        """No runtime boundary may round or coerce a rejected wire value."""
        inputs = CONFORMANCE["session_inputs"]
        for vector in CONFORMANCE["rejected"]:
            with self.subTest(vector=vector["name"]):
                wire = _atom(MIN_OPENED_AT).to_dict()
                if "raw_json_token" in vector:
                    wire_text = json.dumps(
                        wire, sort_keys=True, separators=(",", ":")
                    ).replace(
                        '"opened_at":0',
                        f'"opened_at":{vector["raw_json_token"]}',
                    )
                    with self.assertRaisesRegex(ValueError, "opened_at"):
                        AfpSessionAtom.from_json(wire_text)

                    # A decoded -0 is indistinguishable from 0. Its rejection
                    # therefore belongs to the byte-level parser above.
                    invalid = json.loads(vector["raw_json_token"])
                    if type(invalid) is int:
                        continue
                else:
                    invalid = vector["opened_at"]
                    wire["opened_at"] = invalid
                    with self.assertRaisesRegex(ValueError, "opened_at"):
                        AfpSessionAtom.from_json(
                            json.dumps(wire, sort_keys=True, separators=(",", ":"))
                        )

                atom = _atom(MIN_OPENED_AT)
                atom.opened_at = invalid
                with self.assertRaisesRegex(ValueError, "opened_at"):
                    atom.to_dict()
                with self.assertRaisesRegex(ValueError, "opened_at"):
                    atom.content_for_party()

                wire = _atom(MIN_OPENED_AT).to_dict()
                wire["opened_at"] = invalid
                with self.assertRaisesRegex(ValueError, "opened_at"):
                    AfpSessionAtom.from_dict(wire)

                with self.assertRaisesRegex(ValueError, "opened_at"):
                    compute_session_context(
                        inputs["initiator_entity_aid"],
                        inputs["responder_entity_aid"],
                        inputs["session_id"],
                        invalid,
                    )

    def test_wire_parser_rejects_duplicate_opened_at_members(self):
        wire_text = json.dumps(
            _atom(MIN_OPENED_AT).to_dict(), sort_keys=True, separators=(",", ":")
        ).replace('"opened_at":0', '"opened_at":0,"opened_at":0')

        with self.assertRaisesRegex(ValueError, "malformed"):
            AfpSessionAtom.from_json(wire_text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
