"""ZKA/Pay interaction-context fold v1 KATs (ADR-0006, §15.4).

Consumes the published spec artifact ``docs/pay_interaction_context_kat_v1
.json`` byte-identically — a verbatim copy of ``src/zka-sdk/tests/fixtures/
interaction_context_kat.json`` at immutable revision ``db39afd`` (profile v1).  Its
SHA-256 is pinned below (and in §15.4), so any local drift — edit,
re-format, or a silent re-vendor of a changed upstream — fails this suite
rather than passing as a "fixed" fixture.  Drift in any vector is a breaking
change to the frozen profile, not a fixture to update
(sdd_pay_interaction_binding.md §7); a deliberate upstream v2 reaches AFP
only via a superseding ADR.
"""

from __future__ import annotations

import _path  # noqa: F401

import hashlib
import json
import unittest
from pathlib import Path

from afp_payment import INTERACTION_CONTEXT_TAG, fold_interaction_context

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "pay_interaction_context_kat_v1.json"
)
FIXTURE_SHA256 = "e0d7fd0442b3cfd14c21c949ae13bcf9fba4250b2067300f729aaad2d38a2a8d"
EXPECTED_LABELS = [
    "small-ints",
    "one-one",
    "max-canonical",
    "keccak-derived-quote",
    "asymmetry-pair",
]


class TestInteractionContextKats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = FIXTURE_PATH.read_bytes()
        cls.fixture = json.loads(cls.raw)

    def test_fixture_is_the_pinned_zka_artifact(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(self.fixture["version"], 1)
        self.assertEqual(self.fixture["profile"], "zka/pay/interaction-context/v1")
        self.assertEqual(self.fixture["spec"], "docs/sdd/sdd_pay_interaction_binding.md")
        self.assertEqual(
            int(self.fixture["tag_hex"], 16), INTERACTION_CONTEXT_TAG
        )

    def test_every_frozen_vector_reproduces(self):
        labels = [vector["label"] for vector in self.fixture["vectors"]]
        self.assertEqual(labels, EXPECTED_LABELS)
        for vector in self.fixture["vectors"]:
            with self.subTest(label=vector["label"]):
                got = fold_interaction_context(
                    int(vector["afp_quote_hash"], 16),
                    int(vector["session_context"], 16),
                )
                self.assertEqual(
                    got,
                    int(vector["interaction_context"], 16),
                    f"KAT '{vector['label']}' drifted — cross-repo consumers "
                    "depend on these exact values",
                )

    def test_fold_is_order_sensitive(self):
        # A statement about the implementation, not the fixture: swapping
        # the operands changes the output (the property the upstream
        # asymmetry-pair vector freezes).
        self.assertNotEqual(
            fold_interaction_context(7, 9), fold_interaction_context(9, 7)
        )


if __name__ == "__main__":
    unittest.main()
