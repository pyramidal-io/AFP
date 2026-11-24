"""AFP §15.7-§15.8 interaction-local failure conformance tests."""

import _path  # noqa: F401

import unittest

from afp_payment import PaymentQuoteError
from afp_payment.conformance import InteractionLocalFailure


class TestPaymentConformance(unittest.TestCase):
    def test_failure_model_has_only_interaction_local_effect(self):
        failure = InteractionLocalFailure(
            quote_ref="quote-1", reason="proof submission failed"
        )
        self.assertEqual(failure.scope, "interaction")
        self.assertEqual(failure.effects, ())
        self.assertEqual(
            failure.to_dict(),
            {
                "quote_ref": "quote-1",
                "reason": "proof submission failed",
                "scope": "interaction",
                "effects": [],
            },
        )

    def test_nonlocal_or_privileged_controls_are_rejected(self):
        base = {
            "quote_ref": "quote-1",
            "reason": "route failed",
            "scope": "interaction",
            "effects": [],
        }
        forbidden = (
            "note_freeze",
            "withdrawal_gate",
            "admin_override",
            "clawback",
            "forced_reroute",
        )
        for control in forbidden:
            with self.subTest(control=control), self.assertRaises(PaymentQuoteError):
                InteractionLocalFailure.from_dict({**base, control: True})
            with self.subTest(effect=control), self.assertRaises(PaymentQuoteError):
                InteractionLocalFailure.from_dict({**base, "effects": [control]})

    def test_unknown_scope_and_empty_identity_are_rejected(self):
        with self.assertRaises(PaymentQuoteError):
            InteractionLocalFailure.from_dict(
                {"quote_ref": "q", "reason": "x", "scope": "global", "effects": []}
            )
        for field in ("quote_ref", "reason"):
            wire = {
                "quote_ref": "q",
                "reason": "x",
                "scope": "interaction",
                "effects": [],
            }
            wire[field] = ""
            with self.subTest(field=field), self.assertRaises(PaymentQuoteError):
                InteractionLocalFailure.from_dict(wire)


if __name__ == "__main__":
    unittest.main()
