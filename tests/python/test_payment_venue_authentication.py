"""Authenticated opt-in venue quotes retain the bilateral acceptance boundary."""

import _path  # noqa: F401

from dataclasses import replace
import unittest

from afp_payment import (
    AfpPaymentQuoteV2, InMemoryReplayStore, PaymentQuoteError, accept_payment_quote,
)
from afp_session.canonical import jcs_digest, qb64
from payment_fixtures import (
    accepted_payment_quote_and_ledger, payment_acceptance_inputs, payment_policy,
)
from venue_fixtures import venue_policy, venue_quote


class TestVenueAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Share real immutable signed/session material, never acceptance state.
        cls.inputs = payment_acceptance_inputs(
            policy=venue_policy(), quote_factory=venue_quote, profile="pay_venue",
        )

    def accept(self, **overrides):
        if "profile" in overrides:
            return accepted_payment_quote_and_ledger(
                policy=venue_policy(), quote_factory=venue_quote, **overrides,
            )
        inputs = {**self.inputs, "replay_store": InMemoryReplayStore()}
        transform = overrides.pop("quote_transform", None)
        if transform is not None:
            inputs["quote"] = transform(inputs["quote"])
        inputs.update(overrides)
        return accept_payment_quote(**inputs), inputs["replay_store"]

    def test_signed_quote_survives_sealed_snapshot_and_ledger_binding(self):
        accepted, ledger = self.accept()
        quote = accepted.to_quote()
        self.assertIsInstance(quote, AfpPaymentQuoteV2)
        self.assertEqual(accepted.quote_hash, quote.quote_hash)
        self.assertEqual(accepted.interaction_context, quote.interaction_context)
        self.assertEqual(
            accepted.acceptance_record_hash,
            qb64("D", jcs_digest(quote.to_dict(), floats=True)),
        )
        self.assertTrue(ledger.verifier_view().verify_reservation(
            accepted.quote_id, accepted.quote_hash, accepted.quote_nonce,
            accepted.acceptance_record_hash,
        ))

    def test_legacy_profile_cannot_accept_v2_even_with_matching_v2_policy(self):
        with self.assertRaisesRegex(PaymentQuoteError, "pay_venue profile"):
            self.accept(profile="pay")

    def test_v2_profile_cannot_accept_a_legacy_quote(self):
        with self.assertRaisesRegex(PaymentQuoteError, "pay profile"):
            accepted_payment_quote_and_ledger(profile="pay_venue")

    def test_quote_and_policy_versions_must_match(self):
        with self.assertRaises(PaymentQuoteError):
            self.accept(policy=payment_policy())

    def test_recipient_substitution_invalidates_bilateral_signatures(self):
        def substitute(quote):
            return replace(quote, settlement=replace(
                quote.settlement, recipient_id="0x" + "00" * 31 + "19"
            ))

        with self.assertRaisesRegex(PaymentQuoteError, "signature"):
            self.accept(quote_transform=substitute)

    def test_manifest_substitution_fails_policy_binding(self):
        def substitute(quote):
            return replace(quote, settlement=replace(
                quote.settlement, manifest_hash="sha256:" + "ef" * 32
            ))

        with self.assertRaisesRegex(PaymentQuoteError, "deployment"):
            self.accept(quote_transform=substitute)

    def test_both_signatures_are_required(self):
        for role in ("initiator", "responder"):
            with self.subTest(role=role), self.assertRaisesRegex(
                PaymentQuoteError, "both principal signatures"
            ):
                self.accept(quote_transform=lambda quote: replace(
                    quote, **{role + "_signature": None}
                ))


if __name__ == "__main__":
    unittest.main()
