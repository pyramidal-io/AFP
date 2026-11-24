"""Venue-neutral AFP payment quote v2 tests."""

from __future__ import annotations

import _path  # noqa: F401

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import unittest

from afp_payment import (
    MAX_U128,
    AfpPaymentPolicyV2,
    AfpPaymentQuoteV2,
    PaymentQuoteError,
    settlement_amount_atomic,
    venue_profile_descriptor,
)
from afp_session.canonical import canonical_json
from afp_session.profiles import default_registry
from payment_fixtures import payment_quote

from venue_fixtures import (
    venue_deployment as deployment, venue_policy as policy, venue_quote as quote,
)


class TestPaymentVenueV2(unittest.TestCase):
    def test_published_descriptor_is_in_default_registry_without_activation(self):
        registry = default_registry()
        self.assertTrue(registry.is_registered("pay_venue"))
        self.assertEqual(registry.get("pay_venue").policy_schema_ref, "afp:payment-policy:v2")
        self.assertEqual(registry.get("pay_venue"), venue_profile_descriptor())
        self.assertEqual(registry.get("pay").policy_schema_ref, "afp:payment-policy:v1")

    def test_pinned_cross_implementation_quote_and_context_vector(self):
        path = Path(__file__).resolve().parents[2] / "docs/payment_venue_v2_conformance.json"
        vector = json.loads(path.read_text())
        value = AfpPaymentQuoteV2.from_dict(vector["quote"])
        self.assertEqual(value.canonical_json, vector["canonical_quote_content"])
        self.assertEqual(value.quote_hash, vector["quote_hash"])
        self.assertEqual(value.interaction_context, vector["interaction_context"])
        payment_policy = AfpPaymentPolicyV2.from_dict(vector["policy"])
        self.assertEqual(payment_policy.policy_hash, vector["policy_hash"])
        value.validate(payment_policy)

    def test_fields_and_chain_numbers_reject_alias_encodings(self):
        for changes in (
            {"contract_class_id": "0x" + "ff" * 32},
            {"anchor_chain_id": "eip155:01"},
            {"anchor_chain_id": "eip155:zero"},
            {"asset_id": "eip155:1/unknown:123"},
            {"fee_route": "unregistered-fpc"},
            {"receipt_profile": "unconstrained-log"},
            {"nullifier_semantics": "standalone-zka"},
        ):
            with self.subTest(changes=changes), self.assertRaises(PaymentQuoteError):
                deployment(**changes)
        with self.assertRaises(PaymentQuoteError):
            quote(session_context="D_" + "11" * 32)
        self.assertEqual(quote(quote_nonce="0x" + "ff" * 32).quote_nonce, "0x" + "ff" * 32)

    def test_round_trip_is_strict_immutable_and_policy_bound(self):
        value = quote()
        value.validate(policy())
        decoded = AfpPaymentQuoteV2.from_dict(value.to_dict())
        self.assertEqual(decoded, value)
        self.assertEqual(decoded.quote_hash, value.quote_hash)
        self.assertEqual(decoded.interaction_context, value.interaction_context)
        self.assertEqual(value.canonical_json, canonical_json(value.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            value.quote_id = "changed"

    def test_quote_signs_exact_venue_recipient_and_manifest_identity(self):
        original = quote()
        changes = (
            {"recipient_id": "0x" + "16" * 32},
            {"manifest_hash": "sha256:" + "12" * 32},
            {"contract_instance_id": "0x" + "23" * 32},
            {"settlement_portal_id": "0x" + "67" * 20},
        )
        for change in changes:
            changed = quote(settlement=replace(original.settlement, **change))
            with self.subTest(change=change):
                self.assertNotEqual(changed.quote_hash, original.quote_hash)

    def test_policy_rejects_any_deployment_identity_mismatch(self):
        changed = replace(quote().settlement, manifest_hash="sha256:" + "12" * 32)
        with self.assertRaisesRegex(PaymentQuoteError, "deployment"):
            quote(settlement=changed).validate(policy())

    def test_quote_binds_complete_policy_not_only_visible_settlement(self):
        original = policy()
        substitutions = (
            replace(
                original,
                deployment=replace(
                    original.deployment, asset_commitment="0x" + "16" * 32
                ),
            ),
            replace(
                original,
                deployment=replace(
                    original.deployment, contract_class_id="0x" + "17" * 32
                ),
            ),
            replace(original, required_finality="safe"),
        )
        for substituted in substitutions:
            with self.subTest(policy=substituted), self.assertRaisesRegex(
                PaymentQuoteError, "policy_hash"
            ):
                quote().validate(substituted)

    def test_exact_arithmetic_and_u128_bound(self):
        self.assertEqual(settlement_amount_atomic("1", "3", "10"), "4")
        maximum = str(MAX_U128)
        self.assertEqual(settlement_amount_atomic(maximum, "1", "1"), maximum)
        with self.assertRaisesRegex(PaymentQuoteError, "u128"):
            settlement_amount_atomic(str(MAX_U128 + 1), "1", "1")
        with self.assertRaisesRegex(PaymentQuoteError, "u128"):
            replace(quote().settlement, amount_atomic=str(MAX_U128 + 1))

    def test_wire_decoders_reject_unknown_or_missing_fields(self):
        for mutate in (
            lambda wire: wire.update({"unknown": True}),
            lambda wire: wire["settlement"].pop("recipient_id"),
            lambda wire: wire["rate"].update({"weth_wei": "1"}),
        ):
            wire = quote().to_dict()
            mutate(wire)
            with self.subTest(wire=wire), self.assertRaises(PaymentQuoteError):
                AfpPaymentQuoteV2.from_dict(wire)
        wire = policy().to_dict()
        wire["deployment"]["unknown"] = True
        with self.assertRaises(PaymentQuoteError):
            AfpPaymentPolicyV2.from_dict(wire)

    def test_canonical_venue_identity_encodings_fail_closed(self):
        invalid = (
            {"network_id": "AZTEC:mainnet"},
            {"anchor_chain_id": "1"},
            {"asset_id": "eip155:8453/erc20:0x" + "c0" * 20},
            {"contract_instance_id": "0x1234"},
            {"settlement_portal_id": "0x" + "00" * 20},
            {"manifest_hash": "D_" + "11" * 32},
            {"recipient_id": "0x" + "00" * 32},
        )
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(PaymentQuoteError):
                replace(quote().settlement, **change)

    def test_v1_base_quote_bytes_and_hash_remain_unchanged(self):
        legacy = payment_quote()
        self.assertEqual(legacy.kind, "afp:payment-quote:v1")
        self.assertNotIn("venue_profile", legacy.to_dict()["settlement"])
        self.assertEqual(
            legacy.quote_hash,
            "D_7989872224a89be915f090074f94cfc0eb9b2b17be38768d7c9474baf8d938d7",
        )


if __name__ == "__main__":
    unittest.main()
