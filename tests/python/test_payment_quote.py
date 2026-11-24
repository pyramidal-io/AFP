"""Normative AFP §15.1-§15.4 payment-quote tests."""

from __future__ import annotations

import _path  # noqa: F401
from scripts.check_afp_interface_surface import specification_text

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import pathlib
import unittest

from afp_payment import (
    BASE_CHAIN_ID,
    BASE_WETH9,
    BN254_SCALAR_MODULUS,
    HARD_S3_RISK_PROFILE,
    MAX_NOTE_VALUE_WEI,
    AfpPaymentPolicyV1,
    AfpPaymentQuoteV1,
    Obligation,
    PaymentDeployment,
    PaymentQuoteError,
    Rate,
    Settlement,
    INTERACTION_CONTEXT_TAG,
    derive_interaction_context,
    field_from_digest,
    fold_interaction_context,
    settlement_amount_wei,
    within_slippage,
)
from afp_session.atoms import AfpCommitSignature
from afp_session.canonical import canonical_json, jcs_bytes, qb64
from payment_fixtures import (
    NONCE,
    POOL,
    POOL_CONTEXT,
    SESSION_CONTEXT,
    payment_policy,
    payment_quote,
)


class TestPaymentQuote(unittest.TestCase):
    def test_valid_quote_is_immutable_and_matches_policy(self):
        quote = payment_quote()
        quote.validate(payment_policy())
        self.assertEqual(quote.kind, "afp:payment-quote:v1")
        self.assertEqual(quote.settlement.chain_id, BASE_CHAIN_ID)
        self.assertEqual(quote.settlement.asset, BASE_WETH9)
        self.assertEqual(quote.settlement.asset_risk_profile, HARD_S3_RISK_PROFILE)
        with self.assertRaises(FrozenInstanceError):
            quote.quote_id = "changed"

    def test_canonical_serialization_uses_strings_and_omits_absent_signatures(self):
        quote = payment_quote()
        wire = quote.to_dict()
        self.assertEqual(wire["obligation"], {"currency": "USD", "amount_minor": "2500"})
        self.assertEqual(wire["settlement"]["amount_wei"], "10000000000000000")
        self.assertNotIn("initiator_signature", wire)
        self.assertNotIn("responder_signature", wire)
        self.assertEqual(quote.canonical_json, canonical_json(wire))
        self.assertEqual(quote.quote_content(), wire)

    def test_round_trip_preserves_canonical_content(self):
        quote = payment_quote()
        decoded = type(quote).from_dict(quote.to_dict())
        self.assertEqual(decoded, quote)
        self.assertEqual(decoded.quote_hash, quote.quote_hash)

    def test_wire_decoder_requires_exact_kinds_and_key_sets(self):
        for mutate in (
            lambda wire: wire.pop("kind"),
            lambda wire: wire.update({"unknown": "malleable"}),
            lambda wire: wire["obligation"].update({"unknown": "nested"}),
            lambda wire: wire["settlement"].update({"unknown": "nested"}),
            lambda wire: wire["rate"].update({"unknown": "nested"}),
        ):
            wire = payment_quote().to_dict()
            mutate(wire)
            with self.subTest(wire=wire), self.assertRaises(PaymentQuoteError):
                type(payment_quote()).from_dict(wire)

        for mutate in (
            lambda wire: wire.pop("kind"),
            lambda wire: wire.update({"unknown": "malleable"}),
            lambda wire: wire["deployment"].update({"unknown": "nested"}),
            lambda wire: wire.update({"accepted_rate_sources": "ab"}),
            lambda wire: wire.update({"accepted_rate_sources": ("source",)}),
        ):
            wire = payment_policy().to_dict()
            mutate(wire)
            with self.subTest(wire=wire), self.assertRaises(PaymentQuoteError):
                AfpPaymentPolicyV1.from_dict(wire)

    def test_quote_hash_has_fixed_canonical_vector(self):
        quote = payment_quote()
        self.assertEqual(
            quote.quote_hash,
            "D_7989872224a89be915f090074f94cfc0eb9b2b17be38768d7c9474baf8d938d7",
        )

    def test_exact_ceiling_arithmetic(self):
        self.assertEqual(settlement_amount_wei("1", "3", "10"), "4")
        self.assertEqual(settlement_amount_wei("2", "4", "10"), "5")
        self.assertEqual(
            settlement_amount_wei("2500", "250000", "1000000000000000000"),
            "10000000000000000",
        )
        with self.assertRaisesRegex(PaymentQuoteError, "settlement amount"):
            payment_quote(
                settlement=replace(payment_quote().settlement, amount_wei="9999999999999999")
            )

    def test_settlement_amount_respects_zka_note_value_bound(self):
        maximum = str(MAX_NOTE_VALUE_WEI)
        settlement = replace(payment_quote().settlement, amount_wei=maximum)
        self.assertEqual(settlement.amount_wei, maximum)
        self.assertEqual(settlement_amount_wei(maximum, "1", "1"), maximum)

        too_large = str(MAX_NOTE_VALUE_WEI + 1)
        with self.assertRaisesRegex(PaymentQuoteError, r"settlement.amount_wei.*2\^120 - 1"):
            replace(payment_quote().settlement, amount_wei=too_large)
        with self.assertRaisesRegex(PaymentQuoteError, r"settlement.amount_wei.*2\^120 - 1"):
            settlement_amount_wei(too_large, "1", "1")

    def test_slippage_uses_exact_cross_multiplication(self):
        self.assertTrue(within_slippage("101", "100", "100", "100", 100))
        self.assertFalse(within_slippage("102", "100", "100", "100", 100))
        with self.assertRaisesRegex(PaymentQuoteError, "slippage"):
            payment_quote(
                settlement=replace(
                    payment_quote().settlement, amount_wei="9803921568627451"
                ),
                rate=Rate(
                    source="bilateral:base-weth-usd:v1",
                    usd_minor="255000",
                    weth_wei="1000000000000000000",
                    reference_usd_minor="250000",
                    reference_weth_wei="1000000000000000000",
                )
            )

    def test_rejects_noncanonical_or_nonpositive_money_and_rate_integers(self):
        for value in ("", "0", "00", "01", "-1", "+1", "1.0", "1e3", " 1", 1):
            with self.subTest(value=value), self.assertRaises(PaymentQuoteError):
                payment_quote(obligation=Obligation(currency="USD", amount_minor=value))
        for field in ("usd_minor", "weth_wei", "reference_usd_minor", "reference_weth_wei"):
            with self.subTest(field=field), self.assertRaises(PaymentQuoteError):
                payment_quote(rate=replace(payment_quote().rate, **{field: "01"}))

    def test_rejects_wrong_currency_chain_asset_or_risk_profile(self):
        builders = (
            lambda: Obligation(currency="EUR", amount_minor="2500"),
            lambda: replace(payment_quote().settlement, chain_id=1),
            lambda: replace(payment_quote().settlement, asset=POOL),
            lambda: replace(
                payment_quote().settlement,
                asset_risk_profile="zka:asset-risk:s3-soft:v1",
            ),
        )
        for builder in builders:
            with self.subTest(builder=builder), self.assertRaises(PaymentQuoteError):
                builder()

    def test_rejects_noncanonical_addresses_nonce_and_pool_context(self):
        mixed_case = "0x1234567890aBcdef1234567890abcdef12345678"
        builders = (
            lambda: replace(payment_quote().settlement, pool=mixed_case),
            lambda: replace(payment_quote().settlement, pool="0x1234"),
            lambda: payment_quote(quote_nonce=NONCE.upper()),
            lambda: payment_quote(quote_nonce="0x01"),
            lambda: replace(
                payment_quote().settlement, pool_context="0x" + "00" * 32
            ),
            lambda: replace(
                payment_quote().settlement,
                pool_context=f"0x{BN254_SCALAR_MODULUS:064x}",
            ),
        )
        for builder in builders:
            with self.subTest(builder=builder), self.assertRaises(PaymentQuoteError):
                builder()

    def test_rejects_invalid_or_noncanonical_timestamps_and_order(self):
        invalid = (
            {"quoted_at": "2026-07-11T12:00:00.000Z"},
            {"quoted_at": "2026-07-11T12:00:00+00:00"},
            {"quoted_at": "2026-02-30T12:00:00Z"},
            {"expires_at": "2026-07-11T12:00:00Z"},
            {"expires_at": "2026-07-11T11:59:59Z"},
        )
        for override in invalid:
            with self.subTest(override=override), self.assertRaises(PaymentQuoteError):
                payment_quote(**override)

    def test_rejects_invalid_ids_sources_and_slippage_bounds(self):
        builders = (
            lambda: payment_quote(quote_id=""),
            lambda: payment_quote(session_ref=""),
            lambda: payment_quote(session_context=""),
            lambda: replace(payment_quote().rate, source=""),
            lambda: payment_quote(max_slippage_bps=-1),
            lambda: payment_quote(max_slippage_bps=10001),
            lambda: payment_quote(max_slippage_bps=1.0),
        )
        for builder in builders:
            with self.subTest(builder=builder), self.assertRaises(PaymentQuoteError):
                builder()

    def test_policy_is_strict_and_quote_must_match_it(self):
        policy = payment_policy()
        self.assertEqual(policy.kind, "afp:payment-policy:v1")
        for bad_policy in (
            {"accepted_rate_sources": ()},
            {"accepted_rate_sources": ("source", "source")},
            {"accepted_rate_sources": ("",)},
            {"max_quote_lifetime_seconds": 0},
            {"max_slippage_bps": 10001},
            {"required_finality": "pending"},
        ):
            with self.subTest(bad_policy=bad_policy), self.assertRaises(PaymentQuoteError):
                payment_policy(**bad_policy)

        mismatches = (
            payment_policy(deployment=replace(policy.deployment, pool="0x" + "34" * 20)),
            payment_policy(accepted_rate_sources=("different-source",)),
            payment_policy(max_quote_lifetime_seconds=299),
            payment_policy(max_slippage_bps=99),
        )
        for mismatched_policy in mismatches:
            with self.subTest(policy=mismatched_policy), self.assertRaises(PaymentQuoteError):
                payment_quote().validate(mismatched_policy)

    def test_policy_deployment_round_trip(self):
        policy = payment_policy()
        decoded = AfpPaymentPolicyV1.from_dict(policy.to_dict())
        self.assertEqual(decoded, policy)
        self.assertEqual(decoded.deployment, PaymentDeployment(
            chain_id=8453,
            asset=BASE_WETH9,
            pool=POOL,
            pool_context=POOL_CONTEXT,
            asset_risk_profile=HARD_S3_RISK_PROFILE,
        ))


class TestPaymentContext(unittest.TestCase):
    # §15.4's published end-to-end conformance vector: the complete canonical
    # quote content is the module fixture with the pinned quote_id and an
    # X-coded session context; BOTH digests exceed r, so the SDD §3.3
    # reduction leg is vector-pinned rather than prose-pinned.
    VECTOR_QUOTE_ID = "quote-2026-08-16-0002"
    VECTOR_SESSION_CONTEXT = "X_" + "ee" * 32
    VECTOR_QUOTE_HASH = (
        "D_f5637ad946fbcc4ca76a7bb137a1796c1eb60c24590d773231d36f4759e8462d"
    )
    VECTOR_QUOTE_FIELD = int(
        "036df29ae103ab7c0dd91f20b01abf9a55b282b9f86e445bde69a363a9e84628", 16
    )
    VECTOR_SESSION_FIELD = int(
        "2d5db5236a286e480dadd814e8e98d7a4e1f4dcd08092ca9df67189f2eeeeeea", 16
    )
    VECTOR_INTERACTION_CONTEXT = (
        "0x26232f5bff7eb274b601df155b7b47abf504fc5778bdc2b35b961d14e5140d6d"
    )
    # The exact canonical quote-content JSON published inline in §15.4; a
    # spec edit that changes it must fail here, not pass silently.
    VECTOR_QUOTE_CONTENT_JSON = (
        '{"expires_at":"2026-07-11T12:05:00Z","kind":"afp:payment-quote:v1",'
        '"max_slippage_bps":100,"obligation":{"amount_minor":"2500","currency":"USD"},'
        '"quote_id":"quote-2026-08-16-0002",'
        '"quote_nonce":"0xabababababababababababababababababababababababababababababababab",'
        '"quoted_at":"2026-07-11T12:00:00Z",'
        '"rate":{"reference_usd_minor":"250000","reference_weth_wei":"1000000000000000000",'
        '"source":"bilateral:base-weth-usd:v1","usd_minor":"250000",'
        '"weth_wei":"1000000000000000000"},'
        '"session_context":"X_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
        '"session_ref":"session-0001",'
        '"settlement":{"amount_wei":"10000000000000000",'
        '"asset":"0x4200000000000000000000000000000000000006",'
        '"asset_risk_profile":"zka:asset-risk:s3-hard:v1","chain_id":8453,'
        '"pool":"0x1234567890abcdef1234567890abcdef12345678",'
        '"pool_context":"0x0101010101010101010101010101010101010101010101010101010101010101"}}'
    )

    def test_published_end_to_end_vector(self):
        quote = payment_quote(
            quote_id=self.VECTOR_QUOTE_ID,
            session_context=self.VECTOR_SESSION_CONTEXT,
        )
        self.assertEqual(
            canonical_json(quote.quote_content()), self.VECTOR_QUOTE_CONTENT_JSON
        )
        self.assertEqual(quote.quote_hash, self.VECTOR_QUOTE_HASH)
        quote_digest = bytes.fromhex(quote.quote_hash.split("_", 1)[1])
        session_digest = bytes.fromhex(
            self.VECTOR_SESSION_CONTEXT.split("_", 1)[1]
        )
        # Both digests exceed r: the reduction changes the value.
        self.assertGreater(int.from_bytes(quote_digest, "big"), BN254_SCALAR_MODULUS)
        self.assertGreater(int.from_bytes(session_digest, "big"), BN254_SCALAR_MODULUS)
        self.assertEqual(field_from_digest(quote_digest), self.VECTOR_QUOTE_FIELD)
        self.assertEqual(field_from_digest(session_digest), self.VECTOR_SESSION_FIELD)
        self.assertEqual(
            fold_interaction_context(
                self.VECTOR_QUOTE_FIELD, self.VECTOR_SESSION_FIELD
            ),
            int(self.VECTOR_INTERACTION_CONTEXT[2:], 16),
        )
        self.assertEqual(quote.interaction_context, self.VECTOR_INTERACTION_CONTEXT)

    def test_quote_exposes_derived_nonzero_context(self):
        quote = payment_quote()
        context = quote.interaction_context
        self.assertEqual(context, derive_interaction_context(quote.quote_hash, SESSION_CONTEXT))
        value = int(context[2:], 16)
        self.assertGreaterEqual(value, 1)
        self.assertLess(value, BN254_SCALAR_MODULUS)

    def test_derivation_rejects_other_derivation_codes(self):
        # §15.4: the quote hash is exactly D_ and the session context exactly
        # X_; any other code is out of profile and never mapped by a fallback.
        payload = "11" * 32
        derive_interaction_context("D_" + payload, "X_" + "22" * 32)
        for quote_hash, session_context in (
            ("X_" + payload, "X_" + "22" * 32),
            ("E_" + payload, "X_" + "22" * 32),
            ("D_" + payload, "D_" + "22" * 32),
            ("D_" + payload, "E_" + "22" * 32),
            ("D_" + payload, "Q_" + "22" * 32),
            ("D_" + payload, None),
        ):
            with self.subTest(
                quote_hash=quote_hash, session_context=session_context
            ), self.assertRaisesRegex(PaymentQuoteError, "canonical"):
                derive_interaction_context(quote_hash, session_context)

    def test_review_repro_v1_quote_requires_x_session_context(self):
        # Review E-5: v1 built and decoded D_/E_/Q_ session contexts.
        wire = payment_quote().to_dict()
        for code in ("D_", "E_", "Q_", "x_"):
            session_context = code + "22" * 32
            with self.subTest(code=code):
                with self.assertRaisesRegex(PaymentQuoteError, "X_ digest"):
                    payment_quote(session_context=session_context)
                with self.assertRaisesRegex(PaymentQuoteError, "X_ digest"):
                    AfpPaymentQuoteV1.from_dict(
                        {**wire, "session_context": session_context}
                    )

    def test_field_from_digest_is_plain_mod_r_and_rejects_zero(self):
        # Reduce the big-endian digest integer modulo r; zero is invalid.
        self.assertEqual(field_from_digest(b"\x00" * 31 + b"\x01"), 1)
        reduced = field_from_digest(b"\xff" * 32)
        self.assertEqual(
            reduced, int.from_bytes(b"\xff" * 32, "big") % BN254_SCALAR_MODULUS
        )
        with self.assertRaises(PaymentQuoteError):
            field_from_digest(bytes(32))  # zero digest reduces to zero
        with self.assertRaises(PaymentQuoteError):
            field_from_digest(
                BN254_SCALAR_MODULUS.to_bytes(32, "big")
            )  # exactly r reduces to zero
        with self.assertRaises(PaymentQuoteError):
            field_from_digest(b"short")

    def test_fold_rejects_non_canonical_inputs(self):
        with self.assertRaises(PaymentQuoteError):
            fold_interaction_context(0, 1)
        with self.assertRaises(PaymentQuoteError):
            fold_interaction_context(1, 0)
        with self.assertRaises(PaymentQuoteError):
            fold_interaction_context(BN254_SCALAR_MODULUS, 1)
        with self.assertRaises(PaymentQuoteError):
            fold_interaction_context(True, True)  # bool is not a field element

    def test_derive_rejects_malformed_qb64_inputs(self):
        with self.assertRaises(PaymentQuoteError):
            derive_interaction_context("no-separator", "X_" + "11" * 32)
        with self.assertRaises(PaymentQuoteError):
            derive_interaction_context("D_" + "11" * 32, "X_" + "11" * 16)
        with self.assertRaises(PaymentQuoteError):
            derive_interaction_context("D_zz" + "11" * 31, "X_" + "11" * 32)
        # Non-canonical hex is rejected, never silently normalized (§15.2).
        with self.assertRaises(PaymentQuoteError):
            derive_interaction_context("D_" + "AB" * 32, "X_" + "11" * 32)
        with self.assertRaises(PaymentQuoteError):
            derive_interaction_context("D_" + "ab " * 32, "X_" + "11" * 32)
        with self.assertRaises(PaymentQuoteError):
            derive_interaction_context("D_" + "11" * 32 + "\n", "X_" + "11" * 32)

    def test_derivation_is_construction_time_and_fail_closed(self):
        # §15.4: derivation happens at quote construction, before any
        # signature exists — an out-of-profile session context or a
        # zero-reducing payload rejects construction itself.
        with self.assertRaises(PaymentQuoteError):
            payment_quote(session_context="not-a-digest")
        zero_reducing = "X_" + format(BN254_SCALAR_MODULUS, "064x")
        with self.assertRaises(PaymentQuoteError):
            payment_quote(session_context=zero_reducing)

    def test_tag_constant_matches_sdd_derivation(self):
        expected = int.from_bytes(
            b"\x00" * 2 + b"zka/pay/interaction-context/v1", "big"
        )
        self.assertEqual(INTERACTION_CONTEXT_TAG, expected)


class TestPaymentCanonicalization(unittest.TestCase):
    # §15.3's published escape-sensitive vector: raw UTF-8 for non-ASCII,
    # short escapes for '"' and '\\', \u0007 for a control character, and
    # no escaping of '<', '>' or '/'. Other "sorted, compact" encoders differ.
    VECTOR_QUOTE_ID = 'quote-\u00e9\u20ac-"\\-\u0007-</script>'
    VECTOR_QUOTE_ID_JCS = '"quote_id":"quote-\u00e9\u20ac-\\"\\\\-\\u0007-</script>"'
    VECTOR_QUOTE_HASH = (
        "D_0871468ad31824902243872ef1ac34123dc295a1cd6f314b0ade204346304398"
    )
    VECTOR_INTERACTION_CONTEXT = (
        "0x1071b098cf8e9c1e8319b6e505d4ee76323e653fc063286ec03a9b4d4e529c72"
    )

    def vector_quote(self):
        return payment_quote(
            quote_id=self.VECTOR_QUOTE_ID, session_context="X_" + "ee" * 32
        )

    def test_review_repro_escape_sensitive_vector_is_jcs(self):
        quote = self.vector_quote()
        preimage = jcs_bytes(quote.quote_content())
        self.assertIn(self.VECTOR_QUOTE_ID_JCS.encode("utf-8"), preimage)
        self.assertEqual(quote.quote_hash, self.VECTOR_QUOTE_HASH)
        self.assertEqual(
            quote.quote_hash, qb64("D", hashlib.sha256(preimage).digest())
        )
        self.assertEqual(quote.interaction_context, self.VECTOR_INTERACTION_CONTEXT)
        # Review E-12: other sorted, compact encoders give other hashes.
        content = quote.quote_content()
        ascii_escaped = json.dumps(
            content, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        html_safe = canonical_json(content).replace("<", "\\u003c")
        for encoding in (ascii_escaped, html_safe):
            with self.subTest(encoding=encoding[:40]):
                self.assertNotEqual(
                    qb64("D", hashlib.sha256(encoding.encode("utf-8")).digest()),
                    self.VECTOR_QUOTE_HASH,
                )

    def test_specification_publishes_the_same_vector(self):
        spec = specification_text()
        self.assertIn(self.VECTOR_QUOTE_ID_JCS, spec)
        self.assertIn(self.VECTOR_QUOTE_HASH, spec)
        self.assertIn(self.VECTOR_INTERACTION_CONTEXT, spec)

    def test_policy_hash_is_jcs(self):
        policy = payment_policy()
        self.assertEqual(
            policy.policy_hash,
            qb64("D", hashlib.sha256(jcs_bytes(policy.to_dict())).digest()),
        )

    def test_acceptance_record_hash_uses_jcs_number_form(self):
        signature = AfpCommitSignature(
            signed_by="E_" + "aa" * 32,
            kel_event_dig="D_" + "bb" * 32,
            signature="cc" * 64,
            signed_at=1752235260.0,
        )
        quote = replace(
            self.vector_quote(),
            initiator_signature=signature,
            responder_signature=replace(signature, signed_at=1752235260.25),
        )
        preimage = jcs_bytes(quote.to_dict(), floats=True)
        self.assertIn(b'"signed_at":1752235260,', preimage)
        self.assertIn(b'"signed_at":1752235260.25,', preimage)
        self.assertNotIn(b"1752235260.0", preimage)
        self.assertEqual(
            quote.acceptance_record_hash,
            qb64("D", hashlib.sha256(preimage).digest()),
        )
        # §1.6.1 records signed_at as a JSON number (AFP-0422); these bytes and
        # this hash are the pre-table values and must not move.
        self.assertEqual(
            quote.acceptance_record_hash,
            "D_94717f53f9a13f4e83027470c1d47fdd9240d72536de8ec5392822a26c658f9d",
        )
        reread = AfpPaymentQuoteV1.from_dict(quote.to_dict())
        self.assertEqual(reread.acceptance_record_hash, quote.acceptance_record_hash)
        self.assertEqual(reread.initiator_signature.signed_at, 1752235260.0)

    def test_signed_at_survives_signer_to_wire_to_reader_with_the_same_hash(self):
        # §1.6.1 / AFP-0422: any finite RFC 8785 number, including a large
        # exponent and an exactly representable large integer token.
        for signed_at in (1752235260, 1752235260.25, 1e23, 2.0**53, 2.0**60):
            with self.subTest(signed_at=signed_at):
                signature = AfpCommitSignature(
                    signed_by="E_" + "aa" * 32,
                    kel_event_dig="D_" + "bb" * 32,
                    signature="cc" * 64,
                    signed_at=signed_at,
                )
                quote = replace(
                    self.vector_quote(),
                    initiator_signature=signature,
                    responder_signature=signature,
                )
                wire_text = jcs_bytes(quote.to_dict(), floats=True)
                reread = AfpPaymentQuoteV1.from_dict(json.loads(wire_text))
                self.assertEqual(
                    jcs_bytes(reread.to_dict(), floats=True), wire_text
                )
                self.assertEqual(
                    reread.acceptance_record_hash, quote.acceptance_record_hash
                )

    def test_wire_reader_rejects_a_signed_at_that_is_not_a_finite_json_number(self):
        wire = self.vector_quote().to_dict()
        wire["initiator_signature"] = {
            "signed_by": "E_" + "aa" * 32,
            "kel_event_dig": "D_" + "bb" * 32,
            "signature": "cc" * 64,
            "signed_at": 1752235260,
        }
        wire["responder_signature"] = dict(wire["initiator_signature"])
        AfpPaymentQuoteV1.from_dict(wire)
        for bad in (None, "1752235260", True, float("nan"), float("inf"),
                    2**53 + 1, 10**400, [1752235260]):
            with self.subTest(signed_at=bad):
                mutated = dict(wire)
                mutated["initiator_signature"] = dict(
                    wire["initiator_signature"], signed_at=bad
                )
                with self.assertRaises(PaymentQuoteError):
                    AfpPaymentQuoteV1.from_dict(mutated)
        missing = dict(wire)
        missing["initiator_signature"] = {
            k: v for k, v in wire["initiator_signature"].items() if k != "signed_at"
        }
        with self.assertRaises(PaymentQuoteError):
            AfpPaymentQuoteV1.from_dict(missing)

    def test_jcs_numbers_match_rfc8785_samples(self):
        # RFC 8785 Appendix B sample IEEE-754 values and their JCS text.
        samples = {
            0.0: "0",
            -0.0: "0",
            5e-324: "5e-324",
            1.7976931348623157e308: "1.7976931348623157e+308",
            9007199254740992.0: "9007199254740992",
            295147905179352830000.0: "295147905179352830000",
            1e21: "1e+21",
            1e20: "100000000000000000000",
            0.000001: "0.000001",
            1e-7: "1e-7",
            333333333.3333333: "333333333.3333333",
            -1.5: "-1.5",
        }
        for value, expected in samples.items():
            with self.subTest(value=value):
                self.assertEqual(jcs_bytes(value, floats=True), expected.encode())
        with self.assertRaises(TypeError):
            jcs_bytes(1.5)
        for value in (float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                jcs_bytes(value, floats=True)


if __name__ == "__main__":
    unittest.main()
