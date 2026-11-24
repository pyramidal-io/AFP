"""Synthetic holder disclosures exercise exact venue binding and finality gates."""

import _path  # noqa: F401

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from afp_payment import (
    InMemoryReplayStore, SQLiteReplayStore,
    AfpPaymentReceiptV1, AfpPaymentReceiptV2, PaymentQuoteError,
    PaymentReceiptVerificationContext, PaymentRouteEvidenceV2,
)
from afp_payment.quote import BASE_WETH9
from payment_fixtures import accepted_payment_dispatch
from venue_fixtures import venue_policy, venue_quote


DISPATCH_AT = datetime(2026, 7, 11, 12, 2, 0, tzinfo=timezone.utc)
QUOTE_EXPIRES_AT = datetime(2026, 7, 11, 12, 5, 0, tzinfo=timezone.utc)
INCLUDED_AT = "2026-07-11T12:02:30Z"
OUTPUT_NOTE_HASH = "0x" + "00" * 31 + "23"


def venue_evidence(transaction_id, policy, level, *, included_at=INCLUDED_AT,
                   output_note_hash=OUTPUT_NOTE_HASH, private_event_log_position=0):
    evidence = {
        "synthetic_transaction": transaction_id,
        "manifest_hash": policy.deployment.manifest_hash,
        "level": level,
        "output_note_hash": output_note_hash,
        "private_event_log_position": private_event_log_position,
    }
    if level != "pending":
        evidence["included_at"] = included_at
    return evidence


class SyntheticFinalityVerifier:
    """Accept only evidence that proves inclusion strictly before expiry."""

    def verify(self, *, receipt, route, policy, expires_at):
        evidence = receipt.finality_evidence
        if receipt.finality != "pending":
            included_at = evidence.get("included_at")
            if not isinstance(included_at, str) or datetime.strptime(
                included_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc) >= expires_at:
                return False
        return dict(evidence) == venue_evidence(
            route.transaction_id, policy, receipt.finality,
            included_at=evidence.get("included_at", INCLUDED_AT),
            output_note_hash=receipt.output_note_hash,
            private_event_log_position=receipt.private_event_log_position,
        )


class TestVenueReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = venue_policy()
        dispatch = accepted_payment_dispatch(
            policy=cls.policy, quote_factory=venue_quote, profile="pay_venue",
        )
        cls.accepted, cls.ledger = dispatch.accepted, dispatch.ledger
        cls.live_session = dispatch.live_session
        cls.context = PaymentReceiptVerificationContext(
            acceptance_verifier=cls.ledger.verifier_view(),
            finality_verifier=SyntheticFinalityVerifier(),
            clock=lambda: DISPATCH_AT,
        )
        cls.route = cls.context.route_from_accepted(
            cls.accepted, live_session=cls.live_session,
            transaction_id="synthetic-aztec-transaction",
        )

    def receipt(self, **overrides):
        wire = {
            **self.route.to_dict(),
            "kind": "afp:payment-receipt:v2",
            "output_note_hash": OUTPUT_NOTE_HASH,
            "private_event_log_position": 0,
            "observed_at": "2026-07-11T12:02:00Z",
            "finality": "pending",
            "finality_evidence": venue_evidence(
                self.route.transaction_id, self.policy, "pending"
            ),
        }
        wire.update(overrides)
        return AfpPaymentReceiptV2.from_dict(wire)

    def tracker(self):
        return self.context.tracker(
            accepted=self.accepted, route=self.route, policy=self.policy,
        )

    def test_route_and_receipt_roundtrip_preserve_the_full_settlement(self):
        self.assertIsInstance(self.route, PaymentRouteEvidenceV2)
        self.assertEqual(self.route.settlement, self.accepted.to_quote().settlement)
        self.assertEqual(self.context.route_from_dict(
            self.route.to_dict(), accepted=self.accepted,
        ), self.route)
        receipt = self.receipt()
        self.assertEqual(AfpPaymentReceiptV2.from_dict(receipt.to_dict()), receipt)
        with self.assertRaises(PaymentQuoteError):
            AfpPaymentReceiptV1.from_dict(receipt.to_dict())

    def test_every_changed_target_identity_is_rejected_before_finality(self):
        changes = {
            "recipient_id": "0x" + "00" * 31 + "19",
            "contract_instance_id": "0x" + "00" * 31 + "20",
            "settlement_portal_id": "0x" + "12" * 20,
            "manifest_hash": "sha256:" + "fe" * 32,
            "network_id": "aztec:other",
            "amount_atomic": "1",
            "asset_id": "eip155:1/erc20:0x" + "12" * 20,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                wire = self.route.to_dict()
                wire["settlement"][field] = value
                with self.assertRaises(PaymentQuoteError):
                    self.context.route_from_dict(wire, accepted=self.accepted)
                bad = self.receipt(settlement=wire["settlement"])
                with self.assertRaisesRegex(PaymentQuoteError, "settlement"):
                    self.tracker().observe(bad)

    def test_finality_must_verify_and_advance_monotonically(self):
        tracker = self.tracker()
        pending = self.receipt()
        tracker.observe(pending)
        self.assertFalse(tracker.is_settled)
        with self.assertRaises(PaymentQuoteError):
            tracker.observe(pending)
        with self.assertRaisesRegex(PaymentQuoteError, "does not verify"):
            tracker.observe(self.receipt(finality="finalized"))
        final = self.receipt(
            finality="finalized", observed_at="2026-07-11T12:03:00Z",
            finality_evidence=venue_evidence(
                self.route.transaction_id, self.policy, "finalized"
            ),
        )
        tracker.observe(final)
        self.assertTrue(tracker.is_settled)
        with self.assertRaises(PaymentQuoteError):
            tracker.observe(pending)

    def test_accepted_policy_cannot_be_substituted(self):
        for policy in (
            replace(self.policy, required_finality="safe"),
            replace(self.policy, deployment=replace(
                self.policy.deployment, contract_class_id="0x" + "00" * 31 + "24")),
        ):
            with self.assertRaisesRegex(PaymentQuoteError, "policy_hash"):
                self.context.tracker(accepted=self.accepted, route=self.route, policy=policy)

    def test_verified_occurrence_is_pinned_across_finality(self):
        for field, value in (("output_note_hash", "0x" + "00" * 31 + "24"),
                             ("private_event_log_position", 1)):
            tracker = self.tracker()
            tracker.observe(self.receipt())
            wire = self.receipt().to_dict()
            wire.update(finality="finalized", observed_at="2026-07-11T12:03:00Z")
            wire[field] = value
            wire["finality_evidence"].update(
                level="finalized", included_at=INCLUDED_AT, **{field: value})
            candidate = AfpPaymentReceiptV2.from_dict(wire)
            self.assertTrue(SyntheticFinalityVerifier().verify(
                receipt=candidate, route=self.route, policy=self.policy,
                expires_at=QUOTE_EXPIRES_AT))
            with self.assertRaisesRegex(PaymentQuoteError, "occurrence"):
                tracker.observe(candidate)
            self.assertFalse(tracker.is_settled)

    def test_occurrence_fields_are_required_and_canonical(self):
        self.assertEqual(self.receipt(output_note_hash="0x" + "00" * 32).output_note_hash,
                         "0x" + "00" * 32)
        for field, values in {
            "output_note_hash": [ "0x" + "ff" * 32, "bad"],
            "private_event_log_position": [True, -1, 1.0, "0", 1 << 53],
        }.items():
            wire = self.receipt().to_dict()
            del wire[field]
            with self.assertRaises(PaymentQuoteError):
                AfpPaymentReceiptV2.from_dict(wire)
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(PaymentQuoteError):
                        self.receipt(**{field: value})

    def test_route_claim_cannot_be_reused_for_another_transaction(self):
        with self.assertRaises(PaymentQuoteError):
            self.context.route_from_accepted(
                self.accepted, live_session=self.live_session, transaction_id="another")

    def test_receipt_schema_and_evidence_are_strict_and_detached(self):
        wire = self.receipt().to_dict()
        wire["unexpected"] = True
        with self.assertRaises(PaymentQuoteError):
            AfpPaymentReceiptV2.from_dict(wire)
        with self.assertRaises(PaymentQuoteError):
            self.receipt(finality_evidence={})
        wire = self.receipt().to_dict()
        parsed = AfpPaymentReceiptV2.from_dict(wire)
        wire["settlement"]["recipient_id"] = "changed"
        wire["finality_evidence"]["level"] = "changed"
        self.assertEqual(parsed.settlement, self.route.settlement)
        self.assertEqual(parsed.finality_evidence["level"], "pending")


DISPATCH_VECTORS = json.loads(
    (Path(__file__).resolve().parents[2]
     / "docs/payment_venue_v2_dispatch_conformance_v1.json").read_text()
)
_REASON_PATTERNS = {
    "quote_expired": "quote has expired",
    "quote_not_yet_valid": "not yet valid",
    "session_not_live": "live-session capability is invalid",
    "session_mismatch": "session_context does not match",
    "profile_mismatch": "requires a pay_venue profile session",
    "session_required": "requires a VerifiedLiveSession",
}


def _instant(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class TestVenueDispatchWindowVectors(unittest.TestCase):
    """§15.9 inherits the §15.5 dispatch window and the §15.6 inclusion bound."""

    @classmethod
    def setUpClass(cls):
        cls.policy = venue_policy()
        cls.dispatch = cls.venue_dispatch()
        cls.other = cls.venue_dispatch()
        cls.v1 = accepted_payment_dispatch()

    @classmethod
    def venue_dispatch(cls):
        return accepted_payment_dispatch(
            policy=cls.policy, quote_factory=venue_quote, profile="pay_venue",
        )

    def context(self, dispatch, now):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=dispatch.ledger.verifier_view(),
            finality_verifier=SyntheticFinalityVerifier(),
            clock=lambda: _instant(now),
        )

    def claim(self, dispatch, case, live_session):
        return self.context(dispatch, case["now"]).route_from_accepted(
            dispatch.accepted, live_session=live_session,
            transaction_id="synthetic-aztec-" + case["id"],
        )

    def assert_unclaimed(self, dispatch):
        self.assertNotIn(dispatch.accepted.quote_id, dispatch.ledger._claimed_transaction)

    def test_vector_matches_the_pinned_quote_and_fixture_session(self):
        quote_vector = json.loads(
            (Path(__file__).resolve().parents[2] / DISPATCH_VECTORS["quote_vector"]).read_text()
        )["quote"]
        self.assertEqual(DISPATCH_VECTORS["profile"], "pay_venue")
        self.assertEqual(quote_vector["quoted_at"], DISPATCH_VECTORS["quoted_at"])
        self.assertEqual(quote_vector["expires_at"], DISPATCH_VECTORS["expires_at"])
        quote = self.dispatch.accepted.to_quote()
        self.assertEqual(quote.quoted_at, DISPATCH_VECTORS["quoted_at"])
        self.assertEqual(quote.expires_at, DISPATCH_VECTORS["expires_at"])
        session = self.dispatch.live_session.to_atom()
        self.assertEqual(session.profile, DISPATCH_VECTORS["session"]["profile"])
        self.assertEqual(session.expires_at, DISPATCH_VECTORS["session"]["expires_at"])
        self.assertFalse(DISPATCH_VECTORS["rejected_dispatch_consumes_route_claim"])

    def test_rejected_dispatch_vectors_fail_closed_without_claiming(self):
        sessions = {
            "live": self.dispatch.live_session,
            "other": self.other.live_session,
            "pay": self.v1.live_session,
            "absent": None,
        }
        for case in DISPATCH_VECTORS["dispatch_cases"]:
            if case["result"] != "rejected" or case["session"] not in sessions:
                continue
            with self.subTest(case=case["id"]), self.assertRaisesRegex(
                PaymentQuoteError, _REASON_PATTERNS[case["reason"]]
            ):
                self.claim(self.dispatch, case, sessions[case["session"]])
        self.assert_unclaimed(self.dispatch)

    def test_claimed_dispatch_vectors_return_exact_route(self):
        for case in DISPATCH_VECTORS["dispatch_cases"]:
            if case["result"] != "claimed":
                continue
            with self.subTest(case=case["id"]):
                dispatch = self.venue_dispatch()
                route = self.claim(dispatch, case, dispatch.live_session)
                self.assertIsInstance(route, PaymentRouteEvidenceV2)
                self.assertEqual(route.settlement, dispatch.accepted.to_quote().settlement)
                self.assertEqual(
                    dispatch.ledger._claimed_transaction[dispatch.accepted.quote_id],
                    route.transaction_id,
                )

    def test_dispatch_after_session_close_or_expiry_vectors(self):
        for case in DISPATCH_VECTORS["dispatch_cases"]:
            if case["session"] not in ("closed", "expired"):
                continue
            with self.subTest(case=case["id"]):
                dispatch = self.venue_dispatch()
                if case["session"] == "closed":
                    dispatch.owner.close(dispatch.fsm)
                else:
                    dispatch.session_clock["now"] = _instant(
                        DISPATCH_VECTORS["session"]["expires_at"]
                    ).timestamp()
                with self.assertRaisesRegex(
                    PaymentQuoteError, _REASON_PATTERNS[case["reason"]]
                ):
                    self.claim(dispatch, case, dispatch.live_session)
                self.assert_unclaimed(dispatch)

    def test_inclusion_vectors_bound_settlement_to_expires_at(self):
        dispatch = self.venue_dispatch()
        context = self.context(dispatch, "2026-07-11T12:02:00Z")
        route = context.route_from_accepted(
            dispatch.accepted, live_session=dispatch.live_session,
            transaction_id="synthetic-aztec-inclusion",
        )
        dispatch.owner.close(dispatch.fsm)
        for case in DISPATCH_VECTORS["inclusion_cases"]:
            with self.subTest(case=case["id"]):
                tracker = context.tracker(
                    accepted=dispatch.accepted, route=route, policy=self.policy,
                )
                evidence = venue_evidence(
                    route.transaction_id, self.policy, case["finality"],
                    included_at=case["included_at"],
                )
                if case["included_at"] is None:
                    del evidence["included_at"]
                receipt = AfpPaymentReceiptV2.from_dict({
                    **route.to_dict(),
                    "kind": "afp:payment-receipt:v2",
                    "output_note_hash": OUTPUT_NOTE_HASH,
                    "private_event_log_position": 0,
                    "observed_at": "2026-07-11T12:31:00Z",
                    "finality": case["finality"],
                    "finality_evidence": evidence,
                })
                if case["result"] == "settled":
                    tracker.observe(receipt)
                    self.assertTrue(tracker.is_settled)
                else:
                    with self.assertRaisesRegex(PaymentQuoteError, "does not verify"):
                        tracker.observe(receipt)
                    self.assertFalse(tracker.is_settled)
                    self.assertIsNone(tracker.current)


class TestVenueTransactionBinding(unittest.TestCase):
    """§15.9: one Aztec transaction settles at most one v2 quote."""

    def venue_dispatch(self, store, **overrides):
        return accepted_payment_dispatch(
            policy=venue_policy(),
            quote_factory=lambda **values: venue_quote(**{**values, **overrides}),
            profile="pay_venue",
            replay_store=store,
        )

    def claim(self, store, dispatch, transaction_id):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=store.verifier_view(),
            finality_verifier=SyntheticFinalityVerifier(),
            clock=lambda: DISPATCH_AT,
        ).route_from_accepted(
            dispatch.accepted, live_session=dispatch.live_session,
            transaction_id=transaction_id,
        )

    def assert_one_transaction_claims_one_quote(self, store):
        first = self.venue_dispatch(store)
        second = self.venue_dispatch(
            store, quote_id="quote-venue-0002", quote_nonce="0x" + "cd" * 32,
        )
        self.assertNotEqual(first.accepted.quote_id, second.accepted.quote_id)
        self.claim(store, first, "synthetic-aztec-shared")
        with self.assertRaisesRegex(PaymentQuoteError, "failed closed") as refused:
            self.claim(store, second, "synthetic-aztec-shared")
        self.assertRegex(str(refused.exception.__cause__), "another accepted quote")
        route = self.claim(store, second, "synthetic-aztec-second")
        self.assertEqual(route.transaction_id, "synthetic-aztec-second")
        self.assertEqual(
            self.claim(store, first, "synthetic-aztec-shared").transaction_id,
            "synthetic-aztec-shared",
        )

    def test_in_memory_ledger_refuses_a_shared_v2_transaction(self):
        self.assert_one_transaction_claims_one_quote(InMemoryReplayStore())

    def test_sqlite_ledger_refuses_a_shared_v2_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteReplayStore(f"{directory}/payment-replay.sqlite3")
            try:
                self.assert_one_transaction_claims_one_quote(store)
            finally:
                store.close()


def expected_venue_route(accepted, transaction_id):
    return PaymentRouteEvidenceV2(
        quote_ref=accepted.quote_id,
        quote_hash=accepted.quote_hash,
        interaction_context=accepted.interaction_context,
        settlement=accepted.to_quote().settlement,
        transaction_id=transaction_id,
    )


def unavailable_clock():
    raise RuntimeError("clock unavailable")


class TestVenueLateClaimByObservation(unittest.TestCase):
    """§15.9 inherits the §15.5 claim on verified inclusion before expiry."""

    def setUp(self):
        self.policy = venue_policy()
        self.dispatch = self.venue_dispatch()

    def venue_dispatch(self, store=None, **overrides):
        return accepted_payment_dispatch(
            policy=self.policy,
            quote_factory=lambda **values: venue_quote(**{**values, **overrides}),
            profile="pay_venue",
            replay_store=store,
        )

    def context(self, store, clock=unavailable_clock, verifier=None):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=store.verifier_view(),
            finality_verifier=verifier or SyntheticFinalityVerifier(),
            clock=clock,
        )

    def receipt(self, route, *, finality="finalized", included_at=INCLUDED_AT, **overrides):
        wire = {
            **route.to_dict(),
            "kind": "afp:payment-receipt:v2",
            "output_note_hash": OUTPUT_NOTE_HASH,
            "private_event_log_position": 0,
            "observed_at": "2026-10-04T13:09:45Z",
            "finality": finality,
            "finality_evidence": venue_evidence(
                route.transaction_id, self.policy, finality, included_at=included_at
            ),
        }
        wire.update(overrides)
        return AfpPaymentReceiptV2.from_dict(wire)

    def observe_claim(self, receipt, *, dispatch=None, policy=None, verifier=None):
        dispatch = dispatch or self.dispatch
        return self.context(dispatch.ledger, verifier=verifier).route_from_observation(
            dispatch.accepted, receipt=receipt,
            policy=self.policy if policy is None else policy,
        )

    def assert_unclaimed(self, dispatch=None):
        dispatch = dispatch or self.dispatch
        self.assertNotIn(dispatch.accepted.quote_id, dispatch.ledger._claimed_transaction)

    def test_late_claim_after_expiry_and_close_supports_a_tracker(self):
        route = expected_venue_route(self.dispatch.accepted, "synthetic-aztec-late")
        self.dispatch.owner.close(self.dispatch.fsm)
        late = self.context(
            self.dispatch.ledger,
            lambda: datetime(2026, 10, 4, 13, 9, 45, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(PaymentQuoteError, "quote has expired"):
            late.route_from_accepted(
                self.dispatch.accepted, live_session=self.dispatch.live_session,
                transaction_id=route.transaction_id,
            )
        self.assert_unclaimed()
        receipt = self.receipt(route)
        self.assertEqual(self.observe_claim(receipt), route)
        tracker = late.tracker(
            accepted=self.dispatch.accepted,
            route=late.route_from_dict(route.to_dict(), accepted=self.dispatch.accepted),
            policy=self.policy,
        )
        tracker.observe(receipt)
        self.assertTrue(tracker.is_settled)

    def test_late_inclusion_and_weak_evidence_are_rejected_without_claiming(self):
        route = expected_venue_route(self.dispatch.accepted, "synthetic-aztec-late")
        for receipt, message in (
            (self.receipt(route, included_at="2026-07-11T12:05:00Z"), "does not verify"),
            (self.receipt(route, included_at="2026-07-11T12:30:00Z"), "does not verify"),
            (self.receipt(route, finality="pending"), "required finality"),
            (self.receipt(route, finality="safe"), "required finality"),
        ):
            with self.subTest(receipt=receipt), self.assertRaisesRegex(
                PaymentQuoteError, message
            ):
                self.observe_claim(receipt)
        self.assert_unclaimed()

    def test_verifier_rejection_or_error_is_rejected_without_claiming(self):
        class FalseVerifier:
            def verify(self, **_kwargs):
                return False

        class RaisingVerifier:
            def verify(self, **_kwargs):
                raise RuntimeError("verifier unavailable")

        route = expected_venue_route(self.dispatch.accepted, "synthetic-aztec-late")
        for verifier, message in (
            (FalseVerifier(), "does not verify"),
            (RaisingVerifier(), "failed closed"),
        ):
            with self.subTest(verifier=verifier), self.assertRaisesRegex(
                PaymentQuoteError, message
            ):
                self.observe_claim(self.receipt(route), verifier=verifier)
        self.assert_unclaimed()

    def test_mismatched_settlement_or_policy_is_rejected_without_claiming(self):
        route = expected_venue_route(self.dispatch.accepted, "synthetic-aztec-late")
        for field, value in (
            ("recipient_id", "0x" + "00" * 31 + "19"),
            ("amount_atomic", "1"),
        ):
            settlement = route.settlement.to_dict()
            settlement[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                PaymentQuoteError, "settlement does not match"
            ):
                self.observe_claim(self.receipt(route, settlement=settlement))
        for policy in (
            replace(self.policy, required_finality="safe"),
            replace(self.policy, deployment=replace(
                self.policy.deployment, contract_class_id="0x" + "00" * 31 + "24")),
        ):
            with self.subTest(policy=policy), self.assertRaisesRegex(
                PaymentQuoteError, "policy_hash"
            ):
                self.observe_claim(self.receipt(route), policy=policy)
        v1_receipt = AfpPaymentReceiptV1.from_dict({
            "kind": "afp:payment-receipt:v1",
            "quote_ref": route.quote_ref,
            "quote_hash": route.quote_hash,
            "interaction_context": route.interaction_context,
            "chain_id": 8453,
            "pool": "0x" + "11" * 20,
            "asset": BASE_WETH9,
            "amount_wei": "1",
            "transaction_id": route.transaction_id,
            "observed_at": "2026-10-04T13:09:45Z",
            "finality": "finalized",
            "finality_evidence": {"included_at": INCLUDED_AT},
        })
        with self.assertRaisesRegex(PaymentQuoteError, "AfpPaymentReceiptV2"):
            self.observe_claim(v1_receipt)
        v1 = accepted_payment_dispatch()
        with self.assertRaisesRegex(PaymentQuoteError, "AfpPaymentReceiptV1"):
            self.observe_claim(self.receipt(route), dispatch=v1)
        self.assert_unclaimed()
        self.assert_unclaimed(v1)

    def assert_late_claim_refuses_a_shared_transaction(self, store):
        first = self.venue_dispatch(store)
        second = self.venue_dispatch(
            store, quote_id="quote-venue-0002", quote_nonce="0x" + "cd" * 32,
        )
        self.context(store, lambda: DISPATCH_AT).route_from_accepted(
            first.accepted, live_session=first.live_session,
            transaction_id="synthetic-aztec-shared",
        )
        shared = expected_venue_route(second.accepted, "synthetic-aztec-shared")
        with self.assertRaisesRegex(PaymentQuoteError, "failed closed") as refused:
            self.observe_claim(self.receipt(shared), dispatch=second)
        self.assertRegex(str(refused.exception.__cause__), "another accepted quote")
        own = expected_venue_route(second.accepted, "synthetic-aztec-second")
        self.assertEqual(self.observe_claim(self.receipt(own), dispatch=second), own)

    def test_in_memory_late_claim_refuses_a_shared_v2_transaction(self):
        self.assert_late_claim_refuses_a_shared_transaction(InMemoryReplayStore())

    def test_sqlite_late_claim_refuses_a_shared_v2_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteReplayStore(f"{directory}/payment-replay.sqlite3")
            try:
                self.assert_late_claim_refuses_a_shared_transaction(store)
            finally:
                store.close()

if __name__ == "__main__":
    unittest.main()
