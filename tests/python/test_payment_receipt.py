"""Normative AFP §15.6 receipt and finality tests."""

import _path  # noqa: F401

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from threading import Barrier

from afp_payment import InMemoryReplayStore, PaymentQuoteError, SQLiteReplayStore
from afp_payment.receipt import (
    AfpPaymentReceiptV1,
    PaymentReceiptVerificationContext,
    PaymentRouteEvidence,
)

from payment_fixtures import (
    accepted_payment_dispatch,
    accepted_payment_quote_and_ledger,
    payment_policy,
    payment_quote,
)
from venue_fixtures import venue_policy, venue_quote
from afp_payment import accept_payment_quote
from afp_payment.replay import _AcceptanceVerifierView

# The fixture quote is valid from 12:00:00 and expires at 12:05:00 UTC.
DISPATCH_AT = datetime(2026, 7, 11, 12, 2, 0, tzinfo=timezone.utc)
QUOTE_EXPIRES_AT = datetime(2026, 7, 11, 12, 5, 0, tzinfo=timezone.utc)
INCLUDED_AT = "2026-07-11T12:02:30Z"
_EVIDENCE_KEY = {
    "pending": "submitted_transaction",
    "safe": "safe_transaction",
    "finalized": "finalized_transaction",
}


def dispatch_clock():
    return DISPATCH_AT


def finality_evidence(
    level, route, *, transaction_id=None, chain_id=8453, included_at=INCLUDED_AT,
    chain=None,
):
    """Synthetic evidence; ``chain`` stands for values read from the chain."""
    evidence = {
        _EVIDENCE_KEY[level]: transaction_id or route.transaction_id,
        "chain_id": chain_id,
    }
    if level != "pending":
        evidence["included_at"] = included_at
        evidence["chain"] = dict(
            chain_observation(route, payment_policy()) if chain is None else chain
        )
    return evidence


def chain_observation(route, policy, **overrides):
    """What a deployment verifier reads from the chain and the payee's note."""
    values = {
        "pool": route.pool,
        "pool_context": policy.deployment.pool_context,
        "interaction_context": route.interaction_context,
        "payment_count": 1,
        "slot0_note_opened_by_payee": True,
        "slot0_note_amount_wei": route.amount_wei,
    }
    values.update(overrides)
    return values


class FakeFinalityVerifier:
    """Accept only evidence that meets the §15.6 v1 settlement checks.

    For safe and finalized it requires inclusion strictly before expiry and
    chain-side values: the pool and pool context, the payment's own
    interaction context, one payment in the transaction, and a slot-0 note the
    payee opened whose amount equals the signed amount. Echoed receipt fields
    are never treated as chain observations.
    """

    def verify(self, *, receipt, route, policy, expires_at):
        if policy.deployment.chain_id != receipt.chain_id:
            return False
        evidence = receipt.finality_evidence
        if receipt.finality == "pending":
            return dict(evidence) == finality_evidence(
                "pending", route, chain_id=policy.deployment.chain_id
            )
        included_at = evidence.get("included_at")
        if not isinstance(included_at, str):
            return False
        included = datetime.strptime(
            included_at, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        if included >= expires_at:
            return False
        chain = evidence.get("chain")
        if chain is None or dict(chain) != chain_observation(route, policy):
            return False
        return dict(evidence) == finality_evidence(
            receipt.finality,
            route,
            chain_id=policy.deployment.chain_id,
            included_at=included_at,
            chain=chain,
        )


class TestPaymentReceipt(unittest.TestCase):
    def setUp(self):
        self.dispatch = accepted_payment_dispatch()
        self.accepted = self.dispatch.accepted
        self.acceptance_ledger = self.dispatch.ledger
        self.live_session = self.dispatch.live_session
        self.verifier = FakeFinalityVerifier()
        self.context = self.context_at(dispatch_clock)
        self.route = self.context.route_from_accepted(
            self.accepted,
            live_session=self.live_session,
            transaction_id="0xbase-transaction",
        )

    def context_at(self, clock, *, ledger=None, verifier=None):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=(ledger or self.acceptance_ledger).verifier_view(),
            finality_verifier=verifier or self.verifier,
            clock=clock,
        )

    def receipt(self, **overrides):
        return self.receipt_for(self.route, **overrides)

    def receipt_for(self, route, **overrides):
        # observed_at is observation time, not inclusion time: a receipt
        # observed after expiry still settles if inclusion preceded it.
        finality = overrides.get("finality", "pending")
        values = {
            **route.to_dict(),
            "kind": "afp:payment-receipt:v1",
            "observed_at": "2026-07-11T12:05:01Z",
            "finality": finality,
            "finality_evidence": finality_evidence(finality, route),
        }
        values.update(overrides)
        return AfpPaymentReceiptV1.from_dict(values)

    def test_strict_canonical_round_trip(self):
        receipt = self.receipt()
        self.assertEqual(AfpPaymentReceiptV1.from_dict(receipt.to_dict()), receipt)

        for bad in (
            {**receipt.to_dict(), "unknown": True},
            {key: value for key, value in receipt.to_dict().items() if key != "asset"},
            {**receipt.to_dict(), "observed_at": "2026-07-11T12:05:01.0Z"},
            {**receipt.to_dict(), "observed_at": "2026-07-11T08:05:01-04:00"},
            {**receipt.to_dict(), "finality": "confirmed"},
            {**receipt.to_dict(), "transaction_id": ""},
            {**receipt.to_dict(), "finality_evidence": {}},
            {**receipt.to_dict(), "finality_evidence": "safe"},
        ):
            with self.subTest(bad=bad), self.assertRaises(PaymentQuoteError):
                AfpPaymentReceiptV1.from_dict(bad)

    def test_evidence_is_detached_from_mutable_wire_input(self):
        wire = self.receipt().to_dict()
        receipt = AfpPaymentReceiptV1.from_dict(wire)
        wire["finality_evidence"]["nested"] = {"blocks": ["321"]}
        nested_receipt = AfpPaymentReceiptV1.from_dict(wire)
        wire["finality_evidence"]["nested"]["blocks"][0] = "rewritten"
        self.assertEqual(
            nested_receipt.to_dict()["finality_evidence"]["nested"]["blocks"],
            ["321"],
        )
        with self.assertRaises(TypeError):
            nested_receipt.finality_evidence["nested"]["blocks"][0] = "rewrite"
        with self.assertRaises(TypeError):
            nested_receipt.finality_evidence["nested"]["new"] = True

    def test_exactly_matches_accepted_quote_and_route_evidence(self):
        tracker = self.context.tracker(
            accepted=self.accepted,
            route=self.route,
            policy=payment_policy(),
        )
        tracker.observe(self.receipt())

        mismatches = {
            "quote_ref": "different",
            "quote_hash": "D_" + "00" * 32,
            "interaction_context": "0x" + "02" * 32,
            "chain_id": 1,
            "pool": "0x0000000000000000000000000000000000000001",
            "asset": "0x0000000000000000000000000000000000000002",
            "amount_wei": "2",
            "transaction_id": "different-transaction",
        }
        for field, value in mismatches.items():
            with self.subTest(field=field), self.assertRaises(PaymentQuoteError):
                self.context.tracker(
                    accepted=self.accepted,
                    route=self.route,
                    policy=payment_policy(),
                ).observe(self.receipt(**{field: value}))

    def test_route_evidence_requires_quote_ref_equal_quote_id(self):
        wire = self.route.to_dict()
        wire["quote_ref"] = "different"
        with self.assertRaises(PaymentQuoteError):
            self.context.route_from_dict(wire, accepted=self.accepted)

    def test_forged_nominal_capability_is_rejected_by_route_and_tracker(self):
        forged = object.__new__(type(self.accepted))
        for field, value in (
            ("quote_hash", self.accepted.quote_hash),
            ("quote_id", self.accepted.quote_id),
            ("quote_nonce", self.accepted.quote_nonce),
            ("acceptance_record_hash", self.accepted.acceptance_record_hash),
            ("interaction_context", self.accepted.interaction_context),
            ("profile_policy_hash", self.accepted.profile_policy_hash),
            ("_canonical_wire", self.accepted._canonical_wire),
            ("_acceptance_seal", b"forged"),
        ):
            object.__setattr__(forged, field, value)
        with self.assertRaises(PaymentQuoteError):
            self.context.route_from_accepted(
                forged,
                live_session=self.live_session,
                transaction_id=self.route.transaction_id,
            )
        with self.assertRaises(PaymentQuoteError):
            self.context.tracker(
                accepted=forged,
                route=self.route,
                policy=payment_policy(),
            )

    def test_introspection_issued_unsigned_capability_lacks_ledger_authority(self):
        unsigned = replace(
            self.accepted.to_quote(),
            initiator_signature=None,
            responder_signature=None,
        )
        forged = None
        for cell in accept_payment_quote.__closure__ or ():
            candidate = cell.cell_contents
            if not callable(candidate):
                continue
            try:
                issued = candidate(unsigned, self.accepted.profile_policy_hash)
            except TypeError:
                continue
            if isinstance(issued, type(self.accepted)):
                forged = issued
                break
        self.assertIsNotNone(forged)
        self.assertEqual(forged.to_quote(), unsigned)
        with self.assertRaisesRegex(PaymentQuoteError, "ledger|acceptance"):
            self.context.route_from_accepted(
                forged,
                live_session=self.live_session,
                transaction_id=self.route.transaction_id,
            )

        object.__setattr__(
            forged,
            "acceptance_record_hash",
            self.accepted.acceptance_record_hash,
        )
        with self.assertRaisesRegex(PaymentQuoteError, "record|wire|authority"):
            forged.to_quote()

    def test_context_rejects_writer_and_structural_fake(self):
        class AlwaysTrueVerifier:
            def verify_reservation(self, *_args):
                return True

        for verifier in (self.acceptance_ledger, AlwaysTrueVerifier()):
            with self.subTest(verifier=type(verifier).__name__), self.assertRaises(
                PaymentQuoteError
            ):
                PaymentReceiptVerificationContext(
                    acceptance_verifier=verifier,
                    finality_verifier=self.verifier,
                    clock=dispatch_clock,
                )
        self.assertFalse(
            hasattr(self.acceptance_ledger.verifier_view(), "reserve")
        )
        with self.assertRaises(TypeError):
            _AcceptanceVerifierView(lambda *_args: True)
        forged_view = object.__new__(_AcceptanceVerifierView)
        with self.assertRaises(PaymentQuoteError):
            PaymentReceiptVerificationContext(
                acceptance_verifier=forged_view,
                finality_verifier=self.verifier,
                clock=dispatch_clock,
            )

    def test_one_quote_claims_exactly_one_transaction(self):
        self.assertEqual(
            self.context.route_from_accepted(
                self.accepted,
                live_session=self.live_session,
                transaction_id=self.route.transaction_id,
            ),
            self.route,
        )
        with self.assertRaises(PaymentQuoteError):
            self.context.route_from_accepted(
                self.accepted,
                live_session=self.live_session,
                transaction_id="different-transaction",
            )

    def test_invalid_transaction_does_not_consume_route_claim(self):
        dispatch = accepted_payment_dispatch()
        context = self.context_at(dispatch_clock, ledger=dispatch.ledger)
        with self.assertRaises(PaymentQuoteError):
            context.route_from_accepted(
                dispatch.accepted,
                live_session=dispatch.live_session,
                transaction_id="",
            )
        route = context.route_from_accepted(
            dispatch.accepted,
            live_session=dispatch.live_session,
            transaction_id="valid-transaction",
        )
        self.assertEqual(route.transaction_id, "valid-transaction")

    def test_request_cannot_substitute_fresh_attacker_store(self):
        attacker_view = InMemoryReplayStore().verifier_view()
        with self.assertRaises(TypeError):
            self.context.route_from_accepted(
                self.accepted,
                live_session=self.live_session,
                transaction_id=self.route.transaction_id,
                acceptance_verifier=attacker_view,
            )

    def test_exact_copy_of_genuine_accepted_record_is_equivalent(self):
        copied = object.__new__(type(self.accepted))
        for field in (
            "quote_hash",
            "quote_id",
            "quote_nonce",
            "acceptance_record_hash",
            "interaction_context",
            "profile_policy_hash",
            "_canonical_wire",
            "_acceptance_seal",
        ):
            object.__setattr__(copied, field, getattr(self.accepted, field))
        route = self.context.route_from_accepted(
            copied,
            live_session=self.live_session,
            transaction_id=self.route.transaction_id,
        )
        self.assertEqual(route, self.route)

    def test_finality_progresses_monotonically_without_rewrites(self):
        tracker = self.context.tracker(
            accepted=self.accepted,
            route=self.route,
            policy=payment_policy(required_finality="safe"),
        )
        pending = self.receipt()
        safe = self.receipt(
            observed_at="2026-07-11T12:06:00Z",
            finality="safe",
            finality_evidence=finality_evidence(
                    "safe", self.route
                ),
        )
        finalized = self.receipt(
            observed_at="2026-07-11T12:07:00Z",
            finality="finalized",
            finality_evidence=finality_evidence(
                    "finalized", self.route
                ),
        )

        tracker.observe(pending)
        self.assertFalse(tracker.is_settled)
        tracker.observe(safe)
        self.assertTrue(tracker.is_settled)
        tracker.observe(finalized)
        self.assertTrue(tracker.is_settled)
        self.assertEqual(tracker.current, finalized)

        with self.assertRaises(PaymentQuoteError):
            tracker.observe(safe)
        rewritten = finalized.to_dict()
        rewritten["finality_evidence"] = {"finalized_block": "322"}
        with self.assertRaises(PaymentQuoteError):
            tracker.observe(AfpPaymentReceiptV1.from_dict(rewritten))

    def test_policy_can_require_finalized(self):
        policy = payment_policy(required_finality="finalized")
        dispatch = accepted_payment_dispatch(policy=policy)
        context = self.context_at(dispatch_clock, ledger=dispatch.ledger)
        route = context.route_from_accepted(
            dispatch.accepted,
            live_session=dispatch.live_session,
            transaction_id=self.route.transaction_id,
        )
        tracker = context.tracker(
            accepted=dispatch.accepted, route=route, policy=policy
        )
        tracker.observe(
            self.receipt_for(
                route,
                finality="safe",
                finality_evidence=finality_evidence("safe", route),
            )
        )
        self.assertFalse(tracker.is_settled)
        tracker.observe(
            self.receipt_for(
                route,
                observed_at="2026-07-11T12:06:00Z",
                finality="finalized",
                finality_evidence=finality_evidence(
                    "finalized", route
                ),
            )
        )
        self.assertTrue(tracker.is_settled)

    def test_review_repro_weaker_tracker_policy_is_rejected(self):
        # Review E-2: the session requires finalized; a safe-policy tracker
        # must not report settlement on a reorg-able safe receipt.
        policy = payment_policy(required_finality="finalized")
        dispatch = accepted_payment_dispatch(policy=policy)
        context = self.context_at(dispatch_clock, ledger=dispatch.ledger)
        route = context.route_from_accepted(
            dispatch.accepted,
            live_session=dispatch.live_session,
            transaction_id=self.route.transaction_id,
        )
        self.assertEqual(dispatch.accepted.profile_policy_hash, policy.policy_hash)
        for substituted in (
            payment_policy(required_finality="safe"),
            payment_policy(required_finality="finalized", max_quote_lifetime_seconds=600),
        ):
            with self.subTest(policy=substituted), self.assertRaisesRegex(
                PaymentQuoteError, "policy_hash"
            ):
                context.tracker(
                    accepted=dispatch.accepted, route=route, policy=substituted
                )

    def test_sealed_policy_hash_cannot_be_rewritten(self):
        copied = object.__new__(type(self.accepted))
        for field in (
            "quote_hash", "quote_id", "quote_nonce", "acceptance_record_hash",
            "interaction_context", "_canonical_wire", "_acceptance_seal",
        ):
            object.__setattr__(copied, field, getattr(self.accepted, field))
        weaker = payment_policy(required_finality="finalized")
        object.__setattr__(copied, "profile_policy_hash", weaker.policy_hash)
        with self.assertRaisesRegex(PaymentQuoteError, "seal"):
            copied.to_quote()
        with self.assertRaises(PaymentQuoteError):
            self.context.tracker(accepted=copied, route=self.route, policy=weaker)

    def test_dispatch_rejects_a_session_under_another_policy(self):
        # A capability issued for the same reserved tuple but sealed to a
        # different policy hash must not dispatch in this session.
        issue = None
        for cell in accept_payment_quote.__closure__ or ():
            candidate = cell.cell_contents
            if callable(candidate) and getattr(candidate, "__name__", "") == "issue":
                issue = candidate
        self.assertIsNotNone(issue)
        dispatch = accepted_payment_dispatch()
        other_policy = payment_policy(required_finality="finalized")
        rebound = issue(dispatch.accepted.to_quote(), other_policy.policy_hash)
        context = self.context_at(dispatch_clock, ledger=dispatch.ledger)
        with self.assertRaisesRegex(PaymentQuoteError, "profile_policy_hash"):
            context.route_from_accepted(
                rebound,
                live_session=dispatch.live_session,
                transaction_id="0xrebound",
            )
        route = context.route_from_accepted(
            dispatch.accepted,
            live_session=dispatch.live_session,
            transaction_id="0xbound",
        )
        self.assertEqual(route.transaction_id, "0xbound")

    def test_evidence_verifier_is_required_and_fails_closed(self):
        with self.assertRaises(PaymentQuoteError):
            PaymentReceiptVerificationContext(
                acceptance_verifier=self.acceptance_ledger.verifier_view(),
                finality_verifier=None,
                clock=dispatch_clock,
            )

        class RaisingVerifier:
            def verify(self, **_kwargs):
                raise RuntimeError("backend unavailable")

        context = self.context_at(dispatch_clock, verifier=RaisingVerifier())
        tracker = context.tracker(
            accepted=self.accepted,
            route=self.route,
            policy=payment_policy(),
        )
        with self.assertRaisesRegex(PaymentQuoteError, "finality evidence"):
            tracker.observe(self.receipt())
        self.assertFalse(tracker.is_settled)
        self.assertIsNone(tracker.current)

    def test_unknown_or_mismatched_evidence_never_marks_settled(self):
        tracker = self.context.tracker(
            accepted=self.accepted,
            route=self.route,
            policy=payment_policy(required_finality="safe"),
        )
        for evidence in (
            {"unknown": True},
            finality_evidence("safe", self.route, transaction_id="different"),
            finality_evidence("safe", self.route, chain_id=1),
            {"safe_transaction": self.route.transaction_id, "chain_id": 8453},
        ):
            with self.subTest(evidence=evidence), self.assertRaises(PaymentQuoteError):
                tracker.observe(
                    self.receipt(finality="safe", finality_evidence=evidence)
                )
            self.assertFalse(tracker.is_settled)
            self.assertIsNone(tracker.current)

    def test_concurrent_safe_and_finalized_preserve_maximal_finality(self):
        barrier = Barrier(2)

        class BarrierVerifier(FakeFinalityVerifier):
            def verify(inner_self, **kwargs):
                barrier.wait(timeout=5)
                return super().verify(**kwargs)

        context = self.context_at(dispatch_clock, verifier=BarrierVerifier())
        tracker = context.tracker(
            accepted=self.accepted,
            route=self.route,
            policy=payment_policy(required_finality="safe"),
        )
        safe = self.receipt(
            observed_at="2026-07-11T12:06:00Z",
            finality="safe",
            finality_evidence=finality_evidence(
                    "safe", self.route
                ),
        )
        finalized = self.receipt(
            observed_at="2026-07-11T12:07:00Z",
            finality="finalized",
            finality_evidence=finality_evidence(
                    "finalized", self.route
                ),
        )

        def observe(receipt):
            try:
                tracker.observe(receipt)
                return receipt.finality
            except PaymentQuoteError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(observe, (safe, finalized)))

        self.assertEqual(tracker.current.finality, "finalized")
        self.assertTrue(tracker.is_settled)
        self.assertIn(results, (["safe", "finalized"], ["rejected", "finalized"]))


class TestRouteDispatchWindow(unittest.TestCase):
    """§15.5: dispatch is bound to the quote window and the live session."""

    def setUp(self):
        self.dispatch = accepted_payment_dispatch()
        self.verifier = FakeFinalityVerifier()

    def context_at(self, clock):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=self.dispatch.ledger.verifier_view(),
            finality_verifier=self.verifier,
            clock=clock,
        )

    def claim(self, context, *, live_session=None, transaction_id="0xbase-transaction"):
        return context.route_from_accepted(
            self.dispatch.accepted,
            live_session=(
                self.dispatch.live_session if live_session is None else live_session
            ),
            transaction_id=transaction_id,
        )

    def assert_claim_unconsumed(self):
        route = self.claim(self.context_at(dispatch_clock), transaction_id="0xin-window")
        self.assertEqual(route.transaction_id, "0xin-window")

    def test_review_repro_claim_after_expiry_and_close_is_rejected(self):
        # Review E-1: accepted at 12:01, session closed, claimed at wall time.
        self.dispatch.owner.close(self.dispatch.fsm)
        context = self.context_at(lambda: datetime.now(timezone.utc))
        with self.assertRaisesRegex(PaymentQuoteError, "expired"):
            self.claim(context)

    def test_claim_at_or_after_expires_at_is_rejected_without_consuming(self):
        for now in (
            QUOTE_EXPIRES_AT,
            datetime(2026, 7, 11, 12, 5, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 4, 13, 9, 45, tzinfo=timezone.utc),
        ):
            with self.subTest(now=now), self.assertRaisesRegex(
                PaymentQuoteError, "quote has expired"
            ):
                self.claim(self.context_at(lambda now=now: now))
        self.assert_claim_unconsumed()

    def test_claim_one_second_before_expiry_is_accepted(self):
        route = self.claim(
            self.context_at(
                lambda: datetime(2026, 7, 11, 12, 4, 59, tzinfo=timezone.utc)
            )
        )
        self.assertEqual(route.transaction_id, "0xbase-transaction")

    def test_claim_before_quoted_at_is_rejected(self):
        early = datetime(2026, 7, 11, 11, 59, 59, tzinfo=timezone.utc)
        with self.assertRaisesRegex(PaymentQuoteError, "not yet valid"):
            self.claim(self.context_at(lambda: early))
        self.assert_claim_unconsumed()

    def test_claim_after_session_close_is_rejected_without_consuming(self):
        context = self.context_at(dispatch_clock)
        self.dispatch.owner.close(self.dispatch.fsm)
        with self.assertRaisesRegex(PaymentQuoteError, "live-session"):
            self.claim(context)
        # A new live session for another quote cannot reopen the claim either.
        with self.assertRaises(PaymentQuoteError):
            self.claim(context, live_session=accepted_payment_dispatch().live_session)

    def test_claim_after_session_expiry_is_rejected(self):
        # The fixture session opens at 12:00:00 with a 660-second TTL.
        self.dispatch.session_clock["now"] = datetime(
            2026, 7, 11, 12, 11, 0, tzinfo=timezone.utc
        ).timestamp()
        with self.assertRaisesRegex(PaymentQuoteError, "live-session"):
            self.claim(self.context_at(dispatch_clock))

    def test_claim_requires_the_quote_live_session(self):
        context = self.context_at(dispatch_clock)
        other = accepted_payment_dispatch()
        venue = accepted_payment_dispatch(
            policy=venue_policy(), quote_factory=venue_quote, profile="pay_venue"
        )
        for live_session, message in (
            (object(), "VerifiedLiveSession"),
            (other.live_session, "session_context"),
            (venue.live_session, "pay profile"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                PaymentQuoteError, message
            ):
                self.claim(context, live_session=live_session)
        with self.assertRaises(TypeError):
            context.route_from_accepted(
                self.dispatch.accepted, transaction_id="0xbase-transaction"
            )
        self.assert_claim_unconsumed()

    def test_context_requires_a_trusted_timezone_aware_clock(self):
        with self.assertRaises(TypeError):
            PaymentReceiptVerificationContext(
                acceptance_verifier=self.dispatch.ledger.verifier_view(),
                finality_verifier=self.verifier,
            )
        with self.assertRaisesRegex(PaymentQuoteError, "clock"):
            self.context_at(None)

        def raising_clock():
            raise RuntimeError("clock unavailable")

        for clock in (
            raising_clock,
            lambda: datetime(2026, 7, 11, 12, 2, 0),
            lambda: DISPATCH_AT.timestamp(),
        ):
            with self.subTest(clock=clock), self.assertRaisesRegex(
                PaymentQuoteError, "clock"
            ):
                self.claim(self.context_at(clock))
        self.assert_claim_unconsumed()

    def test_finality_verifier_receives_the_quote_expiry(self):
        seen = []

        class RecordingVerifier(FakeFinalityVerifier):
            def verify(inner_self, **kwargs):
                seen.append(kwargs["expires_at"])
                return super().verify(**kwargs)

        self.verifier = RecordingVerifier()
        context = self.context_at(dispatch_clock)
        route = self.claim(context)
        tracker = context.tracker(
            accepted=self.dispatch.accepted, route=route, policy=payment_policy()
        )
        tracker.observe(
            AfpPaymentReceiptV1.from_dict({
                **route.to_dict(),
                "kind": "afp:payment-receipt:v1",
                "observed_at": "2026-07-11T12:05:01Z",
                "finality": "safe",
                "finality_evidence": finality_evidence("safe", route),
            })
        )
        self.assertEqual(seen, [QUOTE_EXPIRES_AT])
        self.assertTrue(tracker.is_settled)

    def test_inclusion_at_or_after_expiry_leaves_obligation_unsettled(self):
        context = self.context_at(dispatch_clock)
        route = self.claim(context)
        tracker = context.tracker(
            accepted=self.dispatch.accepted, route=route, policy=payment_policy()
        )
        for included_at in ("2026-07-11T12:05:00Z", "2026-07-11T12:30:00Z"):
            with self.subTest(included_at=included_at), self.assertRaisesRegex(
                PaymentQuoteError, "does not verify"
            ):
                tracker.observe(
                    AfpPaymentReceiptV1.from_dict({
                        **route.to_dict(),
                        "kind": "afp:payment-receipt:v1",
                        "observed_at": "2026-07-11T12:31:00Z",
                        "finality": "finalized",
                        "finality_evidence": finality_evidence(
                            "finalized", route,
                            included_at=included_at,
                        ),
                    })
                )
            self.assertFalse(tracker.is_settled)
            self.assertIsNone(tracker.current)

    def test_observation_continues_after_session_close_and_expiry(self):
        context = self.context_at(dispatch_clock)
        route = self.claim(context)
        self.dispatch.owner.close(self.dispatch.fsm)
        late = self.context_at(
            lambda: datetime(2026, 10, 4, 13, 9, 45, tzinfo=timezone.utc)
        )
        decoded = late.route_from_dict(route.to_dict(), accepted=self.dispatch.accepted)
        tracker = late.tracker(
            accepted=self.dispatch.accepted, route=decoded, policy=payment_policy()
        )
        tracker.observe(
            AfpPaymentReceiptV1.from_dict({
                **route.to_dict(),
                "kind": "afp:payment-receipt:v1",
                "observed_at": "2026-10-04T13:09:45Z",
                "finality": "finalized",
                "finality_evidence": finality_evidence(
                    "finalized", route
                ),
            })
        )
        self.assertTrue(tracker.is_settled)


class TestTransactionBinding(unittest.TestCase):
    """§15.5/§15.6: one transaction settles one quote, checked from the chain."""

    def setUp(self):
        self.verifier = FakeFinalityVerifier()

    def two_dispatches(self, store):
        first = accepted_payment_dispatch(replay_store=store)
        second = accepted_payment_dispatch(
            replay_store=store,
            quote_factory=lambda **values: payment_quote(
                quote_id="invoice-2", quote_nonce="0x" + "cd" * 32, **values
            ),
        )
        return first, second

    def context(self, store):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=store.verifier_view(),
            finality_verifier=self.verifier,
            clock=dispatch_clock,
        )

    def claim(self, context, dispatch, transaction_id):
        return context.route_from_accepted(
            dispatch.accepted,
            live_session=dispatch.live_session,
            transaction_id=transaction_id,
        )

    def assert_one_transaction_claims_one_quote(self, store):
        first, second = self.two_dispatches(store)
        self.assertNotEqual(
            first.accepted.interaction_context, second.accepted.interaction_context
        )
        context = self.context(store)
        self.claim(context, first, "0xONE_PAYMENT")
        with self.assertRaisesRegex(PaymentQuoteError, "failed closed") as refused:
            self.claim(context, second, "0xONE_PAYMENT")
        self.assertRegex(str(refused.exception.__cause__), "another accepted quote")
        # The refused claim leaves the second quote free for its own payment.
        route = self.claim(context, second, "0xSECOND_PAYMENT")
        self.assertEqual(route.transaction_id, "0xSECOND_PAYMENT")
        self.assertEqual(
            self.claim(context, first, "0xONE_PAYMENT").transaction_id, "0xONE_PAYMENT"
        )

    def test_review_repro_in_memory_ledger_refuses_a_shared_transaction(self):
        self.assert_one_transaction_claims_one_quote(InMemoryReplayStore())

    def test_review_repro_sqlite_ledger_refuses_a_shared_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteReplayStore(f"{directory}/payment-replay.sqlite3")
            try:
                self.assert_one_transaction_claims_one_quote(store)
            finally:
                store.close()

    def test_sqlite_existing_duplicate_claims_fail_closed_at_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/payment-replay.sqlite3"
            legacy = sqlite3.connect(path)
            legacy.execute(
                "CREATE TABLE accepted_payment_quotes ("
                "quote_id TEXT PRIMARY KEY, quote_hash TEXT NOT NULL, "
                "quote_nonce TEXT NOT NULL UNIQUE, acceptance_record_hash TEXT NOT NULL, "
                "claimed_transaction_id TEXT, UNIQUE (quote_id, claimed_transaction_id))"
            )
            for index in (1, 2):
                legacy.execute(
                    "INSERT INTO accepted_payment_quotes VALUES (?, ?, ?, ?, ?)",
                    (
                        f"quote-{index}", "D_" + f"{index:02x}" * 32,
                        "0x" + f"{index:02x}" * 32, "D_" + "aa" * 32, "0xshared",
                    ),
                )
            legacy.commit()
            legacy.close()
            with self.assertRaisesRegex(PaymentQuoteError, "initialization failed"):
                SQLiteReplayStore(path)

    def test_settlement_requires_chain_side_context_pool_amount_and_payee(self):
        dispatch = accepted_payment_dispatch()
        context = self.context(dispatch.ledger)
        route = self.claim(context, dispatch, "0xbase-transaction")
        policy = payment_policy()
        other = accepted_payment_dispatch().accepted.interaction_context
        for field, value in (
            ("interaction_context", other),
            ("pool_context", "0x" + "02" * 32),
            ("pool", "0x" + "00" * 19 + "01"),
            ("payment_count", 2),
            ("slot0_note_opened_by_payee", False),
            ("slot0_note_amount_wei", "9999999999999999"),
        ):
            with self.subTest(field=field):
                tracker = context.tracker(
                    accepted=dispatch.accepted, route=route, policy=policy
                )
                receipt = AfpPaymentReceiptV1.from_dict({
                    **route.to_dict(),
                    "kind": "afp:payment-receipt:v1",
                    "observed_at": "2026-07-11T12:06:00Z",
                    "finality": "finalized",
                    "finality_evidence": finality_evidence(
                        "finalized", route,
                        chain=chain_observation(route, policy, **{field: value}),
                    ),
                })
                with self.assertRaisesRegex(PaymentQuoteError, "does not verify"):
                    tracker.observe(receipt)
                self.assertFalse(tracker.is_settled)
        # Echoed receipt fields alone, without chain observations, never settle.
        tracker = context.tracker(accepted=dispatch.accepted, route=route, policy=policy)
        evidence = finality_evidence("finalized", route)
        del evidence["chain"]
        with self.assertRaisesRegex(PaymentQuoteError, "does not verify"):
            tracker.observe(AfpPaymentReceiptV1.from_dict({
                **route.to_dict(),
                "kind": "afp:payment-receipt:v1",
                "observed_at": "2026-07-11T12:06:00Z",
                "finality": "finalized",
                "finality_evidence": evidence,
            }))
        self.assertFalse(tracker.is_settled)



LATE_AT = datetime(2026, 10, 4, 13, 9, 45, tzinfo=timezone.utc)


def unavailable_clock():
    raise RuntimeError("clock unavailable")


def expected_route(accepted, transaction_id):
    settlement = accepted.to_quote().settlement
    return PaymentRouteEvidence(
        quote_ref=accepted.quote_id,
        quote_hash=accepted.quote_hash,
        interaction_context=accepted.interaction_context,
        chain_id=settlement.chain_id,
        pool=settlement.pool,
        asset=settlement.asset,
        amount_wei=settlement.amount_wei,
        transaction_id=transaction_id,
    )


def observed_receipt(route, *, finality="finalized", included_at=INCLUDED_AT, **overrides):
    values = {
        **route.to_dict(),
        "kind": "afp:payment-receipt:v1",
        "observed_at": "2026-10-04T13:09:45Z",
        "finality": finality,
        "finality_evidence": finality_evidence(finality, route, included_at=included_at),
    }
    values.update(overrides)
    return AfpPaymentReceiptV1.from_dict(values)


class TestLateClaimByObservation(unittest.TestCase):
    """§15.5: a claim outside dispatch needs verified inclusion before expiry."""

    def setUp(self):
        self.dispatch = accepted_payment_dispatch()
        self.verifier = FakeFinalityVerifier()
        self.route = expected_route(self.dispatch.accepted, "0xbase-transaction")

    def context(self, clock=unavailable_clock, *, store=None, verifier=None):
        return PaymentReceiptVerificationContext(
            acceptance_verifier=(store or self.dispatch.ledger).verifier_view(),
            finality_verifier=verifier or self.verifier,
            clock=clock,
        )

    def observe_claim(self, receipt, *, dispatch=None, policy=None, **context):
        dispatch = dispatch or self.dispatch
        return self.context(store=dispatch.ledger, **context).route_from_observation(
            dispatch.accepted,
            receipt=receipt,
            policy=payment_policy() if policy is None else policy,
        )

    def assert_claim_unconsumed(self):
        self.assertNotIn(
            self.dispatch.accepted.quote_id, self.dispatch.ledger._claimed_transaction
        )
        route = self.observe_claim(observed_receipt(self.route))
        self.assertEqual(route, self.route)

    def test_late_claim_after_expiry_and_close_supports_a_tracker(self):
        self.dispatch.owner.close(self.dispatch.fsm)
        late = self.context(lambda: LATE_AT)
        with self.assertRaisesRegex(PaymentQuoteError, "quote has expired"):
            late.route_from_accepted(
                self.dispatch.accepted,
                live_session=self.dispatch.live_session,
                transaction_id=self.route.transaction_id,
            )
        self.assertNotIn(
            self.dispatch.accepted.quote_id, self.dispatch.ledger._claimed_transaction
        )
        receipt = observed_receipt(self.route, finality="safe")
        # The observation path reads no clock and needs no live session.
        route = self.observe_claim(receipt)
        self.assertEqual(route, self.route)
        self.assertEqual(
            self.dispatch.ledger._claimed_transaction[self.dispatch.accepted.quote_id],
            self.route.transaction_id,
        )
        decoded = late.route_from_dict(route.to_dict(), accepted=self.dispatch.accepted)
        tracker = late.tracker(
            accepted=self.dispatch.accepted, route=decoded, policy=payment_policy()
        )
        tracker.observe(receipt)
        self.assertTrue(tracker.is_settled)
        self.assertEqual(self.observe_claim(observed_receipt(self.route)), self.route)

    def test_inclusion_at_or_after_expiry_is_rejected_without_consuming(self):
        self.dispatch.owner.close(self.dispatch.fsm)
        for included_at in (
            "2026-07-11T12:05:00Z", "2026-07-11T12:05:01Z", "2026-10-04T13:09:00Z",
        ):
            with self.subTest(included_at=included_at), self.assertRaisesRegex(
                PaymentQuoteError, "does not verify"
            ):
                self.observe_claim(observed_receipt(self.route, included_at=included_at))
        self.assert_claim_unconsumed()

    def test_evidence_below_the_policy_finality_is_rejected(self):
        with self.assertRaisesRegex(PaymentQuoteError, "required finality"):
            self.observe_claim(observed_receipt(self.route, finality="pending"))
        self.assert_claim_unconsumed()
        policy = payment_policy(required_finality="finalized")
        dispatch = accepted_payment_dispatch(policy=policy)
        route = expected_route(dispatch.accepted, "0xbase-transaction")
        with self.assertRaisesRegex(PaymentQuoteError, "required finality"):
            self.observe_claim(
                observed_receipt(route, finality="safe"), dispatch=dispatch, policy=policy
            )
        self.assertNotIn(dispatch.accepted.quote_id, dispatch.ledger._claimed_transaction)
        self.assertEqual(
            self.observe_claim(observed_receipt(route), dispatch=dispatch, policy=policy),
            route,
        )

    def test_verifier_rejection_or_error_is_rejected_without_consuming(self):
        class FixedVerifier:
            def __init__(self, result):
                self.result = result

            def verify(self, **_kwargs):
                return self.result

        class RaisingVerifier:
            def verify(self, **_kwargs):
                raise RuntimeError("verifier unavailable")

        for verifier, message in (
            (FixedVerifier(False), "does not verify"),
            (FixedVerifier(1), "does not verify"),
            (RaisingVerifier(), "failed closed"),
        ):
            with self.subTest(verifier=verifier), self.assertRaisesRegex(
                PaymentQuoteError, message
            ):
                self.observe_claim(observed_receipt(self.route), verifier=verifier)
        evidence = finality_evidence(
            "finalized", self.route,
            chain=chain_observation(self.route, payment_policy(), payment_count=2),
        )
        with self.assertRaisesRegex(PaymentQuoteError, "does not verify"):
            self.observe_claim(
                observed_receipt(self.route, finality_evidence=evidence)
            )
        self.assert_claim_unconsumed()

    def test_mismatched_receipt_or_policy_is_rejected_without_consuming(self):
        other = accepted_payment_dispatch().accepted.interaction_context
        for field, value in (
            ("amount_wei", "1"),
            ("pool", "0x" + "00" * 19 + "01"),
            ("interaction_context", other),
            ("quote_ref", "invoice-2"),
            ("quote_hash", "D_" + "ab" * 32),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                PaymentQuoteError, f"{field} does not match"
            ):
                self.observe_claim(observed_receipt(self.route, **{field: value}))
        for policy, message in (
            (payment_policy(required_finality="finalized"), "policy_hash"),
            (payment_policy(max_quote_lifetime_seconds=600), "policy_hash"),
            (venue_policy(), "policy_hash"),
            (object(), "AfpPaymentPolicyV1"),
        ):
            with self.subTest(policy=policy), self.assertRaisesRegex(
                PaymentQuoteError, message
            ):
                self.observe_claim(observed_receipt(self.route), policy=policy)
        with self.assertRaisesRegex(PaymentQuoteError, "AfpPaymentReceiptV1"):
            self.observe_claim(self.route.to_dict())
        self.assert_claim_unconsumed()

    def test_dispatched_quote_cannot_claim_a_second_transaction(self):
        dispatched = self.context(dispatch_clock).route_from_accepted(
            self.dispatch.accepted,
            live_session=self.dispatch.live_session,
            transaction_id=self.route.transaction_id,
        )
        self.assertEqual(self.observe_claim(observed_receipt(self.route)), dispatched)
        second = expected_route(self.dispatch.accepted, "0xsecond-transaction")
        with self.assertRaisesRegex(PaymentQuoteError, "failed closed") as refused:
            self.observe_claim(observed_receipt(second))
        self.assertRegex(str(refused.exception.__cause__), "another transaction")

    def assert_late_claim_refuses_a_shared_transaction(self, store):
        first = accepted_payment_dispatch(replay_store=store)
        second = accepted_payment_dispatch(
            replay_store=store,
            quote_factory=lambda **values: payment_quote(
                quote_id="invoice-2", quote_nonce="0x" + "cd" * 32, **values
            ),
        )
        self.context(dispatch_clock, store=store).route_from_accepted(
            first.accepted, live_session=first.live_session,
            transaction_id="0xONE_PAYMENT",
        )
        shared = expected_route(second.accepted, "0xONE_PAYMENT")
        with self.assertRaisesRegex(PaymentQuoteError, "failed closed") as refused:
            self.observe_claim(observed_receipt(shared), dispatch=second)
        self.assertRegex(str(refused.exception.__cause__), "another accepted quote")
        own = expected_route(second.accepted, "0xSECOND_PAYMENT")
        self.assertEqual(self.observe_claim(observed_receipt(own), dispatch=second), own)

    def test_in_memory_late_claim_refuses_a_shared_transaction(self):
        self.assert_late_claim_refuses_a_shared_transaction(InMemoryReplayStore())

    def test_sqlite_late_claim_refuses_a_shared_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteReplayStore(f"{directory}/payment-replay.sqlite3")
            try:
                self.assert_late_claim_refuses_a_shared_transaction(store)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
