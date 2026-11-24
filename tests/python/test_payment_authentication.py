"""Normative AFP §15.3/§15.5 authentication and replay tests."""

from __future__ import annotations

import _path  # noqa: F401

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone, tzinfo
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import pickle
import tempfile
import unittest

import afp_payment.authentication as payment_authentication

from afp_payment import (
    AcceptedPaymentQuote,
    AfpPaymentQuoteV1,
    InMemoryReplayStore,
    PaymentQuoteError,
    SQLiteReplayStore,
    accept_payment_quote,
    sign_payment_quote,
)
from afp_session import (
    AfpCommitSignature,
    AfpSessionAtom,
    AfpSessionStatus,
    InMemoryTransport,
    Instance,
    RemoteParty,
    SessionError,
    SessionFSM,
    VerifiedLiveSession,
    keri,
)
from afp_session.canonical import digest, jcs_bytes, jcs_digest, qb64
from fixtures import make_witness
from payment_fixtures import NONCE, payment_policy, payment_quote


NOW = datetime(2026, 7, 11, 12, 1, 0, tzinfo=timezone.utc)
CONFORMANCE_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "afp_opened_at_conformance_v1.json"
)
CONFORMANCE = json.loads(CONFORMANCE_PATH.read_text(encoding="utf-8"))

_IDENTITY_KEY = b"\x01" + b"\x00" * 31
_ORDER_TWO_KEY = b"\xec" + b"\xff" * 30 + b"\x7f"
_MIXED_ORDER_KEY = bytes.fromhex(
    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
)
_NONCANONICAL_KEY = b"\xed" + b"\xff" * 30 + b"\x7f"


class AuthenticationFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.initiator_tenant = keri.Identity.incept_tenant()
        self.initiator = keri.Identity.incept_entity(self.initiator_tenant)
        self.responder_tenant = keri.Identity.incept_tenant()
        self.responder = keri.Identity.incept_entity(self.responder_tenant)
        self.initiator_remote = RemoteParty(
            self.initiator.kel, self.initiator_tenant.kel, witness_keys={}
        )
        self.responder_remote = RemoteParty(
            self.responder.kel, self.responder_tenant.kel, witness_keys={}
        )
        self.owner_clock = [NOW.timestamp() - 60]
        clock = lambda: self.owner_clock[0]
        transport = InMemoryTransport()
        self.initiator_instance = Instance(
            tenant=self.initiator_tenant,
            entity=self.initiator,
            transport=transport,
            clock=clock,
        )
        self.responder_instance = Instance(
            tenant=self.responder_tenant,
            entity=self.responder,
            transport=transport,
            clock=clock,
        )
        self.fsm = self.initiator_instance.propose(
            responder_tenant_aid=self.responder_tenant.aid,
            responder_entity_aid=self.responder.aid,
            responder_remote=self.responder_remote,
            agreement_ref="agreement-1",
            agreement_version="1",
            profile="pay",
            profile_policy_hash=payment_policy().policy_hash,
            ttl_seconds=660,
            session_id="session-0001",
        )
        responder_fsm = self.responder_instance.accept(
            self.fsm.atom, initiator_remote=self.initiator_remote
        )
        self.initiator_instance.confirm_open(
            self.fsm,
            responder_fsm.atom,
            responder_remote=self.responder_remote,
        )
        self.initiator_instance.activate(self.fsm)
        self.live_session = self.initiator_instance.verified_live_session(self.fsm)
        self.session = self.live_session.to_atom()

    def signed_quote(self, **overrides):
        overrides.setdefault("session_context", self.session.session_context)
        quote = payment_quote(**overrides)
        quote = sign_payment_quote(quote, self.initiator, role="initiator", signed_at=NOW)
        return sign_payment_quote(quote, self.responder, role="responder", signed_at=NOW)

    def accept(self, quote, store=None, **overrides):
        values = {
            "quote": quote,
            "policy": payment_policy(),
            "live_session": self.live_session,
            "initiator_remote": self.initiator_remote,
            "responder_remote": self.responder_remote,
            "replay_store": store or InMemoryReplayStore(),
            "now": NOW,
        }
        values.update(overrides)
        return accept_payment_quote(**values)


class TestPaymentAuthentication(AuthenticationFixture):
    def test_accepted_capability_cannot_be_constructed_or_publicly_snapshotted(self):
        with self.assertRaises(TypeError):
            AcceptedPaymentQuote()
        with self.assertRaises(TypeError):
            AcceptedPaymentQuote(payment_quote())
        self.assertFalse(hasattr(AcceptedPaymentQuote, "snapshot"))
        self.assertFalse(hasattr(AcceptedPaymentQuote, "_mint"))
        exposed_authority = [
            name
            for name in vars(payment_authentication)
            if "mint" in name.lower() or "token" in name.lower()
        ]
        self.assertEqual(exposed_authority, [])

    def test_both_kel_current_signatures_are_required_and_accepted(self):
        accepted = self.accept(self.signed_quote())
        self.assertIsInstance(accepted, AcceptedPaymentQuote)
        self.assertEqual(accepted.quote_hash, self.signed_quote().quote_hash)
        self.assertEqual(accepted.to_quote().initiator_signature.signed_by, self.initiator.aid)
        self.assertEqual(accepted.to_quote().responder_signature.signed_by, self.responder.aid)
        self.assertEqual(
            accepted.acceptance_record_hash,
            qb64("D", jcs_digest(accepted.to_quote().to_dict(), floats=True)),
        )

        one_sided = sign_payment_quote(
            payment_quote(session_context=self.session.session_context),
            self.initiator,
            role="initiator",
            signed_at=NOW,
        )
        with self.assertRaisesRegex(PaymentQuoteError, "both.*signatures"):
            self.accept(one_sided)

    def test_tampering_forgery_and_stale_keys_fail_closed(self):
        signed = self.signed_quote()
        with self.assertRaisesRegex(PaymentQuoteError, "invalid.*signature"):
            self.accept(replace(signed, quote_id="tampered"))

        forged = signed.to_dict()
        forged["responder_signature"]["signature"] = "00" * 64
        with self.assertRaisesRegex(PaymentQuoteError, "invalid.*signature"):
            self.accept(AfpPaymentQuoteV1.from_dict(forged))

        self.responder.rotate()
        with self.assertRaisesRegex(PaymentQuoteError, "current|stale"):
            self.accept(signed)

    def test_live_session_reference_context_and_expiry_are_checked(self):
        signed = self.signed_quote()
        for quote in (
            self.signed_quote(session_ref="different-session"),
            self.signed_quote(session_context="X_" + "44" * 32),
        ):
            with self.subTest(quote=quote), self.assertRaises(PaymentQuoteError):
                self.accept(quote)

        with self.assertRaisesRegex(PaymentQuoteError, "expired"):
            self.accept(signed, now=datetime(2026, 7, 11, 12, 5, tzinfo=timezone.utc))

    def test_malformed_signature_wire_is_normalized_to_payment_quote_error(self):
        for mutation in (
            lambda sig: sig.pop("signature"),
            lambda sig: sig.update({"unknown": "field"}),
            lambda sig: sig.update({"signature": 7}),
            lambda sig: sig.update({"signed_by": "not-qb64"}),
            lambda sig: sig.update({"kel_event_dig": "not-qb64"}),
            lambda sig: sig.update({"signature": "GG" * 64}),
        ):
            wire = self.signed_quote().to_dict()
            mutation(wire["initiator_signature"])
            with self.subTest(wire=wire), self.assertRaises(PaymentQuoteError):
                quote = AfpPaymentQuoteV1.from_dict(wire)
                self.accept(quote)

    def test_live_context_and_signature_bindings_require_canonical_qb64(self):
        # §15.4 construction-time derivation rejects a malformed session
        # context before a quote object can even exist, so the acceptance
        # gate is never reachable with one.
        with self.assertRaises(PaymentQuoteError):
            self.signed_quote(session_context="not-qb64")

    def test_acceptance_detaches_quote_before_adversarial_validation_mutation(self):
        signed = self.signed_quote()

        class MutatingQuote(AfpPaymentQuoteV1):
            def validate(inner_self, policy):
                super().validate(policy)
                inner_self.initiator_signature.signature = "00" * 64

        adversarial = MutatingQuote(
            **{k: v for k, v in signed.__dict__.items() if not k.startswith("_")}
        )
        expected_hash = adversarial.quote_hash
        accepted = self.accept(adversarial)
        self.assertEqual(accepted.quote_hash, expected_hash)
        self.assertNotEqual(accepted.to_quote().initiator_signature.signature, "00" * 64)

    def test_quote_freshness_uses_signed_quote_times_not_untrusted_signed_at(self):
        future_quote = self.signed_quote(
            quoted_at="2026-07-11T12:02:00Z",
            expires_at="2026-07-11T12:05:00Z",
        )
        with self.assertRaisesRegex(PaymentQuoteError, "not yet valid|quoted_at"):
            self.accept(future_quote)

        signed = self.signed_quote()
        mutated = replace(
            signed,
            initiator_signature=replace(
                signed.initiator_signature, signed_at=NOW.timestamp() + 100_000
            ),
            responder_signature=replace(
                signed.responder_signature, signed_at=0.0
            ),
        )
        self.assertEqual(mutated.quote_hash, signed.quote_hash)
        self.accept(mutated)

    def test_verifier_rejects_inbound_signed_at_that_is_not_a_finite_json_number(self):
        # §1.6.1: a received signed_at is a finite JSON number within 2^53-1.
        # A missing value is rejected, never replaced by the verifier's clock.
        signed = self.signed_quote()
        for bad in (None, "2026-07-11T12:01:00Z", True, float("nan"),
                    float("-inf"), 2**53 + 1, NOW):
            with self.subTest(signed_at=bad):
                mutated = replace(
                    signed,
                    initiator_signature=replace(
                        signed.initiator_signature, signed_at=bad
                    ),
                )
                # Acceptance re-parses the exact wire, so the reader rejects
                # first; the cause names signed_at.
                with self.assertRaises(PaymentQuoteError) as raised:
                    self.accept(mutated)
                cause = raised.exception
                messages = []
                while cause is not None:
                    messages.append(str(cause))
                    cause = cause.__cause__
                self.assertTrue(
                    any("signed_at" in message for message in messages), messages
                )

    def test_signer_rejects_a_native_number_it_would_have_to_round(self):
        # §1.6.1 / AFP-0422: a caller's native number is validated as given. An
        # integer that binary64 cannot hold exactly is rejected, never rounded:
        # the native integer 1152921504606847000 is not 2**60.
        quote = payment_quote(session_context=self.session.session_context)
        for bad in (2**53 + 1, -(2**53 + 1), 1152921504606847000, 10**400,
                    float("nan"), float("inf"), True, "now", [1],
                    datetime(2026, 7, 11, 12, 1, 0)):
            with self.subTest(signed_at=bad), self.assertRaises(PaymentQuoteError):
                sign_payment_quote(quote, self.initiator, role="initiator", signed_at=bad)

    def test_signer_maps_an_unusable_datetime_offset_to_its_own_error(self):
        # A tzinfo that returns an offset datetime cannot use is the signer's
        # error, not a bare ValueError or TypeError.
        class _Offset(tzinfo):
            def __init__(self, offset):
                self._offset = offset

            def utcoffset(self, dt):
                return self._offset

            def dst(self, dt):
                return None

        quote = payment_quote(session_context=self.session.session_context)
        for offset in (timedelta(hours=25), "+01:00"):
            with self.subTest(offset=offset), self.assertRaises(PaymentQuoteError):
                sign_payment_quote(
                    quote, self.initiator, role="initiator",
                    signed_at=datetime(2026, 7, 11, 12, 1, tzinfo=_Offset(offset)),
                )
        # An aware datetime with a usable offset is still accepted.
        signed = sign_payment_quote(
            quote, self.initiator, role="initiator",
            signed_at=datetime(2026, 7, 11, 13, 1, tzinfo=_Offset(timedelta(hours=1))),
        )
        self.assertEqual(signed.initiator_signature.signed_at, NOW.timestamp())

    def test_signer_keeps_an_exact_native_number_through_the_wire_reader(self):
        # A native integer that binary64 holds exactly is accepted and written
        # in RFC 8785 form; the wire reader decodes that canonical token back
        # to the same binary64 value with the same acceptance hash.
        quote = payment_quote(session_context=self.session.session_context)
        for good, canonical in ((1752235260, b"1752235260"),
                                (1752235260.25, b"1752235260.25"),
                                (1e23, b"1e+23"),
                                (2**53, b"9007199254740992"),
                                (2**60, b"1152921504606847000"),
                                (-(2**60), b"-1152921504606847000")):
            with self.subTest(signed_at=good):
                signed = sign_payment_quote(
                    quote, self.initiator, role="initiator", signed_at=good
                )
                signed = sign_payment_quote(
                    signed, self.responder, role="responder", signed_at=good
                )
                wire = jcs_bytes(signed.to_dict(), floats=True)
                # JCS sorts members, so signed_by follows signed_at.
                self.assertIn(b'"signed_at":' + canonical + b',"signed_by"', wire)
                reread = type(signed).from_dict(json.loads(wire))
                self.assertEqual(reread.initiator_signature.signed_at, good)
                self.assertEqual(jcs_bytes(reread.to_dict(), floats=True), wire)
                self.assertEqual(
                    reread.acceptance_record_hash, signed.acceptance_record_hash
                )

    def test_wire_reader_keeps_the_canonical_spelling_rule_for_large_tokens(self):
        # A received token beyond 2^53-1 must be the RFC 8785 spelling of its
        # binary64 value: 1152921504606847000 decodes to 2**60, while the exact
        # decimal 1152921504606846976 is not RFC 8785 form and is rejected.
        signed = sign_payment_quote(
            payment_quote(session_context=self.session.session_context),
            self.initiator, role="initiator", signed_at=2**60,
        )
        signed = sign_payment_quote(
            signed, self.responder, role="responder", signed_at=2**60
        )
        wire = signed.to_dict()
        accepted = dict(wire)
        accepted["initiator_signature"] = dict(
            wire["initiator_signature"], signed_at=1152921504606847000
        )
        reread = type(signed).from_dict(accepted)
        self.assertIs(type(reread.initiator_signature.signed_at), float)
        self.assertEqual(reread.initiator_signature.signed_at, 2**60)
        self.assertEqual(reread.acceptance_record_hash, signed.acceptance_record_hash)
        rejected = dict(wire)
        rejected["initiator_signature"] = dict(
            wire["initiator_signature"], signed_at=2**60
        )
        with self.assertRaises(PaymentQuoteError):
            type(signed).from_dict(rejected)

    def test_full_session_party_refs_and_explicit_witness_material_are_required(self):
        signed = self.signed_quote()
        missing_witness_material = RemoteParty(
            self.initiator.kel, self.initiator_tenant.kel, witness_keys=None
        )
        with self.assertRaisesRegex(PaymentQuoteError, "witness"):
            self.accept(signed, initiator_remote=missing_witness_material)

    def test_thresholded_session_kel_without_receipts_fails_closed(self):
        witnesses = [make_witness()]
        tenant = keri.Identity.incept_tenant(witnesses=witnesses, threshold=1)
        entity = keri.Identity.incept_entity(
            tenant, witnesses=witnesses, threshold=1
        )
        good_keys = {witness.aid: witness.public_key for witness in witnesses}
        initiator_remote = RemoteParty(entity.kel, tenant.kel, witness_keys=good_keys)
        transport = InMemoryTransport()
        clock = lambda: NOW.timestamp() - 60
        initiator_instance = Instance(
            tenant=tenant, entity=entity, transport=transport, clock=clock
        )
        responder_instance = Instance(
            tenant=self.responder_tenant,
            entity=self.responder,
            transport=transport,
            clock=clock,
        )
        fsm = initiator_instance.propose(
            responder_tenant_aid=self.responder_tenant.aid,
            responder_entity_aid=self.responder.aid,
            responder_remote=self.responder_remote,
            agreement_ref="agreement-1",
            agreement_version="1",
            profile="pay",
            profile_policy_hash=payment_policy().policy_hash,
            ttl_seconds=660,
            session_id="witnessed-session",
        )
        responder_fsm = responder_instance.accept(
            fsm.atom, initiator_remote=initiator_remote
        )
        initiator_instance.confirm_open(
            fsm, responder_fsm.atom, responder_remote=self.responder_remote
        )
        initiator_instance.activate(fsm)
        live_session = initiator_instance.verified_live_session(fsm)
        session = live_session.to_atom()
        quote = payment_quote(
            session_ref=session.id, session_context=session.session_context
        )
        quote = sign_payment_quote(
            quote, entity, role="initiator", signed_at=NOW
        )
        quote = sign_payment_quote(
            quote, self.responder, role="responder", signed_at=NOW
        )
        remote = RemoteParty(entity.kel, tenant.kel, witness_keys={})
        with self.assertRaisesRegex(PaymentQuoteError, "threshold"):
            self.accept(
                quote, live_session=live_session, initiator_remote=remote
            )

    def test_payment_rejects_noncanonical_kel_signing_key_code(self):
        entity = keri.Identity.incept_tenant()
        event = entity.kel.events[0]
        event.keys = ["X_" + entity.current_public_key().hex()]
        entity.kel.aid = qb64("E", digest(event.content()))
        quote_hash = qb64("D", digest({"payment": "key-ingestion-probe"}))
        signature = AfpCommitSignature(
            signed_by=entity.aid,
            kel_event_dig=event.digest,
            signature=entity.sign(quote_hash.encode("utf-8")).hex(),
            signed_at=NOW.timestamp(),
        )
        tenant = keri.Identity.incept_tenant()

        with self.assertRaisesRegex(PaymentQuoteError, "KEL-current or valid"):
            payment_authentication._verify_signature(
                quote_hash,
                signature,
                expected_entity_aid=entity.aid,
                expected_tenant_aid=tenant.aid,
                entity_kel=entity.kel,
                tenant_kel=tenant.kel,
                witness_keys={},
                role="initiator",
            )

    def test_payment_rejects_invalid_unused_witness_keys_before_replay(self):
        class RecordingReplayStore:
            def __init__(inner_self):
                inner_self.called = False

            def reserve(inner_self, *_args, **_kwargs):
                inner_self.called = True

        signed = self.signed_quote()
        invalid_keys = (
            b"\x00" * 31,
            _IDENTITY_KEY,
            _ORDER_TWO_KEY,
            _MIXED_ORDER_KEY,
            _NONCANONICAL_KEY,
        )
        for invalid_key in invalid_keys:
            remote = RemoteParty(
                self.initiator.kel,
                self.initiator_tenant.kel,
                witness_keys={make_witness().aid: invalid_key},
            )
            replay_store = RecordingReplayStore()
            with self.subTest(public_key=invalid_key), self.assertRaises(
                PaymentQuoteError
            ):
                self.accept(
                    signed,
                    store=replay_store,
                    initiator_remote=remote,
                )
            self.assertFalse(replay_store.called)

    def test_status_rewrite_cannot_mint_or_substitute_live_session_capability(self):
        proposal = self.initiator_instance.propose(
            responder_tenant_aid=self.responder_tenant.aid,
            responder_entity_aid=self.responder.aid,
            responder_remote=self.responder_remote,
            agreement_ref="agreement-2",
            agreement_version="1",
            profile="pay",
            profile_policy_hash=payment_policy().policy_hash,
            session_id="rewritten-session",
        )
        copied = AfpSessionAtom.from_dict(proposal.atom.to_dict())
        copied.status = AfpSessionStatus.ACTIVE
        forged_fsm = SessionFSM(copied, clock=lambda: NOW.timestamp())
        with self.assertRaises(SessionError):
            self.initiator_instance.verified_live_session(forged_fsm)
        with self.assertRaises(PaymentQuoteError):
            self.accept(self.signed_quote(), live_session=copied)

    def test_detached_active_session_without_responder_signature_fails_closed(self):
        """The payment boundary independently rejects an erased session signature."""
        detached = self.live_session.to_atom()
        detached.responder.signature = ""

        class DetachedActiveSession(VerifiedLiveSession):
            def to_atom(self):
                return detached

        forged_capability = object.__new__(DetachedActiveSession)
        with self.assertRaisesRegex(PaymentQuoteError, "responder signature"):
            self.accept(self.signed_quote(), live_session=forged_capability)

    def test_payment_acceptance_rejects_every_noncanonical_opened_at(self):
        """The value-transfer boundary repeats the shared wire-value validation."""
        for vector in CONFORMANCE["rejected"]:
            if "opened_at" not in vector:
                continue
            with self.subTest(vector=vector["name"]):
                detached = self.live_session.to_atom()
                detached.opened_at = vector["opened_at"]

                class DetachedActiveSession(VerifiedLiveSession):
                    def to_atom(self):
                        return detached

                forged_capability = object.__new__(DetachedActiveSession)
                with self.assertRaisesRegex(PaymentQuoteError, "opened_at"):
                    self.accept(self.signed_quote(), live_session=forged_capability)

    def test_verified_live_session_is_immutable_and_returns_detached_atom(self):
        self.assertIsInstance(self.live_session, VerifiedLiveSession)
        detached = self.live_session.to_atom()
        detached.status = AfpSessionStatus.CLOSED
        self.assertEqual(
            self.live_session.to_atom().status, AfpSessionStatus.ACTIVE
        )
        with self.assertRaises(FrozenInstanceError):
            self.live_session._atom_wire = "{}"

    def test_live_session_handle_is_revoked_by_close_or_abort(self):
        self.initiator_instance.close(self.fsm)
        with self.assertRaises(SessionError):
            self.live_session.to_atom()

    def test_live_session_handle_rechecks_owner_clock_not_acceptance_clock(self):
        signed = self.signed_quote()
        self.owner_clock[0] = self.session.expires_at_seconds
        with self.assertRaisesRegex(PaymentQuoteError, "session|capability"):
            self.accept(signed, now=NOW)

    def test_live_session_handle_is_not_standalone_serializable_authority(self):
        with self.assertRaises(TypeError):
            pickle.dumps(self.live_session)

    def test_live_session_handle_is_revoked_by_abort(self):
        self.fsm.abort("test")
        with self.assertRaises(SessionError):
            self.live_session.to_atom()

    def test_accepted_boundary_snapshots_mutable_signatures(self):
        signed = self.signed_quote()
        accepted = self.accept(signed)
        original_signature = accepted.to_quote().initiator_signature.signature
        signed.initiator_signature.signature = "00" * 64
        self.assertEqual(accepted.to_quote().initiator_signature.signature, original_signature)
        with self.assertRaises(FrozenInstanceError):
            accepted.quote_hash = "D_changed"

    def test_accepted_capability_is_process_local_and_seal_checked(self):
        accepted = self.accept(self.signed_quote())
        with self.assertRaises(TypeError):
            pickle.dumps(accepted)

        forged = object.__new__(AcceptedPaymentQuote)
        for field, value in (
            ("quote_hash", accepted.quote_hash),
            ("quote_id", accepted.quote_id),
            ("quote_nonce", accepted.quote_nonce),
            ("acceptance_record_hash", accepted.acceptance_record_hash),
            ("interaction_context", accepted.interaction_context),
            ("profile_policy_hash", accepted.profile_policy_hash),
            ("_canonical_wire", accepted._canonical_wire),
            ("_acceptance_seal", b"0" * 32),
        ):
            object.__setattr__(forged, field, value)
        with self.assertRaisesRegex(PaymentQuoteError, "seal|authority"):
            forged.to_quote()


class TestPaymentReplay(AuthenticationFixture):
    def test_accepted_quote_consumes_both_keys_and_duplicate_fails(self):
        store = InMemoryReplayStore()
        signed = self.signed_quote()
        self.accept(signed, store)
        with self.assertRaisesRegex(PaymentQuoteError, "duplicate"):
            self.accept(signed, store)

        same_id = self.signed_quote(quote_nonce="0x" + "cd" * 32)
        with self.assertRaisesRegex(PaymentQuoteError, "quote_id"):
            self.accept(same_id, store)

        same_nonce = self.signed_quote(quote_id="quote-other")
        with self.assertRaisesRegex(PaymentQuoteError, "nonce"):
            self.accept(same_nonce, store)

    def test_rejected_quote_consumes_no_replay_state(self):
        store = InMemoryReplayStore()
        invalid = self.signed_quote()
        invalid.responder_signature.signature = "00" * 64
        with self.assertRaises(PaymentQuoteError):
            self.accept(invalid, store)
        self.accept(self.signed_quote(), store)

    def test_sqlite_store_survives_restart_and_reserves_id_and_nonce_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/payment-replay.sqlite3"
            first = SQLiteReplayStore(path)
            first.reserve(
                "quote-1",
                "D_" + "11" * 32,
                "0x" + "22" * 32,
                "D_" + "aa" * 32,
            )
            first.close()

            restarted = SQLiteReplayStore(path)
            verifier = restarted.verifier_view()
            self.assertFalse(hasattr(verifier, "reserve"))
            self.assertTrue(
                verifier.verify_reservation(
                    "quote-1",
                    "D_" + "11" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                )
            )
            self.assertFalse(
                verifier.verify_reservation(
                    "quote-1",
                    "D_" + "33" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                )
            )
            self.assertTrue(
                verifier.claim_route(
                    "quote-1",
                    "D_" + "11" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                    "transaction-1",
                )
            )
            self.assertTrue(
                verifier.claim_route(
                    "quote-1",
                    "D_" + "11" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                    "transaction-1",
                )
            )
            self.assertTrue(
                verifier.verify_route(
                    "quote-1",
                    "D_" + "11" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                    "transaction-1",
                )
            )
            with self.assertRaises(PaymentQuoteError):
                verifier.claim_route(
                    "quote-1",
                    "D_" + "11" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                    "transaction-2",
                )
            with self.assertRaisesRegex(PaymentQuoteError, "duplicate"):
                restarted.reserve(
                    "quote-1",
                    "D_" + "11" * 32,
                    "0x" + "22" * 32,
                    "D_" + "aa" * 32,
                )
            with self.assertRaisesRegex(PaymentQuoteError, "quote_id"):
                restarted.reserve(
                    "quote-1",
                    "D_" + "33" * 32,
                    "0x" + "44" * 32,
                    "D_" + "bb" * 32,
                )
            with self.assertRaisesRegex(PaymentQuoteError, "nonce"):
                restarted.reserve(
                    "quote-2",
                    "D_" + "55" * 32,
                    "0x" + "22" * 32,
                    "D_" + "cc" * 32,
                )
            restarted.reserve(
                "quote-2",
                "D_" + "55" * 32,
                "0x" + "66" * 32,
                "D_" + "dd" * 32,
            )
            restarted.close()

    def test_acceptance_ledger_verifies_only_exact_reserved_tuple(self):
        store = InMemoryReplayStore()
        store.reserve(
            "quote-1",
            "D_" + "11" * 32,
            "0x" + "22" * 32,
            "D_" + "aa" * 32,
        )
        verifier = store.verifier_view()
        self.assertFalse(hasattr(verifier, "reserve"))
        self.assertTrue(
            verifier.verify_reservation(
                "quote-1",
                "D_" + "11" * 32,
                "0x" + "22" * 32,
                "D_" + "aa" * 32,
            )
        )
        self.assertFalse(
            verifier.verify_reservation(
                "quote-1",
                "D_" + "11" * 32,
                "0x" + "22" * 32,
                "D_" + "bb" * 32,
            )
        )

    def test_sqlite_initialization_errors_are_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PaymentQuoteError):
                SQLiteReplayStore(directory)

    def test_sqlite_store_supports_same_instance_concurrent_reservations(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteReplayStore(f"{directory}/concurrent.sqlite3")

            def reserve(index):
                store.reserve(
                    f"quote-{index}",
                    "D_" + f"{index + 1:064x}",
                    "0x" + f"{index + 1:064x}",
                    "D_" + f"{index + 101:064x}",
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(reserve, range(8)))
            store.close()


if __name__ == "__main__":
    unittest.main()
