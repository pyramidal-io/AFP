"""Honest OB-1/OB-2 disclosure conformance tests (§3.5 / §8.9).

Covers the honest OB-1-only disclosure rule (R7): a deployment without an
operational mixnet MUST claim OB-1 (content) only and disclose OB-2 (metadata) as
not-yet-met; deployments surface their true OB level and cannot overclaim.
"""

import unittest
from unittest import mock

import _path  # noqa: F401

from afp_session import SealedChannelAttestation
from afp_session.conformance import (
    ConformanceViolation,
    DeploymentProfile,
    ObLevel,
    assess_ob_disclosure,
    guard_ob_claim,
)
from afp_session.conformance import MetState
from fixtures import establish_channels, make_pair


class ChannelEvidenceFixture(unittest.TestCase):
    """Mint real OB-1 evidence from an authenticated channel receive."""

    def setUp(self):
        (
            _transport,
            self.a,
            self.b,
            self.remote_a,
            self.remote_b,
        ) = make_pair()
        self.fsm_a = self.a.propose(
            responder_tenant_aid=self.b.tenant_aid,
            responder_entity_aid=self.b.entity_aid,
            responder_remote=self.remote_b,
            agreement_ref="ob-disclosure-test",
            agreement_version="1",
            profile="work",
            profile_policy_hash="ob-disclosure-test",
        )
        self.fsm_b = self.b.accept(
            self.fsm_a.atom, initiator_remote=self.remote_a
        )
        self.a.confirm_open(
            self.fsm_a, self.fsm_b.atom, responder_remote=self.remote_b
        )
        self.sender_channel, self.receiver_channel = establish_channels(
            self.a,
            self.b,
            self.remote_a,
            self.remote_b,
            self.fsm_a.atom,
        )

    def mint_channel_attestation(self):
        """Return a capability minted only after a real channel authentication."""
        frame = self.sender_channel.seal(b"ob-1 evidence", "ob-disclosure-test")
        plaintext, attestation = self.receiver_channel.open_with_attestation(
            frame, "ob-disclosure-test"
        )
        self.assertEqual(plaintext, b"ob-1 evidence")
        return attestation

    def profile(self, *, name="test", attestation=None, **kwargs):
        if attestation is None:
            attestation = self.mint_channel_attestation()
        kwargs.setdefault("mixnet_operational", False)
        session_context = kwargs.pop(
            "channel_session_context", self.fsm_a.atom.session_context
        )
        kel_event_dig = kwargs.pop(
            "channel_kel_event_dig", self.evidence_kel_event_dig
        )
        return DeploymentProfile(
            name=name,
            channel_encryption_operational=attestation,
            channel_session_context=session_context,
            channel_kel_event_dig=kel_event_dig,
            **kwargs,
        )

    @property
    def evidence_kel_event_dig(self):
        # The receiving channel attests the KEL pin of its authenticated peer.
        return self.fsm_a.atom.initiator.kel_event_dig

    def assert_ob1_not_met(self, profile):
        claim = assess_ob_disclosure(profile)
        self.assertEqual(claim.ob1, MetState.NOT_MET)
        self.assertEqual(claim.claimed_level, ObLevel.NONE)
        self.assertTrue(any("OB-1" in disclosure for disclosure in claim.disclosures))
        self.assertTrue(any("§3.5" in disclosure for disclosure in claim.disclosures))
        return claim


class HonestDisclosureTest(ChannelEvidenceFixture):
    def test_no_mixnet_claims_ob1_only(self):
        # The headline R7 case: encryption live, mixnet NOT running.
        profile = self.profile(
            name="interim-deployment",
            mixnet_operational=False,
        )
        claim = assess_ob_disclosure(profile)
        self.assertEqual(claim.claimed_level, ObLevel.OB1)
        self.assertEqual(claim.ob1, MetState.MET)
        self.assertEqual(claim.ob2, MetState.NOT_MET)
        # MUST disclose OB-2 as not-yet-met (§3.5 / §8.9).
        self.assertTrue(any("OB-2" in d and "NOT YET MET" in d for d in claim.disclosures))

    def test_full_mixnet_claims_ob2(self):
        profile = self.profile(
            name="appliance-grade",
            mixnet_operational=True,
            mandatory_cover_traffic=True,
            mix_node_count=5,
        )
        claim = assess_ob_disclosure(profile)
        self.assertEqual(claim.claimed_level, ObLevel.OB2)
        self.assertEqual(claim.ob2, MetState.MET)
        self.assertEqual(claim.disclosures, [])

    def test_mixnet_without_cover_traffic_is_ob1_only(self):
        # Capability, not conduct (§3.2): mixnet up but no mandatory cover traffic
        # -> OB-2 not structurally satisfied (§8.5).
        profile = self.profile(
            name="partial",
            mixnet_operational=True,
            mandatory_cover_traffic=False,
            mix_node_count=5,
        )
        claim = assess_ob_disclosure(profile)
        self.assertEqual(claim.claimed_level, ObLevel.OB1)
        self.assertTrue(any("cover traffic" in d for d in claim.disclosures))

    def test_insufficient_mix_node_set_is_ob1_only(self):
        profile = self.profile(
            name="too-small",
            mixnet_operational=True,
            mandatory_cover_traffic=True,
            mix_node_count=1,  # below the sufficient-set threshold (§8.9)
        )
        claim = assess_ob_disclosure(profile)
        self.assertEqual(claim.claimed_level, ObLevel.OB1)
        self.assertTrue(any("mix-node set" in d for d in claim.disclosures))

    def test_no_encryption_is_below_ob1(self):
        profile = DeploymentProfile(
            name="broken",
            channel_encryption_operational=None,
            channel_session_context=self.fsm_a.atom.session_context,
            channel_kel_event_dig=self.evidence_kel_event_dig,
            mixnet_operational=False,
        )
        claim = assess_ob_disclosure(profile)
        self.assertEqual(claim.claimed_level, ObLevel.NONE)
        self.assertEqual(claim.ob1, MetState.NOT_MET)

    def test_ob2_cannot_be_met_without_valid_ob1_evidence(self):
        profile = DeploymentProfile(
            name="routing-without-channel-evidence",
            channel_encryption_operational=None,
            channel_session_context=self.fsm_a.atom.session_context,
            channel_kel_event_dig=self.evidence_kel_event_dig,
            mixnet_operational=True,
            mandatory_cover_traffic=True,
            mix_node_count=5,
        )
        claim = self.assert_ob1_not_met(profile)
        self.assertEqual(claim.ob2, MetState.NOT_MET)
        self.assertTrue(
            any("claims no OB level" in disclosure for disclosure in claim.disclosures)
        )
        self.assertTrue(
            any(
                "OB-2" in disclosure
                and "OB-1 sealed-channel prerequisite" in disclosure
                for disclosure in claim.disclosures
            )
        )

    def test_bare_boolean_channel_status_is_rejected(self):
        for value in (True, False):
            with self.subTest(value=value), self.assertRaises(TypeError):
                DeploymentProfile(
                    name="boolean-is-not-evidence",
                    channel_encryption_operational=value,
                    channel_session_context=self.fsm_a.atom.session_context,
                    channel_kel_event_dig=self.evidence_kel_event_dig,
                    mixnet_operational=False,
                )

    def test_non_minted_values_can_never_produce_ob1_met(self):
        for value in (None, object(), {"sealed": "assertion"}):
            with self.subTest(value=value):
                if value is None:
                    profile = DeploymentProfile(
                        name="no-evidence",
                        channel_encryption_operational=None,
                        channel_session_context=self.fsm_a.atom.session_context,
                        channel_kel_event_dig=self.evidence_kel_event_dig,
                        mixnet_operational=False,
                    )
                    self.assert_ob1_not_met(profile)
                else:
                    with self.assertRaises(TypeError):
                        DeploymentProfile(
                            name="forged-evidence",
                            channel_encryption_operational=value,
                            channel_session_context=self.fsm_a.atom.session_context,
                            channel_kel_event_dig=self.evidence_kel_event_dig,
                            mixnet_operational=False,
                        )

    def test_attestation_constructor_cannot_forge_a_capability(self):
        with self.assertRaises(TypeError):
            SealedChannelAttestation()

    def test_forged_exact_attestation_type_fails_closed(self):
        # An attacker can ask Python for an uninitialized exact-type object, but
        # it has no identity entry in the issuing channel's receipt ledger.
        forged = object.__new__(SealedChannelAttestation)
        self.assert_ob1_not_met(self.profile(attestation=forged))

    def test_copied_private_receipt_handle_cannot_forge_identity(self):
        real = self.mint_channel_attestation()
        forged = object.__new__(SealedChannelAttestation)
        for field in ("_issuer", "_receipt_id"):
            object.__setattr__(
                forged, field, object.__getattribute__(real, field)
            )
        self.assert_ob1_not_met(self.profile(attestation=forged))

    def test_capability_is_frozen_and_public_evidence_is_detached(self):
        attestation = self.mint_channel_attestation()
        original_digest = attestation.transit_evidence.frame_digest

        with self.assertRaises(AttributeError):
            attestation.suite = "afp:forged-suite:v1"
        with self.assertRaises(AttributeError):
            object.__setattr__(attestation, "suite", "afp:forged-suite:v1")

        evidence_copy = attestation.transit_evidence
        object.__setattr__(evidence_copy, "frame_digest", "0" * 64)
        self.assertEqual(
            attestation.transit_evidence.frame_digest, original_digest
        )
        self.assertEqual(
            assess_ob_disclosure(self.profile(attestation=attestation)).ob1,
            MetState.MET,
        )

    def test_tampered_receipt_handle_fails_closed(self):
        attestation = self.mint_channel_attestation()
        object.__setattr__(attestation, "_receipt_id", "0" * 64)
        self.assert_ob1_not_met(self.profile(attestation=attestation))

    def test_malformed_attestation_times_fail_closed(self):
        tamper_cases = (
            ("expires_at", 10**10000),
            ("expires_at", float("nan")),
            ("expires_at", float("inf")),
            ("authenticated_at", 10**10000),
            ("authenticated_at", float("nan")),
            ("authenticated_at", float("inf")),
            ("expires_monotonic", 10**10000),
            ("expires_monotonic", float("nan")),
            ("authenticated_monotonic", float("inf")),
        )
        for field, value in tamper_cases:
            with self.subTest(field=field, value_type=type(value).__name__):
                attestation = self.mint_channel_attestation()
                issuer = object.__getattribute__(attestation, "_issuer")
                receipt_id = object.__getattribute__(attestation, "_receipt_id")
                receipt = issuer._attestation_receipts[receipt_id]
                object.__setattr__(receipt, field, value)
                self.assert_ob1_not_met(self.profile(attestation=attestation))

    def test_expired_capability_fails_closed(self):
        attestation = self.mint_channel_attestation()
        profile = self.profile(attestation=attestation)
        expires_at = attestation.expires_at
        with mock.patch(
            "afp_session.channel.time.time", return_value=expires_at + 1
        ):
            self.assert_ob1_not_met(profile)
        with mock.patch(
            "afp_session.channel.time.time", return_value=expires_at - 1
        ):
            self.assert_ob1_not_met(profile)

    def test_wall_clock_correction_does_not_poison_live_evidence(self):
        attestation = self.mint_channel_attestation()
        profile = self.profile(attestation=attestation)
        issuer = object.__getattribute__(attestation, "_issuer")
        receipt_id = object.__getattribute__(attestation, "_receipt_id")
        receipt = issuer._attestation_receipts[receipt_id]

        samples = (
            (
                receipt.authenticated_at + 2.0,
                receipt.authenticated_monotonic + 2.0,
            ),
            (
                receipt.authenticated_at + 1.0,
                receipt.authenticated_monotonic + 3.0,
            ),
        )
        for wall_now, monotonic_now in samples:
            with (
                mock.patch(
                    "afp_session.channel.time.time",
                    return_value=wall_now,
                ),
                mock.patch(
                    "afp_session.channel.time.monotonic",
                    return_value=monotonic_now,
                ),
            ):
                claim = assess_ob_disclosure(profile)
                self.assertEqual(claim.claimed_level, ObLevel.OB1)

    def test_clock_floor_and_monotonic_expiry_fail_closed(self):
        attestation = self.mint_channel_attestation()
        profile = self.profile(attestation=attestation)
        issuer = object.__getattribute__(attestation, "_issuer")
        receipt_id = object.__getattribute__(attestation, "_receipt_id")
        receipt = issuer._attestation_receipts[receipt_id]

        with (
            mock.patch(
                "afp_session.channel.time.time",
                return_value=receipt.authenticated_at - 1.0,
            ),
            mock.patch(
                "afp_session.channel.time.monotonic",
                return_value=receipt.authenticated_monotonic + 1.0,
            ),
        ):
            self.assert_ob1_not_met(profile)

        with (
            mock.patch(
                "afp_session.channel.time.time",
                return_value=receipt.authenticated_at + 1.0,
            ),
            mock.patch(
                "afp_session.channel.time.monotonic",
                return_value=receipt.authenticated_monotonic + 2.0,
            ),
        ):
            self.assertEqual(
                assess_ob_disclosure(profile).claimed_level,
                ObLevel.OB1,
            )

        with (
            mock.patch(
                "afp_session.channel.time.time",
                return_value=receipt.authenticated_at + 2.0,
            ),
            mock.patch(
                "afp_session.channel.time.monotonic",
                return_value=receipt.expires_monotonic + 1.0,
            ),
        ):
            self.assert_ob1_not_met(profile)

        self.assertNotIn(receipt_id, issuer._attestation_receipts)
        with (
            mock.patch(
                "afp_session.channel.time.time",
                return_value=receipt.authenticated_at + 3.0,
            ),
            mock.patch(
                "afp_session.channel.time.monotonic",
                return_value=receipt.authenticated_monotonic + 3.0,
            ),
        ):
            self.assert_ob1_not_met(profile)

    def test_context_or_kel_mismatch_fails_closed(self):
        for field, value in (
            ("channel_session_context", "wrong-session-context"),
            ("channel_kel_event_dig", "f" * 64),
        ):
            with self.subTest(field=field):
                self.assert_ob1_not_met(self.profile(**{field: value}))


class GuardTest(ChannelEvidenceFixture):
    def test_overclaiming_ob2_without_mixnet_is_a_violation(self):
        profile = self.profile(
            name="overclaimer",
            mixnet_operational=False,
        )
        # Trying to claim OB-2 without it is a conformance violation (§3.5) —
        # independent of cryptographic correctness.
        with self.assertRaises(ConformanceViolation):
            guard_ob_claim(profile, ObLevel.OB2)

    def test_claiming_ob1_is_allowed_for_an_ob1_deployment(self):
        profile = self.profile(
            name="honest-interim",
            mixnet_operational=False,
        )
        claim = guard_ob_claim(profile, ObLevel.OB1)  # permitted
        self.assertEqual(claim.claimed_level, ObLevel.OB1)

    def test_claiming_ob2_is_allowed_when_actually_met(self):
        profile = self.profile(
            name="full",
            mixnet_operational=True,
            mandatory_cover_traffic=True,
            mix_node_count=5,
        )
        claim = guard_ob_claim(profile, ObLevel.OB2)
        self.assertEqual(claim.claimed_level, ObLevel.OB2)

    def test_overclaim_message_includes_disclosure(self):
        profile = self.profile(
            name="x",
            mixnet_operational=False,
        )
        with self.assertRaises(ConformanceViolation) as ctx:
            guard_ob_claim(profile, ObLevel.OB2)
        self.assertIn("OB-2", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
