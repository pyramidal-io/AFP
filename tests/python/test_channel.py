"""AFP §5.2 entity-to-entity sealed-channel conformance tests.

The fixture deliberately uses synthetic identities, and the KAT pins synthetic
ephemeral scalars.  It is only a clean-room interoperability/KAT fixture, never
deployment material.
"""

import _path  # noqa: F401

import hashlib
import hmac
import json
import pickle
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import afp_session as afp
import afp_session.channel as channel_module
from afp_session import keri
from afp_session.canonical import canonical_bytes
from fixtures import make_pair


VECTORS_PATH = Path(__file__).resolve().parents[2] / "docs" / "afp_channel_v1_test_vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
FRAME_PREFIX = b"afp:sealed:v1\x00"


class ChannelFixture(unittest.TestCase):
    """One synthetic bilateral session with explicit test-only channel inputs."""

    @staticmethod
    def _open_pair(*, witnessed=False, session_id="sess-synthetic-channel-kat"):
        transport, a, b, remote_a, remote_b = make_pair(witnessed=witnessed)
        proposed = a.propose(
            responder_tenant_aid=b.tenant_aid,
            responder_entity_aid=b.entity_aid,
            agreement_ref="synthetic-channel-kat",
            agreement_version="1",
            profile="work",
            profile_policy_hash="synthetic",
            responder_remote=remote_b,
            session_id=session_id,
        )
        accepted = b.accept(proposed.atom, initiator_remote=remote_a)
        a.confirm_open(proposed, accepted.atom, responder_remote=remote_b)
        return transport, a, b, remote_a, remote_b, afp.ChannelBinding.from_session(proposed.atom)

    def setUp(self):
        (
            self.transport,
            self.a,
            self.b,
            self.remote_a,
            self.remote_b,
            self.binding,
        ) = self._open_pair()

    def endpoints(self, *, witnessed=False):
        if witnessed:
            (
                self.transport,
                self.a,
                self.b,
                self.remote_a,
                self.remote_b,
                self.binding,
            ) = self._open_pair(
                witnessed=True, session_id="sess-synthetic-channel-kat-witnessed"
            )
        initiator = afp.ChannelEndpoint.create(
            self.binding, afp.ChannelRole.INITIATOR, self.a.entity
        )
        responder = afp.ChannelEndpoint.create(
            self.binding, afp.ChannelRole.RESPONDER, self.b.entity
        )
        return initiator, responder

    def channels(self, *, witnessed=False):
        initiator, responder = self.endpoints(witnessed=witnessed)
        a_channel = initiator.establish(responder.attestation, self.remote_b)
        b_channel = responder.establish(initiator.attestation, self.remote_a)
        return a_channel, b_channel, initiator, responder


class ChannelSurfaceTest(ChannelFixture):
    def test_public_constants_and_published_wire_fixture_are_exact(self):
        self.assertEqual(afp.CHANNEL_KEY_KIND, "afp:channel-key:v1")
        self.assertEqual(afp.SEALED_FRAME_KIND, "afp:sealed:v1")
        self.assertEqual(afp.CHANNEL_SUITE, "afp:x25519-sha256ctr-hmacsha256:v1")
        self.assertEqual(afp.SEALED_FRAME_OVERHEAD, 76)
        self.assertEqual(afp.DEFAULT_REPLAY_WINDOW, 64)
        self.assertEqual(VECTORS["status"], "synthetic-reference-fixture")
        self.assertIn("not a production", VECTORS["warning"])
        self.assertEqual(VECTORS["wire"]["suite"], afp.CHANNEL_SUITE)
        self.assertEqual(bytes.fromhex(VECTORS["wire"]["header_hex"]), FRAME_PREFIX)
        self.assertEqual(VECTORS["wire"]["overhead_bytes"], afp.SEALED_FRAME_OVERHEAD)

    def test_binding_is_session_and_kel_bound(self):
        self.assertEqual(self.binding.session_id, "sess-synthetic-channel-kat")
        self.assertEqual(self.binding.context, self.binding.session_context)
        self.assertEqual(self.binding.initiator_entity_aid, self.a.entity_aid)
        self.assertEqual(self.binding.responder_entity_aid, self.b.entity_aid)
        self.assertEqual(self.binding.initiator_kel_event_dig, self.a.entity.kel.latest_dig)
        self.assertEqual(self.binding.responder_kel_event_dig, self.b.entity.kel.latest_dig)

    def test_binding_rejects_non_live_session_lifecycle_values(self):
        session = self.a.sessions[self.binding.session_id].atom
        for status in (
            afp.AfpSessionStatus.PROPOSED,
            afp.AfpSessionStatus.CLOSING,
            afp.AfpSessionStatus.CLOSED,
            afp.AfpSessionStatus.EXPIRED,
            afp.AfpSessionStatus.ABORTED,
        ):
            invalid = afp.AfpSessionAtom.from_dict(session.to_dict())
            invalid.status = status
            with self.subTest(status=status), self.assertRaises(afp.ChannelError):
                afp.ChannelBinding.from_session(invalid)
        invalid = afp.AfpSessionAtom.from_dict(session.to_dict())
        invalid.closed_at = afp.unix_to_session_datetime(invalid.opened_at + 1)
        with self.assertRaises(afp.ChannelError):
            afp.ChannelBinding.from_session(invalid)
        for expires_at in (
            None,
            float("nan"),
            float("inf"),
            10**10000,
            invalid.opened_at + 3600,
            "2023-11-14T23:13:20.5Z",
            "2023-11-14T23:13:20+00:00",
        ):
            invalid = afp.AfpSessionAtom.from_dict(session.to_dict())
            invalid.expires_at = expires_at
            with self.subTest(value_type=type(expires_at).__name__):
                with self.assertRaises(afp.ChannelError):
                    afp.ChannelBinding.from_session(invalid)

    def test_binding_cannot_be_directly_constructed_or_replaced(self):
        fields = {
            name: getattr(self.binding, name)
            for name in (
                "session_id",
                "session_content_hash",
                "context",
                "profile",
                "initiator_tenant_aid",
                "initiator_entity_aid",
                "initiator_kel_event_dig",
                "responder_tenant_aid",
                "responder_entity_aid",
                "responder_kel_event_dig",
                "_session_wire",
            )
        }
        with self.assertRaises(afp.ChannelError):
            afp.ChannelBinding(**fields)
        with self.assertRaises(afp.ChannelError):
            replace(self.binding, profile="attacker-controlled-profile")

    def test_attestation_wire_is_strict_and_round_trips(self):
        initiator, _ = self.endpoints()
        wire = initiator.attestation.to_dict()
        self.assertEqual(afp.ChannelKeyAttestation.from_dict(wire), initiator.attestation)
        mutations = []
        for key in tuple(wire):
            invalid = dict(wire)
            del invalid[key]
            mutations.append(invalid)
        extra = dict(wire)
        extra["unreviewed"] = True
        mutations.extend((extra, {}, None, [], "not-a-wire"))
        for invalid in mutations:
            with self.subTest(invalid=invalid):
                with self.assertRaises(afp.ChannelError):
                    afp.ChannelKeyAttestation.from_dict(invalid)


class ChannelKatTest(unittest.TestCase):
    """Deterministic clean-room derivation and frame KAT.

    The reference exposes these diagnostic derivation helpers only inside its
    implementation module.  This test deliberately pins them together with the
    observable frame so a refactor cannot silently change the KDF transcript or
    traffic-key separation while retaining a round trip.
    """

    def test_published_deterministic_derivation_and_sealed_frame_kat(self):
        vector = VECTORS["vectors"][0]
        inputs, expected = vector, vector["expected"]
        binding = afp.ChannelBinding.from_session(
            afp.AfpSessionAtom.from_dict(inputs["session"])
        )
        self.assertEqual(
            set(inputs["initiator"]), {"ephemeral_scalar_hex", "generation_salt_hex"}
        )
        self.assertEqual(
            set(inputs["responder"]), {"ephemeral_scalar_hex", "generation_salt_hex"}
        )
        i_scalar = bytes.fromhex(inputs["initiator"]["ephemeral_scalar_hex"])
        r_scalar = bytes.fromhex(inputs["responder"]["ephemeral_scalar_hex"])
        i_salt = bytes.fromhex(inputs["initiator"]["generation_salt_hex"])
        r_salt = bytes.fromhex(inputs["responder"]["generation_salt_hex"])

        i_public = channel_module._x25519(i_scalar, channel_module._BASE_POINT)
        r_public = channel_module._x25519(r_scalar, channel_module._BASE_POINT)
        shared = channel_module._x25519(i_scalar, r_public)
        self.assertEqual(i_public.hex(), expected["initiator_public_key_hex"])
        self.assertEqual(r_public.hex(), expected["responder_public_key_hex"])
        self.assertEqual(shared, channel_module._x25519(r_scalar, i_public))
        self.assertEqual(shared.hex(), expected["x25519_result_hex"])

        def attestation(role, public_key, salt):
            tenant, entity, kel_dig = binding._party(role)
            return afp.ChannelKeyAttestation(
                role=role,
                session_id=binding.session_id,
                session_content_hash=binding.session_content_hash,
                context=binding.context,
                profile=binding.profile,
                tenant_aid=tenant,
                entity_aid=entity,
                kel_event_dig=kel_dig,
                public_key=public_key.hex(),
                generation_salt=salt.hex(),
                signature="00" * 64,
            )

        initiator = attestation(afp.ChannelRole.INITIATOR, i_public, i_salt)
        responder = attestation(afp.ChannelRole.RESPONDER, r_public, r_salt)
        transcript = canonical_bytes(
            {
                "kind": channel_module._TRANSCRIPT_KIND,
                "suite": afp.CHANNEL_SUITE,
                "session": binding._transcript_dict(),
                "initiator_attestation": initiator.to_dict(),
                "responder_attestation": responder.to_dict(),
            }
        )
        transcript_hash = hashlib.sha256(transcript).digest()
        self.assertEqual(transcript_hash.hex(), expected["transcript_sha256_hex"])
        keys = {
            name: channel_module._hkdf(
                shared, salt=transcript_hash, info=label, length=32
            )
            for name, label in channel_module._KEY_INFO.items()
        }
        self.assertEqual(
            {name: value.hex() for name, value in keys.items()},
            expected["directional_keys_hex"],
        )
        sequence = 0
        nonce = hmac.new(
            keys["i2r_nonce"],
            channel_module._NONCE_LABEL + sequence.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()[:16]
        payload = bytes.fromhex(inputs["plaintext_hex"])
        associated_data = channel_module._associated_data(
            binding,
            0,
            sequence,
            inputs["message_class"],
            binding.initiator_entity_aid,
        )
        ciphertext = channel_module._sha256_ctr(
            keys["i2r_cipher"], nonce, sequence, payload
        )
        header = (
            FRAME_PREFIX
            + bytes((1, 0))
            + sequence.to_bytes(8, "big")
            + nonce
            + len(ciphertext).to_bytes(4, "big")
        )
        tag = hmac.new(
            keys["i2r_mac"], associated_data + header + ciphertext, hashlib.sha256
        ).digest()
        self.assertEqual(nonce.hex(), expected["nonce_hex"])
        self.assertEqual(
            hashlib.sha256(associated_data).hexdigest(),
            expected["associated_data_sha256_hex"],
        )
        self.assertEqual(ciphertext.hex(), expected["ciphertext_hex"])
        self.assertEqual(tag.hex(), expected["tag_hex"])
        self.assertEqual((header + ciphertext + tag).hex(), expected["frame_hex"])


class ChannelEstablishmentTest(ChannelFixture):
    def test_threshold_zero_and_witnessed_bilateral_establishment(self):
        for witnessed in (False, True):
            with self.subTest(witnessed=witnessed):
                a_channel, b_channel, _, _ = self.channels(witnessed=witnessed)
                self.assertIsInstance(a_channel, afp.SessionChannel)
                self.assertIsInstance(b_channel, afp.SessionChannel)
                self.assertFalse(a_channel.closed)
                self.assertFalse(b_channel.closed)

    def test_endpoint_is_one_shot(self):
        initiator, responder = self.endpoints()
        initiator.establish(responder.attestation, self.remote_b)
        with self.assertRaises(afp.ChannelError):
            initiator.establish(responder.attestation, self.remote_b)

    def test_wrong_recipient_and_stale_kel_are_rejected_without_a_channel(self):
        initiator, responder = self.endpoints()
        with self.assertRaises(afp.ChannelError):
            initiator.establish(responder.attestation, self.remote_a)

        initiator, responder = self.endpoints()
        self.b.entity.rotate()
        with self.assertRaises(afp.ChannelError):
            initiator.establish(responder.attestation, self.remote_b)

    def test_rotated_local_kel_cannot_establish_old_binding(self):
        initiator, responder = self.endpoints()
        self.a.entity.rotate()
        with self.assertRaises(afp.ChannelError):
            initiator.establish(responder.attestation, self.remote_b)

    def test_runtime_kel_rotation_closes_existing_channel(self):
        a_channel, _, _, _ = self.channels()
        self.a.entity.rotate()
        with self.assertRaises(afp.ChannelError):
            a_channel.seal(b"after-rotation", message_class="afp.work.result")
        self.assertTrue(a_channel.closed)

    def test_interaction_events_do_not_close_an_established_channel(self):
        a_channel, b_channel, _, _ = self.channels()
        pinned_key_event = keri.current_key_event_digest(self.a.entity.kel)
        self.a.entity._anchor_delegation("E_test_delegate", "D_test_inception")
        self.assertNotEqual(self.a.entity.kel.latest_dig, pinned_key_event)
        self.assertEqual(
            keri.current_key_event_digest(self.a.entity.kel), pinned_key_event
        )
        frame = a_channel.seal(
            b"after-interaction", message_class="afp.work.result"
        )
        self.assertEqual(
            b_channel.open(frame, message_class="afp.work.result"),
            b"after-interaction",
        )

    def test_session_opened_after_interactions_pins_the_current_key_events(self):
        transport, a, b, remote_a, remote_b = make_pair()
        a.entity._anchor_delegation("E_test_a", "D_test_a")
        b.entity._anchor_delegation("E_test_b", "D_test_b")
        proposed = a.propose(
            responder_tenant_aid=b.tenant_aid,
            responder_entity_aid=b.entity_aid,
            agreement_ref="synthetic-channel-after-ixn",
            agreement_version="1",
            profile="work",
            profile_policy_hash="synthetic",
            responder_remote=remote_b,
            session_id="sess-synthetic-channel-after-ixn",
        )
        accepted = b.accept(proposed.atom, initiator_remote=remote_a)
        a.confirm_open(proposed, accepted.atom, responder_remote=remote_b)
        binding = afp.ChannelBinding.from_session(proposed.atom)
        self.assertEqual(
            binding.initiator_kel_event_dig,
            keri.current_key_event_digest(a.entity.kel),
        )
        self.assertEqual(
            binding.responder_kel_event_dig,
            keri.current_key_event_digest(b.entity.kel),
        )
        self.assertNotEqual(binding.initiator_kel_event_dig, a.entity.kel.latest_dig)
        self.assertNotEqual(binding.responder_kel_event_dig, b.entity.kel.latest_dig)
        initiator = afp.ChannelEndpoint.create(
            binding, afp.ChannelRole.INITIATOR, a.entity
        )
        responder = afp.ChannelEndpoint.create(
            binding, afp.ChannelRole.RESPONDER, b.entity
        )
        a_channel = initiator.establish(responder.attestation, remote_b)
        b_channel = responder.establish(initiator.attestation, remote_a)
        frame = a_channel.seal(b"post-ixn", message_class="afp.work.result")
        self.assertEqual(
            b_channel.open(frame, message_class="afp.work.result"), b"post-ixn"
        )

    def test_unsigned_local_lifecycle_state_does_not_diverge_traffic_keys(self):
        session_id = self.binding.session_id
        initiator_atom = self.a.sessions[session_id].atom
        responder_atom = self.b.sessions[session_id].atom
        initiator_atom.status = afp.AfpSessionStatus.ACTIVE
        self.assertEqual(responder_atom.status, afp.AfpSessionStatus.OPEN)
        initiator_binding = afp.ChannelBinding.from_session(initiator_atom)
        responder_binding = afp.ChannelBinding.from_session(responder_atom)
        self.assertEqual(
            initiator_binding.session_content_hash,
            responder_binding.session_content_hash,
        )
        initiator = afp.ChannelEndpoint.create(
            initiator_binding, afp.ChannelRole.INITIATOR, self.a.entity
        )
        responder = afp.ChannelEndpoint.create(
            responder_binding, afp.ChannelRole.RESPONDER, self.b.entity
        )
        a_channel = initiator.establish(responder.attestation, self.remote_b)
        b_channel = responder.establish(initiator.attestation, self.remote_a)
        frame = a_channel.seal(
            b"split-lifecycle", message_class="afp.work.result"
        )
        self.assertEqual(
            b_channel.open(frame, message_class="afp.work.result"),
            b"split-lifecycle",
        )


class ChannelSealTest(ChannelFixture):
    def test_authenticated_receive_mints_bound_process_local_evidence(self):
        a_channel, b_channel, _, _ = self.channels()
        frame = a_channel.seal(b"evidence", message_class="afp.work.result")
        plaintext, attestation = b_channel.open_with_attestation(
            frame, message_class="afp.work.result"
        )
        self.assertEqual(plaintext, b"evidence")
        self.assertIsInstance(attestation, afp.SealedChannelAttestation)
        self.assertEqual(attestation.session_id, self.binding.session_id)
        self.assertEqual(attestation.session_context, self.binding.context)
        self.assertEqual(
            attestation.kel_event_dig, self.binding.initiator_kel_event_dig
        )
        self.assertEqual(attestation.suite, afp.CHANNEL_SUITE)
        self.assertEqual(attestation.suite_id, 1)
        self.assertEqual(
            attestation.transit_evidence.frame_digest,
            hashlib.sha256(frame).hexdigest(),
        )
        self.assertTrue(
            afp.validate_sealed_channel_attestation(
                attestation,
                session_context=self.binding.context,
                kel_event_dig=self.binding.initiator_kel_event_dig,
            )
        )
        with self.assertRaises(TypeError):
            pickle.dumps(attestation)
        with self.assertRaises(afp.ChannelError):
            b_channel.open_with_attestation(
                frame, message_class="afp.work.result"
            )

    def test_channel_close_or_kel_rotation_revokes_receive_evidence(self):
        for revoke in ("close", "peer-kel-rotation"):
            with self.subTest(revoke=revoke):
                a_channel, b_channel, _, _ = self.channels()
                frame = a_channel.seal(
                    b"revocable-evidence", message_class="afp.work.result"
                )
                _plaintext, attestation = b_channel.open_with_attestation(
                    frame, message_class="afp.work.result"
                )
                if revoke == "close":
                    b_channel.close()
                else:
                    self.a.entity.rotate()
                self.assertFalse(
                    afp.validate_sealed_channel_attestation(
                        attestation,
                        session_context=self.binding.context,
                        kel_event_dig=self.binding.initiator_kel_event_dig,
                    )
                )

    def test_local_kel_rotation_revokes_receive_evidence(self):
        a_channel, b_channel, _, _ = self.channels()
        frame = a_channel.seal(
            b"local-rotation-evidence", message_class="afp.work.result"
        )
        _plaintext, attestation = b_channel.open_with_attestation(
            frame, message_class="afp.work.result"
        )
        self.b.entity.rotate()
        self.assertFalse(
            afp.validate_sealed_channel_attestation(
                attestation,
                session_context=self.binding.context,
                kel_event_dig=self.binding.initiator_kel_event_dig,
            )
        )

    def test_attestation_expiry_is_capped_and_failed_issuance_is_atomic(self):
        a_channel, b_channel, _, _ = self.channels()
        session_expires_at = afp.session_datetime_to_unix(
            b_channel.binding._session_dict()["expires_at"]
        )

        capped_frame = a_channel.seal(
            b"expiry-capped-evidence", message_class="afp.work.result"
        )
        with mock.patch.object(
            channel_module.time, "time", return_value=session_expires_at - 1
        ):
            _plaintext, attestation = b_channel.open_with_attestation(
                capped_frame, message_class="afp.work.result"
            )
        self.assertEqual(attestation.expires_at, session_expires_at)

        retry_sender, retry_receiver, _, _ = self.channels()
        retryable_frame = retry_sender.seal(
            b"atomic-expiry-failure", message_class="afp.work.result"
        )
        with mock.patch.object(
            channel_module.time, "time", return_value=session_expires_at
        ):
            with self.assertRaisesRegex(afp.ChannelError, "expired session"):
                retry_receiver.open_with_attestation(
                    retryable_frame, message_class="afp.work.result"
                )
        self.assertIsNone(retry_receiver.receive_highest_sequence)

        plaintext, retry_attestation = retry_receiver.open_with_attestation(
            retryable_frame, message_class="afp.work.result"
        )
        self.assertEqual(plaintext, b"atomic-expiry-failure")
        self.assertTrue(
            afp.validate_sealed_channel_attestation(
                retry_attestation,
                session_context=self.binding.context,
                kel_event_dig=self.binding.initiator_kel_event_dig,
            )
        )

        compatibility_frame = retry_sender.seal(
            b"plain-open-does-not-require-evidence",
            message_class="afp.work.result",
        )
        with mock.patch.object(
            channel_module.time, "time", return_value=session_expires_at
        ):
            self.assertEqual(
                retry_receiver.open(
                    compatibility_frame, message_class="afp.work.result"
                ),
                b"plain-open-does-not-require-evidence",
            )

    def test_expired_receipt_is_pruned_while_live_receipt_remains_valid(self):
        a_channel, b_channel, _, _ = self.channels()
        first_frame = a_channel.seal(
            b"first-evidence", message_class="afp.work.result"
        )
        _plaintext, expired = b_channel.open_with_attestation(
            first_frame, message_class="afp.work.result"
        )
        expired_receipt_id = object.__getattribute__(expired, "_receipt_id")
        expired_receipt = b_channel._attestation_receipts[expired_receipt_id]
        object.__setattr__(
            expired_receipt,
            "expires_monotonic",
            expired_receipt.authenticated_monotonic,
        )

        second_frame = a_channel.seal(
            b"second-evidence", message_class="afp.work.result"
        )
        _plaintext, live = b_channel.open_with_attestation(
            second_frame, message_class="afp.work.result"
        )
        self.assertNotIn(expired_receipt_id, b_channel._attestation_receipts)
        self.assertFalse(
            afp.validate_sealed_channel_attestation(
                expired,
                session_context=self.binding.context,
                kel_event_dig=self.binding.initiator_kel_event_dig,
            )
        )
        self.assertTrue(
            afp.validate_sealed_channel_attestation(
                live,
                session_context=self.binding.context,
                kel_event_dig=self.binding.initiator_kel_event_dig,
            )
        )

    def test_bidirectional_empty_binary_and_trailing_zero_payloads(self):
        a_channel, b_channel, _, _ = self.channels()
        cases = (b"", b"binary\x00\xff\x00", b"\x00" * 31)
        for payload in cases:
            with self.subTest(direction="a-to-b", payload=payload):
                frame = a_channel.seal(payload, message_class="afp.work.result")
                self.assertEqual(b_channel.open(frame, message_class="afp.work.result"), payload)
            with self.subTest(direction="b-to-a", payload=payload):
                frame = b_channel.seal(payload, message_class="afp.work.request")
                self.assertEqual(a_channel.open(frame, message_class="afp.work.request"), payload)

    def test_frame_is_a_fixed_header_plus_exact_overhead(self):
        a_channel, _, _, _ = self.channels()
        payload = b"wire\x00"
        frame = a_channel.seal(payload, message_class="afp.work.result")
        self.assertIsInstance(frame, bytes)
        self.assertTrue(frame.startswith(FRAME_PREFIX))
        self.assertEqual(len(frame), len(payload) + afp.SEALED_FRAME_OVERHEAD)
        self.assertEqual(int.from_bytes(frame[40:44], "big"), len(payload))
        self.assertNotIn(b"afp.work.result", frame)

    def test_header_ciphertext_and_tag_bit_flips_are_authenticated(self):
        a_channel, b_channel, _, _ = self.channels()
        frame = a_channel.seal(b"authenticated", message_class="afp.work.result")
        indexes = (0, 14, 15, 16, 24, 40, 44, len(frame) - 1)
        for index in indexes:
            mutated = bytearray(frame)
            mutated[index] ^= 1
            with self.subTest(index=index), self.assertRaises(afp.ChannelError):
                b_channel.open(bytes(mutated), message_class="afp.work.result")

    def test_malformed_frames_fail_as_channel_errors(self):
        _, b_channel, _, _ = self.channels()
        for malformed in (
            b"",
            FRAME_PREFIX,
            FRAME_PREFIX + b"\x01\x00" + b"\x00" * 8 + b"\x00" * 16 + b"\x00" * 4 + b"\x00" * 32,
            b"not-a-sealed-frame" + b"\x00" * afp.SEALED_FRAME_OVERHEAD,
            None,
            bytearray(b"\x00" * afp.SEALED_FRAME_OVERHEAD),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(afp.ChannelError):
                b_channel.open(malformed, message_class="afp.work.result")

    def test_each_associated_data_binding_field_is_authenticated(self):
        a_channel, b_channel, _, _ = self.channels()
        frame = a_channel.seal(b"payload", message_class="afp.work.result")
        direction = frame[15]
        sequence = int.from_bytes(frame[16:24], "big")
        original_ad = json.loads(
            channel_module._associated_data(
                b_channel.binding,
                direction,
                sequence,
                "afp.work.result",
                b_channel.binding.initiator_entity_aid,
            )
        )
        mutations = {
            "frame_version": "afp:sealed:v2",
            "suite": "afp:other-suite:v1",
            "direction": 1,
            "session_id": "other-session",
            "session_content_hash": "D_other-content-hash",
            "context": "X_other-context",
            "profile": "other-profile",
            "message_class": "afp.work.request",
            "sender_entity_aid": "E_other-sender",
            "sequence": 1,
        }
        authenticated = frame[:-32]
        self.assertIsNotNone(b_channel._receive_mac_key)
        for field, value in mutations.items():
            with self.subTest(field=field):
                mutated_ad = dict(original_ad)
                mutated_ad[field] = value
                forged_tag = hmac.new(
                    b_channel._receive_mac_key,
                    canonical_bytes(mutated_ad) + authenticated,
                    hashlib.sha256,
                ).digest()
                with self.assertRaises(afp.ChannelError):
                    b_channel.open(
                        authenticated + forged_tag,
                        message_class="afp.work.result",
                    )
        self.assertIsNone(b_channel.receive_highest_sequence)
        self.assertEqual(
            b_channel.open(frame, message_class="afp.work.result"), b"payload"
        )

    def test_authentication_failure_does_not_consume_replay_state(self):
        a_channel, b_channel, _, _ = self.channels()
        frame = a_channel.seal(b"retry-after-auth-failure", message_class="afp.work.result")
        corrupted = bytearray(frame)
        corrupted[-1] ^= 1
        with self.assertRaises(afp.ChannelError):
            b_channel.open(bytes(corrupted), message_class="afp.work.result")
        self.assertEqual(b_channel.open(frame, message_class="afp.work.result"), b"retry-after-auth-failure")

    def test_wrong_traffic_keys_fail_without_partial_output_or_replay_mutation(self):
        _, b_channel, _, _ = self.channels()
        initiator = afp.ChannelEndpoint.create(
            self.binding, afp.ChannelRole.INITIATOR, self.a.entity
        )
        responder = afp.ChannelEndpoint.create(
            self.binding, afp.ChannelRole.RESPONDER, self.b.entity
        )
        other_a = initiator.establish(responder.attestation, self.remote_b)
        other_b = responder.establish(initiator.attestation, self.remote_a)
        frame = other_a.seal(b"wrong-traffic-key", message_class="afp.work.result")
        with self.assertRaises(afp.ChannelError):
            b_channel.open(frame, message_class="afp.work.result")
        self.assertIsNone(b_channel.receive_highest_sequence)
        self.assertEqual(
            other_b.open(frame, message_class="afp.work.result"), b"wrong-traffic-key"
        )

    def test_replay_and_reorder_window_fail_closed(self):
        a_channel, b_channel, _, _ = self.channels()
        frames = [a_channel.seal(bytes([number]), message_class="afp.work.result") for number in range(66)]
        self.assertEqual(b_channel.open(frames[1], message_class="afp.work.result"), b"\x01")
        self.assertEqual(b_channel.open(frames[0], message_class="afp.work.result"), b"\x00")
        with self.assertRaises(afp.ChannelError):
            b_channel.open(frames[0], message_class="afp.work.result")
        for frame in frames[2:66]:
            b_channel.open(frame, message_class="afp.work.result")
        with self.assertRaises(afp.ChannelError):
            b_channel.open(frames[1], message_class="afp.work.result")

    def test_close_is_terminal(self):
        a_channel, b_channel, _, _ = self.channels()
        a_channel.close()
        self.assertTrue(a_channel.closed)
        with self.assertRaises(afp.ChannelError):
            a_channel.seal(b"after-close", message_class="afp.work.result")
        with self.assertRaises(afp.ChannelError):
            a_channel.open(b_channel.seal(b"after-peer-close", message_class="afp.work.result"), message_class="afp.work.result")

    def test_sequence_exhaustion_closes_the_channel(self):
        a_channel, _, _, _ = self.channels()
        a_channel._send_sequence = 1 << 64
        with self.assertRaises(afp.ChannelError):
            a_channel.seal(b"exhausted", message_class="afp.work.result")
        self.assertTrue(a_channel.closed)

    def test_concurrent_sends_have_unique_sequences_if_supported(self):
        a_channel, _, _, _ = self.channels()
        frames = []
        lock = threading.Lock()

        def send(number):
            frame = a_channel.seal(number.to_bytes(2, "big"), message_class="afp.work.result")
            with lock:
                frames.append(frame)

        threads = [threading.Thread(target=send, args=(number,)) for number in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(frames), 16)
        self.assertEqual({frame[16:24] for frame in frames}, {n.to_bytes(8, "big") for n in range(16)})


if __name__ == "__main__":
    unittest.main()
