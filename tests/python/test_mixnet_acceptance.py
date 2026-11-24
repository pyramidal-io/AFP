"""Headline R7 acceptance test for the AFP §8 Federation Mixnet.

The requirement's acceptance criterion, verbatim:

    "a running mixnet meeting the §8.2 conformance properties carries AFP session
     traffic."

This test demonstrates exactly that, end to end, with REAL cryptography:

  1. A KERI-witnessed mix-node directory (§8.7) is built and verified — the same
     §4 witness machinery the session core uses.
  2. A real ``afp_session`` bilateral session is established (propose→open) with
     mutual KERI identity binding (§12.3).
  3. The session's signed ``afp:envelope:v1`` (§12.7) is carried THROUGH the
     mixnet — a >= 3-hop stratified Sphinx route with per-hop blinding, mixing
     delay, and replay rejection — slotted into the tenant's mandatory cover stream
     (§8.5). The receiving instance verifies it with the UNCHANGED §12.7 path.
  4. The §8.2 conformance properties verifiable from the transit and a second
     same-relationship session are asserted (endpoint unlinkability,
     no-cleartext-relationship, no-single-trusted-relay, cover
     indistinguishability; correlation resistance honestly PARTIAL).
  5. The honest OB-1/OB-2 disclosure guard (``afp_session.conformance``) now reads
     OB-2 — legitimately, because the mixnet is genuinely operational and meets
     §8.2 — and the test proves it reads OB-1 when any precondition is removed.

Tampering is shown to be rejected at both the mixnet (replay) and sealed-channel
authentication layers, before the unchanged session-envelope verifier is reached.
"""

import _path  # noqa: F401

import copy
import hashlib
import json
import random
import unittest

import afp_mixnet as mix
from afp_session import (
    AfpEnvelope,
    BundleVerificationResult,
    ChannelError,
    Instance,
    InMemoryTransport,
    ObLevel,
    RemoteParty,
    ZkaBundle,
    keri,
    session_context_field,
)
from afp_session.canonical import canonical_bytes
from afp_session.channel import SEALED_FRAME_OVERHEAD
from afp_session.profiles import AfpProfileDescriptor, default_registry
from fixtures import establish_channels
from mixnet_fixtures import build_mixnet

pytestmark = None


def _nested_observation_bytes(value):
    """Yield byte representations from supported nested observation values."""
    if isinstance(value, bytes):
        yield value
    elif isinstance(value, str):
        yield value.encode("utf-8")
    elif isinstance(value, dict):
        for key, nested_value in value.items():
            yield from _nested_observation_bytes(key)
            yield from _nested_observation_bytes(nested_value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for nested_value in value:
            yield from _nested_observation_bytes(nested_value)


class MixnetCarriesSessionTrafficTest(unittest.TestCase):
    def setUp(self):
        self.mixnet, self.directory, self.builder, self.nodes = build_mixnet(
            rng=random.Random(2024)
        )
        # Two ADAMAS instances (distinct KERI tenant+entity identities).
        self.tA = keri.Identity.incept_tenant()
        self.eA = keri.Identity.incept_entity(self.tA)
        self.tB = keri.Identity.incept_tenant()
        self.eB = keri.Identity.incept_entity(self.tB)
        transport = InMemoryTransport()
        # Both parties recognize the test-only profile bilaterally (§12.4 rule 2).
        profiles = default_registry()
        profiles.register(
            AfpProfileDescriptor(
                name="work_final_hop_privacy",
                version="0.0.0",
                spec_ref="test-only final-hop privacy session",
                atom_kinds=[],
                policy_schema_ref="afp:agreement-policy:work:v1",
                status="experimental",
            )
        )
        self.A = Instance(
            tenant=self.tA, entity=self.eA, transport=transport, profile_registry=profiles
        )
        self.B = Instance(
            tenant=self.tB, entity=self.eB, transport=transport, profile_registry=profiles
        )
        self.remote_a = RemoteParty(self.eA.kel, self.tA.kel, witness_keys={})
        self.remote_b = RemoteParty(self.eB.kel, self.tB.kel, witness_keys={})

    def _open_session(self, *, profile="work"):
        fsm_a = self.A.propose(
            responder_tenant_aid=self.tB.aid,
            responder_entity_aid=self.eB.aid,
            responder_remote=self.remote_b,
            agreement_ref="agreement-ab",
            agreement_version="1.0",
            profile=profile,
            profile_policy_hash="policyhash",
        )
        fsm_b = self.B.accept(fsm_a.atom, initiator_remote=self.remote_a)
        self.A.confirm_open(fsm_a, fsm_b.atom, responder_remote=self.remote_b)
        return fsm_a, fsm_b

    def _send_comparison_session(
        self, *, reference_log, reference_session_context, profile
    ):
        """Carry a fresh same-relationship session over the identical relay path."""
        fsm_a, fsm_b = self._open_session(profile=profile)
        self.assertNotEqual(fsm_a.atom.session_context, reference_session_context)
        sender_channel, receiver_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )
        bundle = ZkaBundle(
            kind="zka:bundle:v1",
            context=session_context_field(fsm_a.atom.session_context),
            coord_proof="opaque-cross-session-comparison",
        )
        cover = mix.CoverScheduler()
        cover.run_slots(1)
        node_aids = [
            observation.node_aid for observation in reference_log.observations
        ]
        route = mix.Route(
            node_aids=node_aids,
            public_keys=[
                self.nodes[node_aid].keypair.public_point for node_aid in node_aids
            ],
            addresses=[self.mixnet._addr(node_aid) for node_aid in node_aids[1:]]
            + [b"\x00" * 32],
        )
        original_select_route = self.mixnet.select_route
        self.mixnet.select_route = lambda: route
        try:
            result = mix.send_envelope_via_mixnet(
                sender=self.A,
                fsm=fsm_a,
                bundle=bundle,
                message_class="result_cross_session_comparison",
                receiver=self.B,
                receiver_fsm=fsm_b,
                sender_remote=self.remote_a,
                sender_channel=sender_channel,
                receiver_channel=receiver_channel,
                mixnet=self.mixnet,
                sender_cover=cover,
                recipient_entity_aid=self.eB.aid,
                bundle_verifier=BundleVerificationResult.accepted,
            )
        finally:
            self.mixnet.select_route = original_select_route
        self.assertEqual(
            [observation.node_aid for observation in result.transit_log.observations],
            node_aids,
        )
        return result

    def test_session_envelope_transits_mixnet_and_ob2_is_honestly_claimable(self):
        fsm_a, fsm_b = self._open_session(profile="work_final_hop_privacy")
        self.assertEqual(fsm_a.atom.session_context, fsm_b.atom.session_context)
        sender_channel, receiver_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )

        bundle = ZkaBundle(
            kind="zka:bundle:v1",
            context=session_context_field(fsm_a.atom.session_context),
            transaction="opaque-zka-transaction-proof: TRANSPORT-PLAINTEXT-SENTINEL",
            coord_proof="opaque-zka-coord-proof: TRANSPORT-PLAINTEXT-SENTINEL",
            compliance_proofs=[
                "opaque-zkc-proof-one: TRANSPORT-PLAINTEXT-SENTINEL",
                "opaque-zkc-proof-two: TRANSPORT-PLAINTEXT-SENTINEL",
            ],
            binding_proof="opaque-zka-binding-proof: TRANSPORT-PLAINTEXT-SENTINEL",
        )

        # Tenant A's mandatory cover stream: idle slots, then the real envelope.
        cover_a = mix.CoverScheduler()
        cover_a.run_slots(4)  # constant cover while idle (§8.5)

        captured_payloads = []
        captured_packets = {}
        original_send = self.mixnet.send
        original_processes = {}

        # Preserve the exact packet each relay receives.  These are the only
        # packet bytes a compromised relay starts with; below we independently
        # peel them with that relay's private key to model its derivable view.
        for node_aid, node in self.nodes.items():
            original_processes[node_aid] = node.process

            def capture_process(packet, *, params, node_aid=node_aid):
                captured_packets[node_aid] = packet
                return original_processes[node_aid](packet, params=params)

            node.process = capture_process

        def capture_send(*, route, destination_handle, payload):
            captured_payloads.append(payload)
            return original_send(
                route=route, destination_handle=destination_handle, payload=payload
            )

        self.mixnet.send = capture_send
        try:
            result = mix.send_envelope_via_mixnet(
                sender=self.A,
                fsm=fsm_a,
                bundle=bundle,
                message_class="result_final_hop_privacy",
                receiver=self.B,
                receiver_fsm=fsm_b,
                sender_remote=self.remote_a,
                sender_channel=sender_channel,
                receiver_channel=receiver_channel,
                mixnet=self.mixnet,
                sender_cover=cover_a,
                recipient_entity_aid=self.eB.aid,
                bundle_verifier=BundleVerificationResult.accepted,
            )
        finally:
            self.mixnet.send = original_send
            for node_aid, node in self.nodes.items():
                node.process = original_processes[node_aid]

        # The final Sphinx delivery is still the §5.2 sealed frame, never a
        # plaintext/canonical envelope.  Only B's channel boundary may decode it.
        self.assertEqual(len(captured_payloads), 1)
        self.assertTrue(captured_payloads[0].startswith(b"afp:sealed:v1\x00"))
        self.assertNotIn(b"TRANSPORT-PLAINTEXT-SENTINEL", captured_payloads[0])
        self.assertIsNotNone(result.transit_log.delivered_payload)
        self.assertTrue(
            result.transit_log.delivered_payload.startswith(b"afp:sealed:v1\x00")
        )
        self.assertEqual(
            result.transit_log.delivered_payload, captured_payloads[0]
        )
        with self.assertRaises((UnicodeDecodeError, json.JSONDecodeError)):
            AfpEnvelope.from_dict(
                json.loads(result.transit_log.delivered_payload.decode())
            )
        plaintext_envelope = canonical_bytes(result.received_envelope.to_dict())
        self.assertNotEqual(
            captured_payloads[0], plaintext_envelope
        )

        # The envelope traversed >= 3 hops and was delivered + verified by B.
        self.assertTrue(result.transit_log.delivered)
        self.assertGreaterEqual(len(result.transit_log.observations), 3)
        self.assertEqual(len(self.B.inbox[fsm_b.atom.id]), 1)
        self.assertEqual(
            result.received_envelope.message_class, "result_final_hop_privacy"
        )
        self.assertEqual(
            result.received_envelope.bundle.context,
            session_context_field(fsm_b.atom.session_context),
        )

        # No plaintext envelope metadata or opaque proof may occur in the final
        # delivery or in any individual relay observation.
        secrets = [
            self.tA.aid,
            self.eA.aid,
            fsm_a.atom.id,
            fsm_a.atom.session_context,
            fsm_a.atom.profile,
            result.received_envelope.message_class,
            bundle.transaction,
            bundle.coord_proof,
            *bundle.compliance_proofs,
            bundle.binding_proof,
        ]
        secret_bytes = [
            value.encode("utf-8") for value in secrets if value is not None
        ]
        for value in secret_bytes:
            self.assertIn(value, plaintext_envelope)
            self.assertNotIn(value, result.transit_log.delivered_payload)
            for observation in result.transit_log.observations:
                for field_value in vars(observation).values():
                    for observed_bytes in _nested_observation_bytes(field_value):
                        self.assertNotIn(value, observed_bytes)

        # Compromise every relay in turn.  Reconstruct exactly one Sphinx peel
        # with its MixNodeKeypair private key (without that node's replay state),
        # and ensure no derivation exposes envelope fields verbatim; even the
        # final relay's application payload remains the sealed channel frame.
        from afp_mixnet import crypto, sphinx

        observations = result.transit_log.observations
        self.assertEqual(set(captured_packets), set(o.node_aid for o in observations))
        for index, observation in enumerate(observations):
            received_packet = captured_packets[observation.node_aid]
            shared_secret = crypto.x25519_raw(
                self.nodes[observation.node_aid].keypair.private_int,
                received_packet.alpha,
            )
            blind, mac_key, header_key, payload_key = sphinx._derive_keys(
                shared_secret
            )

            # Independently reconstruct every artifact available to this relay,
            # rather than relying only on process_packet's returned object.
            per_hop = 1 + 32 + crypto.MAC_SIZE
            routing_size = self.mixnet.params.routing_info_size
            incoming_mac = received_packet.header[: crypto.MAC_SIZE]
            encrypted_routing = received_packet.header[crypto.MAC_SIZE :]
            expected_mac = crypto.mac(mac_key, encrypted_routing)
            self.assertEqual(incoming_mac, expected_mac)
            routing_stream = crypto.stream_xor(
                header_key, b"\x00" * (routing_size + per_hop)
            )
            decoded_routing = sphinx._xor(
                encrypted_routing + b"\x00" * per_hop, routing_stream
            )
            flag = decoded_routing[0]
            decoded_address = decoded_routing[1:33]
            next_mac = decoded_routing[33:per_hop]
            next_routing = decoded_routing[per_hop:]
            peeled_payload_body = crypto.stream_xor(
                payload_key, received_packet.payload
            )
            derived = sphinx.process_packet(
                received_packet,
                self.nodes[observation.node_aid].keypair,
                params=self.mixnet.params,
            )
            self.assertEqual(derived.is_final, observation.is_final)
            relay_view = [
                received_packet.to_bytes(),
                shared_secret,
                blind,
                mac_key,
                header_key,
                payload_key,
                incoming_mac,
                encrypted_routing,
                expected_mac,
                routing_stream,
                decoded_routing,
                decoded_address,
                next_mac,
                next_routing,
                peeled_payload_body,
            ]
            if derived.is_final:
                self.assertEqual(flag, 1)
                self.assertEqual(
                    decoded_address,
                    mix.rendezvous_handle(
                        session_context=fsm_a.atom.session_context,
                        recipient_entity_aid=self.eB.aid,
                    ),
                )
                length_prefix = peeled_payload_body[:4]
                payload_length = int.from_bytes(length_prefix, "big")
                self.assertLessEqual(
                    payload_length, self.mixnet.params.usable_payload_size
                )
                delivered_payload = peeled_payload_body[4 : 4 + payload_length]
                padding = peeled_payload_body[4 + payload_length :]
                self.assertEqual(
                    len(padding),
                    self.mixnet.params.usable_payload_size - payload_length,
                )
                self.assertEqual(delivered_payload, derived.delivered_payload)
                self.assertEqual(
                    derived.delivered_payload, result.transit_log.delivered_payload
                )
                relay_view.extend([length_prefix, delivered_payload, padding])
            else:
                self.assertEqual(flag, 0)
                self.assertIsNotNone(derived.next_packet)
                next_address = decoded_address
                self.assertEqual(
                    derived.next_address,
                    next_address,
                )
                self.assertEqual(
                    derived.next_address,
                    self.mixnet._addr(observation.next_hop),
                )
                reconstructed_forward = sphinx.SphinxPacket(
                    alpha=crypto.x25519_raw(
                        crypto.scalar_from_bytes(blind), received_packet.alpha
                    ),
                    header=next_mac + next_routing,
                    payload=peeled_payload_body,
                )
                self.assertEqual(
                    derived.next_packet.to_bytes(),
                    reconstructed_forward.to_bytes(),
                )
                self.assertEqual(
                    reconstructed_forward.to_bytes(),
                    captured_packets[observations[index + 1].node_aid].to_bytes(),
                )
                relay_view.extend([next_address, reconstructed_forward.to_bytes()])
            for value in secret_bytes:
                for derivable_bytes in relay_view:
                    self.assertNotIn(value, derivable_bytes)

        # The realized path crosses 3 distinct layers and >= 3 distinct operators.
        layers = sorted(o.layer_index for o in result.transit_log.observations)
        self.assertEqual(layers, [0, 1, 2])

        # --- §8.2 conformance over the REAL transit -----------------------------
        handle = mix.rendezvous_handle(
            session_context=fsm_a.atom.session_context,
            recipient_entity_aid=self.eB.aid,
        )
        comparison = self._send_comparison_session(
            reference_log=result.transit_log,
            reference_session_context=fsm_a.atom.session_context,
            profile=fsm_a.atom.profile,
        )
        conf = mix.assess_routing_layer(
            log=result.transit_log,
            comparison_logs=(comparison.transit_log,),
            directory=self.directory,
            scheduler=cover_a,
            originator=self.eA.aid,
            recipient_handle=handle.hex(),
        )
        self.assertTrue(conf.ob2_eligible, conf.summary())
        self.assertEqual(conf.failures(), [])

        # --- honest OB disclosure: OB-2 is now legitimately claimable -----------
        self.assertEqual(
            result.channel_attestation.transit_evidence.frame_digest,
            hashlib.sha256(result.transit_log.delivered_payload).hexdigest(),
        )
        claim = mix.ob_claim_for_mixnet(
            name="ob2-pilot",
            channel_encryption_operational=result.channel_attestation,
            channel_session_context=fsm_a.atom.session_context,
            channel_kel_event_dig=fsm_a.atom.initiator.kel_event_dig,
            directory=self.directory,
            transit_log=result.transit_log,
            scheduler=cover_a,
            originator=self.eA.aid,
            recipient_handle=handle.hex(),
            comparison_logs=(comparison.transit_log,),
        )
        self.assertEqual(claim.claimed_level, ObLevel.OB2)
        self.assertEqual(claim.disclosures, [])

        # A genuine receive capability is still not transferable to a different
        # transit: §3.5 must fail closed if the final payload is swapped.
        tampered_log = copy.copy(result.transit_log)
        tampered_log.delivered_payload = b"not-the-authenticated-sealed-frame"
        tampered_claim = mix.ob_claim_for_mixnet(
            name="transit-tampered",
            channel_encryption_operational=result.channel_attestation,
            channel_session_context=fsm_a.atom.session_context,
            channel_kel_event_dig=fsm_a.atom.initiator.kel_event_dig,
            directory=self.directory,
            transit_log=tampered_log,
            scheduler=cover_a,
            originator=self.eA.aid,
            recipient_handle=handle.hex(),
            comparison_logs=(comparison.transit_log,),
        )
        self.assertEqual(tampered_claim.ob1.value, "not-met")
        self.assertEqual(tampered_claim.claimed_level, ObLevel.NONE)
        self.assertTrue(any("§3.5" in d for d in tampered_claim.disclosures))

        mismatched_claim = mix.ob_claim_for_mixnet(
            name="cross-session-substitution",
            channel_encryption_operational=result.channel_attestation,
            channel_session_context=comparison.received_envelope.session_context,
            channel_kel_event_dig=fsm_a.atom.initiator.kel_event_dig,
            directory=self.directory,
            transit_log=result.transit_log,
            scheduler=cover_a,
            originator=self.eA.aid,
            recipient_handle=handle.hex(),
            comparison_logs=(comparison.transit_log,),
        )
        self.assertEqual(mismatched_claim.ob1.value, "not-met")
        self.assertEqual(mismatched_claim.claimed_level, ObLevel.NONE)

        object.__setattr__(
            result.channel_attestation, "_receipt_id", "0" * 64
        )
        invalid_receipt_claim = mix.ob_claim_for_mixnet(
            name="invalid-receipt",
            channel_encryption_operational=result.channel_attestation,
            channel_session_context=fsm_a.atom.session_context,
            channel_kel_event_dig=fsm_a.atom.initiator.kel_event_dig,
            directory=self.directory,
            transit_log=result.transit_log,
            scheduler=cover_a,
            originator=self.eA.aid,
            recipient_handle=handle.hex(),
            comparison_logs=(comparison.transit_log,),
        )
        self.assertEqual(invalid_receipt_claim.ob1.value, "not-met")
        self.assertEqual(invalid_receipt_claim.claimed_level, ObLevel.NONE)
        self.assertTrue(
            any("§3.5" in d for d in invalid_receipt_claim.disclosures)
        )

    def test_ob2_is_NOT_claimable_without_cover_traffic(self):
        # Remove the §8.5 precondition: a missed cover slot -> the guard MUST drop
        # to OB-1, never overclaim OB-2 (the honesty invariant).
        fsm_a, fsm_b = self._open_session()
        sender_channel, receiver_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )
        bundle = ZkaBundle(
            kind="zka:bundle:v1",
            context=session_context_field(fsm_a.atom.session_context),
            coord_proof="opaque",
        )
        cover_a = mix.CoverScheduler()
        result = mix.send_envelope_via_mixnet(
            sender=self.A,
            fsm=fsm_a,
            bundle=bundle,
            message_class="result",
            receiver=self.B,
            receiver_fsm=fsm_b,
            sender_remote=self.remote_a,
            sender_channel=sender_channel,
            receiver_channel=receiver_channel,
            mixnet=self.mixnet,
            sender_cover=cover_a,
            recipient_entity_aid=self.eB.aid,
            bundle_verifier=BundleVerificationResult.accepted,
        )
        cover_a.record_missed_slot()  # OB-2 health failure (§8.5)

        handle = mix.rendezvous_handle(
            session_context=fsm_a.atom.session_context,
            recipient_entity_aid=self.eB.aid,
        )
        comparison = self._send_comparison_session(
            reference_log=result.transit_log,
            reference_session_context=fsm_a.atom.session_context,
            profile=fsm_a.atom.profile,
        )
        claim = mix.ob_claim_for_mixnet(
            name="degraded",
            channel_encryption_operational=result.channel_attestation,
            channel_session_context=fsm_a.atom.session_context,
            channel_kel_event_dig=fsm_a.atom.initiator.kel_event_dig,
            directory=self.directory,
            transit_log=result.transit_log,
            scheduler=cover_a,
            originator=self.eA.aid,
            recipient_handle=handle.hex(),
            comparison_logs=(comparison.transit_log,),
        )
        self.assertEqual(claim.claimed_level, ObLevel.OB1)
        self.assertTrue(
            any("OB-2" in d and "NOT YET MET" in d for d in claim.disclosures)
        )

    def test_replayed_packet_is_rejected_by_the_mixnet(self):
        # The mixnet's per-hop replay set rejects a re-injected packet.
        route = self.mixnet.select_route()
        log = self.mixnet.send(
            route=route, destination_handle=b"h" * 32, payload=b"once"
        )
        self.assertTrue(log.delivered)
        # Re-send the SAME packet by reconstructing it deterministically: a fresh
        # send uses a new ephemeral, so to test replay we re-process the captured
        # first-hop packet directly against the first node's now-populated set.
        from afp_mixnet import crypto, sphinx

        x = crypto.random_scalar()
        pkt = sphinx.create_packet(
            session_scalar=x,
            hop_public_keys=route.public_keys,
            hop_addresses=route.addresses,
            destination=b"h" * 32,
            payload=b"twice",
            params=self.mixnet.params,
        )
        node0 = self.nodes[route.node_aids[0]]
        node0.process(pkt, params=self.mixnet.params)  # first time OK
        with self.assertRaises(sphinx.ReplayError):
            node0.process(pkt, params=self.mixnet.params)  # replay rejected

    def test_tampered_sealed_frame_fails_closed_before_envelope_verification(self):
        # The transport boundary must authenticate the sealed frame before it
        # attempts the unchanged §12.7 envelope verification path.
        fsm_a, fsm_b = self._open_session()
        sender_channel, receiver_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )
        bundle = ZkaBundle(
            kind="zka:bundle:v1",
            context=session_context_field(fsm_a.atom.session_context),
            coord_proof="opaque",
        )
        envelope = self.A.build_envelope(fsm_a, bundle=bundle, message_class="result")
        sealed = bytearray(self.A.seal_envelope(fsm_a, envelope, channel=sender_channel))
        sealed[-1] ^= 0x01  # an authenticated sealed-frame byte, not envelope JSON
        tampered_sealed = bytes(sealed)

        route = self.mixnet.select_route()
        handle = mix.rendezvous_handle(
            session_context=fsm_a.atom.session_context,
            recipient_entity_aid=self.eB.aid,
        )
        log = self.mixnet.send(
            route=route,
            destination_handle=handle,
            payload=tampered_sealed,
        )
        self.assertTrue(log.delivered)
        self.assertEqual(log.delivered_payload, tampered_sealed)
        self.assertTrue(log.delivered_payload.startswith(b"afp:sealed:v1\x00"))

        verification_called = []
        original_verify = self.B._verify_received_envelope
        receiver_replay_state = (
            receiver_channel._receive_highest,
            receiver_channel._receive_bitmap,
        )
        receiver_fsm_status = fsm_b.status

        def record_verification(*args, **kwargs):
            verification_called.append(True)
            return original_verify(*args, **kwargs)

        self.B._verify_received_envelope = record_verification
        try:
            with self.assertRaisesRegex(ChannelError, "authentication failed"):
                self.B.receive_envelope(
                    fsm_b,
                    log.delivered_payload,
                    message_class="result",
                    channel=receiver_channel,
                    sender_remote=self.remote_a,
                    bundle_verifier=BundleVerificationResult.accepted,
                )
        finally:
            self.B._verify_received_envelope = original_verify
        self.assertEqual(verification_called, [])
        self.assertEqual(
            (receiver_channel._receive_highest, receiver_channel._receive_bitmap),
            receiver_replay_state,
        )
        self.assertEqual(fsm_b.status, receiver_fsm_status)
        self.assertEqual(self.B.inbox.get(fsm_b.atom.id, []), [])

    def test_sealed_payload_budget_uses_the_fragmentation_seam(self):
        """The mixnet budget accounts for the authenticated sealed-frame overhead."""
        fsm_a, fsm_b = self._open_session()
        sender_channel, receiver_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )
        wrong_recipient_cover = mix.CoverScheduler()
        with self.assertRaisesRegex(
            mix.MixnetTransitError, "does not match the receiving Instance"
        ):
            mix.send_envelope_via_mixnet(
                sender=self.A,
                fsm=fsm_a,
                bundle=ZkaBundle(
                    kind="zka:bundle:v1",
                    context=session_context_field(
                        fsm_a.atom.session_context
                    ),
                    coord_proof="wrong-recipient-must-not-send",
                ),
                message_class="result",
                receiver=self.B,
                receiver_fsm=fsm_b,
                sender_remote=self.remote_a,
                sender_channel=sender_channel,
                receiver_channel=receiver_channel,
                mixnet=self.mixnet,
                sender_cover=wrong_recipient_cover,
                recipient_entity_aid="E_wrong-recipient",
                bundle_verifier=BundleVerificationResult.accepted,
            )
        self.assertEqual(sender_channel.send_sequence, 0)
        self.assertEqual(wrong_recipient_cover.trace, [])
        self.assertEqual(fsm_a.status.value, "open")

        target_raw_size = self.mixnet.params.usable_payload_size - SEALED_FRAME_OVERHEAD
        original_clock = self.A._clock
        self.A._clock = lambda: float(fsm_a.atom.opened_at) + 1.0

        def envelope_of_size(raw_size):
            base_bundle = ZkaBundle(
                kind="zka:bundle:v1",
                context=session_context_field(
                    fsm_a.atom.session_context
                ),
                coord_proof="",
            )
            base = self.A.build_envelope(
                fsm_a, bundle=base_bundle, message_class="result"
            )
            padding = raw_size - len(canonical_bytes(base.to_dict()))
            self.assertGreaterEqual(padding, 0)
            envelope = self.A.build_envelope(
                fsm_a,
                bundle=ZkaBundle(
                    kind="zka:bundle:v1",
                    context=session_context_field(
                        fsm_a.atom.session_context
                    ),
                    coord_proof="x" * padding,
                ),
                message_class="result",
            )
            self.assertEqual(len(canonical_bytes(envelope.to_dict())), raw_size)
            return envelope

        max_envelope = envelope_of_size(target_raw_size)
        plus_one_envelope = envelope_of_size(target_raw_size + 1)
        original_build = self.A.build_envelope
        original_send = self.mixnet.send
        sent_payloads = []

        def capture_send(*, route, destination_handle, payload):
            sent_payloads.append(payload)
            return original_send(
                route=route, destination_handle=destination_handle, payload=payload
            )

        self.mixnet.send = capture_send
        try:
            oversized_cover = mix.CoverScheduler()
            self.A.build_envelope = lambda *args, **kwargs: plus_one_envelope
            with self.assertRaisesRegex(mix.MixnetTransitError, r"fragmentation.*seam"):
                mix.send_envelope_via_mixnet(
                    sender=self.A,
                    fsm=fsm_a,
                    bundle=plus_one_envelope.bundle,
                    message_class="result",
                    receiver=self.B,
                    receiver_fsm=fsm_b,
                    sender_remote=self.remote_a,
                    sender_channel=sender_channel,
                    receiver_channel=receiver_channel,
                    mixnet=self.mixnet,
                    sender_cover=oversized_cover,
                    recipient_entity_aid=self.eB.aid,
                    bundle_verifier=BundleVerificationResult.accepted,
                )
            self.assertEqual(sender_channel.send_sequence, 0)
            self.assertEqual(oversized_cover.trace, [])
            self.assertEqual(sent_payloads, [])

            self.A.build_envelope = lambda *args, **kwargs: max_envelope
            result = mix.send_envelope_via_mixnet(
                sender=self.A,
                fsm=fsm_a,
                bundle=max_envelope.bundle,
                message_class="result",
                receiver=self.B,
                receiver_fsm=fsm_b,
                sender_remote=self.remote_a,
                sender_channel=sender_channel,
                receiver_channel=receiver_channel,
                mixnet=self.mixnet,
                sender_cover=mix.CoverScheduler(),
                recipient_entity_aid=self.eB.aid,
                bundle_verifier=BundleVerificationResult.accepted,
            )
            self.assertEqual(result.payload_bytes, self.mixnet.params.usable_payload_size)
            self.assertEqual(len(sent_payloads), 1)
        finally:
            self.A.build_envelope = original_build
            self.mixnet.send = original_send
            self.A._clock = original_clock


if __name__ == "__main__":
    unittest.main()
