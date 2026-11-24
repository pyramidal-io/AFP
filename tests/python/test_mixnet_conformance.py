"""§8.2 conformance-property tests over REAL transit/cover artifacts.

These assert the §8.2 properties the routing layer must provide, proven from an
actual Sphinx transit (``afp_mixnet.network``) and a cover-traffic trace
(``afp_mixnet.cover``) — not by assertion. The honest proven/partial/seam verdicts
are checked, and the conservative OB-2 eligibility gate is exercised in both
directions (eligible when met; ineligible when any property fails / cover unhealthy
/ node set too small).
"""

import _path  # noqa: F401

from dataclasses import replace
import random
import unittest

import afp_mixnet as mix
from afp_session import (
    AfpEnvelope,
    AfpPartyRef,
    ZkaBundle,
    session_context_field,
)
from afp_session.canonical import canonical_bytes
from afp_mixnet.conformance import PropertyStatus
from afp_mixnet.network import HopObservation, TransitLog
from mixnet_fixtures import build_mixnet

pytestmark = None


SEALED_FRAME_PREFIX = b"afp:sealed:v1\x00"


def _sealed_frame(ciphertext=b"opaque-final-hop-ciphertext", *, sequence=0):
    """Build public v1 geometry; authentication is intentionally opaque here."""
    return (
        SEALED_FRAME_PREFIX
        + b"\x01\x00"
        + sequence.to_bytes(8, "big")
        + bytes((sequence % 256,)) * 16
        + len(ciphertext).to_bytes(4, "big")
        + ciphertext
        + bytes(((sequence + 1) % 256,)) * 32
    )


SEALED_FINAL_PAYLOAD = _sealed_frame()


class RealTransitConformanceTest(unittest.TestCase):
    def setUp(self):
        self.mixnet, self.directory, self.builder, self.nodes = build_mixnet(
            rng=random.Random(99)
        )
        self.route = self.mixnet.select_route()
        self.handle = b"rendezvous-handle" + b"\x00" * 15
        self.second_handle = b"second-session-handle" + b"\x00" * 11
        self._packet_number = 0
        self.log = self._send(destination_handle=self.handle)
        self.cover = mix.CoverScheduler()
        self.cover.enqueue_real("env-1")
        self.cover.run_slots(6)

    def _send(self, *, destination_handle, payload=None):
        """Produce a distinct-session Sphinx transit over the same route."""
        self._packet_number += 1
        if payload is None:
            payload = _sealed_frame(
                f"opaque-session-{self._packet_number}".encode(),
                sequence=self._packet_number,
            )
        return self.mixnet.send(
            route=self.route,
            destination_handle=destination_handle,
            payload=payload,
            session_scalar=bytes((self._packet_number,)) * 32,
        )

    def _assess(self, log, *, comparison_log=None):
        return mix.assess_routing_layer(
            log=log,
            comparison_logs=(comparison_log,) if comparison_log is not None else None,
            directory=self.directory,
            scheduler=self.cover,
            originator="tenant-A",
            recipient_handle=self.handle.hex(),
        )

    def test_endpoint_unlinkability_proven(self):
        res = mix.check_endpoint_unlinkability(
            self.log, originator="tenant-A", recipient_handle=self.handle.hex()
        )
        self.assertEqual(res.status, PropertyStatus.PROVEN, res.evidence)
        self.assertIn("sealed", res.evidence.lower())
        self.assertTrue(self.log.delivered_payload.startswith(SEALED_FRAME_PREFIX))

    def test_no_cleartext_relationship_is_partial_without_second_session(self):
        res = mix.check_no_cleartext_relationship(self.log)
        self.assertEqual(res.status, PropertyStatus.PARTIAL, res.evidence)
        self.assertIn("cross-session", res.evidence.lower())
        # The final relay is part of the evidence set even though it does not
        # forward an alpha; without a second session its identifier cannot yet be
        # shown to be non-stable.
        self.assertTrue(self.log.observations[-1].is_final)
        self.assertFalse(self._assess(self.log).ob2_eligible)

    def test_no_cleartext_relationship_proven_against_clean_second_session(self):
        comparison_log = self._send(destination_handle=self.second_handle)
        res = mix.check_no_cleartext_relationship(
            self.log, comparison_logs=(comparison_log,)
        )
        self.assertEqual(res.status, PropertyStatus.PROVEN, res.evidence)
        self.assertIn("final", res.evidence.lower())
        self.assertIn("routing", res.evidence.lower())
        self.assertIn("address", res.evidence.lower())

        # Each packet's blinded alpha/header changes.  The fixed intermediate
        # next-hop addresses may repeat, but the final destination handle MUST be
        # per-session and therefore differ.
        for original, comparison in zip(
            self.log.observations, comparison_log.observations, strict=True
        ):
            self.assertNotEqual(original.received_alpha, comparison.received_alpha)
            self.assertNotEqual(
                original.received_header_prefix, comparison.received_header_prefix
            )
        self.assertNotEqual(
            self.log.observations[-1].routing_address,
            comparison_log.observations[-1].routing_address,
        )

        # Confirm every forwarding hop actually blinded the element.
        for obs in self.log.observations:
            if not obs.is_final:
                self.assertNotEqual(obs.received_alpha, obs.forwarded_alpha)

    def test_observations_prove_route_adjacency_and_final_destination(self):
        self.assertTrue(self.log.delivered)
        self.assertEqual(len(self.log.observations), len(self.route.node_aids))
        for index, observation in enumerate(self.log.observations):
            self.assertEqual(observation.node_aid, self.route.node_aids[index])
            self.assertEqual(
                observation.prev_hop,
                None if index == 0 else self.route.node_aids[index - 1],
            )
            if index == len(self.route.node_aids) - 1:
                self.assertTrue(observation.is_final)
                self.assertIsNone(observation.next_hop)
                self.assertEqual(observation.routing_address, self.handle)
            else:
                self.assertFalse(observation.is_final)
                self.assertEqual(
                    observation.next_hop, self.route.node_aids[index + 1]
                )
                self.assertEqual(
                    observation.routing_address,
                    self.mixnet._addr(self.route.node_aids[index + 1]),
                )

    def test_correlation_resistance_is_honestly_partial(self):
        # The mechanism (mixing delay + fixed size) is present, but the asymptotic
        # bound is a declared seam -> PARTIAL, not PROVEN. This is the honesty point.
        res = mix.check_correlation_resistance(
            self.log, payload_size=self.directory.profile.payload_bytes
        )
        self.assertEqual(res.status, PropertyStatus.PARTIAL, res.evidence)
        self.assertIn("seam", res.evidence.lower())
        self.assertGreater(self.log.total_delay_seconds, 0.0)

    def test_no_single_trusted_relay_proven(self):
        res = mix.check_no_single_trusted_relay(self.log, self.directory)
        self.assertEqual(res.status, PropertyStatus.PROVEN, res.evidence)

    def test_cover_indistinguishability_proven(self):
        res = mix.check_cover_indistinguishability(self.cover)
        self.assertEqual(res.status, PropertyStatus.PROVEN, res.evidence)

    def test_path_crosses_three_distinct_layers(self):
        layers = [o.layer_index for o in self.log.observations]
        self.assertEqual(sorted(layers), [0, 1, 2])

    def test_aggregate_is_ob2_eligible_when_all_met(self):
        comparison_log = self._send(destination_handle=self.second_handle)
        conf = self._assess(self.log, comparison_log=comparison_log)
        self.assertTrue(conf.ob2_eligible, conf.summary())
        self.assertTrue(conf.all_non_failed)
        self.assertEqual(conf.failures(), [])
        self.assertIn("8.2.1 endpoint unlinkability: proven", conf.summary())
        self.assertIn(
            "8.2.2 no cleartext relationship in addressing: proven", conf.summary()
        )


class ConformanceFailureModesTest(unittest.TestCase):
    """The §8.2 checks must FAIL honestly when a property is actually violated."""

    def setUp(self):
        self.mixnet, self.directory, _, _ = build_mixnet(rng=random.Random(5))
        self.route = self.mixnet.select_route()
        self.handle = b"failure-rendezvous-handle" + b"\x00" * 7
        self.second_handle = b"failure-second-handle" + b"\x00" * 11
        self._packet_number = 30
        self.cover = mix.CoverScheduler()
        self.cover.enqueue_real("env-failure")
        self.cover.run_slots(6)

    def _send(self, *, payload=None, route=None, destination_handle=None):
        self._packet_number += 1
        if payload is None:
            payload = _sealed_frame(
                f"failure-session-{self._packet_number}".encode(),
                sequence=self._packet_number,
            )
        return self.mixnet.send(
            route=route or self.route,
            destination_handle=(
                self.handle if destination_handle is None else destination_handle
            ),
            payload=payload,
            session_scalar=bytes((self._packet_number,)) * 32,
        )

    def _assess(self, log, *, comparison_log=None):
        return mix.assess_routing_layer(
            log=log,
            comparison_logs=(comparison_log,) if comparison_log is not None else None,
            directory=self.directory,
            scheduler=self.cover,
            originator="tenant-A",
            recipient_handle=self.handle.hex(),
        )

    @staticmethod
    def _plaintext_envelope():
        """Canonical, parseable §12.7 bytes that a final relay must never receive."""
        session_context = "X_" + "7e" * 32
        envelope = AfpEnvelope(
            session_ref="session-stable-identifier",
            session_context=session_context,
            profile="work",
            bundle=ZkaBundle(
                kind="zka:bundle:v1",
                context=session_context_field(session_context),
                coord_proof="opaque-proof",
            ),
            message_class="result",
            generated_at=1.0,
            expires_at=2.0,
            sender=AfpPartyRef(
                tenant_aid="tenant-A",
                entity_aid="entity-A",
                kel_event_dig="E-tenant-A",
                signature="00",
            ),
        )
        return canonical_bytes(envelope.to_dict())

    def _assert_endpoint_failure(self, log, *, expected_evidence):
        result = mix.check_endpoint_unlinkability(
            log, originator="tenant-A", recipient_handle=self.handle.hex()
        )
        self.assertEqual(result.property_id, "8.2.1")
        self.assertEqual(result.status, PropertyStatus.FAILED, result.evidence)
        self.assertIn(expected_evidence, result.evidence.lower())

    def test_no_mixing_delay_fails_correlation_resistance(self):
        log = TransitLog()
        log.observations = [
            HopObservation(
                node_aid="m",
                layer_index=0,
                received_alpha=b"a",
                received_header_prefix=b"h",
                prev_hop=None,
                next_hop=None,
                is_final=True,
            )
        ]
        log.total_delay_seconds = 0.0
        res = mix.check_correlation_resistance(log, payload_size=4096)
        self.assertEqual(res.status, PropertyStatus.FAILED)

    def test_unblinded_forward_fails_no_cleartext(self):
        log = TransitLog()
        log.observations = [
            HopObservation(
                node_aid="m0",
                layer_index=0,
                received_alpha=b"same" * 8,
                received_header_prefix=b"h" * 16,
                prev_hop=None,
                next_hop="m1",
                is_final=False,
                forwarded_alpha=b"same" * 8,  # NOT blinded -> stable identifier
                routing_address=self.mixnet._addr("m1"),
            ),
            HopObservation(
                node_aid="m1",
                layer_index=1,
                received_alpha=b"same" * 8,
                received_header_prefix=b"f" * 16,
                prev_hop="m0",
                next_hop=None,
                is_final=True,
                routing_address=b"d" * 32,
            ),
        ]
        log.delivered = True
        log.delivered_payload = SEALED_FINAL_PAYLOAD
        res = mix.check_no_cleartext_relationship(log)
        self.assertEqual(res.status, PropertyStatus.FAILED)
        self.assertEqual(res.property_id, "8.2.2")
        self.assertIn("stable", res.evidence.lower())

    def test_plaintext_envelope_at_final_hop_fails_aggregate_and_summary(self):
        plaintext_log = self._send(payload=self._plaintext_envelope())
        comparison = self._send(destination_handle=self.second_handle)
        # This assertion is intentionally a regression proof: on the pre-repair
        # implementation the aggregate incorrectly accepted this plaintext final
        # delivery as eligible.
        conformance = self._assess(plaintext_log, comparison_log=comparison)
        endpoint = next(
            prop for prop in conformance.properties if prop.property_id == "8.2.1"
        )
        self.assertEqual(endpoint.status, PropertyStatus.FAILED, endpoint.evidence)
        self.assertIn("parseable", endpoint.evidence.lower())
        self.assertFalse(conformance.ob2_eligible)
        self.assertIn("8.2.1", [prop.property_id for prop in conformance.failures()])
        summary = conformance.summary()
        self.assertIn("8.2.1 endpoint unlinkability: failed", summary)
        self.assertIn("parseable", summary.lower())

    def test_endpoint_check_rejects_originator_bytes_unsealed_and_missing_delivery(self):
        cases = (
            (
                self._send(payload=_sealed_frame(b"opaque-tenant-A-ciphertext")),
                "originator",
            ),
            (self._send(payload=b"opaque-but-not-sealed"), "sealed"),
            (self._send(payload=SEALED_FRAME_PREFIX + b"x"), "structurally"),
            (
                TransitLog(
                    observations=self._send().observations,
                    delivered_payload=None,
                    total_delay_seconds=1.0,
                    delivered=False,
                ),
                "deliver",
            ),
        )
        for log, expected_evidence in cases:
            with self.subTest(expected_evidence=expected_evidence):
                self._assert_endpoint_failure(log, expected_evidence=expected_evidence)

    def test_final_observation_repeated_identifier_is_not_ignored(self):
        original = self._send()
        comparison = self._send(destination_handle=self.second_handle)
        final = original.observations[-1]
        comparison_final = comparison.observations[-1]

        for field_name, evidence_name in (
            ("routing_address", "routing address"),
            ("received_alpha", "alpha"),
            ("received_header_prefix", "header"),
        ):
            repeated_final = replace(
                comparison_final, **{field_name: getattr(final, field_name)}
            )
            comparison_observations = list(comparison.observations)
            if field_name == "received_alpha":
                comparison_observations[-2] = replace(
                    comparison_observations[-2],
                    forwarded_alpha=repeated_final.received_alpha,
                )
            comparison_observations[-1] = repeated_final
            repeated = TransitLog(
                observations=comparison_observations,
                delivered_payload=comparison.delivered_payload,
                total_delay_seconds=comparison.total_delay_seconds,
                delivered=comparison.delivered,
            )
            with self.subTest(field_name=field_name):
                result = mix.check_no_cleartext_relationship(
                    original, comparison_logs=(repeated,)
                )
                self.assertEqual(result.property_id, "8.2.2")
                self.assertEqual(result.status, PropertyStatus.FAILED, result.evidence)
                self.assertIn("final", result.evidence.lower())
                self.assertIn(evidence_name, result.evidence)

        repeated_payload = TransitLog(
            observations=comparison.observations,
            delivered_payload=original.delivered_payload,
            total_delay_seconds=comparison.total_delay_seconds,
            delivered=True,
        )
        result = mix.check_no_cleartext_relationship(
            original, comparison_logs=(repeated_payload,)
        )
        self.assertEqual(result.status, PropertyStatus.FAILED, result.evidence)
        self.assertIn("sealed payload", result.evidence)

    def test_comparison_must_validate_the_same_full_relay_path(self):
        original = self._send()
        comparison = self._send(destination_handle=self.second_handle)
        copied_first_hop = replace(
            comparison.observations[0],
            received_alpha=original.observations[0].received_alpha,
            received_header_prefix=original.observations[0].received_header_prefix,
        )
        copied_forwarding = TransitLog(
            observations=[
                copied_first_hop,
                *comparison.observations[1:],
            ],
            delivered_payload=comparison.delivered_payload,
            total_delay_seconds=comparison.total_delay_seconds,
            delivered=True,
        )
        result = mix.check_no_cleartext_relationship(
            original, comparison_logs=(copied_forwarding,)
        )
        self.assertEqual(result.status, PropertyStatus.FAILED, result.evidence)
        self.assertIn("hop 0", result.evidence)

    def test_cross_session_identifier_reuse_at_a_different_hop_fails(self):
        original = self._send()
        comparison = self._send(destination_handle=self.second_handle)
        reused_at_ingress = replace(
            comparison.observations[0],
            received_alpha=original.observations[1].received_alpha,
            received_header_prefix=original.observations[1].received_header_prefix,
        )
        cross_hop_reuse = TransitLog(
            observations=[reused_at_ingress, *comparison.observations[1:]],
            delivered_payload=comparison.delivered_payload,
            total_delay_seconds=comparison.total_delay_seconds,
            delivered=True,
        )
        result = mix.check_no_cleartext_relationship(
            original, comparison_logs=(cross_hop_reuse,)
        )
        self.assertEqual(result.status, PropertyStatus.FAILED, result.evidence)
        self.assertIn("primary transit hop 1", result.evidence)
        self.assertIn("comparison transit 1", result.evidence)

    def test_mismatched_route_address_fails_closed(self):
        bad_addresses = list(self.route.addresses)
        bad_addresses[0] = b"\x00" * 32
        bad_route = mix.Route(
            node_aids=list(self.route.node_aids),
            public_keys=list(self.route.public_keys),
            addresses=bad_addresses,
        )
        replay_state = {
            node_aid: set(node.seen_tags)
            for node_aid, node in self.mixnet.nodes.items()
        }
        with self.assertRaisesRegex(mix.MixnetError, "forwarding addresses"):
            self._send(route=bad_route)
        self.assertEqual(
            replay_state,
            {
                node_aid: set(node.seen_tags)
                for node_aid, node in self.mixnet.nodes.items()
            },
        )

    def test_route_node_must_belong_to_verified_directory_layer(self):
        rogue_aid = "rogue-not-in-directory"
        rogue_keypair = mix.MixNodeKeypair.generate()
        self.mixnet.nodes[rogue_aid] = mix.MixNode(
            mix_node_aid=rogue_aid,
            operator_aid="rogue-operator",
            layer_index=1,
            keypair=rogue_keypair,
        )
        node_aids = list(self.route.node_aids)
        public_keys = list(self.route.public_keys)
        node_aids[1] = rogue_aid
        public_keys[1] = rogue_keypair.public_point
        rogue_route = mix.Route(
            node_aids=node_aids,
            public_keys=public_keys,
            addresses=[
                self.mixnet._addr(node_aids[1]),
                self.mixnet._addr(node_aids[2]),
                b"\x00" * 32,
            ],
        )
        with self.assertRaisesRegex(mix.MixnetError, "verified directory layer"):
            self._send(route=rogue_route)

    def test_unknown_directory_node_fails_no_single_relay_evidence(self):
        log = self._send()
        log.observations[1] = replace(
            log.observations[1], node_aid="rogue-not-in-directory"
        )
        result = mix.check_no_single_trusted_relay(log, self.directory)
        self.assertEqual(result.status, PropertyStatus.FAILED, result.evidence)
        self.assertIn("verified directory", result.evidence)

    def test_single_operator_path_fails_no_single_relay(self):
        # Build a 1-node-per-layer directory where all nodes share one operator is
        # rejected at directory time; here simulate a realized single-operator path.
        log = TransitLog()
        log.observations = [
            HopObservation("a", 0, b"\x01", b"h", None, "b", False, b"\x02"),
            HopObservation("b", 1, b"\x02", b"h", "a", "c", False, b"\x03"),
            HopObservation("c", 2, b"\x03", b"h", "b", None, True),
        ]
        # Build a tiny directory whose nodes a/b/c all map to one operator.
        from afp_mixnet.directory import MixNodeDescriptor, MixnetDirectory
        from afp_mixnet.profiles import OB2_BASELINE

        layers = [
            [MixNodeDescriptor("a", "solo", "e", b"\x00" * 32)],
            [MixNodeDescriptor("b", "solo", "e", b"\x00" * 32)],
            [MixNodeDescriptor("c", "solo", "e", b"\x00" * 32)],
        ]
        directory = MixnetDirectory(
            epoch=1, valid_from="1970-01-01T00:00:00Z",
            valid_until="9999-12-31T23:59:59Z",
            keri_anchor_event_dig="E", profile=OB2_BASELINE, layers=layers,
        )
        res = mix.check_no_single_trusted_relay(log, directory)
        self.assertEqual(res.status, PropertyStatus.FAILED)

    def test_missed_cover_makes_aggregate_ineligible(self):
        log = self._send()
        comparison = self._send(destination_handle=self.second_handle)
        cover = mix.CoverScheduler()
        cover.run_slots(3)
        cover.record_missed_slot()
        conf = mix.assess_routing_layer(
            log=log,
            comparison_logs=(comparison,),
            directory=self.directory,
            scheduler=cover,
            originator="tenant-A",
            recipient_handle=self.handle,
        )
        self.assertFalse(conf.ob2_eligible)
        self.assertTrue(conf.routing_evidence_sufficient, conf.summary())
        self.assertEqual(
            [failure.property_id for failure in conf.failures()], ["8.5"]
        )


if __name__ == "__main__":
    unittest.main()
