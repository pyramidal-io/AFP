"""KERI-witnessed mix-node directory tests (§8.7) and profile comparison (§8.4)."""

import _path  # noqa: F401

import unittest
from unittest import mock
from dataclasses import replace

import afp_mixnet as mix
from afp_mixnet.directory import DirectoryBuilder, descriptor_for
from afp_mixnet.profiles import OB2_BASELINE, MixnetProfile, ProfileError
from fixtures import make_witness

pytestmark = None

_IDENTITY_KEY = b"\x01" + b"\x00" * 31
_ORDER_TWO_KEY = b"\xec" + b"\xff" * 30 + b"\x7f"
_MIXED_ORDER_KEY = bytes.fromhex(
    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
)
_NONCANONICAL_KEY = b"\xed" + b"\xff" * 30 + b"\x7f"


def _witnesses(n=3):
    return [make_witness() for _ in range(n)]


def _layers(nodes_dict, nodes_per_layer=2, layers_n=3, single_operator_layer=None,
            spanning_operator=None):
    """Build ``layers_n`` layers, registering MixNode objects into ``nodes_dict``."""
    layers = []
    oi = 0
    ops = [f"op-{i}" for i in range(100)]
    for li in range(layers_n):
        layer = []
        for j in range(nodes_per_layer):
            kp = mix.MixNodeKeypair.generate()
            aid = f"m-{li}-{j}"
            if single_operator_layer == li:
                op = "solo-op"
            elif spanning_operator is not None:
                op = "spanner" if j == 0 else ops[oi]
            else:
                op = ops[oi]
            oi += 1
            layer.append(
                descriptor_for(kp, mix_node_aid=aid, operator_aid=op, endpoint="e")
            )
            nodes_dict[aid] = mix.MixNode(
                mix_node_aid=aid, operator_aid=op, layer_index=li, keypair=kp
            )
        layers.append(layer)
    return layers


class DirectoryVerificationTest(unittest.TestCase):
    def setUp(self):
        self.witnesses = _witnesses(3)
        self.builder = DirectoryBuilder(self.witnesses, quorum_threshold=2)
        self.nodes = {}
        self.layers = _layers(self.nodes)

    def _build(self, **kw):
        return self.builder.build(
            epoch=1,
            layers=self.layers,
            keri_anchor_event_dig="Eanchor",
            **kw,
        )

    def test_valid_directory_verifies(self):
        d = self._build()
        mix.verify_directory(
            d, witness_keys=self.builder.witness_keys, quorum_threshold=2
        )  # no raise

    def _verify_at(self, directory, clock):
        mix.verify_directory(
            directory,
            witness_keys=self.builder.witness_keys,
            quorum_threshold=2,
            now=clock,
        )

    def test_unusable_clock_is_rejected_before_validity(self):
        d = self._build(valid_from=1_000, ttl_seconds=100)
        for clock in (
            float("nan"), float("inf"), float("-inf"), True, False, "1050", [1050],
        ):
            with self.subTest(clock=clock), self.assertRaisesRegex(
                mix.DirectoryError, "finite number of seconds"
            ):
                self._verify_at(d, clock)

    def test_unusable_default_clock_is_rejected(self):
        d = self._build(valid_from=1_000, ttl_seconds=100)
        for bad in (float("nan"), float("inf")):
            with self.subTest(clock=bad), mock.patch(
                "afp_mixnet.directory.time.time", return_value=bad
            ), self.assertRaisesRegex(mix.DirectoryError, "finite number of seconds"):
                mix.verify_directory(
                    d,
                    witness_keys=self.builder.witness_keys,
                    quorum_threshold=2,
                )

    def test_validity_window_boundaries_with_valid_clocks(self):
        d = self._build(valid_from=1_000, ttl_seconds=100)
        for ok in (1_000, 1_000.0, 1_000.5, 1_099, 1_099.999):
            with self.subTest(clock=ok):
                self._verify_at(d, ok)
        for bad, msg in (
            (999, "not yet valid"),
            (999.999, "not yet valid"),
            (1_100, "expired"),
            (1_100.0, "expired"),
            (1_100.001, "expired"),
        ):
            with self.subTest(clock=bad), self.assertRaisesRegex(
                mix.DirectoryError, msg
            ):
                self._verify_at(d, bad)

    def test_every_supplied_quorum_key_is_validated(self):
        directory = self._build()
        invalid_keys = (
            b"\x00" * 31,
            _IDENTITY_KEY,
            _ORDER_TWO_KEY,
            _MIXED_ORDER_KEY,
            _NONCANONICAL_KEY,
        )
        for invalid_key in invalid_keys:
            witness_keys = {
                **self.builder.witness_keys,
                make_witness().aid: invalid_key,
            }
            with self.subTest(public_key=invalid_key), self.assertRaisesRegex(
                mix.DirectoryError, "invalid Ed25519"
            ):
                mix.verify_directory(
                    directory, witness_keys=witness_keys, quorum_threshold=2
                )

        with self.assertRaisesRegex(mix.DirectoryError, "invalid Ed25519"):
            mix.verify_directory(
                directory,
                witness_keys={make_witness().aid: _IDENTITY_KEY},
                quorum_threshold=0,
            )
        mix.verify_directory(directory, witness_keys={}, quorum_threshold=0)

    def test_missing_keri_anchor_is_rejected(self):
        d = self.builder.build(epoch=1, layers=self.layers, keri_anchor_event_dig="")
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )

    def test_below_quorum_is_rejected(self):
        # Only one witness signs -> below threshold 2.
        d = self.builder.build(
            epoch=1,
            layers=self.layers,
            keri_anchor_event_dig="Eanchor",
            signing_witnesses=[self.witnesses[0]],
        )
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )

    def test_forged_signature_does_not_count(self):
        # Build with exactly 2 signers at threshold 2, then forge one -> 1 valid < 2.
        d = self._build(signing_witnesses=self.witnesses[:2])
        from afp_mixnet.directory import _QuorumSignature

        d.quorum_signatures[0] = _QuorumSignature(
            witness_aid=self.witnesses[0].aid, signature=b"\x00" * 64
        )
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )

    def test_expired_directory_is_rejected(self):
        d = self._build(valid_from=0.0, ttl_seconds=10.0)
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d,
                witness_keys=self.builder.witness_keys,
                quorum_threshold=2,
                now=1_000_000.0,
            )

    def test_validity_window_is_signed_as_utc_datetime_text(self):
        # §1.6.1: valid_from/valid_until are whole-second UTC strings, and the
        # witness quorum signs that text.
        d = self._build(valid_from=1_752_235_200, ttl_seconds=86_400.0)
        self.assertEqual(d.valid_from, "2025-07-11T12:00:00Z")
        self.assertEqual(d.valid_until, "2025-07-12T12:00:00Z")
        content = d.signing_content()
        self.assertEqual(content["valid_from"], "2025-07-11T12:00:00Z")
        self.assertEqual(content["valid_until"], "2025-07-12T12:00:00Z")
        mix.verify_directory(
            d,
            witness_keys=self.builder.witness_keys,
            quorum_threshold=2,
            now=1_752_235_300.0,
        )

    def test_rounding_never_starts_the_window_early_or_leaves_it_empty(self):
        d = self._build(valid_from=1_752_235_199.25, ttl_seconds=10.5)
        self.assertEqual(d.valid_from, "2025-07-11T12:00:00Z")
        self.assertEqual(d.valid_until, "2025-07-11T12:00:09Z")
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d,
                witness_keys=self.builder.witness_keys,
                quorum_threshold=2,
                now=1_752_235_199.5,
            )
        with self.assertRaises(mix.DirectoryError):
            self._build(valid_from=1_752_235_199.25, ttl_seconds=0.5)

    def test_default_start_is_the_current_whole_second(self):
        with mock.patch("afp_mixnet.directory.time.time", return_value=1_752_235_200.25):
            d = self._build(ttl_seconds=10.0)
        self.assertEqual(d.valid_from, "2025-07-11T12:00:00Z")
        self.assertEqual(d.valid_until, "2025-07-11T12:00:10Z")
        mix.verify_directory(
            d,
            witness_keys=self.builder.witness_keys,
            quorum_threshold=2,
            now=1_752_235_200.25,
        )

    def test_builder_rejects_unusable_scheduling_inputs(self):
        # Every unusable input is a DirectoryError, never an OverflowError or a
        # TypeError: non-finite, boolean, string, out-of-calendar, and values
        # whose int-to-float conversion or sum would overflow binary64.
        for kwargs in ({"valid_from": True}, {"ttl_seconds": False},
                       {"valid_from": float("nan")}, {"ttl_seconds": float("nan")},
                       {"valid_from": float("-inf")}, {"ttl_seconds": float("inf")},
                       {"valid_from": "2025-07-11T12:00:00Z"},
                       {"ttl_seconds": "86400"}, {"valid_from": [0]},
                       {"valid_from": -1e12}, {"valid_from": 1e12},
                       {"valid_from": 10**400}, {"ttl_seconds": 10**400},
                       {"valid_from": -(10**400)},
                       {"valid_from": 1e308, "ttl_seconds": 1e308},
                       {"valid_from": 1_752_235_200, "ttl_seconds": 1e308},
                       {"valid_from": 253_402_300_799, "ttl_seconds": 1},
                       # Just outside the calendar: never rounded into it.
                       {"valid_from": -62_135_596_800.25, "ttl_seconds": 2.25},
                       {"valid_from": 253_402_300_798, "ttl_seconds": 1.5},
                       {"valid_from": 1_752_235_200, "ttl_seconds": -1}):
            with self.subTest(**{k: repr(v)[:40] for k, v in kwargs.items()}):
                with self.assertRaises(mix.DirectoryError):
                    self._build(**kwargs)

    def test_window_arithmetic_is_exact_at_the_calendar_limits(self):
        # The sum is exact, so a window ending on the last representable
        # second is accepted rather than lost to float rounding.
        d = self._build(valid_from=253_402_300_798, ttl_seconds=1)
        self.assertEqual(d.valid_from, "9999-12-31T23:59:58Z")
        self.assertEqual(d.valid_until, "9999-12-31T23:59:59Z")
        d = self._build(valid_from=-62_135_596_800, ttl_seconds=1)
        self.assertEqual(d.valid_from, "0001-01-01T00:00:00Z")
        # Fractional instants inside the range still round as usual.
        d = self._build(valid_from=-62_135_596_799.75, ttl_seconds=2)
        self.assertEqual(d.valid_from, "0001-01-01T00:00:01Z")
        self.assertEqual(d.valid_until, "0001-01-01T00:00:02Z")
        d = self._build(valid_from=253_402_300_797.5, ttl_seconds=1.5)
        self.assertEqual(d.valid_from, "9999-12-31T23:59:58Z")
        self.assertEqual(d.valid_until, "9999-12-31T23:59:59Z")

    def test_quorum_signature_covers_the_window_text(self):
        # A fresh signature covers the UTC strings: changing either one to
        # another valid instant invalidates the witness quorum.
        d = self._build(valid_from=1_752_235_200, ttl_seconds=86_400)
        for member, value in (("valid_from", "2025-07-11T11:00:00Z"),
                              ("valid_until", "2025-07-12T13:00:00Z")):
            with self.subTest(member=member):
                tampered = replace(d, **{member: value})
                with self.assertRaisesRegex(mix.DirectoryError, "0 valid witness"):
                    mix.verify_directory(
                        tampered,
                        witness_keys=self.builder.witness_keys,
                        quorum_threshold=2,
                        now=1_752_235_300.0,
                    )

    def test_verifier_rejects_a_directory_whose_window_was_mutated_to_numbers(self):
        # Rolling upgrade: a number-valued window (the old release's form) is
        # rejected, never translated; such a directory must be rebuilt.
        d = self._build(valid_from=1_752_235_200, ttl_seconds=86_400)
        d.valid_from = 1_752_235_200.0
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d,
                witness_keys=self.builder.witness_keys,
                quorum_threshold=2,
                now=1_752_235_300.0,
            )

    def test_signing_content_rechecks_a_mutated_window(self):
        d = self._build()
        d.valid_until = 1_752_235_200.0
        with self.assertRaises(ValueError):
            d.signing_content()

    def test_float_or_noncanonical_validity_window_is_rejected(self):
        d = self._build()
        for bad in (0.0, 1_752_235_200, None, "2025-07-11T12:00:00.0Z",
                    "2025-07-11T12:00:00+00:00", "2025-07-11 12:00:00Z"):
            for member in ("valid_from", "valid_until"):
                with self.subTest(member=member, value=bad):
                    with self.assertRaises(ValueError):
                        replace(d, **{member: bad})

    def test_empty_layer_is_rejected(self):
        layers = [self.layers[0], [], self.layers[2]]
        d = self.builder.build(
            epoch=1, layers=layers, keri_anchor_event_dig="Eanchor"
        )
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )

    def test_too_few_layers_is_rejected(self):
        nodes = {}
        layers = _layers(nodes, layers_n=2)
        d = self.builder.build(epoch=1, layers=layers, keri_anchor_event_dig="Eanchor")
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )

    def test_single_operator_layer_violates_8_6(self):
        nodes = {}
        layers = _layers(nodes, single_operator_layer=1)
        d = self.builder.build(epoch=1, layers=layers, keri_anchor_event_dig="Eanchor")
        with self.assertRaises(mix.DirectoryError) as ctx:
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )
        self.assertIn("single operator", str(ctx.exception))

    def test_operator_spanning_all_layers_violates_8_6(self):
        nodes = {}
        layers = _layers(nodes, spanning_operator="spanner")
        d = self.builder.build(epoch=1, layers=layers, keri_anchor_event_dig="Eanchor")
        with self.assertRaises(mix.DirectoryError) as ctx:
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )
        self.assertIn("every layer", str(ctx.exception))

    def test_weaker_profile_is_rejected(self):
        weak = MixnetProfile(
            name="weak",
            packet_format="sphinx",
            hop_count=2,  # below baseline 3
            layer_count=2,
            payload_bytes=4096,
            delay_distribution="exponential",
            mean_delay_seconds=30.0,
            packet_ttl_seconds=900.0,
            tenant_cover_interval_seconds=10.0,
            mix_loop_interval_seconds=10.0,
            directory_epoch_seconds=86400.0,
        )
        nodes = {}
        layers = _layers(nodes, layers_n=3)
        d = self.builder.build(
            epoch=1, layers=layers, keri_anchor_event_dig="Eanchor", profile=weak
        )
        with self.assertRaises(mix.DirectoryError):
            mix.verify_directory(
                d, witness_keys=self.builder.witness_keys, quorum_threshold=2
            )


class ProfileComparisonTest(unittest.TestCase):
    def test_baseline_accepts_itself(self):
        OB2_BASELINE.assert_not_weaker_than_baseline(OB2_BASELINE)  # no raise

    def test_stricter_profile_is_accepted(self):
        stricter = MixnetProfile(
            name="strict",
            packet_format="sphinx",
            hop_count=4,
            layer_count=4,
            payload_bytes=4096,
            delay_distribution="exponential",
            mean_delay_seconds=60.0,
            packet_ttl_seconds=900.0,
            tenant_cover_interval_seconds=5.0,  # more frequent cover
            mix_loop_interval_seconds=5.0,
            directory_epoch_seconds=3600.0,  # shorter epoch
        )
        OB2_BASELINE.assert_not_weaker_than_baseline(stricter)  # no raise

    def test_fewer_hops_is_weaker(self):
        weak = MixnetProfile(
            name="w", packet_format="sphinx", hop_count=2, layer_count=3,
            payload_bytes=4096, delay_distribution="exponential",
            mean_delay_seconds=30.0, packet_ttl_seconds=900.0,
            tenant_cover_interval_seconds=10.0, mix_loop_interval_seconds=10.0,
            directory_epoch_seconds=86400.0,
        )
        with self.assertRaises(ProfileError):
            OB2_BASELINE.assert_not_weaker_than_baseline(weak)

    def test_non_sphinx_is_weaker(self):
        weak = MixnetProfile(
            name="w", packet_format="onion", hop_count=3, layer_count=3,
            payload_bytes=4096, delay_distribution="exponential",
            mean_delay_seconds=30.0, packet_ttl_seconds=900.0,
            tenant_cover_interval_seconds=10.0, mix_loop_interval_seconds=10.0,
            directory_epoch_seconds=86400.0,
        )
        with self.assertRaises(ProfileError):
            OB2_BASELINE.assert_not_weaker_than_baseline(weak)

    def test_longer_directory_epoch_is_weaker(self):
        weak = MixnetProfile(
            name="w", packet_format="sphinx", hop_count=3, layer_count=3,
            payload_bytes=4096, delay_distribution="exponential",
            mean_delay_seconds=30.0, packet_ttl_seconds=900.0,
            tenant_cover_interval_seconds=10.0, mix_loop_interval_seconds=10.0,
            directory_epoch_seconds=172800.0,  # 48 h > 24 h baseline
        )
        with self.assertRaises(ProfileError):
            OB2_BASELINE.assert_not_weaker_than_baseline(weak)


if __name__ == "__main__":
    unittest.main()
