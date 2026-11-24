"""§6.3.1 ``afp:publisher-key-state:v1`` and ``root_material_digest``.

The property everything else rests on: a verifier holding only the published
KELs must recompute a byte-identical ``root_material_digest``. §6.3.1 spells out
what is forfeited otherwise — without the recomputation "a party could construct
a key-state record naming another organization's root AID as ``authority_aid``,
sign its own manifest with its own keys, and satisfy every in-circuit
constraint".
"""

import _path  # noqa: F401  (path setup)

import unittest

import ceremony_fixtures as cf
from afp_session.canonical import canonical_json

from afp_ceremony import (
    AfpPublisherKeyState,
    KeyStateError,
    JcsError,
    PUBLISHER_KEY_STATE_KIND,
    SUBSET_SIGNING_THRESHOLD,
    ceremony as ceremony_mod,
    jcs_bytes,
    jcs_string,
    keystate,
    resolve_publisher_key_state,
)

WEIGHTED_THRESHOLD = [["1/2", "1/2", "1/2"], ["1", "1"]]


def _record(**overrides):
    base = dict(
        authority_aid="E_authority",
        signing_aid="E_signer",
        delegation_anchor_dig="D_anchor",
        key_state_event_dig="D_establishment",
        key_state_sequence_number=0,
        signing_public_keys=("K_one",),
        signing_threshold=SUBSET_SIGNING_THRESHOLD,
        next_key_digests=("D_next",),
        next_threshold=SUBSET_SIGNING_THRESHOLD,
    )
    base.update(overrides)
    return AfpPublisherKeyState(**base)


class RootMaterialDigestDeterminismTest(unittest.TestCase):
    """The digest must recompute identically from resolved KEL state."""

    @classmethod
    def setUpClass(cls):
        cls.result = cf.staging_ceremony()

    def test_resolution_is_deterministic_across_independent_resolutions(self):
        first = resolve_publisher_key_state(
            authority_kel=self.result.authority.kel,
            signing_kel=self.result.published_signer.kel,
            witness_keys=self.result.witness_material,
        )
        second = resolve_publisher_key_state(
            authority_kel=self.result.authority.kel,
            signing_kel=self.result.published_signer.kel,
            witness_keys=self.result.witness_material,
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.root_material_digest(), second.root_material_digest())

    def test_digest_recomputes_from_serialized_and_reloaded_kels(self):
        """A verifier holding only published KEL bytes gets the same digest."""
        authority = ceremony_mod.kel_from_dict(
            ceremony_mod.kel_to_dict(self.result.authority.kel)
        )
        signer = ceremony_mod.kel_from_dict(
            ceremony_mod.kel_to_dict(self.result.published_signer.kel)
        )
        reloaded = resolve_publisher_key_state(
            authority_kel=authority,
            signing_kel=signer,
            witness_keys=self.result.witness_material,
        )
        self.assertEqual(
            reloaded.root_material_digest(),
            self.result.published_key_state.root_material_digest(),
        )

    def test_digest_shape_is_sha256_prefixed_lowercase_hex(self):
        value = self.result.published_key_state.root_material_digest()
        self.assertTrue(value.startswith("sha256:"))
        body = value[len("sha256:"):]
        self.assertEqual(len(body), 64)
        self.assertEqual(body, body.lower())
        int(body, 16)

    def test_rotation_changes_the_digest(self):
        """§6.3.1: root_material_digest "changes at every published rotation"."""
        self.assertIsNotNone(self.result.rotated_root_material_digest)
        self.assertNotEqual(
            self.result.root_material_digest,
            self.result.rotated_root_material_digest,
        )

    def test_delegated_case_pins_the_authority_kel_anchor(self):
        state = self.result.published_key_state
        self.assertTrue(state.is_delegated)
        self.assertNotEqual(state.signing_aid, state.authority_aid)
        self.assertIsNotNone(state.delegation_anchor_dig)
        anchor = keystate.find_delegation_anchor(
            self.result.authority.kel, self.result.published_signer.kel
        )
        self.assertEqual(state.delegation_anchor_dig, anchor)
        self.assertIn(
            anchor, {event.digest for event in self.result.authority.kel.events}
        )

    def test_non_delegated_case_has_a_null_anchor(self):
        """§6.3.1: "null iff signing_aid == authority_aid"."""
        state = resolve_publisher_key_state(
            authority_kel=self.result.authority.kel,
            signing_kel=self.result.authority.kel,
            witness_keys=self.result.witness_material,
        )
        self.assertFalse(state.is_delegated)
        self.assertEqual(state.signing_aid, state.authority_aid)
        self.assertIsNone(state.delegation_anchor_dig)
        self.assertEqual(state.to_dict()["delegation_anchor_dig"], None)
        # A distinct authority yields a distinct digest even over the same KEL.
        self.assertNotEqual(
            state.root_material_digest(),
            self.result.published_key_state.root_material_digest(),
        )

    def test_subset_threshold_is_one_and_is_declared_as_such(self):
        state = self.result.published_key_state
        self.assertEqual(state.signing_threshold, SUBSET_SIGNING_THRESHOLD)
        self.assertEqual(state.next_threshold, SUBSET_SIGNING_THRESHOLD)


class ResolutionRefusesAmbiguousOrUnanchoredStateTest(unittest.TestCase):
    """The two ways published KEL state can fail to determine a key state."""

    def test_a_duplicated_delegation_anchor_is_unresolvable(self):
        """§6.3.1 names *the* anchoring event; two of them determine nothing."""
        authority, signer, anchor, witnesses = cf.minimal_authority()
        witness_material = {w.aid: w.public_key for w in witnesses}
        # Baseline: one anchor resolves.
        resolve_publisher_key_state(
            authority_kel=authority.kel,
            signing_kel=signer.kel,
            witness_keys=witness_material,
        )
        # Append a second, fully receipted ixn carrying the identical seal — a
        # re-anchor after a recovery, or an appended replay.
        identity = authority.as_keri_identity()
        duplicate = identity._anchor_delegation(signer.aid, signer.kel.events[0].digest)
        self.assertEqual(
            2,
            sum(
                1
                for event in authority.kel.events
                if event.ilk == "ixn"
                and event.seal == keystate.delegation_seal(
                    signer.aid, signer.kel.events[0].digest
                )
            ),
        )
        with self.assertRaises(KeyStateError) as ctx:
            resolve_publisher_key_state(
                authority_kel=authority.kel,
                signing_kel=signer.kel,
                witness_keys=witness_material,
            )
        self.assertIn("not uniquely determined", str(ctx.exception))
        # The anchor a first-wins reader would have picked is the original.
        self.assertNotEqual(anchor, duplicate.digest)

    def test_an_unanchored_delegated_rotation_is_unresolvable(self):
        """§6.3.1: each delegated rotation is anchored by a seal in the authority KEL."""
        authority, signer, _anchor, witnesses = cf.minimal_authority()
        witness_material = {w.aid: w.public_key for w in witnesses}
        rotated = ceremony_mod.rotate_identity(signer)
        with self.assertRaises(KeyStateError) as ctx:
            resolve_publisher_key_state(
                authority_kel=authority.kel,
                signing_kel=rotated.kel,
                witness_keys=witness_material,
            )
        self.assertIn("not anchored", str(ctx.exception))
        # Anchoring it makes the identical KEL state resolvable.
        ceremony_mod.anchor_rotation(
            authority,
            delegate_aid=rotated.aid,
            rotation_dig=rotated.kel.latest.digest,
        )
        state = resolve_publisher_key_state(
            authority_kel=authority.kel,
            signing_kel=rotated.kel,
            witness_keys=witness_material,
        )
        self.assertEqual(state.key_state_sequence_number, 1)

    def test_an_unanchored_non_head_rotation_is_unresolvable(self):
        authority, signer, _anchor, witnesses = cf.minimal_authority()
        witness_material = {w.aid: w.public_key for w in witnesses}
        first = ceremony_mod.rotate_identity(signer)
        second = ceremony_mod.rotate_identity(first)
        ceremony_mod.anchor_rotation(
            authority,
            delegate_aid=second.aid,
            rotation_dig=second.kel.latest.digest,
        )
        with self.assertRaises(KeyStateError) as ctx:
            resolve_publisher_key_state(
                authority_kel=authority.kel,
                signing_kel=second.kel,
                witness_keys=witness_material,
            )
        self.assertIn("not anchored", str(ctx.exception))


class SequenceNumberEncodingTest(unittest.TestCase):
    """KERI serializes ``s`` as lowercase hex; the record field is a JSON number."""

    def test_hex_sequence_numbers_read_as_hex_not_decimal(self):
        self.assertEqual(keystate.kel_sequence_number("1a"), 26)
        self.assertEqual(keystate.kel_sequence_number("10"), 16)
        self.assertEqual(keystate.kel_sequence_number("a"), 10)

    def test_integers_pass_through(self):
        self.assertEqual(keystate.kel_sequence_number(0), 0)
        self.assertEqual(keystate.kel_sequence_number(26), 26)

    def test_malformed_values_are_rejected(self):
        for bad in ("", "0x1a", "1A", -1, True, None, 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(KeyStateError):
                    keystate.kel_sequence_number(bad)


class PublisherKeyStateRecordTest(unittest.TestCase):
    def test_record_carries_kind_plus_the_nine_specified_fields(self):
        data = _record().to_dict()
        self.assertEqual(data["kind"], PUBLISHER_KEY_STATE_KIND)
        self.assertEqual(
            set(data),
            {
                "kind",
                "authority_aid",
                "signing_aid",
                "delegation_anchor_dig",
                "key_state_event_dig",
                "key_state_sequence_number",
                "signing_public_keys",
                "signing_threshold",
                "next_key_digests",
                "next_threshold",
            },
        )

    def test_round_trip_is_exact(self):
        record = _record()
        self.assertEqual(
            AfpPublisherKeyState.from_dict(record.to_dict()).to_dict(), record.to_dict()
        )

    def test_decoding_rejects_extra_or_missing_members(self):
        data = _record().to_dict()
        data["extra"] = 1
        with self.assertRaises(KeyStateError):
            AfpPublisherKeyState.from_dict(data)
        data = _record().to_dict()
        del data["next_threshold"]
        with self.assertRaises(KeyStateError):
            AfpPublisherKeyState.from_dict(data)

    def test_decoding_rejects_a_wrong_kind(self):
        data = _record().to_dict()
        data["kind"] = "afp:publisher-key-state:v2"
        with self.assertRaises(KeyStateError):
            AfpPublisherKeyState.from_dict(data)

    def test_decoding_rejects_non_list_key_collections(self):
        for field in ("signing_public_keys", "next_key_digests"):
            with self.subTest(field=field):
                data = _record().to_dict()
                data[field] = "K_deadbeef"
                with self.assertRaises(KeyStateError):
                    AfpPublisherKeyState.from_dict(data)

    def test_kel_native_fields_are_not_sha256_re_encoded(self):
        """§6.3.1: these fields are "**NOT** re-encoded under the sha256: rule"."""
        with self.assertRaises(KeyStateError):
            _record(key_state_event_dig="sha256:" + "0" * 64)
        with self.assertRaises(KeyStateError):
            _record(delegation_anchor_dig="sha256:" + "0" * 64)
        with self.assertRaises(KeyStateError):
            _record(next_key_digests=("sha256:" + "0" * 64,))

    def test_anchor_nullity_is_tied_to_delegation(self):
        with self.assertRaises(KeyStateError):
            _record(delegation_anchor_dig=None)
        with self.assertRaises(KeyStateError):
            _record(signing_aid="E_authority", authority_aid="E_authority")
        # The consistent non-delegated form is accepted.
        record = _record(
            signing_aid="E_authority",
            authority_aid="E_authority",
            delegation_anchor_dig=None,
        )
        self.assertFalse(record.is_delegated)

    def test_sequence_number_must_be_a_non_negative_integer(self):
        with self.assertRaises(KeyStateError):
            _record(key_state_sequence_number=-1)
        with self.assertRaises(KeyStateError):
            _record(key_state_sequence_number=True)
        with self.assertRaises(KeyStateError):
            _record(key_state_sequence_number="0")

    def test_empty_ordered_lists_are_rejected(self):
        with self.assertRaises(KeyStateError):
            _record(signing_public_keys=())
        with self.assertRaises(KeyStateError):
            _record(next_key_digests=())


class WeightedThresholdCanonicalizationTest(unittest.TestCase):
    """§6.3.1: kt/nt are copied verbatim, "including a nested threshold"."""

    def test_nested_weighted_threshold_canonicalizes_deterministically(self):
        record = _record(
            signing_threshold=WEIGHTED_THRESHOLD,
            next_threshold=["1/2", "1/2", "1/2"],
        )
        text = jcs_string(record.to_dict())
        self.assertIn(
            '"signing_threshold":[["1/2","1/2","1/2"],["1","1"]]', text
        )
        self.assertIn('"next_threshold":["1/2","1/2","1/2"]', text)
        # Members are in RFC 8785 order and there is no insignificant whitespace.
        self.assertTrue(text.startswith('{"authority_aid":'))
        self.assertNotIn(": ", text)
        self.assertNotIn(", ", text)
        # And the digest over it is stable.
        self.assertEqual(record.root_material_digest(), record.root_material_digest())

    def test_weighted_and_simple_thresholds_produce_different_digests(self):
        simple = _record()
        weighted = _record(signing_threshold=WEIGHTED_THRESHOLD)
        self.assertNotEqual(
            simple.root_material_digest(), weighted.root_material_digest()
        )

    def test_weighted_thresholds_do_not_alias_caller_lists(self):
        threshold = [["1/2", "1/2"], ["1"]]
        record = _record(signing_threshold=threshold)
        before = record.root_material_digest()
        threshold[0][0] = "1"
        self.assertEqual(record.root_material_digest(), before)

    def test_malformed_thresholds_are_rejected(self):
        with self.assertRaises(KeyStateError):
            _record(signing_threshold=[])
        with self.assertRaises(KeyStateError):
            _record(signing_threshold=1)
        with self.assertRaises(KeyStateError):
            _record(signing_threshold=["1/2", ["1/2"]])
        with self.assertRaises(KeyStateError):
            _record(signing_threshold="")


class JcsTest(unittest.TestCase):
    """RFC 8785 details the digest depends on."""

    def test_members_sort_by_utf16_code_unit_not_code_point(self):
        value = {"￿": 1, "\U00010000": 2}
        # RFC 8785 sorts by UTF-16 code unit, so the astral key sorts FIRST.
        self.assertEqual(jcs_string(value), '{"\U00010000":2,"￿":1}')
        # afp_session.canonical sorts by code point and disagrees — which is why
        # this module exists rather than reusing it for the §6.3.1 preimage.
        self.assertNotEqual(jcs_string(value), canonical_json(value))

    def test_escapes_follow_ecmascript(self):
        self.assertEqual(
            jcs_string({"a": "\b\t\n\f\r\"\\"}),
            '{"a":"\\b\\t\\n\\f\\r\\"\\\\\\u0001"}',
        )

    def test_literals_arrays_and_integers(self):
        self.assertEqual(
            jcs_string({"n": None, "t": True, "f": False, "l": [1, 2], "i": -3}),
            '{"f":false,"i":-3,"l":[1,2],"n":null,"t":true}',
        )

    def test_non_integral_numbers_are_a_declared_seam(self):
        with self.assertRaises(JcsError):
            jcs_string({"x": 1.5})

    def test_unsupported_types_are_rejected(self):
        with self.assertRaises(JcsError):
            jcs_bytes({"x": {1, 2}})
        with self.assertRaises(JcsError):
            jcs_bytes({1: "x"})

    def test_bytes_are_utf8(self):
        self.assertEqual(jcs_bytes({"k": "é"}), '{"k":"é"}'.encode("utf-8"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
