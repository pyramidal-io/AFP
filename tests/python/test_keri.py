"""KERI subset tests — AID self-certification, KEL chain, pre-rotation, delegation,
witnesses, and stale-keystate detection (§4 / §12.3)."""

import _path  # noqa: F401

import unittest

from afp_session import keri
from afp_session.canonical import digest, qb64
from fixtures import make_witness

pytestmark = None

_IDENTITY_KEY = b"\x01" + b"\x00" * 31
_ORDER_TWO_KEY = b"\xec" + b"\xff" * 30 + b"\x7f"
_MIXED_ORDER_KEY = bytes.fromhex(
    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
)
_NONCANONICAL_KEY = b"\xed" + b"\xff" * 30 + b"\x7f"


def _kel_with_inception_key(encoded_key: str) -> keri.Kel:
    event = keri.KelEvent(
        ilk="icp",
        sn=0,
        keys=[encoded_key],
        next_key_digest=keri._next_key_digest(keri.KeyPair.generate().public_key),
        prior_dig=None,
    )
    return keri.Kel(aid=qb64("E", digest(event.content())), events=[event])


class AidAndKelTest(unittest.TestCase):
    def test_tenant_aid_is_self_certifying(self):
        tenant = keri.Identity.incept_tenant()
        # The AID is derived from the inception event content; verify_kel checks it.
        latest = keri.verify_kel(tenant.kel)
        self.assertEqual(latest.ilk, "icp")

    def test_tampered_inception_breaks_self_certification(self):
        tenant = keri.Identity.incept_tenant()
        tenant.kel.events[0].sn = 99  # mutate inception content
        with self.assertRaises(keri.KeriError):
            keri.verify_kel(tenant.kel)

    def test_kel_chain_break_detected(self):
        tenant = keri.Identity.incept_tenant()
        tenant.rotate()
        tenant.kel.events[1].prior_dig = "D_deadbeef"
        with self.assertRaises(keri.KeriError):
            keri.verify_kel(tenant.kel)


def _witnessed_tenant(count=3, threshold=2):
    witnesses = [make_witness() for _ in range(count)]
    tenant = keri.Identity.incept_tenant(witnesses=witnesses, threshold=threshold)
    return tenant, witnesses, {w.aid: w.public_key for w in witnesses}


def _append(identity, receipting, signer, /, **fields):
    """Append a signed event that every ``receipting`` witness has receipted."""
    event = keri.sign_event(keri.KelEvent(**fields), signer)
    identity.kel.events.append(event)
    for witness in receipting:
        identity.kel.add_receipt(witness.receipt(event.digest))
    return event


def _interaction_fields(identity, **overrides):
    prior = identity.kel.latest
    fields = dict(
        ilk="ixn",
        sn=prior.sn + 1,
        keys=list(prior.keys),
        next_key_digest=prior.next_key_digest,
        prior_dig=prior.digest,
        witnesses=list(prior.witnesses),
        threshold=prior.threshold,
        seal="D_" + "00" * 32,
    )
    fields.update(overrides)
    return fields


class ControllerAuthorizationTest(unittest.TestCase):
    """§4.4: every event is signed by the key set that authorizes it."""

    def setUp(self):
        self.tenant, self.witnesses, self.keys = _witnessed_tenant()

    def _verify(self, kel=None):
        return keri.verify_kel(kel or self.tenant.kel, witness_keys=self.keys)

    def test_identity_events_verify_under_their_authorizing_keys(self):
        keri.Identity.incept_entity(self.tenant)
        self.tenant.rotate()
        self.assertEqual(self._verify().ilk, "rot")

    def test_signature_covers_the_domain_separated_event_digest(self):
        event = self.tenant.kel.events[0]
        self.assertEqual(
            keri.kel_event_signing_input(event),
            b"afp:kel-event:v1\x00" + event.digest.encode("ascii"),
        )
        self.assertNotIn("controller_signature", event.content())

    def test_inception_without_a_valid_signature_is_rejected(self):
        inception = self.tenant.kel.events[0]
        signature = inception.controller_signature
        bare = self.tenant.signing_key.sign(inception.digest.encode("ascii"))
        for name, value in (
            ("missing", None),
            ("hex text", signature.hex()),
            ("flipped bit", bytes([signature[0] ^ 1]) + signature[1:]),
            ("other key", keri.KeyPair.generate().sign(
                keri.kel_event_signing_input(inception))),
            ("no domain separation", bare),
        ):
            with self.subTest(signature=name):
                inception.controller_signature = value
                with self.assertRaises(keri.EventAuthorizationError):
                    self._verify()
        inception.controller_signature = signature
        self._verify()

    def test_interaction_must_be_signed_by_the_current_key(self):
        _append(
            self.tenant,
            self.witnesses,
            keri.KeyPair.generate(),
            **_interaction_fields(self.tenant),
        )
        with self.assertRaises(keri.EventAuthorizationError):
            self._verify()

    def test_signed_interaction_cannot_change_establishment_state(self):
        changes = {
            "keys": [keri.KeyPair.generate().public_qb64],
            "next_key_digest": keri._next_key_digest(
                keri.KeyPair.generate().public_key
            ),
            "witnesses": [make_witness().aid, make_witness().aid],
            "threshold": 1,
        }
        for field_name, value in changes.items():
            with self.subTest(field=field_name):
                tenant, witnesses, keys = _witnessed_tenant()
                _append(
                    tenant,
                    witnesses,
                    tenant.signing_key,
                    **_interaction_fields(tenant, **{field_name: value}),
                )
                with self.assertRaisesRegex(
                    keri.EventAuthorizationError, "changes establishment state"
                ):
                    keri.verify_kel(tenant.kel, witness_keys=keys)

    def test_only_rotations_and_interactions_follow_inception(self):
        for ilk in ("icp", "dip", "drt", "rct"):
            with self.subTest(ilk=ilk):
                tenant, witnesses, keys = _witnessed_tenant()
                fields = _interaction_fields(tenant, ilk=ilk, seal=None)
                if ilk == "dip":
                    fields["delegator_aid"] = tenant.aid
                _append(tenant, witnesses, tenant.signing_key, **fields)
                with self.assertRaisesRegex(keri.KeriError, "must be rot or ixn"):
                    keri.verify_kel(tenant.kel, witness_keys=keys)

    def test_inception_must_be_sequence_zero_without_a_predecessor(self):
        current = keri.KeyPair.generate()
        for name, overrides in (
            ("sn", {"sn": 1}),
            ("prior_dig", {"prior_dig": "D_" + "00" * 32}),
        ):
            with self.subTest(field=name):
                fields = dict(
                    ilk="icp",
                    sn=0,
                    keys=[current.public_qb64],
                    next_key_digest=keri._next_key_digest(
                        keri.KeyPair.generate().public_key
                    ),
                    prior_dig=None,
                    witnesses=[w.aid for w in self.witnesses],
                    threshold=2,
                )
                fields.update(overrides)
                event = keri.sign_event(keri.KelEvent(**fields), current)
                kel = keri.Kel(aid=qb64("E", digest(event.content())), events=[event])
                for witness in self.witnesses:
                    kel.add_receipt(witness.receipt(event.digest))
                with self.assertRaisesRegex(keri.KeriError, "sn=0 and no prior"):
                    self._verify(kel)

    def test_rotation_must_be_signed_by_the_key_it_reveals(self):
        prior = self.tenant.kel.latest
        current = self.tenant.signing_key
        revealed = self.tenant._next
        following = keri.KeyPair.generate()
        fields = dict(
            ilk="rot",
            sn=prior.sn + 1,
            keys=[revealed.public_qb64],
            next_key_digest=keri._next_key_digest(following.public_key),
            prior_dig=prior.digest,
            witnesses=list(prior.witnesses),
            threshold=prior.threshold,
        )
        for name, signer in (
            ("prior key", current),
            ("unrelated key", keri.KeyPair.generate()),
        ):
            with self.subTest(signer=name):
                kel = keri.Kel(
                    aid=self.tenant.aid,
                    events=list(self.tenant.kel.events),
                    receipts=dict(self.tenant.kel.receipts),
                )
                event = keri.sign_event(keri.KelEvent(**fields), signer)
                kel.events.append(event)
                for witness in self.witnesses:
                    kel.add_receipt(witness.receipt(event.digest))
                with self.assertRaises(keri.EventAuthorizationError):
                    self._verify(kel)

        _append(self.tenant, self.witnesses, revealed, **fields)
        self.assertEqual(self._verify().keys, [revealed.public_qb64])

    def test_rotation_after_interaction_honors_the_establishment_commitment(self):
        keri.Identity.incept_entity(self.tenant)
        self.assertEqual(self.tenant.kel.latest.ilk, "ixn")
        self.tenant.rotate()
        self._verify()
        self.tenant.kel.events[-1].keys = [keri.KeyPair.generate().public_qb64]
        with self.assertRaises(keri.PreRotationError):
            self._verify()

    def test_delegation_anchor_signed_by_another_key_is_rejected(self):
        entity = keri.Identity.incept_entity(self.tenant)
        anchor = self.tenant.kel.latest
        anchor.controller_signature = entity.signing_key.sign(
            keri.kel_event_signing_input(anchor)
        )
        with self.assertRaises(keri.EventAuthorizationError):
            keri.verify_kel(entity.kel, tenant_kel=self.tenant.kel, witness_keys=self.keys)


class _EqualsAnything(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


class PlainTypeTest(unittest.TestCase):
    """Values that override equality cannot stand in for AIDs or digests."""

    def test_lying_aid_cannot_claim_another_identity(self):
        victim = keri.Identity.incept_tenant()
        impostor = keri.Identity.incept_tenant()
        impostor.kel.aid = _EqualsAnything(victim.aid)
        with self.assertRaisesRegex(keri.KeriError, "plain values"):
            keri.verify_kel(impostor.kel)

    def test_events_cannot_shadow_their_digested_content(self):
        tenant = keri.Identity.incept_tenant()
        event = tenant.kel.events[0]
        with self.assertRaises(AttributeError):
            event.content = lambda: {}
        with self.assertRaises(AttributeError):
            tenant.kel.latest_dig = "D_" + "00" * 32

    def test_lying_prior_digest_cannot_splice_events(self):
        tenant = keri.Identity.incept_tenant()
        tenant.rotate()
        tenant.kel.events[1].prior_dig = _EqualsAnything(tenant.kel.events[1].prior_dig)
        with self.assertRaisesRegex(keri.KeriError, "non-plain prior_dig"):
            keri.verify_kel(tenant.kel)

    def test_lying_tenant_aid_cannot_satisfy_a_delegation(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        other = keri.Identity.incept_tenant()
        other.kel.aid = _EqualsAnything(other.kel.aid)
        with self.assertRaises(keri.KeriError):
            keri.verify_kel(entity.kel, tenant_kel=other.kel)

    def test_list_and_receipt_subclasses_are_rejected(self):
        class LyingList(list):
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

        tenant, witnesses, keys = _witnessed_tenant()
        _append(
            tenant,
            witnesses,
            tenant.signing_key,
            **_interaction_fields(tenant, witnesses=LyingList([witnesses[0].aid]), threshold=1),
        )
        with self.assertRaisesRegex(keri.KeriError, "non-plain witnesses"):
            keri.verify_kel(tenant.kel, witness_keys=keys)

        tenant, witnesses, keys = _witnessed_tenant()
        dig = tenant.kel.events[0].digest
        tenant.kel.receipts[dig] = tuple(tenant.kel.receipts[dig])
        with self.assertRaisesRegex(keri.KeriError, "plain list"):
            keri.verify_kel(tenant.kel, witness_keys=keys)


class WitnessChangeTest(unittest.TestCase):
    """§4.5: a rotation is receipted under the policy it replaces and its own."""

    def setUp(self):
        self.tenant, self.outgoing, self.keys = _witnessed_tenant(count=2, threshold=2)
        self.incoming = [make_witness()]
        self.keys.update({w.aid: w.public_key for w in self.incoming})

    def test_witness_change_receipted_under_both_policies_verifies(self):
        rotation = self.tenant.rotate(witnesses=self.incoming)
        self.assertEqual((rotation.witnesses, rotation.threshold), ([self.incoming[0].aid], 1))
        keri.Identity.incept_entity(self.tenant)
        keri.verify_kel(self.tenant.kel, witness_keys=self.keys)

    def test_witness_change_receipted_only_by_the_new_set_is_rejected(self):
        rotation = self.tenant.rotate(witnesses=self.incoming)
        self.tenant.kel.receipts[rotation.digest] = [
            r for r in self.tenant.kel.receipts[rotation.digest]
            if r.witness_aid == self.incoming[0].aid
        ]
        with self.assertRaisesRegex(keri.WitnessThresholdError, "prior witness set"):
            keri.verify_kel(self.tenant.kel, witness_keys=self.keys)

    def test_witness_change_receipted_only_by_the_old_set_is_rejected(self):
        rotation = self.tenant.rotate(witnesses=self.incoming)
        self.tenant.kel.receipts[rotation.digest] = [
            r for r in self.tenant.kel.receipts[rotation.digest]
            if r.witness_aid != self.incoming[0].aid
        ]
        with self.assertRaises(keri.WitnessThresholdError):
            keri.verify_kel(self.tenant.kel, witness_keys=self.keys)

    def test_dropping_every_witness_still_needs_the_prior_receipts(self):
        rotation = self.tenant.rotate(witnesses=[])
        self.assertEqual((rotation.witnesses, rotation.threshold), ([], 0))
        keri.verify_kel(self.tenant.kel, witness_keys=self.keys)
        self.tenant.kel.receipts[rotation.digest] = []
        with self.assertRaises(keri.WitnessThresholdError):
            keri.verify_kel(self.tenant.kel, witness_keys=self.keys)

    def test_rotation_without_witness_objects_keeps_the_published_policy(self):
        view = keri.Identity(self.tenant.kel, self.tenant.signing_key, self.tenant._next)
        rotation = view.rotate()
        self.assertEqual(
            (rotation.witnesses, rotation.threshold),
            ([w.aid for w in self.outgoing], 2),
        )
        keri.verify_kel(self.tenant.kel)
        with self.assertRaises(keri.WitnessThresholdError):
            keri.verify_kel(self.tenant.kel, witness_keys=self.keys)

    def test_invalid_policies_are_refused_before_any_state_changes(self):
        events_before = list(self.tenant.kel.events)
        signing_key = self.tenant.signing_key
        for name, kwargs in (
            ("threshold above set size", {"witnesses": self.incoming, "threshold": 2}),
            ("negative threshold", {"threshold": -1}),
            ("duplicate witness", {"witnesses": self.incoming * 2}),
            ("threshold without witnesses", {"witnesses": [], "threshold": 1}),
        ):
            with self.subTest(case=name), self.assertRaises(ValueError):
                self.tenant.rotate(**kwargs)
        self.assertEqual(self.tenant.kel.events, events_before)
        self.assertIs(self.tenant.signing_key, signing_key)
        with self.assertRaises(ValueError):
            keri.Identity.incept_tenant(witnesses=self.outgoing, threshold=3)

    def test_one_key_pinned_under_two_witness_ids_is_rejected(self):
        aliased = dict(self.keys)
        aliased[make_witness().aid] = self.outgoing[0].public_key
        with self.assertRaisesRegex(keri.InvalidPublicKeyError, "two witness"):
            keri.verify_kel(self.tenant.kel, witness_keys=aliased)

    def test_interaction_receipts_follow_the_establishment_policy(self):
        self.tenant.rotate(witnesses=self.incoming)
        keri.Identity.incept_entity(self.tenant)
        anchor = self.tenant.kel.latest
        self.assertEqual(anchor.witnesses, [self.incoming[0].aid])
        self.tenant.kel.receipts[anchor.digest] = []
        with self.assertRaises(keri.WitnessThresholdError):
            keri.verify_kel(self.tenant.kel, witness_keys=self.keys)


class DelegationTest(unittest.TestCase):
    def test_entity_verifies_up_to_tenant_root(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        latest = keri.verify_kel(entity.kel, tenant_kel=tenant.kel)
        self.assertEqual(latest.ilk, "dip")

    def test_delegated_aid_without_tenant_kel_rejected(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        with self.assertRaises(keri.DelegationError):
            keri.verify_kel(entity.kel)

    def test_wrong_delegator_rejected(self):
        tenant = keri.Identity.incept_tenant()
        other = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        with self.assertRaises(keri.DelegationError):
            keri.verify_kel(entity.kel, tenant_kel=other.kel)

    def test_self_rooted_aid_is_not_an_entity_of_any_tenant(self):
        tenant, witnesses, keys = _witnessed_tenant()
        keri.Identity.incept_entity(tenant)
        impostor = keri.Identity.incept_tenant()
        with self.assertRaisesRegex(keri.DelegationError, "opens with dip"):
            keri.verify_kel(impostor.kel, tenant_kel=tenant.kel, witness_keys=keys)
        keri.verify_kel(impostor.kel)  # still a valid tenant root on its own

    def test_tenant_kel_must_be_a_verifiable_root(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        with self.assertRaisesRegex(keri.KeriError, "empty KEL"):
            keri.verify_kel(entity.kel, tenant_kel=keri.Kel(aid=tenant.aid, events=[]))

        # A delegated AID cannot stand in as a tenant root, even one that
        # anchors the delegation it is asked to confirm.
        root = keri.Identity.incept_tenant()
        intermediate = keri.Identity.incept_entity(root)
        nested = keri.Identity.incept_entity(intermediate)
        with self.assertRaisesRegex(keri.DelegationError, "must open with icp"):
            keri.verify_kel(nested.kel, tenant_kel=intermediate.kel)

    def test_unanchored_delegation_rejected(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        # Remove the anchoring interaction event from the tenant KEL.
        tenant.kel.events = [e for e in tenant.kel.events if e.ilk != "ixn"]
        with self.assertRaises(keri.DelegationError):
            keri.verify_kel(entity.kel, tenant_kel=tenant.kel)


class PreRotationTest(unittest.TestCase):
    def test_rotation_honoring_commitment_verifies(self):
        tenant = keri.Identity.incept_tenant()
        tenant.rotate()
        keri.verify_kel(tenant.kel)  # should not raise

    def test_rotation_violating_commitment_rejected(self):
        tenant = keri.Identity.incept_tenant()
        tenant.rotate()
        # Forge the revealed key so it no longer matches the pre-rotation digest.
        tenant.kel.events[1].keys = [keri.KeyPair.generate().public_qb64]
        with self.assertRaises(keri.PreRotationError):
            keri.verify_kel(tenant.kel)


class PublicKeyValidationTest(unittest.TestCase):
    def test_qb64_adapter_kel_verifier_and_resolver_reject_invalid_keys(self):
        valid_key = keri.KeyPair.generate().public_key

        class SpoofedKey(str):
            def partition(self, separator):
                _code, marker, payload = str(self).partition(separator)
                return ("K", marker, payload)

        invalid_values = (
            ("wrong code", qb64("X", valid_key)),
            ("spoofed code", SpoofedKey(qb64("X", valid_key))),
            ("uppercase hex", "K_" + valid_key.hex().upper()),
            ("short", qb64("K", b"\x00" * 31)),
            ("long", qb64("K", b"\x00" * 33)),
            ("identity", qb64("K", _IDENTITY_KEY)),
            ("torsion", qb64("K", _ORDER_TWO_KEY)),
            ("mixed order", qb64("K", _MIXED_ORDER_KEY)),
            ("noncanonical", qb64("K", _NONCANONICAL_KEY)),
        )
        for name, encoded_key in invalid_values:
            with self.subTest(name=name):
                with self.assertRaises(keri.InvalidPublicKeyError):
                    keri._pub_from_qb64(encoded_key)
                kel = _kel_with_inception_key(encoded_key)
                with self.assertRaises(keri.InvalidPublicKeyError):
                    keri.verify_kel(kel)
                with self.assertRaises(keri.InvalidPublicKeyError):
                    keri.resolve_current_key(kel)

    def test_historical_and_interaction_event_keys_are_validated(self):
        rotated = keri.Identity.incept_tenant()
        rotated.rotate()
        rotated.kel.events[0].keys = [qb64("K", _IDENTITY_KEY)]
        rotated.kel.aid = qb64("E", digest(rotated.kel.events[0].content()))
        rotated.kel.events[1].prior_dig = rotated.kel.events[0].digest
        with self.assertRaises(keri.InvalidPublicKeyError):
            keri.verify_kel(rotated.kel)

        tenant = keri.Identity.incept_tenant()
        keri.Identity.incept_entity(tenant)
        tenant.kel.events[-1].keys = [qb64("K", _IDENTITY_KEY)]
        with self.assertRaises(keri.InvalidPublicKeyError):
            keri.verify_kel(tenant.kel)

    def test_every_event_requires_exactly_one_signing_key(self):
        valid_key = keri.KeyPair.generate().public_qb64
        for keys in ([], [valid_key, valid_key]):
            kel = _kel_with_inception_key(valid_key)
            kel.events[0].keys = keys
            kel.aid = qb64("E", digest(kel.events[0].content()))
            with self.subTest(keys=keys), self.assertRaises(
                keri.InvalidPublicKeyError
            ):
                keri.verify_kel(kel)

    def test_every_supplied_witness_key_is_validated_at_threshold_zero(self):
        tenant = keri.Identity.incept_tenant()
        invalid_keys = (
            b"\x00" * 31,
            _IDENTITY_KEY,
            _ORDER_TWO_KEY,
            _MIXED_ORDER_KEY,
            _NONCANONICAL_KEY,
        )
        for invalid_key in invalid_keys:
            with self.subTest(public_key=invalid_key):
                with self.assertRaises(keri.InvalidPublicKeyError):
                    keri.verify_kel(
                        tenant.kel, witness_keys={make_witness().aid: invalid_key}
                    )

        keri.verify_kel(tenant.kel, witness_keys={})


class WitnessTest(unittest.TestCase):
    def setUp(self):
        self.witnesses = [
            make_witness() for _ in range(3)
        ]
        self.keys = {w.aid: w.public_key for w in self.witnesses}

    def test_threshold_met_verifies(self):
        tenant = keri.Identity.incept_tenant(witnesses=self.witnesses, threshold=2)
        entity = keri.Identity.incept_entity(
            tenant, witnesses=self.witnesses, threshold=2
        )
        keri.verify_kel(entity.kel, tenant_kel=tenant.kel, witness_keys=self.keys)

    def test_threshold_not_met_rejected(self):
        tenant = keri.Identity.incept_tenant(witnesses=self.witnesses, threshold=2)
        # Drop receipts below threshold on the inception event.
        dig = tenant.kel.events[0].digest
        tenant.kel.receipts[dig] = tenant.kel.receipts[dig][:1]
        with self.assertRaises(keri.WitnessThresholdError):
            keri.verify_kel(tenant.kel, witness_keys=self.keys)

    def test_forged_receipt_does_not_count(self):
        tenant = keri.Identity.incept_tenant(witnesses=self.witnesses, threshold=2)
        dig = tenant.kel.events[0].digest
        # Replace a real receipt with a forged-signature one.
        forged = keri.WitnessReceipt(
            witness_aid=self.witnesses[0].aid, event_dig=dig, signature=b"\x00" * 64
        )
        tenant.kel.receipts[dig] = [forged, tenant.kel.receipts[dig][1]]
        with self.assertRaises(keri.WitnessThresholdError):
            keri.verify_kel(tenant.kel, witness_keys=self.keys)

    def test_witness_map_key_subclass_cannot_alias_trusted_witness(self):
        trusted = self.witnesses[0]
        attacker = make_witness()
        tenant = keri.Identity.incept_tenant(witnesses=[trusted], threshold=1)
        dig = tenant.kel.events[0].digest
        tenant.kel.receipts[dig] = [
            keri.WitnessReceipt(
                witness_aid=trusted.aid,
                event_dig=dig,
                signature=attacker.receipt(dig).signature,
            )
        ]

        alias_aid = attacker.aid

        class AliasedMapKey(str):
            def __new__(cls):
                value = super().__new__(cls, alias_aid)
                return value

            def __hash__(self):
                return hash(trusted.aid)

            def __eq__(self, other):
                return other == trusted.aid

        with self.assertRaises(keri.InvalidPublicKeyError):
            keri.verify_kel(
                tenant.kel,
                witness_keys={AliasedMapKey(): attacker.public_key},
            )

    def test_receipt_id_subclass_cannot_alias_trusted_witness(self):
        trusted = self.witnesses[0]
        attacker = make_witness()
        tenant = keri.Identity.incept_tenant(witnesses=[trusted], threshold=1)
        dig = tenant.kel.events[0].digest

        class AliasedReceiptId(str):
            def __eq__(self, other):
                return str.__eq__(self, other) or other == trusted.aid

            __hash__ = str.__hash__

        tenant.kel.receipts[dig] = [
            keri.WitnessReceipt(
                witness_aid=AliasedReceiptId(attacker.aid),
                event_dig=dig,
                signature=attacker.receipt(dig).signature,
            )
        ]
        with self.assertRaises(keri.InvalidPublicKeyError):
            keri.verify_kel(
                tenant.kel,
                witness_keys={attacker.aid: attacker.public_key},
            )


class StaleKeyStateTest(unittest.TestCase):
    def test_current_keystate_accepted(self):
        entity = keri.Identity.incept_entity(keri.Identity.incept_tenant())
        keri.assert_keystate_current(entity.kel, entity.kel.latest_dig)  # no raise

    def test_superseded_keystate_rejected(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        stale_dig = entity.kel.events[0].digest
        entity.rotate()  # supersedes the inception key state
        with self.assertRaises(keri.StaleKeyStateError):
            keri.assert_keystate_current(entity.kel, stale_dig)

    def test_resolve_current_key_after_rotation(self):
        tenant = keri.Identity.incept_tenant()
        entity = keri.Identity.incept_entity(tenant)
        before = keri.resolve_current_key(entity.kel)
        entity.rotate()
        after = keri.resolve_current_key(entity.kel)
        self.assertNotEqual(before, after)
        self.assertEqual(after, entity.current_public_key())


if __name__ == "__main__":
    unittest.main()
