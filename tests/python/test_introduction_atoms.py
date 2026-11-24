"""§14 introduction-tier atoms — kinds, content addressing, provisional agreement."""

import _path  # noqa: F401

import hashlib
import json
import unittest
from dataclasses import replace

import afp_introduction as intro
from afp_introduction import atoms
from afp_session.canonical import jcs_bytes


class TestIntroductionAtoms(unittest.TestCase):
    def test_kinds_are_namespaced(self):
        self.assertEqual(atoms.OFFER_KIND, "afp:introduction-offer:v1")
        self.assertEqual(atoms.PROVISIONAL_AGREEMENT_KIND, "afp:provisional-agreement:v1")
        # all seven §14.2 atom kinds are exported on the package
        for kind in (
            "afp:introduction-offer:v1", "afp:introduction-request:v1",
            "afp:credential-presentation:v1", "afp:provisional-agreement:v1",
            "afp:limit-adjustment:v1", "afp:downgrade:v1", "afp:termination:v1",
        ):
            self.assertIn(kind, intro.INTRODUCTION_ATOM_KINDS)

    def test_offer_roundtrips_and_is_content_addressable(self):
        offer = atoms.IntroductionOffer(
            tenant_aid="EtenantA",
            accepted_credential_classes=["zkc:proof:jurisdiction:v1"],
            entertained_envelope=atoms.Envelope(
                assets=["USDC"], max_per_interaction="100", max_cumulative="1000",
                collateral_required=True,
            ),
            route_handle="rendezvous-handle",
            directory_epoch=7,
        )
        self.assertEqual(offer.kind, atoms.OFFER_KIND)
        self.assertEqual(atoms.content_digest(offer), atoms.content_digest(offer))

    def test_request_carries_explicit_attestation_window(self):
        request = atoms.IntroductionRequest(
            initiator_tenant_aid="EtenantA",
            responder_tenant_aid="EtenantB",
            offered_credential_classes=["afp.telemetry.instance_attestation.v2"],
            required_credential_classes=["afp.telemetry.instance_attestation.v2"],
            proposed_envelope=atoms.Envelope(["USDC"], "100", "1000", True),
            attestation_window=atoms.AttestationWindow(
                "2026-08-08T10:00:00Z", "2026-08-08T11:00:00Z"),
        )
        self.assertEqual(
            atoms.asdict(request)["attestation_window"],
            {
                "starts_at": "2026-08-08T10:00:00Z",
                "ends_at": "2026-08-08T11:00:00Z",
            },
        )

    @staticmethod
    def _agreement(**overrides):
        kw = dict(
            tier="introduction",
            policy=atoms.IntroductionPolicy(
                permitted_entities=["EentityA", "EentityB"], permitted_assets=["USDC"],
                max_per_interaction="100", max_cumulative_outstanding="1000",
                bond_ref="escrow:0xabc",
                accepted_credentials=[atoms.AcceptedCredential(
                    "zkc:proof:jurisdiction:v1", "1970-01-01T02:46:39Z")],
                accepted_instance_attestation_roots=[atoms.InstanceAttestationRoot(
                    root_class="root:build-provenance",
                    root_authority_identifier="rekor:sigstore.dev",
                )],
                rotation_policy="rot-30d",
                growth_curve={"step_factor": "2", "cap": "10000"},
                agreement_expires_at="1970-01-01T02:46:39Z",
            ),
            reputation_state=atoms.ReputationState(0, "0", 0, None),
            initiator_signature=None, responder_signature=None,
        )
        kw.update(overrides)
        return atoms.ProvisionalAgreement(**kw)

    def test_provisional_agreement_carries_tier_and_bilateral_sigs(self):
        agr = self._agreement()
        self.assertEqual(agr.tier, "introduction")
        self.assertEqual(agr.kind, atoms.PROVISIONAL_AGREEMENT_KIND)

    def test_content_digest_binds_only_signed_by(self):
        # Signing must NOT change the content digest: an unsigned draft with the
        # planned signers and the signed agreement hash identically, because
        # §14.4 keeps only each signature's signed_by in the content.
        unsigned = self._agreement()
        sig = atoms.AfpCommitSignature(
            signed_by="EentityA", kel_event_dig="kel-evt", signature="abcd", signed_at=1.0)
        signed = self._agreement(
            initiator_signature=sig,
            responder_signature=replace(sig, signed_by="EentityB", signature="ef"),
        )
        self.assertNotEqual(unsigned.initiator_signature, signed.initiator_signature)
        self.assertEqual(
            unsigned.content_hash("EentityA", "EentityB"), atoms.content_digest(signed)
        )
        # A draft has no digest until both signers are planned.
        with self.assertRaises(atoms.IntroductionWireError):
            atoms.content_digest(unsigned)

    def test_content_digest_changes_when_policy_changes(self):
        # ...but a change to a NON-signature field does move the digest.
        a = self._agreement()
        b = self._agreement(
            reputation_state=atoms.ReputationState(3, "300", 0, "cmt3"))
        self.assertNotEqual(
            a.content_hash("EentityA", "EentityB"), b.content_hash("EentityA", "EentityB")
        )

    def test_signed_policy_carries_instance_attestation_root_constraints(self):
        roots = self._agreement().policy.accepted_instance_attestation_roots
        self.assertEqual(roots[0].root_class, "root:build-provenance")
        serialized_policy = atoms.asdict(self._agreement().policy)
        self.assertEqual(
            serialized_policy["accepted_instance_attestation_roots"],
            [{
                "root_class": "root:build-provenance",
                "root_authority_identifier": "rekor:sigstore.dev",
            }],
        )



SIGNATURE = {
    "signed_by": "EentityA",
    "kel_event_dig": "kel-evt",
    "signature": "abcd",
    "signed_at": 1.0,
}


class TestProvisionalAgreementWire(unittest.TestCase):
    """§14.4 wire shape: object entries and string times, never arrays or numbers."""

    @staticmethod
    def _wire():
        return {
            "kind": "afp:provisional-agreement:v1",
            "tier": "introduction",
            "policy": {
                "permitted_entities": ["EentityA", "EentityB"],
                "permitted_assets": ["USDC"],
                "max_per_interaction": "100",
                "max_cumulative_outstanding": "1000",
                "bond_ref": "escrow:0xabc",
                "accepted_credentials": [
                    {"class": "zkc:proof:jurisdiction:v1",
                     "valid_until": "2027-01-15T08:00:00Z"},
                ],
                "accepted_instance_attestation_roots": [
                    {"root_class": "root:build-provenance",
                     "root_authority_identifier": "rekor:sigstore.dev"},
                ],
                "rotation_policy": "rot-30d",
                "growth_curve": {"step_factor": "2", "cap": "10000"},
                "agreement_expires_at": "2027-06-01T00:00:00Z",
            },
            "reputation_state": {
                "settled_interactions": 0,
                "cumulative_settled_value": "0",
                "slash_events": 0,
            },
            "initiator_signature": dict(SIGNATURE),
            "responder_signature": dict(SIGNATURE, signed_by="EentityB"),
        }

    def _rejects(self, mutate):
        wire = self._wire()
        mutate(wire)
        with self.assertRaises(ValueError):
            atoms.ProvisionalAgreement.from_dict(wire)

    def test_round_trip_emits_the_published_object_shape(self):
        wire = self._wire()
        agreement = atoms.ProvisionalAgreement.from_dict(wire)
        entry = agreement.policy.accepted_credentials[0]
        self.assertIs(type(entry), atoms.AcceptedCredential)
        self.assertEqual(entry.credential_class, "zkc:proof:jurisdiction:v1")
        self.assertEqual(entry.valid_until, "2027-01-15T08:00:00Z")
        self.assertEqual(agreement.policy.agreement_expires_at, "2027-06-01T00:00:00Z")
        self.assertEqual(agreement.to_dict(), wire)
        self.assertEqual(
            json.loads(json.dumps(agreement.to_dict())), wire,
        )

    def test_absent_optional_members_stay_absent(self):
        wire = self._wire()
        del wire["policy"]["bond_ref"]
        agreement = atoms.ProvisionalAgreement.from_dict(wire)
        self.assertIsNone(agreement.policy.bond_ref)
        self.assertIsNone(agreement.reputation_state.last_commitment_ref)
        self.assertEqual(agreement.to_dict(), wire)
        self._rejects(lambda w: w["policy"].__setitem__("bond_ref", None))
        self._rejects(
            lambda w: w["reputation_state"].__setitem__("last_commitment_ref", None)
        )

    def test_reader_rejects_numeric_times(self):
        # The earlier reference emitted Unix seconds as JSON numbers.
        for bad in (1_800_000_000.0, 1_800_000_000, 9e9, 0, True, None):
            with self.subTest(member="agreement_expires_at", value=bad):
                self._rejects(
                    lambda w: w["policy"].__setitem__("agreement_expires_at", bad)
                )
            with self.subTest(member="valid_until", value=bad):
                self._rejects(
                    lambda w: w["policy"]["accepted_credentials"][0].__setitem__(
                        "valid_until", bad
                    )
                )

    def test_reader_carries_any_string_time_verbatim(self):
        # §14.4 types both members as string and §1.6.1 leaves the spelling
        # unresolved, so the reference neither rejects nor normalizes one.
        for text in ("2027-01-15T08:00:00+00:00", "2027-01-15T08:00:00.5Z",
                     "2027-01-15t08:00:00z", "1800000000", ""):
            with self.subTest(value=text):
                wire = self._wire()
                wire["policy"]["agreement_expires_at"] = text
                wire["policy"]["accepted_credentials"][0]["valid_until"] = text
                agreement = atoms.ProvisionalAgreement.from_dict(wire)
                self.assertEqual(agreement.policy.agreement_expires_at, text)
                self.assertEqual(agreement.to_dict(), wire)

    def test_reader_rejects_the_array_entry_form(self):
        # dataclasses.asdict turned the earlier (class, valid_until) tuple
        # into a JSON array.
        for bad in (["zkc:proof:jurisdiction:v1", 1_800_000_000.0],
                    ["zkc:proof:jurisdiction:v1", "2027-01-15T08:00:00Z"],
                    "zkc:proof:jurisdiction:v1",
                    {"class": "zkc:proof:jurisdiction:v1"},
                    {"class": "zkc:proof:jurisdiction:v1",
                     "valid_until": "2027-01-15T08:00:00Z", "extra": 1},
                    {"class": 7, "valid_until": "2027-01-15T08:00:00Z"}):
            with self.subTest(entry=bad):
                self._rejects(
                    lambda w: w["policy"].__setitem__("accepted_credentials", [bad])
                )

    def test_reader_rejects_other_shapes(self):
        self._rejects(lambda w: w.__setitem__("kind", "afp:session:v1"))
        self._rejects(lambda w: w.__setitem__("tier", "standard"))
        self._rejects(lambda w: w.__delitem__("responder_signature"))
        for member in ("signed_by", "kel_event_dig", "signature"):
            for bad in (None, 7, ["x"]):
                with self.subTest(member=member, value=bad):
                    self._rejects(
                        lambda w: w["initiator_signature"].__setitem__(member, bad)
                    )
        self._rejects(lambda w: w["responder_signature"].__setitem__("signed_at", None))
        self._rejects(lambda w: w["responder_signature"].__setitem__("extra", 1))
        self._rejects(lambda w: w.__setitem__("extra", 1))
        self._rejects(lambda w: w["policy"].__setitem__("extra", 1))
        self._rejects(lambda w: w["policy"].__setitem__("accepted_credentials", {}))
        self._rejects(
            lambda w: w["reputation_state"].__setitem__("slash_events", True)
        )

    def test_constructor_and_emitter_reject_the_float_and_tuple_forms(self):
        policy = atoms.ProvisionalAgreement.from_dict(self._wire()).policy
        with self.assertRaises(ValueError):
            replace(policy, agreement_expires_at=1_800_000_000.0)
        with self.assertRaises(ValueError):
            replace(
                policy,
                accepted_credentials=[("zkc:proof:jurisdiction:v1", 1_800_000_000.0)],
            )
        with self.assertRaises(ValueError):
            atoms.AcceptedCredential("zkc:proof:jurisdiction:v1", 1_800_000_000.0)
        # A live record edited after construction is not emitted or digested.
        policy.agreement_expires_at = 1_800_000_000.0
        with self.assertRaises(ValueError):
            policy.to_dict()
        with self.assertRaises(ValueError):
            atoms.content_digest(policy)

    def test_emitter_never_writes_what_the_reader_refuses(self):
        agreement = atoms.ProvisionalAgreement.from_dict(self._wire())
        for field, value in (("kind", "afp:session:v1"), ("tier", "standard")):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    replace(agreement, **{field: value})
                edited = replace(agreement)
                setattr(edited, field, value)
                with self.assertRaises(ValueError):
                    edited.to_dict()
        edited = replace(agreement)
        edited.initiator_signature = atoms.AfpCommitSignature(
            signed_by=None, kel_event_dig="kel-evt", signature="abcd", signed_at=1.0
        )
        with self.assertRaises(ValueError):
            edited.to_dict()
        # The digest covers signed_by, so a signature without one has none.
        with self.assertRaises(atoms.IntroductionWireError):
            atoms.content_digest(edited)
        # It does not read the other signature members.
        edited.initiator_signature = atoms.AfpCommitSignature(
            signed_by="EentityA", kel_event_dig=None, signature=7, signed_at="x"
        )
        self.assertEqual(atoms.content_digest(edited), atoms.content_digest(agreement))

    def test_emitter_requires_both_signatures_and_unsigned_use_stays_on_content(self):
        signed = atoms.ProvisionalAgreement.from_dict(self._wire())
        for missing in (("initiator_signature",), ("responder_signature",),
                        ("initiator_signature", "responder_signature")):
            with self.subTest(missing=missing):
                draft = replace(signed, **{name: None for name in missing})
                with self.assertRaises(atoms.IntroductionWireError):
                    draft.to_dict()
                unsigned = {k: v for k, v in self._wire().items()
                            if not k.endswith("_signature")}
                self.assertEqual(draft.content(), unsigned)
                planned = (SIGNATURE["signed_by"], "EentityB")
                self.assertEqual(
                    draft.content_hash(*planned), atoms.content_digest(signed)
                )

    def test_amounts_leave_only_as_strings(self):
        policy = atoms.ProvisionalAgreement.from_dict(self._wire()).policy
        for field in ("max_per_interaction", "max_cumulative_outstanding"):
            for bad in (1, 1.0, None, True):
                with self.subTest(field=field, value=bad):
                    with self.assertRaises(atoms.IntroductionWireError):
                        replace(policy, **{field: bad})
                    edited = replace(policy)
                    setattr(edited, field, bad)
                    with self.assertRaises(atoms.IntroductionWireError):
                        edited.to_dict()

    @staticmethod
    def _bytes(wire):
        return json.dumps(
            wire, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()

    def test_whatever_the_emitter_accepts_reads_back_and_re_emits_identically(self):
        """Emit -> read -> emit is byte-identical; anything else is refused on emit."""
        root = atoms.InstanceAttestationRoot
        cred = atoms.AcceptedCredential("c", "2027-01-15T08:00:00Z")
        bent = atoms.AcceptedCredential("c", "2027-01-15T08:00:00Z")
        object.__setattr__(bent, "valid_until", 1.0)
        sig = atoms.AfpCommitSignature

        def good_sig(**changes):
            return sig(**dict(SIGNATURE, **changes))

        # (target, attribute, value, emitted?)
        policy_cases = {
            "permitted_entities": [([], True), (["E"], True), ([1], False),
                                   ("E", False), (None, False), (("E",), False)],
            "permitted_assets": [([], True), (["USDC"], True), ([None], False)],
            "max_per_interaction": [("1", True), (1, False), (1.0, False),
                                    (None, False), (True, False)],
            "max_cumulative_outstanding": [("1000", True), (1000, False)],
            "bond_ref": [(None, True), ("escrow", True), ("", True), (1, False)],
            "accepted_credentials": [([], True), ([cred], True),
                                     ([("c", "t")], False),
                                     ([{"class": "c", "valid_until": "t"}], False),
                                     ([bent], False), ((cred,), False), (None, False)],
            "accepted_instance_attestation_roots": [
                ([], True), ([root("root:build-provenance", "a")], True),
                ([root(1, "a")], False), ([object()], False), (None, False)],
            "rotation_policy": [("r", True), (1, False), (None, False)],
            "growth_curve": [({}, True), ({"a": "b"}, True),
                             ({"a": {"b": [1, 2.5, None, True, "x"]}}, True),
                             ({1: "x"}, False), ({"a": float("nan")}, False),
                             ({"a": (1,)}, False), ({"a": b"x"}, False),
                             (None, False), ([], False)],
            "agreement_expires_at": [("2027-06-01T00:00:00Z", True), ("", True),
                                     ("2027-06-01T00:00:00+00:00", True),
                                     (1.0, False), (None, False)],
        }
        reputation_cases = {
            "settled_interactions": [(0, True), (5, True), (-1, False),
                                     (True, False), (1.0, False), ("1", False)],
            "cumulative_settled_value": [("0", True), (0, False)],
            "slash_events": [(0, True), (None, False)],
            "last_commitment_ref": [(None, True), ("cmt", True), (1, False)],
        }
        agreement_cases = {
            "kind": [("afp:provisional-agreement:v1", True), ("afp:session:v1", False)],
            "tier": [("introduction", True), ("standard", False)],
            "initiator_signature": [
                (good_sig(), True), (None, False), (good_sig(signed_by=None), False),
                (good_sig(signature=7), False), (good_sig(signed_at=5), True),
                # 2^60 in RFC 8785 spelling leaves as its binary64 value.
                (good_sig(signed_at=1152921504606847000), True),
                (good_sig(signed_at=2**60), False),
                (good_sig(signed_at=float("nan")), False),
                (good_sig(signed_at="1"), False), (SIGNATURE, False)],
        }
        emitted = refused = 0
        for target, cases in (("policy", policy_cases),
                              ("reputation_state", reputation_cases),
                              (None, agreement_cases)):
            for field, values in cases.items():
                for value, expected in values:
                    with self.subTest(target=target, field=field, value=repr(value)):
                        agreement = atoms.ProvisionalAgreement.from_dict(self._wire())
                        holder = getattr(agreement, target) if target else agreement
                        setattr(holder, field, value)
                        try:
                            first = self._bytes(agreement.to_dict())
                        except atoms.IntroductionWireError:
                            refused += 1
                            self.assertFalse(expected, "a valid value was refused")
                            continue
                        emitted += 1
                        self.assertTrue(expected, "an excluded value was emitted")
                        reread = atoms.ProvisionalAgreement.from_dict(json.loads(first))
                        self.assertEqual(self._bytes(reread.to_dict()), first)
                        self.assertEqual(
                            atoms.content_digest(reread),
                            atoms.content_digest(agreement),
                        )
        self.assertGreater(emitted, 20)
        self.assertGreater(refused, 30)

    def test_digest_covers_the_published_bytes_and_both_signers(self):
        wire = self._wire()
        agreement = atoms.ProvisionalAgreement.from_dict(wire)
        unsigned = {k: v for k, v in wire.items() if not k.endswith("_signature")}
        content = dict(
            unsigned,
            initiator_signature={"signed_by": SIGNATURE["signed_by"]},
            responder_signature={"signed_by": "EentityB"},
        )
        self.assertEqual(
            atoms.content_digest(agreement),
            atoms.qb64("D", hashlib.sha256(jcs_bytes(content, floats=True)).digest()),
        )
        self.assertNotEqual(
            atoms.content_digest(agreement), atoms.qb64("X", atoms.digest(unsigned))
        )
        # The earlier reference shape is a different preimage: an agreement
        # signed in that shape is not translated, its parties sign afresh.
        legacy = json.loads(json.dumps(unsigned))
        legacy["policy"]["accepted_credentials"] = [
            ["zkc:proof:jurisdiction:v1", 1_800_000_000.0]
        ]
        self.assertNotEqual(
            atoms.content_digest(agreement), atoms.qb64("X", atoms.digest(legacy))
        )


if __name__ == "__main__":
    unittest.main()
