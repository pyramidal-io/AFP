"""§14.4 — the afp:provisional-agreement:v1 signature preimage and its vectors."""

import _path  # noqa: F401

import hashlib
import json
import unittest
from dataclasses import replace
from unittest import mock

from afp_introduction import atoms, signing
from afp_session import ed25519, keri
from afp_session.canonical import canonical_bytes, digest, jcs_digest, qb64
from afp_session.session import RemoteParty


def _seeded(*octets):
    pairs = iter([keri.KeyPair.from_seed(bytes([octet]) * 32) for octet in octets])
    return mock.patch.object(
        keri.KeyPair, "generate", classmethod(lambda cls: next(pairs))
    )


def _party(tenant, tenant_next, entity, entity_next):
    with _seeded(tenant, tenant_next, entity, entity_next):
        tenant_identity = keri.Identity.incept_tenant()
        entity_identity = keri.Identity.incept_entity(tenant_identity)
    return tenant_identity, entity_identity


# Synthetic test-only identities. Each party is a witnessless tenant root and a
# delegated entity whose keys come from 32-byte seeds of one repeated octet:
# initiator tenant 0x41 (next 0x42), entity 0x43 (next 0x44); responder tenant
# 0x51 (next 0x52), entity 0x53 (next 0x54); outsider 0x61 to 0x64. The AIDs
# are derived from the seeds, not written out; the pinned content hashes and
# signatures below fix them.
_INITIATOR = _party(0x41, 0x42, 0x43, 0x44)
_RESPONDER = _party(0x51, 0x52, 0x53, 0x54)
_OUTSIDER = _party(0x61, 0x62, 0x63, 0x64)
INITIATOR_TENANT, INITIATOR_ENTITY = (identity.aid for identity in _INITIATOR)
RESPONDER_TENANT, RESPONDER_ENTITY = (identity.aid for identity in _RESPONDER)

_PREFIX = (
    f'{{"initiator_signature":{{"signed_by":"{INITIATOR_ENTITY}"}},'
    '"kind":"afp:provisional-agreement:v1","policy":{"accepted_credentials":'
    '[{"class":"afp.telemetry.instance_attestation.v2",'
    '"valid_until":"2027-01-15T08:00:00Z"}],"accepted_instance_attestation_roots":'
    '[{"root_authority_identifier":"rekor:sigstore.dev",'
    '"root_class":"root:build-provenance"}],'
    '"agreement_expires_at":"2027-06-01T00:00:00Z",'
    '"bond_ref":"escrow:introduction-kat","growth_curve":'
)
_SUFFIX = (
    ',"max_cumulative_outstanding":"1000","max_per_interaction":"100",'
    '"permitted_assets":["USDC"],"permitted_entities":'
    f'["{INITIATOR_ENTITY}","{RESPONDER_ENTITY}"],"rotation_policy":"rot-30d"}},'
    '"reputation_state":{"cumulative_settled_value":"0","settled_interactions":0,'
    '"slash_events":0},'
    f'"responder_signature":{{"signed_by":"{RESPONDER_ENTITY}"}},"tier":"introduction"}}'
)

# name -> (growth_curve, JCS bytes, content hash, initiator sig, responder sig)
VECTORS = {
    # Every member name is ASCII and every value a string or a small integer,
    # so JCS and sorted-key JSON coincide here.
    "baseline": (
        {"step_factor": "2", "cap": "10000"},
        _PREFIX + '{"cap":"10000","step_factor":"2"}' + _SUFFIX,
        "D_56120431aad03ee7a95cf908f82c458deec3b1f455184b22033f32504ae06c50",
        "dccd0da9824b8d5e8946fcaeb7f29999d64c35e709123cf3fc5fa7dbc6a93eb9"
        "6172d6cd68e4e8190310989d8b663f057a5fd164d04a547cb73c8cf41c847f0d",
        "7c44463682e422f19cac2fd7db2240c7f61264f49d30837c7a100dcda7f1e718"
        "7afbc53a907acf73a0ff566ceb3444b2a875ad05b8c5e64785ac0514cc31db05",
    ),
    # 2^60 is a binary64 value. RFC 8785 writes it 1152921504606847000;
    # sorted-key JSON writes the Python integer 1152921504606846976.
    "large": (
        {"n": 2**60},
        _PREFIX + '{"n":1152921504606847000}' + _SUFFIX,
        "D_8c0bd855719a58e767a9c45644e67722d9cd756c81150e073829ae6498c611d4",
        "00fb923d49580a5e83304110f2c2431a50adccc9ad241505803f65b3d2215798"
        "2ebfb4a1ea6c555142d813b6904bbbe836050254fd088eec8e4bf4843f371203",
        "039a947e64b12dae5f43531bc3a002e317f174e5098accf0b7dfb92a9c343658"
        "9e33648499a01de0fbb5e626632a969d870ed85e93f8841f76af970b8ec04204",
    ),
    # JCS writes the integral float 100.0 as 100, and orders U+1F600 (UTF-16
    # D83D DE00) before U+E000; sorted-key JSON writes 100.0 and orders by
    # code point, so the two byte strings differ.
    "jcs-differs": (
        {"step": 100.0, "decay": 0.5, "": "private-use", "\U0001f600": "astral"},
        _PREFIX
        + '{"decay":0.5,"step":100,"\U0001f600":"astral","":"private-use"}'
        + _SUFFIX,
        "D_26dc2db5ee0bf9f449e32e6acae4de3272e340e4c80dc6a020425b698f2675bb",
        "6119a254d533b8bfc814a830e9cca719036a882e025fff6727370c3d2b0e6f0e"
        "d30aca5482fcbe993f813d89d16d962732e66fc0ea16e87ffbf8a02570506901",
        "8138a827f76783fb4640c78e722ca51c069ce77e6031296a4784e3c16bd1083d"
        "ea0265ae4c86d2035727285fa36f4a9f249715b274442e04840a8754988cfd0f",
    ),
}


def _agreement(growth_curve, **policy_changes):
    policy = dict(
        permitted_entities=[INITIATOR_ENTITY, RESPONDER_ENTITY],
        permitted_assets=["USDC"],
        max_per_interaction="100",
        max_cumulative_outstanding="1000",
        bond_ref="escrow:introduction-kat",
        accepted_credentials=[
            atoms.AcceptedCredential(
                "afp.telemetry.instance_attestation.v2", "2027-01-15T08:00:00Z"
            )
        ],
        accepted_instance_attestation_roots=[
            atoms.InstanceAttestationRoot("root:build-provenance", "rekor:sigstore.dev")
        ],
        rotation_policy="rot-30d",
        growth_curve=growth_curve,
        agreement_expires_at="2027-06-01T00:00:00Z",
    )
    policy.update(policy_changes)
    return atoms.ProvisionalAgreement(
        tier="introduction",
        policy=atoms.IntroductionPolicy(**policy),
        reputation_state=atoms.ReputationState(0, "0", 0, None),
        initiator_signature=None,
        responder_signature=None,
    )


class AgreementSignatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.i_tenant, cls.i_entity = _INITIATOR
        cls.r_tenant, cls.r_entity = _RESPONDER
        cls.x_tenant, cls.x_entity = _OUTSIDER

    def _remote(self, tenant, entity):
        return RemoteParty(entity.kel, tenant.kel, {})

    def _parties(self):
        return {
            "initiator": self._remote(self.i_tenant, self.i_entity),
            "responder": self._remote(self.r_tenant, self.r_entity),
        }

    def _signed(self, agreement, initiator=None, responder=None):
        initiator = initiator or self.i_entity
        responder = responder or self.r_entity
        planned = dict(initiator_signed_by=initiator.aid, responder_signed_by=responder.aid)
        agreement = signing.sign_provisional_agreement(
            agreement, initiator, role="initiator", signed_at=1800000000, **planned
        )
        return signing.sign_provisional_agreement(
            agreement, responder, role="responder", signed_at=1800000060, **planned
        )

    def _verify(self, agreement):
        return signing.verify_provisional_agreement(agreement, **self._parties())

    def _rejects(self, agreement, fragment=None):
        with self.assertRaises(signing.AgreementSignatureError) as caught:
            self._verify(agreement)
        if fragment is not None:
            self.assertIn(fragment, str(caught.exception))

    # -- vectors -----------------------------------------------------------

    def test_vectors_pin_jcs_bytes_content_hash_and_both_signatures(self):
        for name, (growth, jcs, content_hash, sig_i, sig_r) in VECTORS.items():
            with self.subTest(vector=name):
                agreement = self._signed(_agreement(growth))
                jcs_bytes = jcs.encode("utf-8")
                self.assertEqual(agreement.content_bytes(), jcs_bytes)
                self.assertEqual(
                    content_hash, "D_" + hashlib.sha256(jcs_bytes).hexdigest()
                )
                self.assertEqual(agreement.content_hash(), content_hash)
                self.assertEqual(atoms.content_digest(agreement), content_hash)
                signed_bytes = signing.agreement_signing_input(agreement)
                self.assertEqual(signed_bytes, content_hash.encode("ascii"))
                self.assertEqual(len(signed_bytes), 66)
                self.assertEqual(agreement.initiator_signature.signature, sig_i)
                self.assertEqual(agreement.responder_signature.signature, sig_r)
                # Each signature is plain strict Ed25519 over the 66 octets
                # with the signer's seeded key; no KEL is needed to check it.
                for octet, signature in ((0x43, sig_i), (0x53, sig_r)):
                    public_key = keri.KeyPair.from_seed(bytes([octet]) * 32).public_key
                    self.assertTrue(
                        ed25519.verify_strict(
                            signed_bytes, bytes.fromhex(signature), public_key
                        )
                    )
                self.assertEqual(self._verify(agreement), content_hash)

    def test_vectors_read_back_from_the_wire_and_still_verify(self):
        for name, (growth, _jcs, content_hash, _i, _r) in VECTORS.items():
            with self.subTest(vector=name):
                wire = json.loads(json.dumps(self._signed(_agreement(growth)).to_dict()))
                reread = atoms.ProvisionalAgreement.from_dict(wire)
                self.assertEqual(self._verify(reread), content_hash)

    def test_jcs_and_sorted_key_json_differ_except_in_the_baseline(self):
        for name, (growth, jcs, content_hash, _i, _r) in VECTORS.items():
            with self.subTest(vector=name):
                agreement = _agreement(growth)
                sorted_key = canonical_bytes(
                    agreement.signed_content(INITIATOR_ENTITY, RESPONDER_ENTITY)
                )
                self.assertEqual(sorted_key == jcs.encode("utf-8"), name == "baseline")
                if name != "baseline":
                    # The earlier reference digest is a different value.
                    self.assertNotEqual(
                        content_hash, qb64("D", hashlib.sha256(sorted_key).digest())
                    )
                    self.assertNotEqual(
                        content_hash, qb64("X", digest(agreement.content()))
                    )

    # -- what the preimage covers ----------------------------------------

    def test_only_signed_by_of_each_signature_is_in_the_preimage(self):
        agreement = self._signed(_agreement(VECTORS["baseline"][0]))
        unsigned = _agreement(VECTORS["baseline"][0])
        self.assertEqual(
            agreement.content_hash(),
            unsigned.content_hash(INITIATOR_ENTITY, RESPONDER_ENTITY),
        )
        self.assertEqual(
            agreement.signed_content()["initiator_signature"],
            {"signed_by": INITIATOR_ENTITY},
        )
        for name in ("initiator_signature", "responder_signature"):
            sig = getattr(agreement, name)
            for value in (sig.kel_event_dig, sig.signature):
                self.assertNotIn(value.encode(), agreement.content_bytes())
        # An unsigned draft has no content hash until both signers are planned.
        with self.assertRaises(atoms.IntroductionWireError):
            unsigned.content_hash()
        with self.assertRaises(atoms.IntroductionWireError):
            unsigned.content_hash(INITIATOR_ENTITY)
        # signed_at is observational: changing it does not affect verification.
        moved = replace(
            agreement,
            initiator_signature=replace(agreement.initiator_signature, signed_at=0.5),
        )
        self.assertEqual(self._verify(moved), agreement.content_hash())

    def test_altered_members_are_rejected(self):
        signed = self._signed(_agreement(VECTORS["jcs-differs"][0]))

        def policy(**changes):
            return replace(signed, policy=replace(signed.policy, **changes))

        cred = atoms.AcceptedCredential
        altered = {
            "max_per_interaction": policy(max_per_interaction="101"),
            "permitted_entities order": policy(
                permitted_entities=[RESPONDER_ENTITY, INITIATOR_ENTITY]
            ),
            "permitted_assets": policy(permitted_assets=["USDC", "EURC"]),
            "bond_ref absent": policy(bond_ref=None),
            "valid_until": policy(
                accepted_credentials=[
                    cred("afp.telemetry.instance_attestation.v2", "2027-01-15T08:00:01Z")
                ]
            ),
            "roots": policy(accepted_instance_attestation_roots=[]),
            "rotation_policy": policy(rotation_policy="rot-31d"),
            "growth_curve value": policy(
                growth_curve={**signed.policy.growth_curve, "decay": 0.25}
            ),
            "agreement_expires_at": policy(agreement_expires_at="2027-06-01T00:00:01Z"),
            "settled_interactions": replace(
                signed, reputation_state=atoms.ReputationState(1, "0", 0, None)
            ),
            "last_commitment_ref present": replace(
                signed, reputation_state=atoms.ReputationState(0, "0", 0, "cmt-1")
            ),
        }
        for name, agreement in altered.items():
            with self.subTest(member=name):
                self.assertNotEqual(agreement.content_hash(), signed.content_hash())
                self._rejects(agreement, "does not verify")

    def test_policy_time_members_are_covered_verbatim(self):
        # The spelling is unresolved (core §1.6.1): the hash covers the string
        # as signed, and the same instant spelled differently does not verify.
        offset = "2027-06-01T00:00:00+00:00"
        signed = self._signed(
            _agreement(VECTORS["baseline"][0], agreement_expires_at=offset)
        )
        self.assertIn(b'"agreement_expires_at":"2027-06-01T00:00:00+00:00"',
                      signed.content_bytes())
        self.assertEqual(self._verify(signed), signed.content_hash())
        respelled = replace(
            signed,
            policy=replace(signed.policy, agreement_expires_at="2027-06-01T00:00:00Z"),
        )
        self._rejects(respelled, "does not verify")

    def test_large_binary64_numbers_round_trip(self):
        jcs_hash = VECTORS["large"][2]
        signed = self._signed(_agreement({"n": 2**60}))
        native = json.dumps(signed.to_dict())
        self.assertIn('"n": 1152921504606846976', native)
        canonical = native.replace("1152921504606846976", "1152921504606847000")
        for name, text in (("native token", native), ("RFC 8785 token", canonical)):
            with self.subTest(wire=name):
                reread = atoms.ProvisionalAgreement.from_dict(json.loads(text))
                self.assertEqual(reread.content_hash(), jcs_hash)
                self.assertEqual(self._verify(reread), jcs_hash)
        self.assertEqual(
            atoms.ProvisionalAgreement.from_dict(json.loads(canonical)).policy.growth_curve,
            {"n": 2**60},
        )
        # A standalone policy keeps the value as read, so its sorted-key
        # digest does not change.
        policy_wire = json.loads(canonical)["policy"]
        standalone = atoms.IntroductionPolicy.from_dict(policy_wire)
        self.assertEqual(standalone.growth_curve, {"n": 1152921504606847000})
        self.assertEqual(
            atoms.content_digest(standalone), qb64("X", digest(policy_wire))
        )

    def test_fractional_tokens_are_read_as_rfc8785_reads_them(self):
        # 2e-3 is not the RFC 8785 spelling and 0.002 is not exact in binary64;
        # both name the same binary64 value, so both give the same content.
        signed = self._signed(_agreement({"x": 0.002}))
        self.assertIn(b'"growth_curve":{"x":0.002}', signed.content_bytes())
        native = json.dumps(signed.to_dict(), separators=(",", ":"))
        self.assertIn('"x":0.002', native)
        for token in ("0.002", "2e-3", "2E-3", "0.0020"):
            with self.subTest(token=token):
                reread = atoms.ProvisionalAgreement.from_dict(
                    json.loads(native.replace('"x":0.002', f'"x":{token}'))
                )
                self.assertEqual(reread.content_bytes(), signed.content_bytes())
                self.assertEqual(self._verify(reread), signed.content_hash())

    def test_counts_read_the_same_from_native_and_rfc8785_tokens(self):
        # (count, its native JSON token, its RFC 8785 token)
        for count, native_token, jcs_token in (
            (2**60, "1152921504606846976", "1152921504606847000"),
            (10**21, "1000000000000000000000", "1e+21"),
        ):
            with self.subTest(count=count):
                signed = self._signed(
                    replace(
                        _agreement(VECTORS["baseline"][0]),
                        reputation_state=atoms.ReputationState(count, "0", count, None),
                    )
                )
                self.assertIn(
                    f'"settled_interactions":{jcs_token}'.encode(), signed.content_bytes()
                )
                native = json.dumps(signed.to_dict(), separators=(",", ":"))
                self.assertIn(f'"settled_interactions":{native_token}', native)
                canonical = native.replace(native_token, jcs_token)
                for name, text in (("native", native), ("RFC 8785", canonical)):
                    with self.subTest(wire=name):
                        reread = atoms.ProvisionalAgreement.from_dict(json.loads(text))
                        state = reread.reputation_state
                        self.assertEqual(
                            (type(state.settled_interactions), state.settled_interactions),
                            (int, count),
                        )
                        self.assertEqual(state.slash_events, count)
                        self.assertEqual(
                            json.dumps(reread.to_dict(), separators=(",", ":")), native
                        )
                        self.assertEqual(self._verify(reread), signed.content_hash())

    def test_received_counts_must_be_non_negative_integral_values(self):
        wire = json.loads(json.dumps(self._signed(_agreement(VECTORS["baseline"][0])).to_dict()))
        wire["reputation_state"]["settled_interactions"] = 5.0
        reread = atoms.ProvisionalAgreement.from_dict(wire)
        self.assertEqual(reread.reputation_state.settled_interactions, 5)
        for bad in (1.5, -1.0, float("inf"), -1, True, "5"):
            with self.subTest(value=repr(bad)):
                wire["reputation_state"]["settled_interactions"] = bad
                with self.assertRaises(atoms.IntroductionWireError):
                    atoms.ProvisionalAgreement.from_dict(wire)
        # A native integer that binary64 cannot hold exactly is never signed,
        # even when it is the RFC 8785 spelling of another value.
        native = replace(
            _agreement(VECTORS["baseline"][0]),
            reputation_state=atoms.ReputationState(1152921504606847000, "0", 0, None),
        )
        with self.assertRaises(atoms.IntroductionWireError):
            native.content_hash(INITIATOR_ENTITY, RESPONDER_ENTITY)

    def test_content_without_a_jcs_form_cannot_be_signed_or_verified(self):
        planned = dict(
            initiator_signed_by=INITIATOR_ENTITY, responder_signed_by=RESPONDER_ENTITY
        )
        for growth in (
            {"n": 2**53 + 1}, {"n": -(2**53 + 1)}, {"n": 2**1024},
            {"\ud800": "x"}, {"s": "\udfff"},
        ):
            with self.subTest(growth=repr(growth)):
                agreement = _agreement(growth)
                with self.assertRaises(atoms.IntroductionWireError):
                    agreement.content_hash(INITIATOR_ENTITY, RESPONDER_ENTITY)
                with self.assertRaises(signing.AgreementSignatureError):
                    signing.sign_provisional_agreement(
                        agreement, self.i_entity, role="initiator", signed_at=1, **planned
                    )
        counter = replace(
            _agreement(VECTORS["baseline"][0]),
            reputation_state=atoms.ReputationState(2**53 + 1, "0", 0, None),
        )
        with self.assertRaises(atoms.IntroductionWireError):
            counter.content_hash(INITIATOR_ENTITY, RESPONDER_ENTITY)
        # The reader shape is not narrowed: the record still reads; only
        # hashing, signing and verification refuse it.
        signed = self._signed(_agreement({"n": 2**53 - 1}))
        wire = json.loads(json.dumps(signed.to_dict()))
        wire["policy"]["growth_curve"]["n"] = 2**53 + 1
        reread = atoms.ProvisionalAgreement.from_dict(wire)
        self._rejects(reread, "cannot be signed")

    # -- signers and roles -------------------------------------------------

    def test_swapped_roles_are_rejected(self):
        signed = self._signed(_agreement(VECTORS["baseline"][0]))
        swapped = replace(
            signed,
            initiator_signature=signed.responder_signature,
            responder_signature=signed.initiator_signature,
        )
        self._rejects(swapped, "other party")
        # One party's signature in both members is still a swapped role.
        doubled = replace(signed, responder_signature=signed.initiator_signature)
        self._rejects(doubled, "other party")

    def test_wrong_signer_is_rejected(self):
        base = _agreement(VECTORS["baseline"][0])
        outsider = self._signed(base, responder=self.x_entity)
        self._rejects(outsider, "neither AID")
        # A third party's signature labelled with the responder's AID and key
        # state fails Ed25519 under the responder's key.
        signed = self._signed(base)
        forged = replace(
            signed,
            responder_signature=replace(
                signed.responder_signature,
                signature=outsider.responder_signature.signature,
            ),
        )
        self._rejects(forged, "does not verify")

    def test_changing_a_signed_by_breaks_both_signatures(self):
        signed = self._signed(_agreement(VECTORS["baseline"][0]))
        # Both are permitted AIDs of their roles, but neither was signed for.
        for role, tenant in (("initiator", self.i_tenant), ("responder", self.r_tenant)):
            with self.subTest(role=role):
                name = f"{role}_signature"
                pin = keri.current_key_event_digest(tenant.kel)
                moved = replace(
                    signed,
                    **{name: replace(
                        getattr(signed, name), signed_by=tenant.aid, kel_event_dig=pin
                    )},
                )
                self.assertNotEqual(moved.content_hash(), signed.content_hash())
                self._rejects(moved, "does not verify")

    def test_signing_needs_the_planned_signers(self):
        agreement = _agreement(VECTORS["baseline"][0])
        with self.assertRaises(signing.AgreementSignatureError):
            signing.sign_provisional_agreement(
                agreement, self.i_entity, role="initiator", signed_at=1,
                initiator_signed_by=INITIATOR_TENANT, responder_signed_by=RESPONDER_ENTITY,
            )
        with self.assertRaises(signing.AgreementSignatureError):
            signing.sign_provisional_agreement(
                agreement, self.i_entity, role="initiator", signed_at=1,
                initiator_signed_by=INITIATOR_ENTITY, responder_signed_by=INITIATOR_ENTITY,
            )
        # The responder must sign for the pair the initiator already signed for.
        half = signing.sign_provisional_agreement(
            agreement, self.i_entity, role="initiator", signed_at=1,
            initiator_signed_by=INITIATOR_ENTITY, responder_signed_by=RESPONDER_ENTITY,
        )
        with self.assertRaises(signing.AgreementSignatureError):
            signing.sign_provisional_agreement(
                half, self.r_entity, role="responder", signed_at=1,
                initiator_signed_by=INITIATOR_TENANT, responder_signed_by=RESPONDER_ENTITY,
            )

    def test_tenant_root_may_sign_its_role(self):
        signed = self._signed(
            _agreement(VECTORS["baseline"][0]),
            initiator=self.i_tenant,
            responder=self.r_tenant,
        )
        self.assertEqual(signed.initiator_signature.signed_by, INITIATOR_TENANT)
        self.assertEqual(self._verify(signed), signed.content_hash())
        # The other tenant root is still the other party.
        crossed = self._signed(
            _agreement(VECTORS["baseline"][0]), initiator=self.r_tenant
        )
        self.assertEqual(crossed.responder_signature.signed_by, RESPONDER_ENTITY)
        self._rejects(crossed, "other party")

    def test_stale_key_state_is_rejected(self):
        tenant, entity = _party(0x71, 0x72, 0x73, 0x74)
        signed = self._signed(_agreement(VECTORS["baseline"][0]), initiator=entity)
        parties = self._parties()
        parties["initiator"] = self._remote(tenant, entity)
        self.assertEqual(
            signing.verify_provisional_agreement(signed, **parties), signed.content_hash()
        )
        entity.rotate()
        with self.assertRaises(signing.AgreementSignatureError) as caught:
            signing.verify_provisional_agreement(signed, **parties)
        self.assertIn("not KEL-current", str(caught.exception))

    def test_both_signatures_are_required_and_well_formed(self):
        signed = self._signed(_agreement(VECTORS["baseline"][0]))
        for role in signing.AGREEMENT_SIGNATURE_ROLES:
            with self.subTest(missing=role):
                self._rejects(replace(signed, **{f"{role}_signature": None}), "required")
        sig = signed.initiator_signature
        for field, value in (
            ("signature", sig.signature.upper()),
            ("signature", sig.signature[:-2]),
            ("signed_by", sig.signed_by.upper()),
            ("kel_event_dig", "kel-evt"),
            ("signed_at", "1800000000"),
        ):
            with self.subTest(field=field, value=value):
                self._rejects(
                    replace(signed, initiator_signature=replace(sig, **{field: value}))
                )

    def test_the_two_parties_must_be_different_tenants(self):
        signed = self._signed(_agreement(VECTORS["baseline"][0]))
        same = self._remote(self.i_tenant, self.i_entity)
        with self.assertRaises(signing.AgreementSignatureError):
            signing.verify_provisional_agreement(signed, initiator=same, responder=same)

    # -- domain separation (AFP-0104) ----------------------------------------

    def test_signatures_made_for_another_preimage_are_rejected(self):
        growth = VECTORS["jcs-differs"][0]
        signed = self._signed(_agreement(growth))
        content = signed.signed_content()
        content_hash = signed.content_hash()
        other_kind = dict(content, kind="afp:limit-adjustment:v1")
        preimages = {
            "raw SHA-256 digest": hashlib.sha256(signed.content_bytes()).digest(),
            "JCS bytes": signed.content_bytes(),
            "KEL controller preimage": b"afp:kel-event:v1\x00" + content_hash.encode(),
            "KEL receipt preimage": keri.receipt_signing_input(content_hash),
            "another kind's D_ hash": qb64("D", jcs_digest(other_kind, floats=True)).encode(),
            "sorted-key D_ hash": qb64("D", digest(content)).encode(),
            "earlier X_ digest": qb64("X", digest(signed.content())).encode(),
            "D_ hash without signers": qb64(
                "D", jcs_digest(signed.content(), floats=True)
            ).encode(),
        }
        for name, preimage in preimages.items():
            with self.subTest(preimage=name):
                self.assertNotEqual(preimage, signing.agreement_signing_input(signed))
                other = replace(
                    signed,
                    initiator_signature=replace(
                        signed.initiator_signature,
                        signature=self.i_entity.sign(preimage).hex(),
                    ),
                )
                self._rejects(other, "does not verify")

    def test_signing_rejects_an_unknown_role(self):
        with self.assertRaises(signing.AgreementSignatureError):
            signing.sign_provisional_agreement(
                _agreement(VECTORS["baseline"][0]), self.i_entity, role="arbiter",
                signed_at=1, initiator_signed_by=INITIATOR_ENTITY,
                responder_signed_by=RESPONDER_ENTITY,
            )


if __name__ == "__main__":
    unittest.main()
