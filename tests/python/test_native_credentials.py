"""Native credential carrier integration; cryptographic fixtures are synthetic.

The fixture adapter verifies independent Ed25519-signed subject/public-input
statements and linkable/anonymous Ed25519 APRs. Scoped APR acceptance is a
deterministic exact-byte synthetic oracle, NOT ECDSA verification. Its SEC1-key
association resolver verifies a KERI signature over fixture-only association
material, not a registered protocol wire artifact. No production ZKC circuit,
subject adapter, or APR-key association implementation is claimed.
"""

import _path  # noqa: F401

from dataclasses import replace
import copy
import json
import unittest

import afp_session as afp
from afp_session import ed25519, keri
from afp_session.canonical import jcs_bytes
from fixtures import establish_channels, make_pair


NOW = 1_700_000_000
SCOPED_APR_KEY = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
KYC_V2 = afp.ProvenPredicate("zkc:proof:kyc:v2", "2")
KYC_V1 = afp.ProvenPredicate("zkc:proof:kyc:v1", "1")


class NativeCredentialTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._initialize_fixture(cls, "work")

    @staticmethod
    def _initialize_fixture(cls, profile):
        cls.transport, cls.a, cls.b, cls.ra, cls.rb = make_pair()
        descriptor = getattr(cls, "session_descriptor", None)
        if descriptor is not None:
            cls.a.profiles.register(descriptor)
            cls.b.profiles.register(descriptor)
        cls.clock = [NOW]
        cls.a._clock = cls.b._clock = lambda: cls.clock[0]
        cls.fa = cls.a.propose(
            responder_tenant_aid=cls.b.tenant_aid,
            responder_entity_aid=cls.b.entity_aid,
            agreement_ref="agreement", agreement_version="1", profile=profile,
            profile_policy_hash="policy", responder_remote=cls.rb,
        )
        cls.fb = cls.b.accept(cls.fa.atom, initiator_remote=cls.ra)
        cls.a.confirm_open(cls.fa, cls.fb.atom, responder_remote=cls.rb)
        cls.ca, cls.cb = establish_channels(cls.a, cls.b, cls.ra, cls.rb, cls.fa.atom)
        cls.issuer = keri.Identity.incept_tenant()

    def setUp(self):
        profile = getattr(self, "session_profile", "work")
        if not hasattr(self, "fa") or self.fa.atom.profile != profile:
            self._initialize_fixture(self, profile)
        # Reuse real authenticated identities/channel setup; reset test-owned
        # lifecycle/replay records while channel sequence numbers remain fresh.
        self.clock[0] = NOW
        self.fa.atom.status = self.fb.atom.status = afp.AfpSessionStatus.OPEN
        self.fa.atom.closed_at = self.fb.atom.closed_at = None
        self.a._normally_activated_fsms.clear()
        self.b._normally_activated_fsms.clear()
        self.b.credential_inbox.clear()
        self.b._native_results.clear()
        self.b._credential_seen.clear()
        self.b._credential_pending.clear()
        self.flow = getattr(self, "trust_flow", afp.AfpTrustFlow.OPEN_FEDERATION)
        self.calls = 0
        self.captured_requests = []
        self.scoped_apr_oracle = set()
        self.b._apr_signer_binding_resolver = self.resolve_apr_signer

    def resolve_apr_signer(self, request):
        # Fixture-only real KERI signature authenticates this exact association.
        association = jcs_bytes({
            "public_key": SCOPED_APR_KEY.hex(),
            "verifier_aid": request.expected_verifier_aid,
            "kel_event_dig": request.expected_kel_event_dig,
            "session_ref": request.expected_session_ref,
            "session_context": request.expected_session_context,
            "policy": request.expected_session_policy_hash,
        })
        signature = self.b.entity.sign(association)
        if not ed25519.verify_strict(association, signature, request.expected_keri_public_key):
            return None
        # Resolve SEC1 only when the fixture explicitly selected scoped proof;
        # native v1 keeps the KERI Ed25519 key for actual APR verification.
        public_key = SCOPED_APR_KEY if self._resolve_scoped else request.expected_keri_public_key
        return afp.NativeAprSignerBinding(public_key, request.expected_verifier_aid,
                                          request.expected_kel_event_dig)

    def policy(self, profile=afp.SCOPED_PROFILE):
        predicate = KYC_V1 if profile == afp.LINKABLE_PROFILE else KYC_V2
        return afp.RequiredPredicatePolicy(
            accepted_predicate_ids=frozenset({predicate.predicate_id}),
            required_predicate_ids=frozenset({predicate.predicate_id}),
        )

    def artifacts(self, profile=afp.SCOPED_PROFILE, consent=False):
        self._resolve_scoped = profile == afp.SCOPED_PROFILE
        scope_policy = afp.afp_scope_policy("policy") if profile == afp.SCOPED_PROFILE else None
        context = afp.presentation_proof_context(
            flow=self.flow, responder_aid=self.a.entity_aid,
            session_context=self.fa.atom.session_context,
            apr_verifier_aid=self.b.entity_aid, profile=profile,
            scope_policy=scope_policy,
        )
        key = SCOPED_APR_KEY if profile == afp.SCOPED_PROFILE else keri.resolve_current_key(self.b.entity.kel)
        handles = {}
        if profile == afp.SCOPED_PROFILE:
            handles = {"scopeId": afp.derive_scope_id(key, scope_policy, 0),
                       "presentationPseudonym": 123}
        elif profile == afp.LINKABLE_PROFILE:
            handles = {"holderCommitment": 456}
        else:
            handles = {"scopeId": 0, "presentationPseudonym": 0}
        predicate = KYC_V1 if profile == afp.LINKABLE_PROFILE else KYC_V2
        signed = {
            "subject": self.a.entity_aid, "context": context, "profile": profile,
            "predicate": predicate.predicate_id,
            "handles": {name: f"0x{value:064x}" for name, value in handles.items()},
        }
        presentation = {
            "version": "zkc:proof:v1" if profile == afp.LINKABLE_PROFILE else "zkc:proof:v2",
            "metadata": {
                "generatedAt": "2023-11-14T22:13:20Z",
                "expiresAt": "2023-11-14T22:23:20Z",
                "context": {"profile": afp.AFP_ZKC_PRESENTATION_CONTEXT_V2,
                            "value": context, "timestamp": NOW},
            },
            "proofs": [{
                "proofType": predicate.predicate_id,
                # Synthetic authenticated subject adapter transcript lives
                # inside the opaque proof string, never in a new wire member.
                "proof": jcs_bytes({"statement": signed,
                                    "signature": self.issuer.sign(jcs_bytes(signed)).hex()}).hex(),
                "publicInputs": {"proof_context": context},
                "principalConsent": consent,
            }],
        }
        if profile == afp.LINKABLE_PROFILE:
            presentation["holderBinding"] = {"commitment": f"0x{456:064x}"}
            presentation["proofs"][0]["publicInputs"]["holder_commitment"] = f"0x{456:064x}"
        else:
            presentation["presentationBinding"] = {"profile": profile}
            presentation["proofs"][0]["publicInputs"].update({
                "scope_id": f"0x{handles['scopeId']:064x}",
                "presentation_pseudonym": f"0x{handles['presentationPseudonym']:064x}",
            })
            if profile == afp.SCOPED_PROFILE:
                presentation["presentationBinding"].update({
                    "scopeId": f"0x{handles['scopeId']:064x}", "pseudonym": f"0x{123:064x}",
                })
        request = {
            "requirements": {"context": {"value": context},
                             "proofTypes": [predicate.predicate_id]},
            "presentation": {"profile": profile, "scopePolicy": scope_policy},
            "principalConsent": consent,
        }
        apr_content = {
            "request": request, "verifierId": self.b.entity_aid,
            "nonce": "0x" + "ab" * 32, "issuedAt": NOW, "expiresAt": NOW + 600,
        }
        if profile == afp.SCOPED_PROFILE:
            apr = dict(apr_content, signature={
                "scheme": "ECDSA_SECP256K1", "verifierKey": key.hex(),
                "value": "synthetic-exact-byte-oracle-only",
            })
            self.scoped_apr_oracle.add(jcs_bytes(apr))
        else:
            apr = dict(apr_content, signature={
                "scheme": "Ed25519", "verifierKey": key.hex(),
                "value": self.b.entity.sign(jcs_bytes(apr_content)).hex(),
            })
        return presentation, apr

    def adapter(self, request):
        """Verify exact retained proof/APR bytes and derive their public meaning."""
        self.calls += 1
        self.captured_requests.append(request)
        envelope = request.envelope
        presentation, apr = envelope.presentation, envelope.apr
        binding_member = "holderBinding" if presentation["version"] == "zkc:proof:v1" else "presentationBinding"
        if set(presentation) != {"version", "metadata", "proofs", binding_member}:
            return None
        proof = presentation["proofs"][0]
        transcript = json.loads(bytes.fromhex(proof["proof"]))
        signed = transcript["statement"]
        if not ed25519.verify_strict(jcs_bytes(signed), bytes.fromhex(transcript["signature"]),
                                    keri.resolve_current_key(self.issuer.kel)):
            return None
        if proof["proofType"] != signed["predicate"] or proof["publicInputs"]["proof_context"] != signed["context"]:
            return None
        if presentation["metadata"]["context"]["value"] != signed["context"]:
            return None
        apr_content = {key: value for key, value in apr.items() if key != "signature"}
        apr_key = bytes.fromhex(apr["signature"]["verifierKey"])
        if apr_key != request.expected_apr_signer_public_key:
            return None
        if apr_key == SCOPED_APR_KEY:
            # A deterministic scoped-adapter oracle, deliberately no claim of
            # ECDSA/APR signature conformance for this test fixture.
            if jcs_bytes(apr) not in self.scoped_apr_oracle:
                return None
        elif not ed25519.verify_strict(jcs_bytes(apr_content), bytes.fromhex(apr["signature"]["value"]), apr_key):
            return None
        if not apr["issuedAt"] <= self.clock[0] < apr["expiresAt"]:
            return None
        if apr["request"]["requirements"]["context"]["value"] != signed["context"]:
            return None
        if apr["request"]["requirements"]["proofTypes"] != [signed["predicate"]]:
            return None
        handles = {name: int(value, 16) for name, value in signed["handles"].items()}
        predicate = afp.ProvenPredicate(signed["predicate"], signed["predicate"].rsplit("v", 1)[1])
        evidence = afp.ZkcPresentationEvidence(
            flow=request.expected_flow, profile=signed["profile"],
            requested_profile=apr["request"]["presentation"]["profile"],
            presenter_aid=envelope.sender.entity_aid,
            credential_subject_aid=signed["subject"], proven_predicates=(predicate,),
            session_context=envelope.session_context, proof_context=signed["context"],
            apr_verifier_aid=apr["verifierId"], apr_signer_public_key=apr_key,
            scope_policy=apr["request"]["presentation"]["scopePolicy"], rotation_epoch=0,
            scope_id=handles.get("scopeId"),
            presentation_pseudonym=handles.get("presentationPseudonym"),
            holder_commitment=handles.get("holderCommitment"),
            zkc_envelope_version=presentation["version"], zka_bundle_kind=None,
            linkable_consent=apr["request"]["principalConsent"],
            receipt_response=({} if signed["profile"] == afp.ANONYMOUS_PROFILE else handles),
            rotation_binding=({} if signed["profile"] == afp.ANONYMOUS_PROFILE else handles),
            carrier_kind=afp.CREDENTIAL_ENVELOPE_KIND,
        )
        return afp.NativeCredentialVerification(
            envelope.content_hash, evidence,
            afp.ZkcVerifiedPublicStatement(signed["context"], signed["subject"], (predicate,)),
        )

    def build(self, profile=afp.SCOPED_PROFILE, consent=False):
        presentation, apr = self.artifacts(profile, consent)
        return self.a.build_credential_envelope(
            self.fa, presentation=presentation, apr=apr, message_class="credential",
        )

    def sign(self, envelope):
        envelope.sender.signature = self.a.entity.sign(envelope.content_hash.encode()).hex()
        return envelope

    def seal(self, envelope):
        return self.ca.seal(envelope.to_json(), message_class="credential")

    def receive(self, envelope, *, adapter=None, profile=afp.SCOPED_PROFILE, flow=None):
        return self.b.receive_credential_envelope(
            self.fb, self.seal(envelope), message_class="credential", channel=self.cb,
            sender_remote=self.ra, expected_flow=flow or self.flow,
            required_predicates=self.policy(profile),
            credential_verifier=adapter or self.adapter,
        )

    def assert_unaccepted(self):
        self.assertEqual(self.fb.status, afp.AfpSessionStatus.OPEN)
        self.assertFalse(self.b.credential_inbox.get(self.fb.atom.id))
        self.assertFalse(self.b._credential_seen)
        self.assertFalse(self.b._credential_pending)

    def test_scoped_native_exchange_retains_exact_objects_and_activates(self):
        envelope = self.build()
        self.assertEqual(self.fa.status, afp.AfpSessionStatus.OPEN)
        accepted = self.receive(envelope)
        self.assertIs(afp.require_verified_native_credential(accepted), accepted)
        self.assertEqual(accepted.envelope.to_dict(), envelope.to_dict())
        self.assertEqual(accepted.envelope.presentation, envelope.presentation)
        self.assertEqual(accepted.envelope.apr, envelope.apr)
        self.assertEqual(accepted.proven_predicates, (KYC_V2,))
        self.assertEqual(accepted.evidence.carrier_kind, afp.CREDENTIAL_ENVELOPE_KIND)
        self.assertIsNone(accepted.evidence.zka_bundle_kind)
        self.assertEqual(self.fb.status, afp.AfpSessionStatus.ACTIVE)
        self.assertEqual(self.b.inbox.get(self.fb.atom.id, []), [])
        self.assertEqual(self.b.credential_inbox[self.fb.atom.id], [accepted])
        self.assertEqual(self.calls, 1)

    def test_linkable_v1_requires_explicit_consent(self):
        rejected = self.build(afp.LINKABLE_PROFILE, False)
        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(rejected, profile=afp.LINKABLE_PROFILE)
        self.assert_unaccepted()
        accepted = self.receive(self.build(afp.LINKABLE_PROFILE, True), profile=afp.LINKABLE_PROFILE)
        self.assertEqual(accepted.evidence.holder_commitment, 456)
        self.assertIsNone(accepted.evidence.presentation_pseudonym)

    def test_signed_content_replay_in_a_fresh_sealed_frame_is_rejected(self):
        envelope = self.build()
        self.receive(envelope)
        with self.assertRaisesRegex(afp.CredentialEnvelopeError, "replay"):
            self.receive(envelope)
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(self.b.credential_inbox[self.fb.atom.id]), 1)

    def test_inflight_replay_is_reserved_before_adapter(self):
        envelope = self.build()

        def reenter(request):
            with self.assertRaisesRegex(afp.CredentialEnvelopeError, "replay"):
                self.receive(envelope)
            return self.adapter(request)

        self.receive(envelope, adapter=reenter)
        self.assertEqual(self.calls, 1)

    def test_resolver_reentry_is_reserved_and_resolver_request_is_immutable(self):
        envelope = self.build()

        def mutate(request):
            result = self.resolve_apr_signer(request)
            object.__setattr__(request, "expected_session_ref", "other")
            return result

        self.b._apr_signer_binding_resolver = mutate
        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(envelope)
        self.assert_unaccepted()

        def reenter(request):
            with self.assertRaisesRegex(afp.CredentialEnvelopeError, "replay"):
                self.receive(envelope)
            return self.resolve_apr_signer(request)

        self.b._apr_signer_binding_resolver = reenter
        self.receive(envelope)
        self.assertEqual(self.calls, 1)

    def test_send_publishes_only_sealed_bytes_and_does_not_need_a_zka_verifier(self):
        presentation, apr = self.artifacts()
        envelope = self.a.send_credential_envelope(
            self.fa, presentation=presentation, apr=apr, message_class="credential",
            channel=self.ca,
        )
        self.assertEqual(self.fa.status, afp.AfpSessionStatus.OPEN)
        subject, sealed = self.transport.published[-1]
        self.assertTrue(subject.endswith(".work.credential"))
        self.assertNotIn(presentation["proofs"][0]["proof"].encode(), sealed)
        accepted = self.b.receive_credential_envelope(
            self.fb, sealed, message_class="credential", channel=self.cb,
            sender_remote=self.ra, expected_flow=self.flow,
            required_predicates=self.policy(), credential_verifier=self.adapter,
        )
        self.assertEqual(accepted.envelope.to_dict(), envelope.to_dict())

    def test_nested_native_float_types_are_retained_for_lower_verifier(self):
        envelope = self.build()
        envelope.apr["issuedAt"] = float(NOW)
        self.sign(envelope)
        decoded = afp.AfpCredentialEnvelope.from_json(envelope.to_json())
        self.assertIs(type(decoded.apr["issuedAt"]), float)

        def reject_native_float(request):
            self.assertIs(type(request.envelope.apr["issuedAt"]), float)
            return None

        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(envelope, adapter=reject_native_float)
        self.assert_unaccepted()

    def test_scoped_key_binding_is_required_and_not_an_unsigned_label(self):
        envelope = self.build()
        self.b._apr_signer_binding_resolver = None
        with self.assertRaisesRegex(afp.CredentialEnvelopeError, "SEC1"):
            self.receive(envelope)
        for callback in (
            lambda request: True,
            lambda request: None,
            lambda request: afp.NativeAprSignerBinding(SCOPED_APR_KEY, "other", request.expected_kel_event_dig),
            lambda request: afp.NativeAprSignerBinding(SCOPED_APR_KEY, request.expected_verifier_aid, "old"),
            lambda request: afp.NativeAprSignerBinding(b"bad", request.expected_verifier_aid, request.expected_kel_event_dig),
        ):
            with self.subTest(callback=callback):
                self.b._apr_signer_binding_resolver = callback
                with self.assertRaises(afp.CredentialEnvelopeError):
                    self.receive(envelope)
                self.assertEqual(self.calls, 0)
                self.assert_unaccepted()

    def test_anonymous_bilateral_uses_native_v2_without_sec1_key(self):
        self.flow = afp.AfpTrustFlow.BILATERAL
        self.b._apr_signer_binding_resolver = None
        envelope = self.build(afp.ANONYMOUS_PROFILE)
        accepted = self.receive(envelope, profile=afp.ANONYMOUS_PROFILE)
        self.assertEqual(accepted.evidence.profile, afp.ANONYMOUS_PROFILE)
        self.assertEqual(accepted.evidence.scope_id, 0)
        self.assertNotIn("holderBinding", accepted.envelope.presentation)

    def test_outer_binding_failures_precede_native_crypto(self):
        changes = {
            "session": lambda e: setattr(e, "session_ref", "other"),
            "context": lambda e: setattr(e, "session_context", "X_" + "12" * 32),
            "profile": lambda e: setattr(e, "profile", "pay"),
            "class": lambda e: setattr(e, "message_class", "other"),
            "future": lambda e: setattr(e, "generated_at", NOW + 1),
            "expired": lambda e: setattr(e, "expires_at", NOW),
            "session-expiry": lambda e: setattr(e, "expires_at", self.fb.atom.expires_at_seconds + 1),
            "identity": lambda e: setattr(e.sender, "entity_aid", self.b.entity_aid),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                envelope = self.build()
                change(envelope)
                self.sign(envelope)
                with self.assertRaises((afp.CredentialEnvelopeError, afp.IdentityBindingError)):
                    self.receive(envelope)
                self.assertEqual(self.calls, 0)
                self.assert_unaccepted()

    def test_unsigned_carrier_and_apr_are_rejected_before_adapter(self):
        for target in ("carrier", "apr"):
            with self.subTest(target=target):
                envelope = self.build()
                if target == "carrier":
                    envelope.sender.signature = ""
                else:
                    envelope.apr.pop("signature")
                    self.sign(envelope)
                with self.assertRaises(afp.CredentialEnvelopeError):
                    self.receive(envelope)
                self.assertEqual(self.calls, 0)
                self.assert_unaccepted()

    def test_noncanonical_signature_spellings_fail_without_resigning(self):
        for spelling in (lambda value: value.upper(), lambda value: value + " "):
            envelope = self.build()
            original_hash = envelope.content_hash
            envelope.sender.signature = spelling(envelope.sender.signature)
            self.assertEqual(envelope.content_hash, original_hash)
            with self.assertRaises(afp.CredentialEnvelopeError):
                self.receive(envelope)
            self.assertEqual(self.calls, 0)
            self.assert_unaccepted()

    def test_payload_tampering_and_wrong_authenticated_subject_fail(self):
        for field, value, resign_proof in (
            ("subject", self.b.entity_aid, False),
            ("subject", self.b.entity_aid, True),
            ("context", "0x" + "12" * 32, True),
            ("predicate", "zkc:proof:jurisdiction:v2", True),
        ):
            with self.subTest(field=field, authenticated=resign_proof):
                envelope = self.build()
                proof = envelope.presentation["proofs"][0]
                transcript = json.loads(bytes.fromhex(proof["proof"]))
                transcript["statement"][field] = value
                if resign_proof:
                    transcript["signature"] = self.issuer.sign(jcs_bytes(transcript["statement"])).hex()
                proof["proof"] = jcs_bytes(transcript).hex()
                self.sign(envelope)
                with self.assertRaises(afp.CredentialEnvelopeError):
                    self.receive(envelope)
                self.assert_unaccepted()

    def test_wrong_purpose_apr_and_claimed_meaning_fail(self):
        envelope = self.build()
        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(envelope, flow=afp.AfpTrustFlow.BILATERAL)
        self.assert_unaccepted()
        envelope.apr["request"]["requirements"]["context"]["value"] = "other"
        self.sign(envelope)
        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(envelope)
        self.assert_unaccepted()

        def wrong_meaning(request):
            result = self.adapter(request)
            return replace(result, statement=replace(result.statement, proven_predicates=(
                afp.ProvenPredicate("zkc:proof:jurisdiction:v2", "2"),
            )))

        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(self.build(), adapter=wrong_meaning)
        self.assert_unaccepted()

    def test_closed_wire_and_json_failures_do_not_reach_adapter(self):
        envelope = self.build()
        base = envelope.to_dict()
        malformed = []
        for field in ("kind", "apr", "sender", "presentation"):
            value = dict(base)
            value.pop(field)
            malformed.append(jcs_bytes(value))
        malformed.extend([
            jcs_bytes(dict(base, extra=True)),
            envelope.to_json().replace(b'"kind":', b'"kind":"duplicate","kind":', 1),
            envelope.to_json().replace(str(NOW).encode(), b"NaN", 1),
            jcs_bytes(dict(base, generated_at=True)),
            jcs_bytes(dict(base, presentation={"version": "zkc:proof:v3"})),
            jcs_bytes(dict(base, sender=dict(base["sender"], extra=True))),
        ])
        for raw in malformed:
            with self.subTest(raw=raw[:40]):
                sealed = self.ca.seal(raw, message_class="credential")
                with self.assertRaises(afp.CredentialEnvelopeError):
                    self.b.receive_credential_envelope(
                        self.fb, sealed, message_class="credential", channel=self.cb,
                        sender_remote=self.ra, expected_flow=self.flow,
                        required_predicates=self.policy(), credential_verifier=self.adapter,
                    )
                self.assertEqual(self.calls, 0)
                self.assert_unaccepted()

    def test_plaintext_and_wrong_channel_message_class_are_rejected(self):
        envelope = self.build()
        for payload, message_class in ((envelope.to_json(), "credential"),
                                       (self.seal(envelope), "other")):
            with self.assertRaises(afp.ChannelError):
                self.b.receive_credential_envelope(
                    self.fb, payload, message_class=message_class, channel=self.cb,
                    sender_remote=self.ra, expected_flow=self.flow,
                    required_predicates=self.policy(), credential_verifier=self.adapter,
                )
        self.assertEqual(self.calls, 0)
        self.assert_unaccepted()

    def test_exceptions_booleans_and_substituted_result_fail_without_leaks(self):
        def raises(_request):
            raise RuntimeError("private issuer witness material")

        def wrong_hash(request):
            return replace(self.adapter(request), envelope_content_hash="other")

        for callback in (raises, lambda request: True, lambda request: None, wrong_hash):
            with self.subTest(callback=callback):
                with self.assertRaises(afp.CredentialEnvelopeError) as caught:
                    self.receive(self.build(), adapter=callback)
                self.assertNotIn("private issuer", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assert_unaccepted()
        # Rejection releases application replay reservation for a corrected
        # adapter retry over a fresh authenticated frame.
        self.receive(self.build())

    def test_callback_cannot_relabel_request_or_carrier(self):
        def mutate_request(request):
            result = self.adapter(request)
            object.__setattr__(request, "expected_flow", afp.AfpTrustFlow.BILATERAL)
            return result

        def wrong_carrier(request):
            result = self.adapter(request)
            object.__setattr__(result.evidence, "carrier_kind", "zka:bundle:v1")
            object.__setattr__(result.evidence, "zka_bundle_kind", "zka:bundle:v1")
            return result

        for callback in (mutate_request, wrong_carrier):
            with self.assertRaises(afp.CredentialEnvelopeError):
                self.receive(self.build(), adapter=callback)
            self.assert_unaccepted()

    def test_callback_abort_and_expiry_prevent_acceptance(self):
        def abort(request):
            result = self.adapter(request)
            self.fb.abort()
            return result

        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(self.build(), adapter=abort)
        self.assertEqual(self.fb.status, afp.AfpSessionStatus.ABORTED)
        self.assertFalse(self.b.credential_inbox.get(self.fb.atom.id))
        self.assertFalse(self.b._credential_seen)

    def test_callback_expiry_prevents_acceptance(self):
        envelope = self.build()

        def expire(request):
            result = self.adapter(request)
            self.clock[0] = envelope.expires_at
            return result

        with self.assertRaises(afp.CredentialEnvelopeError):
            self.receive(envelope, adapter=expire)
        self.assertFalse(self.b.credential_inbox.get(self.fb.atom.id))
        self.assertFalse(self.b._credential_seen)

    def retained_kel_updates(self):
        updates = []
        for name, instance in (("sender", self.a), ("verifier", self.b)):
            rotated = copy.deepcopy(instance.entity)
            rotated.rotate()
            updates.append((name + " rotation", rotated.kel, rotated._delegator.kel))
            revoked = copy.deepcopy(instance.tenant)
            revoked.revoke_delegation(instance.entity_aid, instance.entity.kel.events[0].digest)
            updates.append((name + " revocation", revoked.kel, None))
        return updates

    def isolated_retained_stores(self):
        self.addCleanup(setattr, self.b, "kel_state", self.b.kel_state)
        self.addCleanup(setattr, self.ra, "kel_state", self.ra.kel_state)
        self.b.kel_state = keri.KelStateStore()
        self.ra.kel_state = keri.KelStateStore()
        return (("receiver", self.b.kel_state), ("remote", self.ra.kel_state))

    def test_retained_kel_advance_during_callbacks_prevents_acceptance(self):
        updates = self.retained_kel_updates()
        for boundary in ("resolver", "proof"):
            for store_name in ("receiver", "remote"):
                for label, kel, tenant_kel in updates:
                    with self.subTest(boundary=boundary, store=store_name, update=label):
                        stores = dict(self.isolated_retained_stores())
                        store = stores[store_name]
                        envelope = self.build()
                        learned = []

                        def learn():
                            keri.verify_kel(kel, tenant_kel=tenant_kel, witness_keys={}, first_seen=store)
                            learned.append(True)

                        def resolve(request):
                            result = self.resolve_apr_signer(request)
                            if boundary == "resolver":
                                learn()
                            return result

                        def prove(request):
                            result = self.adapter(request)
                            if boundary == "proof":
                                learn()
                            return result

                        self.b._apr_signer_binding_resolver = resolve
                        with self.assertRaises(afp.CredentialEnvelopeError):
                            self.receive(envelope, adapter=prove)
                        self.assertEqual(learned, [True])
                        self.assert_unaccepted()

    def test_receive_capability_rejects_newer_retained_kel_state(self):
        accepted = self.receive(self.build())
        for store_name in ("receiver", "remote"):
            for label, kel, tenant_kel in self.retained_kel_updates():
                with self.subTest(store=store_name, update=label):
                    store = dict(self.isolated_retained_stores())[store_name]
                    keri.verify_kel(kel, tenant_kel=tenant_kel, witness_keys={}, first_seen=store)
                    with self.assertRaises(afp.CredentialEnvelopeError):
                        afp.require_verified_native_credential(accepted)
                    self.assertEqual(self.b.credential_inbox[self.fb.atom.id], [accepted])
                    self.assertEqual(len(self.b._credential_seen), 1)

    def test_unrelated_retained_kel_progress_preserves_acceptance(self):
        stores = self.isolated_retained_stores()
        unrelated = keri.Identity.incept_tenant()

        def prove(request):
            result = self.adapter(request)
            for _, store in stores:
                keri.verify_kel(unrelated.kel, witness_keys={}, first_seen=store)
            return result

        accepted = self.receive(self.build(), adapter=prove)
        self.assertIs(afp.require_verified_native_credential(accepted), accepted)
        for _, store in stores:
            self.assertEqual(store.accepted_length(unrelated.aid), 1)
            # Currency checking must not authenticate or retain unseen local KELs.
            self.assertEqual(store.accepted_length(self.b.entity_aid), 0)

    def test_closing_channel_in_either_callback_prevents_acceptance(self):
        for boundary in ("resolver", "proof"):
            with self.subTest(boundary=boundary):
                # Closing wipes channel keys, so use fresh test-owned channels
                # instead of the shared class fixture's authenticated pair.
                self.ca, self.cb = establish_channels(
                    self.a, self.b, self.ra, self.rb, self.fa.atom,
                )
                envelope = self.build()

                def close_resolver(request):
                    result = self.resolve_apr_signer(request)
                    if boundary == "resolver":
                        self.cb.close()
                    return result

                def close_proof(request):
                    result = self.adapter(request)
                    if boundary == "proof":
                        self.cb.close()
                    return result

                self.b._apr_signer_binding_resolver = close_resolver
                with self.assertRaisesRegex(afp.CredentialEnvelopeError, "channel closed"):
                    self.receive(envelope, adapter=close_proof)
                self.assert_unaccepted()

    def test_receive_capability_rejects_forgery_mutation_and_closed_session(self):
        with self.assertRaises(afp.CredentialEnvelopeError):
            afp.AcceptedCredentialEnvelope(None, b"", None, None, None, "")
        with self.assertRaises(afp.CredentialEnvelopeError):
            afp.require_verified_native_credential(object.__new__(afp.AcceptedCredentialEnvelope))
        accepted = self.receive(self.build())
        detached = accepted.envelope
        detached.presentation["proofs"][0]["proof"] = "changed"
        self.assertNotEqual(accepted.envelope.presentation["proofs"][0]["proof"], "changed")
        original = accepted._evidence
        object.__setattr__(accepted, "_evidence", replace(original, credential_subject_aid=self.b.entity_aid))
        with self.assertRaises(afp.CredentialEnvelopeError):
            afp.require_verified_native_credential(accepted)
        object.__setattr__(accepted, "_evidence", original)
        self.fb.abort()
        with self.assertRaises(afp.CredentialEnvelopeError):
            afp.require_verified_native_credential(accepted)

    def test_substantive_zka_rule_unchanged_for_both_bundle_forms(self):
        called = []
        lightweight = afp.ZkaBundle(
            kind="zka:bundle:v1",
            context=afp.session_context_field(self.fa.atom.session_context),
            compliance_proofs=["native-is-not-a-substantive-bundle"],
        )
        with self.assertRaisesRegex(afp.BundleError, "EMPTY_BUNDLE"):
            afp.verify_bundle(lightweight, expected_session_context=self.fa.atom.session_context,
                              bundle_verifier=lambda bundle: called.append(bundle))
        self.assertFalse(called)
        canonical = afp.ZkaBundle.from_canonical_payload({
            "metadata": {"version": "zka:bundle:v1", "generatedAt": "2023-11-14T22:13:20Z",
                         "expiresAt": "2023-11-14T22:23:20Z",
                         "context": afp.session_context_field(self.fa.atom.session_context)},
            "compliance": {"proofs": [self.artifacts()[0]]},
        })
        with self.assertRaisesRegex(afp.BundleError, "EMPTY_BUNDLE"):
            afp.verify_bundle(canonical, expected_session_context=self.fa.atom.session_context,
                              bundle_verifier=lambda bundle: called.append(bundle))
        self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
