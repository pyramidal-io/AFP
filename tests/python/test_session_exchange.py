"""Session establishment + envelope exchange integration tests (§12.3 / §12.7)."""

import _path  # noqa: F401

import json
from pathlib import Path
import unittest

import afp_session as afp
from afp_session import keri
from afp_session.atoms import AfpSessionAtom, AfpSessionStatus
from afp_session.canonical import canonical_bytes
from fixtures import establish_channels, make_pair


CONFORMANCE_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "afp_opened_at_conformance_v1.json"
)
CONFORMANCE = json.loads(CONFORMANCE_PATH.read_text(encoding="utf-8"))


def _bundle(ctx, **kw):
    kw.setdefault("coord_proof", "opaque")
    return afp.ZkaBundle(
        kind="zka:bundle:v1",
        context=afp.session_context_field(ctx),
        **kw,
    )


def _accept_bundle(bundle):
    return afp.BundleVerificationResult.accepted(bundle)


class EstablishmentTest(unittest.TestCase):
    def test_propose_normalizes_local_clock_to_a_whole_unix_second(self):
        """A local clock is floored before its value becomes signed wire data."""
        transport, A, B, _, rB = make_pair()
        initiator = afp.Instance(
            tenant=A.tenant,
            entity=A.entity,
            transport=transport,
            clock=lambda: 1_700_000_000.75,
        )

        fsm = initiator.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )

        self.assertEqual(fsm.atom.opened_at, 1_700_000_000)

    def test_propose_preserves_each_published_integer_value_exactly_on_the_wire(self):
        """A JSON number must survive proposer, serializer, and parser byte-for-byte."""
        for vector in CONFORMANCE["accepted"]:
            with self.subTest(vector=vector["name"]):
                transport, A, B, _, rB = make_pair()
                initiator = afp.Instance(
                    tenant=A.tenant,
                    entity=A.entity,
                    transport=transport,
                    clock=lambda value=vector["opened_at"]: value,
                )
                propose = lambda: initiator.propose(
                    responder_tenant_aid=B.tenant_aid,
                    responder_entity_aid=B.entity_aid,
                    agreement_ref="agr",
                    agreement_version="1",
                    profile="work",
                    profile_policy_hash="h",
                    responder_remote=rB,
                )
                if vector["opened_at"] == afp.MAX_OPENED_AT:
                    # §12.2.1: no in-range expires_at can follow the last second.
                    with self.assertRaisesRegex(afp.SessionError, "expires_at"):
                        propose()
                    continue
                proposed = propose()

                wire = proposed.atom.to_dict()
                self.assertIs(type(wire["opened_at"]), int)
                self.assertEqual(wire["opened_at"], vector["opened_at"])
                wire_text = json.dumps(wire, sort_keys=True, separators=(",", ":"))
                restored = AfpSessionAtom.from_json(wire_text)
                self.assertEqual(restored.opened_at, vector["opened_at"])

    def test_propose_rejects_out_of_range_local_clock_values(self):
        for vector in CONFORMANCE["rejected"]:
            if vector.get("reason") not in {
                "negative",
                "out-of-range",
                "out-of-range-and-outside-safe-integer-range",
            }:
                continue
            with self.subTest(vector=vector["name"]):
                transport, A, B, _, rB = make_pair()
                initiator = afp.Instance(
                    tenant=A.tenant,
                    entity=A.entity,
                    transport=transport,
                    clock=lambda value=vector["opened_at"]: value,
                )
                with self.assertRaisesRegex(ValueError, "opened_at"):
                    initiator.propose(
                        responder_tenant_aid=B.tenant_aid,
                        responder_entity_aid=B.entity_aid,
                        agreement_ref="agr",
                        agreement_version="1",
                        profile="work",
                        profile_policy_hash="h",
                        responder_remote=rB,
                    )

    def test_proposal_round_trips_with_an_unsigned_responder_binding(self):
        _, A, B, rA, rB = make_pair()
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )

        wire = proposed.atom.to_dict()
        self.assertEqual(wire["responder"]["tenant_aid"], B.tenant_aid)
        self.assertEqual(wire["responder"]["entity_aid"], B.entity_aid)
        self.assertEqual(wire["responder"]["signature"], "")
        restored = AfpSessionAtom.from_dict(wire)
        self.assertEqual(restored.content_hash, proposed.atom.content_hash)

        accepted = B.accept(restored, initiator_remote=rA)
        self.assertEqual(accepted.status, AfpSessionStatus.OPEN)
        self.assertTrue(accepted.atom.responder.signature)
        A.confirm_open(proposed, accepted.atom, responder_remote=rB)
        self.assertEqual(proposed.status, AfpSessionStatus.OPEN)

    def test_session_atom_rejects_a_null_responder_wire_value(self):
        _, A, B, _, rB = make_pair()
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        wire = proposed.atom.to_dict()
        wire["responder"] = None

        with self.assertRaisesRegex(ValueError, "responder party ref is required"):
            AfpSessionAtom.from_dict(wire)

    def test_accept_normalizes_a_malformed_direct_proposal_to_session_error(self):
        _, A, B, rA, rB = make_pair()
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        proposed.atom.responder = None

        with self.assertRaisesRegex(afp.SessionError, "proposal session atom is malformed"):
            B.accept(proposed.atom, initiator_remote=rA)

    def test_proposal_responder_binding_is_committed_by_the_signed_context(self):
        transport, A, B, rA, rB = make_pair()
        tenant_c = keri.Identity.incept_tenant()
        entity_c = keri.Identity.incept_entity(tenant_c)
        C = afp.Instance(tenant=tenant_c, entity=entity_c, transport=transport)
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        original_content_hash = proposed.atom.content_hash
        original_signature = proposed.atom.initiator.signature
        proposed.atom.responder.tenant_aid = tenant_c.aid
        proposed.atom.responder.entity_aid = entity_c.aid
        proposed.atom.responder.kel_event_dig = entity_c.kel.latest_dig
        self.assertEqual(proposed.atom.content_hash, original_content_hash)
        self.assertEqual(proposed.atom.initiator.signature, original_signature)

        with self.assertRaisesRegex(afp.SessionError, "does not recompute"):
            C.accept(proposed.atom, initiator_remote=rA)

    def test_wrong_responder_cannot_accept_a_proposal(self):
        transport, A, B, rA, rB = make_pair()
        tenant_c = keri.Identity.incept_tenant()
        entity_c = keri.Identity.incept_entity(tenant_c)
        C = afp.Instance(tenant=tenant_c, entity=entity_c, transport=transport)
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )

        with self.assertRaisesRegex(afp.SessionError, "responder binding"):
            C.accept(proposed.atom, initiator_remote=rA)

    def test_accept_requires_the_exact_empty_responder_signature_sentinel(self):
        _, A, B, rA, rB = make_pair()
        for malformed in (None, 0, [], {}, "00"):
            with self.subTest(malformed=malformed):
                proposed = A.propose(
                    responder_tenant_aid=B.tenant_aid,
                    responder_entity_aid=B.entity_aid,
                    agreement_ref="agr",
                    agreement_version="1",
                    profile="work",
                    profile_policy_hash="h",
                    responder_remote=rB,
                )
                proposed.atom.responder.signature = malformed

                with self.assertRaisesRegex(afp.SessionError, "exactly empty"):
                    B.accept(proposed.atom, initiator_remote=rA)

    def test_accept_rejects_a_proposal_with_closed_at(self):
        _, A, B, rA, rB = make_pair()
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        proposed.atom.closed_at = afp.unix_to_session_datetime(proposed.atom.opened_at)

        with self.assertRaisesRegex(afp.SessionError, "carries closed_at"):
            B.accept(proposed.atom, initiator_remote=rA)

    def test_propose_requires_explicit_responder_witness_material(self):
        _, A, B, _, rB = make_pair(witnessed=True)
        remote_without_witnesses = afp.RemoteParty(
            rB.entity_kel, rB.tenant_kel, witness_keys=None
        )

        with self.assertRaisesRegex(afp.IdentityBindingError, "witness key material"):
            A.propose(
                responder_tenant_aid=B.tenant_aid,
                responder_entity_aid=B.entity_aid,
                agreement_ref="agr",
                agreement_version="1",
                profile="work",
                profile_policy_hash="h",
                responder_remote=remote_without_witnesses,
            )

    def test_accept_requires_explicit_initiator_witness_material(self):
        _, A, B, rA, rB = make_pair(witnessed=True)
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        remote_without_witnesses = afp.RemoteParty(
            rA.entity_kel, rA.tenant_kel, witness_keys=None
        )

        with self.assertRaisesRegex(afp.IdentityBindingError, "witness key material"):
            B.accept(proposed.atom, initiator_remote=remote_without_witnesses)

    def test_confirm_open_rejects_a_changed_echoed_initiator_signature(self):
        _, A, B, rA, rB = make_pair()
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        accepted = B.accept(proposed.atom, initiator_remote=rA)
        accepted.atom.initiator.signature = ""

        with self.assertRaisesRegex(afp.SessionError, "initiator party reference"):
            A.confirm_open(proposed, accepted.atom, responder_remote=rB)

    def test_confirm_open_normalizes_a_malformed_direct_atom_to_session_error(self):
        _, A, B, rA, rB = make_pair()
        proposed = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        accepted = B.accept(proposed.atom, initiator_remote=rA)
        accepted.atom.responder = None

        with self.assertRaisesRegex(afp.SessionError, "accepted session atom is malformed"):
            A.confirm_open(proposed, accepted.atom, responder_remote=rB)

    def test_open_with_witnessed_identities(self):
        _, A, B, rA, rB = make_pair(witnessed=True)
        fsm_a = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        fsm_b = B.accept(fsm_a.atom, initiator_remote=rA)
        A.confirm_open(fsm_a, fsm_b.atom, responder_remote=rB)
        self.assertEqual(fsm_a.status, AfpSessionStatus.OPEN)
        self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)

    def test_accept_rejects_forged_initiator_signature(self):
        _, A, B, rA, rB = make_pair()
        fsm_a = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        # Forge the initiator signature.
        sig = bytearray(bytes.fromhex(fsm_a.atom.initiator.signature))
        sig[0] ^= 0x01
        fsm_a.atom.initiator.signature = bytes(sig).hex()
        with self.assertRaises(afp.IdentityBindingError):
            B.accept(fsm_a.atom, initiator_remote=rA)

    def test_accept_rejects_identity_mismatch(self):
        _, A, B, rA, rB = make_pair()
        # A third identity whose KEL does not match A's party ref.
        impostor_tenant = keri.Identity.incept_tenant()
        impostor_entity = keri.Identity.incept_entity(impostor_tenant)
        wrong_remote = afp.RemoteParty(
            impostor_entity.kel, impostor_tenant.kel, witness_keys={}
        )
        fsm_a = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        with self.assertRaises(afp.IdentityBindingError):
            B.accept(fsm_a.atom, initiator_remote=wrong_remote)

    def test_accept_rejects_validly_signed_nonrecomputing_context(self):
        """A signature cannot authorize a context that differs from §5.2's derivation."""
        _, A, B, rA, rB = make_pair()
        fsm_a = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        fsm_a.atom.session_context = "X_" + "01" * 32
        fsm_a.atom.initiator.signature = A.entity.sign(
            fsm_a.atom.content_hash.encode("utf-8")
        ).hex()

        with self.assertRaisesRegex(afp.SessionError, "does not recompute"):
            B.accept(fsm_a.atom, initiator_remote=rA)


class ExchangeTest(unittest.TestCase):
    def _open(self):
        transport, A, B, rA, rB = make_pair()
        fsm_a = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        fsm_b = B.accept(fsm_a.atom, initiator_remote=rA)
        A.confirm_open(fsm_a, fsm_b.atom, responder_remote=rB)
        a_channel, b_channel = establish_channels(A, B, rA, rB, fsm_a.atom)
        return transport, A, B, rA, rB, fsm_a, fsm_b, a_channel, b_channel

    def test_bidirectional_exchange(self):
        transport, A, B, rA, rB, fsm_a, fsm_b, a_channel, b_channel = self._open()
        ctx = fsm_a.atom.session_context
        A.send_envelope(
            fsm_a, bundle=_bundle(ctx), message_class="request", channel=a_channel
        )
        B.receive_envelope(
            fsm_b,
            transport.published[-1][1],
            message_class="request",
            channel=b_channel,
            sender_remote=rA,
            bundle_verifier=_accept_bundle,
        )
        B.send_envelope(
            fsm_b, bundle=_bundle(ctx), message_class="result", channel=b_channel
        )
        A.receive_envelope(
            fsm_a,
            transport.published[-1][1],
            message_class="result",
            channel=a_channel,
            sender_remote=rB,
            bundle_verifier=_accept_bundle,
        )
        self.assertEqual(len(A.inbox[fsm_a.atom.id]), 1)
        self.assertEqual(len(B.inbox[fsm_b.atom.id]), 1)

    def test_envelope_wrong_session_context_rejected(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a,
            bundle=_bundle(fsm_a.atom.session_context),
            message_class="result",
        )
        env.session_context = "X_" + "11" * 32  # replay to another session
        with self.assertRaisesRegex(
            afp.EnvelopeError, "session_context does not match the live session"
        ):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )

    def test_envelope_bundle_context_mismatch_rejected(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        # Bundle context must equal the field projection of session_context (§12.7).
        env = A.build_envelope(
            fsm_a,
            bundle=afp.ZkaBundle(
                kind="zka:bundle:v1",
                context="0x" + "11" * 32,
                coord_proof="opaque",
            ),
            message_class="result",
        )
        with self.assertRaisesRegex(
            afp.BundleError, "canonical BN254 projection"
        ):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )

    def test_envelope_profile_mismatch_rejected(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a,
            bundle=_bundle(fsm_a.atom.session_context),
            message_class="result",
        )
        env.profile = "vxp"
        with self.assertRaisesRegex(
            afp.EnvelopeError, "envelope profile does not match the session profile"
        ):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )

    def test_empty_bundle_rejected(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        bundle = afp.ZkaBundle(
            kind="zka:bundle:v1",
            context=afp.session_context_field(
                fsm_a.atom.session_context
            ),
        )
        env = A.build_envelope(fsm_a, bundle=bundle, message_class="result")
        with self.assertRaisesRegex(afp.BundleError, "bundle carries no proofs"):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )

    def test_transaction_less_bundle_needs_coord_proof(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        # compliance-only, no transaction and no coord_proof -> non-conforming.
        bundle = afp.ZkaBundle(
            kind="zka:bundle:v1",
            context=afp.session_context_field(
                fsm_a.atom.session_context
            ),
            compliance_proofs=["x"],
        )
        env = A.build_envelope(fsm_a, bundle=bundle, message_class="result")
        with self.assertRaisesRegex(
            afp.BundleError, "transaction-less bundle MUST carry a coord_proof"
        ):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )
        self.assertIs(fsm_b.status, AfpSessionStatus.OPEN)
        self.assertNotIn(fsm_b.atom.id, B.inbox)

    def test_envelope_bundle_version_mismatch_is_rejected_without_activation(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a, bundle=_bundle(fsm_a.atom.session_context), message_class="result"
        )
        env.bundle_version = "zka:bundle:v0"

        with self.assertRaises(afp.EnvelopeError):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(
                    canonical_bytes(env.to_dict()), message_class="result"
                ),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )

        self.assertIs(fsm_b.status, AfpSessionStatus.OPEN)
        self.assertNotIn(fsm_b.atom.id, B.inbox)

    def test_bundle_verifier_seam_invoked(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a,
            bundle=_bundle(fsm_a.atom.session_context),
            message_class="result",
        )
        frame = a_channel.seal(
            canonical_bytes(env.to_dict()), message_class="result"
        )
        seen_contexts = []

        def rejecting_zka_verifier(bundle):
            seen_contexts.append(bundle.context)
            return afp.BundleVerificationResult.rejected(bundle)

        # A rejecting ZKA verifier seam must cause rejection (§12.7 ZKA layer),
        # and the callback sees ZKA's field value rather than AFP's X_ wire atom.
        with self.assertRaisesRegex(
            afp.BundleError, "ZKA bundle verifier rejected the bundle proofs"
        ):
            B.receive_envelope(
                fsm_b,
                frame,
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=rejecting_zka_verifier,
            )
        self.assertEqual(
            seen_contexts,
            [afp.session_context_field(fsm_a.atom.session_context)],
        )
        self.assertTrue(seen_contexts[0].startswith("0x"))

    def test_envelope_round_trips_through_serialization(self):
        transport, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.send_envelope(
            fsm_a,
            bundle=_bundle(fsm_a.atom.session_context),
            message_class="result",
            channel=a_channel,
        )
        restored = afp.AfpEnvelope.from_dict(env.to_dict())
        self.assertEqual(restored.content_hash, env.content_hash)
        received = B.receive_envelope(
            fsm_b,
            transport.published[-1][1],
            message_class="result",
            channel=b_channel,
            sender_remote=rA,
            bundle_verifier=_accept_bundle,
        )
        self.assertEqual(received.content_hash, restored.content_hash)

    def test_receive_envelope_none_verifier_fails_closed(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a, bundle=_bundle(fsm_a.atom.session_context), message_class="result"
        )
        with self.assertRaisesRegex(
            afp.BundleError, "no ZKA bundle verifier supplied"
        ):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=None,
            )

    def test_verify_bundle_none_verifier_fails_closed(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()
        bundle = _bundle(fsm_a.atom.session_context)
        with self.assertRaisesRegex(
            afp.BundleError, "no ZKA bundle verifier supplied"
        ):
            afp.verify_bundle(
                bundle,
                expected_session_context=fsm_a.atom.session_context,
                bundle_verifier=None,
            )

    def test_verify_bundle_rejects_bool_and_truthy_non_result(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()
        bundle = _bundle(fsm_a.atom.session_context)

        class TruthyResult:
            def __bool__(self):
                return True

        for result in (True, TruthyResult()):
            with self.subTest(result=type(result).__name__), self.assertRaisesRegex(
                afp.BundleError, "exact BundleVerificationResult"
            ):
                afp.verify_bundle(
                    bundle,
                    expected_session_context=fsm_a.atom.session_context,
                    bundle_verifier=lambda _bundle, value=result: value,
                )

    def test_verify_bundle_rejects_equality_spoofed_kind_before_verifier(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()

        class EqualitySpoofedKind(str):
            def __ne__(self, _other):
                return False

        bundle = _bundle(fsm_a.atom.session_context)
        bundle.kind = EqualitySpoofedKind("zka:bundle:v0")
        verifier_called = False

        def verifier(candidate):
            nonlocal verifier_called
            verifier_called = True
            return afp.BundleVerificationResult.accepted(candidate)

        with self.assertRaisesRegex(afp.BundleError, "bundle kind must be"):
            afp.verify_bundle(
                bundle,
                expected_session_context=fsm_a.atom.session_context,
                bundle_verifier=verifier,
            )
        self.assertFalse(verifier_called)

    def test_verify_bundle_rejects_subclass_and_lookalike_before_field_access(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()

        class BundleSubclass(afp.ZkaBundle):
            pass

        class BundleLookalike:
            @property
            def kind(self):
                raise AssertionError("lookalike fields must not be accessed")

        honest = _bundle(fsm_a.atom.session_context)
        subclass = BundleSubclass(**honest.to_dict())
        for candidate in (subclass, BundleLookalike()):
            with self.subTest(candidate=type(candidate).__name__), self.assertRaisesRegex(
                afp.BundleError, "exact ZkaBundle"
            ):
                afp.verify_bundle(
                    candidate,
                    expected_session_context=fsm_a.atom.session_context,
                    bundle_verifier=lambda _bundle: self.fail(
                        "verifier must not run for an invalid bundle container"
                    ),
                )

    def test_verify_bundle_accepts_exact_bundle_and_content_bound_receipt(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()
        bundle = _bundle(fsm_a.atom.session_context)
        seen = []

        def verifier(candidate):
            seen.append(candidate)
            return afp.BundleVerificationResult.accepted(candidate)

        afp.verify_bundle(
            bundle,
            expected_session_context=fsm_a.atom.session_context,
            bundle_verifier=verifier,
        )
        self.assertEqual(seen, [bundle])

    def test_verify_bundle_rejects_callback_mutation(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()
        bundle = _bundle(fsm_a.atom.session_context)
        original_hash = bundle.content_hash

        def mutating_verifier(candidate):
            candidate.coord_proof = None
            return afp.BundleVerificationResult(
                bundle_content_hash=original_hash,
                verified=True,
            )

        with self.assertRaisesRegex(afp.BundleError, "mutated the bundle"):
            afp.verify_bundle(
                bundle,
                expected_session_context=fsm_a.atom.session_context,
                bundle_verifier=mutating_verifier,
            )

    def test_verify_bundle_rejects_result_bound_to_another_bundle(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()
        bundle = _bundle(fsm_a.atom.session_context)
        other = _bundle(fsm_a.atom.session_context, coord_proof="different-proof")

        with self.assertRaisesRegex(afp.BundleError, "bound to a different bundle"):
            afp.verify_bundle(
                bundle,
                expected_session_context=fsm_a.atom.session_context,
                bundle_verifier=lambda _bundle: (
                    afp.BundleVerificationResult.accepted(other)
                ),
            )

    def test_verify_bundle_rejects_nested_callback_mutation(self):
        _, _, _, _, _, fsm_a, _, _, _ = self._open()
        bundle = _bundle(fsm_a.atom.session_context)
        bundle.compliance_proofs = [{"proof": {"value": "original"}}]
        original_hash = bundle.content_hash

        def nested_mutating_verifier(candidate):
            candidate.compliance_proofs[0]["proof"]["value"] = "mutated"
            return afp.BundleVerificationResult(
                bundle_content_hash=original_hash,
                verified=True,
            )

        with self.assertRaisesRegex(afp.BundleError, "mutated the bundle"):
            afp.verify_bundle(
                bundle,
                expected_session_context=fsm_a.atom.session_context,
                bundle_verifier=nested_mutating_verifier,
            )

    def test_receive_rejects_mutating_verifier_without_state_change(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a, bundle=_bundle(fsm_a.atom.session_context), message_class="result"
        )
        original_hash = env.bundle.content_hash

        def mutating_verifier(candidate):
            candidate.compliance_proofs.append("injected-after-signature")
            return afp.BundleVerificationResult(
                bundle_content_hash=original_hash,
                verified=True,
            )

        with self.assertRaisesRegex(afp.BundleError, "mutated the bundle"):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=mutating_verifier,
            )
        self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)
        self.assertEqual(B.inbox.get(fsm_b.atom.id, []), [])

    def test_receive_detaches_accepted_envelope_from_verifier_reference(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        env = A.build_envelope(
            fsm_a, bundle=_bundle(fsm_a.atom.session_context), message_class="result"
        )
        retained = []

        def retaining_verifier(candidate):
            retained.append(candidate)
            return afp.BundleVerificationResult.accepted(candidate)

        received = B.receive_envelope(
            fsm_b,
            a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
            message_class="result",
            channel=b_channel,
            sender_remote=rA,
            bundle_verifier=retaining_verifier,
        )
        accepted_hash = received.content_hash
        retained[0].coord_proof = "mutated-after-return"
        self.assertEqual(received.content_hash, accepted_hash)
        self.assertEqual(B.inbox[fsm_b.atom.id][0].content_hash, accepted_hash)

    def test_rejected_envelope_does_not_activate_session_or_inbox(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)
        env = A.build_envelope(
            fsm_a,
            bundle=afp.ZkaBundle(
                kind="zka:bundle:v1",
                context="0x" + "11" * 32,
                coord_proof="opaque",
            ),
            message_class="result",
        )
        with self.assertRaisesRegex(
            afp.BundleError, "canonical BN254 projection"
        ):
            B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(env.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=rA,
                bundle_verifier=_accept_bundle,
            )
        self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)
        self.assertEqual(B.inbox.get(fsm_b.atom.id, []), [])

    def test_noncanonical_or_out_of_field_bundle_contexts_fail_closed(self):
        _, A, B, rA, _, fsm_a, fsm_b, a_channel, b_channel = self._open()
        modulus = (
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        )
        invalid_contexts = (
            "0x" + "00" * 32,
            f"0x{modulus:064x}",
            "0X" + "11" * 32,
            "0x" + "AA" * 32,
            "11" * 32,
            "0x11",
        )
        for context in invalid_contexts:
            with self.subTest(context=context):
                bundle = afp.ZkaBundle(
                    kind="zka:bundle:v1", context=context, coord_proof="opaque"
                )
                envelope = A.build_envelope(
                    fsm_a, bundle=bundle, message_class="result"
                )
                with self.assertRaises(afp.BundleError):
                    B.receive_envelope(
                        fsm_b,
                        a_channel.seal(
                            canonical_bytes(envelope.to_dict()),
                            message_class="result",
                        ),
                        message_class="result",
                        channel=b_channel,
                        sender_remote=rA,
                        bundle_verifier=_accept_bundle,
                    )
                self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)

    def test_cannot_send_before_open(self):
        _, A, B, _, rB = make_pair()
        fsm_a = A.propose(
            responder_tenant_aid=B.tenant_aid,
            responder_entity_aid=B.entity_aid,
            agreement_ref="agr",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=rB,
        )
        with self.assertRaises(afp.SessionError):
            A.build_envelope(
                fsm_a, bundle=_bundle(fsm_a.atom.session_context), message_class="result"
            )
        with self.assertRaises(TypeError):
            A.send_envelope(
                fsm_a, bundle=_bundle(fsm_a.atom.session_context), message_class="result"
            )


if __name__ == "__main__":
    unittest.main()
