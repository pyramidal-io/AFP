"""Headline acceptance test for the AFP §12 Bilateral Session Core.

The requirement's acceptance criterion, verbatim:

    "two instances open/close a real bilateral session and exchange a signed
     envelope."

This test demonstrates exactly that with REAL cryptography and the full §12
lifecycle: two in-process :class:`Instance`s (distinct KERI tenant+entity
identities, sharing one in-memory transport) complete
propose→open→active→closing→closed and exchange a signed, signature-verified
``afp:envelope:v1`` carrying a ``zka:bundle:v1`` payload — with mutual KERI
identity binding verified up to each tenant root AID (§12.3), the envelope bound
to the session context (§12.7), and the bilateral commitment (§12.6) closing the
session. Tampering with the signature is shown to be rejected, so the
verification is genuine and not a no-op.
"""

import _path  # noqa: F401

import unittest

import afp_session as afp
from afp_session import keri
from afp_session.atoms import AfpSessionStatus
from afp_session.canonical import canonical_bytes
from fixtures import establish_channels

pytestmark = None  # this suite runs under unittest discovery (CI), no pytest marker needed


class BilateralSessionAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.transport = afp.InMemoryTransport()
        # Two distinct ADAMAS instances: tenant root + delegated entity each.
        self.tenant_a = keri.Identity.incept_tenant()
        self.entity_a = keri.Identity.incept_entity(self.tenant_a)
        self.tenant_b = keri.Identity.incept_tenant()
        self.entity_b = keri.Identity.incept_entity(self.tenant_b)
        self.A = afp.Instance(
            tenant=self.tenant_a, entity=self.entity_a, transport=self.transport
        )
        self.B = afp.Instance(
            tenant=self.tenant_b, entity=self.entity_b, transport=self.transport
        )
        # Each side's verifier-facing material for the other (§12.3).
        self.remote_a = afp.RemoteParty(
            self.entity_a.kel, self.tenant_a.kel, witness_keys={}
        )
        self.remote_b = afp.RemoteParty(
            self.entity_b.kel, self.tenant_b.kel, witness_keys={}
        )

    def test_two_instances_open_exchange_signed_envelope_and_close(self):
        # --- propose -> open (mutual authentication, §12.2.2 / §12.3) ---------
        fsm_a = self.A.propose(
            responder_tenant_aid=self.tenant_b.aid,
            responder_entity_aid=self.entity_b.aid,
            responder_remote=self.remote_b,
            agreement_ref="agreement-ab",
            agreement_version="1.0",
            profile="work",
            profile_policy_hash="policyhash",
        )
        self.assertEqual(fsm_a.status, AfpSessionStatus.PROPOSED)

        # B verifies A's identity binding up to A's tenant root, accepts -> OPEN.
        fsm_b = self.B.accept(fsm_a.atom, initiator_remote=self.remote_a)
        self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)

        # A verifies B's responder ref and confirms open on its own copy -> OPEN.
        self.A.confirm_open(fsm_a, fsm_b.atom, responder_remote=self.remote_b)
        self.assertEqual(fsm_a.status, AfpSessionStatus.OPEN)

        a_channel, b_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )

        # Both sides bound the SAME session context (§12.3).
        self.assertEqual(fsm_a.atom.session_context, fsm_b.atom.session_context)

        # --- active: exchange a signed, signature-verified envelope (§12.7) ---
        bundle = afp.ZkaBundle(
            kind="zka:bundle:v1",
            context=afp.session_context_field(
                fsm_a.atom.session_context
            ),
            coord_proof="opaque-zka-coord-proof",
            compliance_proofs=["opaque-zkc-proof"],
        )
        envelope = self.A.send_envelope(
            fsm_a, bundle=bundle, message_class="result", channel=a_channel
        )
        self.assertEqual(fsm_a.status, AfpSessionStatus.ACTIVE)  # first exchange -> ACTIVE

        received = self.B.receive_envelope(
            fsm_b,
            self.transport.published[-1][1],
            message_class="result",
            channel=b_channel,
            sender_remote=self.remote_a,
            bundle_verifier=afp.BundleVerificationResult.accepted,
        )
        self.assertEqual(fsm_b.status, AfpSessionStatus.ACTIVE)
        # The envelope round-tripped, signature verified, and is in B's inbox.
        self.assertEqual(received.message_class, "result")
        self.assertEqual(
            received.bundle.context,
            afp.session_context_field(fsm_b.atom.session_context),
        )
        self.assertEqual(len(self.B.inbox[fsm_b.atom.id]), 1)

        # It actually traversed the transport on the §12.4 namespace.
        self.assertTrue(self.transport.published)
        published_subject, published_frame = self.transport.published[0]
        self.assertTrue(published_subject.startswith("afp."))
        self.assertIn(".work.", published_subject)
        self.assertTrue(published_frame.startswith(b"afp:sealed:v1\0"))
        self.assertNotIn(canonical_bytes(envelope.to_dict()), published_frame)
        self.assertNotIn(b"opaque-zka-coord-proof", published_frame)

        # --- a bilateral commitment justifies the clean close (§12.6) --------
        outcome_root = afp.outcome_root_for({"work": "done", "result": "ok"})
        commitment = afp.build_commitment(
            commitment_id="commit-1",
            session_ref=fsm_a.atom.id,
            outcome_root=outcome_root,
            profile="work",
            sequence_number=0,
        )
        afp.sign_commitment(commitment, self.entity_a, role="initiator")
        afp.sign_commitment(commitment, self.entity_b, role="responder")
        afp.verify_commitment(
            commitment,
            initiator_kel=self.entity_a.kel,
            responder_kel=self.entity_b.kel,
            initiator_tenant_kel=self.tenant_a.kel,
            responder_tenant_kel=self.tenant_b.kel,
            initiator_witness_keys={},
            responder_witness_keys={},
        )
        self.assertTrue(commitment.is_fully_signed)

        # --- closing -> closed (§12.2.2) -------------------------------------
        self.A.begin_close(fsm_a)
        self.assertEqual(fsm_a.status, AfpSessionStatus.CLOSING)
        self.A.complete_close(fsm_a)
        self.assertEqual(fsm_a.status, AfpSessionStatus.CLOSED)
        self.B.close(fsm_b)
        self.assertEqual(fsm_b.status, AfpSessionStatus.CLOSED)

    def test_envelope_signature_verification_is_genuine(self):
        """A tampered envelope signature MUST be rejected (verification is real)."""
        fsm_a = self.A.propose(
            responder_tenant_aid=self.tenant_b.aid,
            responder_entity_aid=self.entity_b.aid,
            responder_remote=self.remote_b,
            agreement_ref="agreement-ab",
            agreement_version="1.0",
            profile="work",
            profile_policy_hash="policyhash",
        )
        fsm_b = self.B.accept(fsm_a.atom, initiator_remote=self.remote_a)
        self.A.confirm_open(fsm_a, fsm_b.atom, responder_remote=self.remote_b)
        a_channel, b_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )

        bundle = afp.ZkaBundle(
            kind="zka:bundle:v1",
            context=afp.session_context_field(
                fsm_a.atom.session_context
            ),
            coord_proof="opaque",
        )
        envelope = self.A.send_envelope(
            fsm_a, bundle=bundle, message_class="result", channel=a_channel
        )

        # Flip one byte of the signature.
        sig = bytearray(bytes.fromhex(envelope.sender.signature))
        sig[0] ^= 0x01
        envelope.sender.signature = bytes(sig).hex()

        with self.assertRaises(afp.IdentityBindingError):
            self.B.receive_envelope(
                fsm_b,
                a_channel.seal(canonical_bytes(envelope.to_dict()), message_class="result"),
                message_class="result",
                channel=b_channel,
                sender_remote=self.remote_a,
                bundle_verifier=afp.BundleVerificationResult.accepted,
            )

    def test_plaintext_and_wrong_version_frames_fail_closed(self):
        fsm_a = self.A.propose(
            responder_tenant_aid=self.tenant_b.aid,
            responder_entity_aid=self.entity_b.aid,
            responder_remote=self.remote_b,
            agreement_ref="agreement-ab",
            agreement_version="1.0",
            profile="work",
            profile_policy_hash="policyhash",
        )
        fsm_b = self.B.accept(fsm_a.atom, initiator_remote=self.remote_a)
        self.A.confirm_open(fsm_a, fsm_b.atom, responder_remote=self.remote_b)
        _, b_channel = establish_channels(
            self.A, self.B, self.remote_a, self.remote_b, fsm_a.atom
        )
        plaintext = canonical_bytes(
            afp.AfpEnvelope(
                session_ref=fsm_a.atom.id,
                session_context=fsm_a.atom.session_context,
                profile="work",
                bundle=afp.ZkaBundle(
                    kind="zka:bundle:v1",
                    context=afp.session_context_field(
                        fsm_a.atom.session_context
                    ),
                    coord_proof="opaque",
                ),
                message_class="result",
                generated_at=0,
                expires_at=1,
            ).to_dict()
        )
        wrong_version = b"afp:sealed:v2\0" + b"\0" * 62
        for frame in (plaintext, wrong_version):
            with self.subTest(frame=frame[:16]):
                with self.assertRaises(afp.ChannelError):
                    self.B.receive_envelope(
                        fsm_b,
                        frame,
                        message_class="result",
                        channel=b_channel,
                        sender_remote=self.remote_a,
                        bundle_verifier=afp.BundleVerificationResult.accepted,
                    )
                self.assertNotIn(fsm_b.atom.id, self.B.inbox)
                self.assertEqual(fsm_b.status, AfpSessionStatus.OPEN)
                self.assertIsNone(b_channel.receive_highest_sequence)

    def test_envelope_content_hash_golden_is_stable(self):
        """Sealing is transport-only and cannot alter the §12.7 signed content."""
        context = "X_" + "01" * 32
        envelope = afp.AfpEnvelope(
            session_ref="sess-golden",
            session_context=context,
            profile="work",
            bundle=afp.ZkaBundle(
                kind="zka:bundle:v1",
                context=afp.session_context_field(context),
                coord_proof="golden",
            ),
            message_class="result",
            generated_at=1_700_000_000,
            expires_at=1_700_000_600,
            sender=afp.AfpPartyRef(
                tenant_aid="T_" + "02" * 32,
                entity_aid="E_" + "03" * 32,
                kel_event_dig="D_" + "04" * 32,
                signature="05" * 64,
            ),
        )
        self.assertEqual(
            envelope.content_hash,
            "D_5d210c5d34c2da63ffd68354b5dea702ec6bc0bce61164e499e95f2f4f6b20e0",
        )


if __name__ == "__main__":
    unittest.main()
