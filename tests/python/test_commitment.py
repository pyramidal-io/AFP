"""Commitment + optional anchor tests (§12.6)."""

import _path  # noqa: F401

import unittest

import afp_session as afp
from afp_session import keri
from fixtures import make_witness


def _identities():
    tA = keri.Identity.incept_tenant()
    eA = keri.Identity.incept_entity(tA)
    tB = keri.Identity.incept_tenant()
    eB = keri.Identity.incept_entity(tB)
    return tA, eA, tB, eB


def _signed_commitment(eA, eB, seq=0, prev=None):
    c = afp.build_commitment(
        commitment_id=f"commit-{seq}",
        session_ref="sess-1",
        outcome_root=afp.outcome_root_for({"seq": seq}),
        profile="work",
        sequence_number=seq,
        previous_commitment_ref=prev,
    )
    afp.sign_commitment(c, eA, role="initiator")
    afp.sign_commitment(c, eB, role="responder")
    return c


class CommitmentTest(unittest.TestCase):
    def setUp(self):
        self.tA, self.eA, self.tB, self.eB = _identities()

    def test_fully_signed_commitment_verifies(self):
        c = _signed_commitment(self.eA, self.eB)
        afp.verify_commitment(
            c,
            initiator_kel=self.eA.kel,
            responder_kel=self.eB.kel,
            initiator_tenant_kel=self.tA.kel,
            responder_tenant_kel=self.tB.kel,
            initiator_witness_keys={},
            responder_witness_keys={},
        )

    def test_one_signature_is_not_a_commitment(self):
        c = afp.build_commitment(
            commitment_id="c1",
            session_ref="sess-1",
            outcome_root=afp.outcome_root_for("o"),
            profile="work",
            sequence_number=0,
        )
        afp.sign_commitment(c, self.eA, role="initiator")
        self.assertFalse(c.is_fully_signed)
        with self.assertRaises(afp.CommitmentError):
            afp.verify_commitment(
                c,
                initiator_kel=self.eA.kel,
                responder_kel=self.eB.kel,
                initiator_tenant_kel=self.tA.kel,
                responder_tenant_kel=self.tB.kel,
                initiator_witness_keys={},
                responder_witness_keys={},
            )

    def test_forged_signature_rejected(self):
        c = _signed_commitment(self.eA, self.eB)
        sig = bytearray(bytes.fromhex(c.responder_signature.signature))
        sig[0] ^= 0x01
        c.responder_signature.signature = bytes(sig).hex()
        with self.assertRaises(afp.CommitmentError):
            afp.verify_commitment(
                c,
                initiator_kel=self.eA.kel,
                responder_kel=self.eB.kel,
                initiator_tenant_kel=self.tA.kel,
                responder_tenant_kel=self.tB.kel,
                initiator_witness_keys={},
                responder_witness_keys={},
            )

    def test_stale_keystate_signature_rejected(self):
        c = _signed_commitment(self.eA, self.eB)
        # Rotate eB after signing -> its pinned kel_event_dig is now stale (§12.3).
        self.eB.rotate()
        with self.assertRaises(keri.StaleKeyStateError):
            afp.verify_commitment(
                c,
                initiator_kel=self.eA.kel,
                responder_kel=self.eB.kel,
                initiator_tenant_kel=self.tA.kel,
                responder_tenant_kel=self.tB.kel,
                initiator_witness_keys={},
                responder_witness_keys={},
            )

    def test_outcome_opacity(self):
        # The commitment carries only the root, not the cleartext outcome.
        root = afp.outcome_root_for({"secret": "amount=500"})
        c = afp.build_commitment(
            commitment_id="c1",
            session_ref="s",
            outcome_root=root,
            profile="work",
            sequence_number=0,
        )
        self.assertNotIn("amount", afp.AfpCommitmentAtom.content_to_sign.__doc__ or "")
        self.assertEqual(c.outcome_root, root)
        self.assertNotIn("500", c.outcome_root)


class ChainingTest(unittest.TestCase):
    def setUp(self):
        self.tA, self.eA, self.tB, self.eB = _identities()

    def test_monotonic_chain_verifies(self):
        c0 = _signed_commitment(self.eA, self.eB, seq=0)
        c1 = _signed_commitment(self.eA, self.eB, seq=1, prev="commit-0")
        afp.verify_commitment(
            c1,
            initiator_kel=self.eA.kel,
            responder_kel=self.eB.kel,
            initiator_tenant_kel=self.tA.kel,
            responder_tenant_kel=self.tB.kel,
            initiator_witness_keys={},
            responder_witness_keys={},
            previous=c0,
        )

    def test_sequence_gap_detected(self):
        c0 = _signed_commitment(self.eA, self.eB, seq=0)
        c2 = _signed_commitment(self.eA, self.eB, seq=2, prev="commit-0")
        with self.assertRaises(afp.SequenceError):
            afp.verify_commitment(
                c2,
                initiator_kel=self.eA.kel,
                responder_kel=self.eB.kel,
                initiator_tenant_kel=self.tA.kel,
                responder_tenant_kel=self.tB.kel,
                initiator_witness_keys={},
                responder_witness_keys={},
                previous=c0,
            )

    def test_wrong_previous_ref_detected(self):
        c0 = _signed_commitment(self.eA, self.eB, seq=0)
        c1 = _signed_commitment(self.eA, self.eB, seq=1, prev="commit-wrong")
        with self.assertRaises(afp.SequenceError):
            afp.verify_commitment(
                c1,
                initiator_kel=self.eA.kel,
                responder_kel=self.eB.kel,
                initiator_tenant_kel=self.tA.kel,
                responder_tenant_kel=self.tB.kel,
                initiator_witness_keys={},
                responder_witness_keys={},
                previous=c0,
            )


class WitnessedCommitmentTest(unittest.TestCase):
    """Commitment verification must enforce every signer's KEL receipts."""

    def setUp(self):
        self.initiator_witness = make_witness()
        self.responder_witness = make_witness()
        self.tA = keri.Identity.incept_tenant(
            witnesses=[self.initiator_witness], threshold=1
        )
        self.eA = keri.Identity.incept_entity(
            self.tA, witnesses=[self.initiator_witness], threshold=1
        )
        self.tB = keri.Identity.incept_tenant(
            witnesses=[self.responder_witness], threshold=1
        )
        self.eB = keri.Identity.incept_entity(
            self.tB, witnesses=[self.responder_witness], threshold=1
        )
        self.initiator_keys = {self.initiator_witness.aid: self.initiator_witness.public_key}
        self.responder_keys = {self.responder_witness.aid: self.responder_witness.public_key}

    def _verify(self, commitment, **overrides):
        kwargs = {
            "initiator_kel": self.eA.kel,
            "responder_kel": self.eB.kel,
            "initiator_tenant_kel": self.tA.kel,
            "responder_tenant_kel": self.tB.kel,
            "initiator_witness_keys": self.initiator_keys,
            "responder_witness_keys": self.responder_keys,
        }
        kwargs.update(overrides)
        afp.verify_commitment(commitment, **kwargs)

    def test_witnessed_commitment_verifies_with_per_principal_maps(self):
        self._verify(_signed_commitment(self.eA, self.eB))

    def test_removed_receipts_fail_closed(self):
        commitment = _signed_commitment(self.eA, self.eB)
        event = self.eA.kel.events[0]
        self.eA.kel.receipts[event.digest] = []
        with self.assertRaises(keri.WitnessThresholdError):
            self._verify(commitment)

    def test_missing_or_malformed_witness_maps_fail_closed(self):
        commitment = _signed_commitment(self.eA, self.eB)
        for field, value in (
            ("initiator_witness_keys", None),
            ("responder_witness_keys", []),
        ):
            with self.subTest(field=field):
                with self.assertRaises(afp.CommitmentError):
                    self._verify(commitment, **{field: value})


class AnchorTest(unittest.TestCase):
    def setUp(self):
        self.tA, self.eA, self.tB, self.eB = _identities()

    def test_anchor_an_anchored_commitment(self):
        c = _signed_commitment(self.eA, self.eB)
        anchor = afp.anchor_commitment(
            c,
            anchor_id="anchor-1",
            chain="ethereum:base",
            transaction_id="0xabc",
            block_number=123,
            block_timestamp="2026-07-11T12:00:00Z",
            inclusion_proof="proof",
            parties=[self.eA.aid, self.eB.aid],
        )
        self.assertEqual(c.anchor_ref, "anchor-1")
        self.assertEqual(anchor.via, "apl")
        self.assertEqual(anchor.commitment_hash, c.content_hash)
        self.assertEqual(anchor.outcome_root, c.outcome_root)
        # Only hashes are anchored — never raw AIDs (§12.6.2).
        self.assertNotIn(self.eA.aid, anchor.parties)
        self.assertEqual(len(anchor.parties), 2)
        # §1.6.1: block_timestamp is a UTC datetime string on the wire.
        self.assertEqual(anchor.to_dict()["block_timestamp"], "2026-07-11T12:00:00Z")

    def test_anchor_to_dict_rechecks_a_mutated_block_timestamp(self):
        c = _signed_commitment(self.eA, self.eB)
        anchor = afp.anchor_commitment(
            c,
            anchor_id="anchor-2",
            chain="ethereum:base",
            transaction_id="0xabc",
            block_number=123,
            block_timestamp="2026-07-11T12:00:00Z",
            inclusion_proof="proof",
            parties=[self.eA.aid, self.eB.aid],
        )
        anchor.block_timestamp = 1752235200.0
        with self.assertRaises(ValueError):
            anchor.to_dict()

    def test_anchor_block_timestamp_is_a_utc_datetime_string(self):
        c = _signed_commitment(self.eA, self.eB)
        for bad in (1.0, 1752235200, True, None, "2026-07-11T12:00:00.0Z",
                    "2026-07-11T12:00:00+00:00", "2026-02-30T00:00:00Z"):
            with self.subTest(block_timestamp=bad), self.assertRaises(ValueError):
                afp.anchor_commitment(
                    c,
                    anchor_id="anchor-bad",
                    chain="ethereum:base",
                    transaction_id="0xabc",
                    block_number=123,
                    block_timestamp=bad,
                    inclusion_proof="proof",
                    parties=[self.eA.aid, self.eB.aid],
                )

    def test_cannot_anchor_unsigned_commitment(self):
        c = afp.build_commitment(
            commitment_id="c1",
            session_ref="s",
            outcome_root=afp.outcome_root_for("o"),
            profile="work",
            sequence_number=0,
        )
        with self.assertRaises(afp.CommitmentError):
            afp.anchor_commitment(
                c,
                anchor_id="a1",
                chain="ethereum:base",
                transaction_id="0x",
                block_number=1,
                block_timestamp="2026-07-11T12:00:00Z",
                inclusion_proof="p",
                parties=[self.eA.aid, self.eB.aid],
            )

    def test_no_anchor_is_conformant(self):
        # A commitment is fully valid without any anchor (§12.6.2 default).
        c = _signed_commitment(self.eA, self.eB)
        self.assertIsNone(c.anchor_ref)
        afp.verify_commitment(
            c,
            initiator_kel=self.eA.kel,
            responder_kel=self.eB.kel,
            initiator_tenant_kel=self.tA.kel,
            responder_tenant_kel=self.tB.kel,
            initiator_witness_keys={},
            responder_witness_keys={},
        )


if __name__ == "__main__":
    unittest.main()
